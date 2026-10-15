//! gim hub server binary.

use std::{
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use gim_hub_api::{AppState, Clock, Config, HubIdentity};
use gim_hub_db::Db;
use gim_hub_push::{Dispatcher, DispatcherSettings, PushLog};
use gim_hub_s2s::{
    ops::hosting_record::HostingRecordService, FederationConfig, FederationService, GroupService,
    GroupSource, Hosting, HostingSettings, Outbox, OutboxConfig, PushGate,
};
use tracing_subscriber::EnvFilter;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("healthcheck") => {
            let config = Config::from_env()?;
            return Ok(healthcheck(probe_addr(config.listen))?);
        }
        Some("hub-id") => {
            let config = Config::from_env()?;
            println!(
                "{}",
                HubIdentity::load_or_create(&config.hub_key_path())?.hub_id()
            );
            return Ok(());
        }
        Some("version" | "--version") => {
            println!(
                "gim-hub {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("GIM_HUB_BUILD_REV").unwrap_or("unknown")
            );
            return Ok(());
        }
        Some(other) => {
            return Err(format!(
                "unknown command {other:?}; usage: gim-hub [healthcheck|hub-id|version]"
            )
            .into())
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let federation_config = FederationConfig::from_env(&config.data_dir)?;
    let mut state = open_state(config)?;
    tracing::info!(hub_id = %state.hub.hub_id(), "hub identity loaded");
    let push = start_push(&mut state).await?;
    let federation = start_federation(&federation_config, &state).await?;
    let (republish, outbox) = match &federation {
        Some(service) => {
            let (republish, outbox) = enable_federation(&mut state, service, &federation_config);
            (republish, Some(outbox))
        }
        None => (None, None),
    };
    let push_gate = match &federation {
        Some(service) => Some(install_push_gate(&state, service).await),
        None => None,
    };
    // Registered last: the handlers keep a copy of the final state.
    let _ops = federation
        .as_ref()
        .map(|service| register_ops(&state, service));

    let listener = tokio::net::TcpListener::bind(state.config.listen).await?;
    tracing::info!(listen = %state.config.listen, "gim-hub listening");

    let pruning = tokio::spawn(prune_periodically(state.clone()));
    axum::serve(
        listener,
        gim_hub_api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    pruning.abort();
    for task in push {
        task.abort();
    }
    if let Some(republish) = republish {
        republish.abort();
    }
    if let Some(push_gate) = push_gate {
        push_gate.abort();
    }
    if let Some(outbox) = outbox {
        outbox.shutdown();
    }
    if let Some(federation) = federation {
        federation.shutdown();
    }
    tracing::info!("gim-hub stopped");
    Ok(())
}

/// Creates the data directory, opens the database (applying migrations) and
/// loads or creates the hub key.
fn open_state(config: Config) -> Result<AppState, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::create_dir_all(config.blobs_dir())?;
    let db = Db::open(&config.database_path)?;
    let hub = HubIdentity::load_or_create(&config.hub_key_path())?;
    Ok(AppState::new(db, config, hub, Clock::system()))
}

/// Replaces the default push dispatcher with one on the configured providers,
/// tailing events from the current head, and starts it.
async fn start_push(
    state: &mut AppState,
) -> Result<Vec<tokio::task::JoinHandle<()>>, Box<dyn std::error::Error>> {
    let log = PushLog::default();
    let providers = gim_hub_push::build_providers(&state.config.push, log.clone())?;
    let names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
    let head = state.db.read(gim_hub_db::events::head_cursor).await?;
    state.push = Dispatcher::new(
        state.db.clone(),
        providers,
        log,
        DispatcherSettings::from(&state.config.push),
        head,
    );
    tracing::info!(providers = ?names, "push dispatcher started");
    Ok(state.push.start())
}

/// Starts the federation service when `GIM_HUB_FEDERATION=true`.
async fn start_federation(
    config: &FederationConfig,
    state: &AppState,
) -> Result<Option<FederationService>, Box<dyn std::error::Error>> {
    if !config.enabled {
        tracing::info!("federation disabled");
        return Ok(None);
    }
    let federation =
        FederationService::start_with_allowlist(config, state.hub.signing_key()).await?;
    tracing::info!(
        addrs = ?federation.transport().advertised_addrs(),
        "federation started"
    );
    Ok(Some(federation))
}

/// Wires a started federation service into `state`: S2S sends, hosting
/// resolution through peers and the DHT, the `/gim/user/` validator, the
/// `GetHostingRecord` op and the outbox. Returns the hosting record
/// republish task and the started outbox.
fn enable_federation(
    state: &mut AppState,
    service: &FederationService,
    config: &FederationConfig,
) -> (Option<tokio::task::JoinHandle<()>>, Outbox) {
    state.federation = Arc::new(service.clone());
    state.hosting = Hosting::new(
        state.db.clone(),
        state.hub.hub_id().clone(),
        state.federation.clone(),
        Some(service.transport().clone()),
        HostingSettings::from_config(config),
        state.clock.as_now(),
    );
    state.hosting.register(service);
    let outbox = start_outbox(config, state, service);
    state.outbox = Arc::new(outbox.clone());
    state.device_lists = state.device_lists.with_federation(
        state.federation.clone(),
        state.hosting.clone(),
        Duration::from_secs(u64::from(config.device_list_cache_hours) * 3600),
    );
    (state.hosting.spawn_republisher(), outbox)
}

/// Installs the multi-homing push gate (docs/multihoming.md §8) on the push
/// dispatcher. Stored records of local users update its view at once; the
/// returned task reloads the view and keeps the co-host connections current.
async fn install_push_gate(
    state: &AppState,
    service: &FederationService,
) -> tokio::task::JoinHandle<()> {
    let (gate, task) =
        PushGate::start(state.db.clone(), service.transport(), state.clock.as_now()).await;
    let listener = gate.clone();
    state
        .hosting
        .set_local_record_listener(Arc::new(move |record| listener.set_record(record)));
    state.push.set_gate(Arc::new(move |user_id, _device_id| {
        gate.should_push(user_id)
    }));
    task
}

/// Registers the remote identity ops (`GetDeviceList`, `NotifyDeviceList`,
/// `ClaimKeyPackage`), the group ops (`SubmitCommit`, `SubmitMessage`,
/// `Deliver`, `DeliverWelcome`, `FetchLog`, `SeedReplica`,
/// `CopyPendingWelcomes`, plus the replica bootstrap hub-set hook),
/// `NotifyHostingRecord` and `FetchBlob` with handlers on `state`. Returns
/// the claim, group, hosting record and blob handlers, which must be kept
/// alive.
fn register_ops(
    state: &AppState,
    service: &FederationService,
) -> (
    Arc<gim_hub_s2s::ClaimService>,
    Arc<GroupService>,
    Arc<HostingRecordService>,
    Arc<gim_hub_s2s::BlobService>,
) {
    gim_hub_api::handlers::register_device_list_ops(state, service);
    (
        gim_hub_api::handlers::register_claim_op(state, service),
        gim_hub_api::handlers::register_group_ops(state, service),
        gim_hub_api::handlers::register_hosting_record_op(state, service),
        gim_hub_api::handlers::register_blob_op(state, service),
    )
}

/// Starts the S2S outbox worker, sending through `federation`. Entries are
/// built from the group log and the `users` table ([`GroupSource`]); an
/// `UNAUTHORIZED` refreshes hosting records through `state.hosting`.
fn start_outbox(
    config: &FederationConfig,
    state: &AppState,
    federation: &FederationService,
) -> Outbox {
    let outbox = Outbox::new(
        state.db.clone(),
        Arc::new(federation.clone()),
        Arc::new(GroupSource::new(state.hub.hub_id().clone()).with_hosting(state.hosting.clone())),
        OutboxConfig::from(config),
    );
    outbox.start(Some(federation.transport().subscribe()));
    outbox
}

/// Deletes events and detached replicas older than the retention window and
/// expired link bundles, expires hosting records and emits `hosting_record.expiring`, and purges
/// users removed longer than `GIM_HUB_UNHOSTED_GRACE_HOURS` ago, now and
/// then hourly.
async fn prune_periodically(state: AppState) {
    let mut interval = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        interval.tick().await;
        match prune(&state).await {
            Ok((0, 0, 0)) => {}
            Ok((events, link_bundles, replicas)) => {
                tracing::info!(events, link_bundles, replicas, "pruned")
            }
            Err(err) => tracing::error!(%err, "pruning failed"),
        }
        match gim_hub_api::handlers::prune_remote_claims(&state).await {
            Ok(0) => {}
            Ok(claims) => tracing::info!(claims, "remote KeyPackage claims pruned"),
            Err(err) => tracing::error!(%err, "pruning remote KeyPackage claims failed"),
        }
        match gim_hub_api::handlers::check_hosting_records(&state).await {
            Ok((0, 0)) => {}
            Ok((expired, notified)) => {
                tracing::info!(expired, notified, "hosting records checked")
            }
            Err(err) => tracing::error!(%err, "hosting record check failed"),
        }
        match gim_hub_api::handlers::purge_removed_users(&state).await {
            Ok(0) => {}
            Ok(users) => tracing::info!(users, "removed users purged"),
            Err(err) => tracing::error!(%err, "purging removed users failed"),
        }
    }
}

/// Runs one pruning pass; returns the deleted events, link bundles and
/// detached replicas (docs/federation.md §5.4).
async fn prune(state: &AppState) -> Result<(usize, usize, usize), gim_hub_db::DbError> {
    let now = state.clock.now_ms();
    let cutoff = now - i64::from(state.config.event_retention_days) * DAY_MS;
    state
        .db
        .write(move |tx| {
            Ok((
                gim_hub_db::events::prune_before(tx, cutoff)?,
                gim_hub_db::links::prune_expired(tx, now)?,
                gim_hub_db::groups::delete_detached_replicas(tx, cutoff)?,
            ))
        })
        .await
}

/// Address the healthcheck connects to: the listen address, with an
/// unspecified IP replaced by loopback.
fn probe_addr(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        ip if !ip.is_unspecified() => ip,
        IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
    };
    SocketAddr::new(ip, listen.port())
}

/// `gim-hub healthcheck`: succeeds if `GET /healthz` on `addr` returns 200.
/// Used by the container HEALTHCHECK, so the image needs no HTTP client.
fn healthcheck(addr: SocketAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&addr, HEALTHCHECK_TIMEOUT)?;
    stream.set_read_timeout(Some(HEALTHCHECK_TIMEOUT))?;
    stream.set_write_timeout(Some(HEALTHCHECK_TIMEOUT))?;
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status_line = String::new();
    BufReader::new(stream).read_line(&mut status_line)?;
    if status_line.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "unhealthy: {:?}",
            status_line.trim_end()
        )))
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use gim_hub_api::testing::TestHub;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn healthz_reports_ok_and_version() {
        let response = TestHub::new()
            .router()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value,
            json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") })
        );
    }

    async fn serve(router: axum::Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn healthcheck_passes_against_running_hub() {
        let hub = TestHub::new();
        let addr = serve(hub.router()).await;
        tokio::task::spawn_blocking(move || healthcheck(addr))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn healthcheck_fails_on_error_status_or_no_listener() {
        let router = axum::Router::new().route(
            "/healthz",
            axum::routing::get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        let addr = serve(router).await;
        let result = tokio::task::spawn_blocking(move || healthcheck(addr))
            .await
            .unwrap();
        assert!(result.unwrap_err().to_string().contains("503"));

        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(healthcheck(closed).is_err());
    }

    #[test]
    fn probe_addr_uses_loopback_for_unspecified_ip() {
        let probe = |listen: &str| probe_addr(listen.parse().unwrap()).to_string();
        assert_eq!(probe("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(probe("[::]:8080"), "[::1]:8080");
        assert_eq!(probe("10.0.0.5:9000"), "10.0.0.5:9000");
    }

    #[tokio::test]
    async fn prune_deletes_expired_link_bundles() {
        let hub = TestHub::new();
        let now = hub.state.clock.now_ms();
        hub.state
            .db
            .write(move |tx| {
                gim_hub_db::links::insert(tx, "expired-link-0001", b"a", now - 2, now - 1)?;
                gim_hub_db::links::insert(tx, "live-link-000001", b"b", now, now + 60_000)
            })
            .await
            .unwrap();
        assert_eq!(prune(&hub.state).await.unwrap(), (0, 1, 0));
        assert_eq!(prune(&hub.state).await.unwrap(), (0, 0, 0));
    }

    #[tokio::test]
    async fn prune_deletes_detached_replicas_past_retention() {
        let hub = TestHub::new();
        let now = hub.state.clock.now_ms();
        let retention = i64::from(hub.state.config.event_retention_days) * DAY_MS;
        hub.state
            .db
            .write(move |tx| {
                for gid in ["h2/old", "h2/recent"] {
                    let group = gim_hub_db::groups::Group {
                        gid: gid.into(),
                        kind: "group".into(),
                        epoch: 0,
                        last_seq: 0,
                        created_by_user_id: "u".into(),
                        created_by_device_id: "d".into(),
                        created_at: 0,
                    };
                    gim_hub_db::groups::create_replica(tx, &group, &[], now)?;
                }
                gim_hub_db::groups::set_detached(tx, "h2/old", Some(now - retention - 1))?;
                gim_hub_db::groups::set_detached(tx, "h2/recent", Some(now - retention + 60_000))
            })
            .await
            .unwrap();
        assert_eq!(prune(&hub.state).await.unwrap(), (0, 0, 1));
        let left = |gid: &'static str| {
            hub.state
                .db
                .read(move |conn| gim_hub_db::groups::get(conn, gid))
        };
        assert!(left("h2/old").await.unwrap().is_none());
        assert!(left("h2/recent").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn push_starts_with_log_provider_only_by_default() {
        let mut state = TestHub::new().state.clone();
        let tasks = start_push(&mut state).await.unwrap();
        assert!(!tasks.is_empty());
        for task in tasks {
            task.abort();
        }
        assert_eq!(state.push.metrics(), Default::default());
    }

    #[tokio::test]
    async fn federation_is_off_by_default() {
        let hub = TestHub::new();
        let config = FederationConfig::from_vars(Vec::new(), &hub.state.config.data_dir).unwrap();
        assert!(start_federation(&config, &hub.state)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn federation_starts_when_enabled_and_fails_without_allowlist() {
        let hub = TestHub::new();
        let data_dir = hub.state.config.data_dir.clone();
        let config = |allowlist: &std::path::Path| {
            FederationConfig::from_vars(
                [
                    ("GIM_HUB_FEDERATION", "true"),
                    ("GIM_HUB_P2P_LISTEN", "/ip4/127.0.0.1/tcp/0"),
                    ("GIM_HUB_FEDERATION_ALLOWLIST", allowlist.to_str().unwrap()),
                ]
                .map(|(k, v)| (k.to_owned(), v.to_owned())),
                &data_dir,
            )
            .unwrap()
        };
        let allowlist = data_dir.join("allowlist");
        assert!(start_federation(&config(&allowlist), &hub.state)
            .await
            .is_err());

        let peer = HubIdentity::from_seed(&[9; 32]);
        std::fs::write(&allowlist, format!("{}\n", peer.hub_id())).unwrap();
        let federation = start_federation(&config(&allowlist), &hub.state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(federation.hub_id(), hub.state.hub.hub_id());
        assert!(data_dir.join("runtime_key").is_file());
        assert!(data_dir.join("runtime_cert").is_file());
        let mut state = hub.state.clone();
        let (republish, outbox) = enable_federation(&mut state, &federation, &config(&allowlist));
        assert!(state.federation.is_enabled());
        drop(register_ops(&state, &federation));
        republish.unwrap().abort();
        outbox.shutdown();
        federation.shutdown();
    }

    #[tokio::test]
    async fn open_state_lays_out_data_dir_and_keeps_hub_key() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let config = || {
            Config::from_vars([(
                "GIM_HUB_DATA_DIR".to_owned(),
                dir.join("data").display().to_string(),
            )])
            .unwrap()
        };
        let first = open_state(config()).unwrap();
        assert!(dir.join("data/hub.db").is_file());
        assert!(dir.join("data/hub_key").is_file());
        assert!(dir.join("data/blobs").is_dir());
        let hub_id = first.hub.hub_id().clone();
        drop(first);
        assert_eq!(open_state(config()).unwrap().hub.hub_id(), &hub_id);
    }
}
