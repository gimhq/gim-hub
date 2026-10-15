//! gim hub server binary.

use std::{
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use gim_hub_api::{AppState, Clock, Config, HubIdentity, Notifier};
use gim_hub_db::Db;
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
        Some(other) => {
            return Err(format!("unknown command {other:?}; usage: gim-hub [healthcheck]").into())
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let state = open_state(config)?;
    tracing::info!(hub_id = %state.hub.hub_id(), "hub identity loaded");

    let listener = tokio::net::TcpListener::bind(state.config.listen).await?;
    tracing::info!(listen = %state.config.listen, "gim-hub listening");

    let pruning = tokio::spawn(prune_periodically(state.clone()));
    axum::serve(listener, gim_hub_api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    pruning.abort();
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
    Ok(AppState {
        db,
        config: Arc::new(config),
        hub,
        notifier: Notifier::default(),
        clock: Clock::system(),
    })
}

/// Deletes events older than the retention window and expired link bundles,
/// now and then hourly.
async fn prune_periodically(state: AppState) {
    let mut interval = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        interval.tick().await;
        match prune(&state).await {
            Ok((0, 0)) => {}
            Ok((events, link_bundles)) => tracing::info!(events, link_bundles, "pruned"),
            Err(err) => tracing::error!(%err, "pruning failed"),
        }
    }
}

/// Runs one pruning pass; returns the deleted events and link bundles.
async fn prune(state: &AppState) -> Result<(usize, usize), gim_hub_db::DbError> {
    let now = state.clock.now_ms();
    let cutoff = now - i64::from(state.config.event_retention_days) * DAY_MS;
    state
        .db
        .write(move |tx| {
            Ok((
                gim_hub_db::events::prune_before(tx, cutoff)?,
                gim_hub_db::links::prune_expired(tx, now)?,
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
        assert_eq!(prune(&hub.state).await.unwrap(), (0, 1));
        assert_eq!(prune(&hub.state).await.unwrap(), (0, 0));
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
