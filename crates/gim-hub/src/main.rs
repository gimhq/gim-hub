//! gim hub server binary.

use std::{sync::Arc, time::Duration};

use gim_hub_api::{AppState, Clock, Config, HubIdentity, Notifier};
use gim_hub_db::Db;
use tracing_subscriber::EnvFilter;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let pruning = tokio::spawn(prune_events_periodically(state.clone()));
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

/// Deletes events older than the retention window, now and then hourly.
async fn prune_events_periodically(state: AppState) {
    let mut interval = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        interval.tick().await;
        let cutoff = state.clock.now_ms() - i64::from(state.config.event_retention_days) * DAY_MS;
        match state
            .db
            .write(move |tx| gim_hub_db::events::prune_before(tx, cutoff))
            .await
        {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(deleted, "pruned events"),
            Err(err) => tracing::error!(%err, "event pruning failed"),
        }
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
