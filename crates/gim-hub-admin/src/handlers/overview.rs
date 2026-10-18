//! GET /admin/api/overview.

use std::path::{Path, PathBuf};

use axum::{extract::State, Json};
use gim_hub_api::dto::Error;
use gim_hub_db::admin;

use crate::{
    auth::seconds,
    dto::{Counts, Overview, PushCounters, Storage},
    error::AdminError,
    state::AdminState,
};

#[utoipa::path(
    get,
    path = "/admin/api/overview",
    tag = "overview",
    summary = "Hub overview",
    description = "Version, uptime, storage sizes, aggregate counts and push counters. Group data \
is a count only.",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Overview", body = Overview),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_overview(State(state): State<AdminState>) -> Result<Json<Overview>, AdminError> {
    let counts = state.app.db.read(admin::counts).await?;
    let db_path = state.app.config.load().database_path.clone();
    let blobs_dir = state.app.config.load().blobs_dir();
    let storage = tokio::task::spawn_blocking(move || Storage {
        db_bytes: file_size(&db_path) + file_size(&wal_path(&db_path)),
        blob_bytes: dir_size(&blobs_dir),
    })
    .await
    .map_err(|err| AdminError::Internal(err.to_string()))?;
    let push = state.app.push.metrics();
    let now = state.now_ms();
    Ok(Json(Overview {
        version: state.app.config.load().release_version.clone(),
        revision: option_env!("GIM_HUB_BUILD_REV")
            .unwrap_or("unknown")
            .to_owned(),
        hub_id: state.app.hub.hub_id().to_string(),
        public_url: state.app.config.load().public_url.clone(),
        started_at: seconds(state.started_at),
        uptime_seconds: seconds(now - state.started_at).max(0),
        storage,
        counts: Counts {
            users: counts.users,
            devices: counts.devices,
            groups: counts.groups,
            blobs: counts.blobs,
        },
        push: PushCounters {
            enqueued: push.enqueued,
            coalesced: push.coalesced,
            upgraded: push.upgraded,
            dropped: push.dropped,
            sent: push.sent,
            skipped: push.skipped,
            invalid_token: push.invalid_token,
            retried: push.retried,
            failed: push.failed,
        },
        event_retention_days: state.app.config.load().event_retention_days,
    }))
}

fn wal_path(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |meta| meta.len())
}

/// Total size of the regular files under `dir`; unreadable entries count 0.
fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => dir_size(&entry.path()),
            Ok(kind) if kind.is_file() => entry.metadata().map_or(0, |meta| meta.len()),
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_files_and_nested_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), [0; 10]).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b"), [0; 5]).unwrap();
        assert_eq!(dir_size(dir.path()), 15);
        assert_eq!(dir_size(&dir.path().join("missing")), 0);
        assert_eq!(file_size(&dir.path().join("a")), 10);
        assert_eq!(
            wal_path(Path::new("/data/hub.db")),
            PathBuf::from("/data/hub.db-wal")
        );
    }
}
