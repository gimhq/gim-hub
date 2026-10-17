//! The lode panel: `$LODE_DIR/state.json` through the vendored lode SDK
//! (`crates/gim-hub/src/lode.rs`), whose requests are a locked
//! read-modify-write that keeps lode's fields.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    Extension, Json,
};
use gim_hub_api::dto::Error;

use crate::{
    auth::Caller,
    dto::{LodeHistoryEntry, LodeRollback, LodeState, LodeStatus, LodeUpdate},
    error::AdminError,
    handlers::users::optional_json,
    lode::{self, Lode},
    state::AdminState,
};

fn supervisor(state: &AdminState) -> Result<Arc<Lode>, AdminError> {
    state
        .lode
        .clone()
        .ok_or_else(|| AdminError::Unavailable("the hub is not supervised by lode".into()))
}

/// Runs a blocking lode SDK call.
async fn run<T: Send + 'static>(
    lode: Arc<Lode>,
    call: impl FnOnce(&Lode) -> lode::Result<T> + Send + 'static,
) -> Result<T, AdminError> {
    tokio::task::spawn_blocking(move || call(&lode))
        .await
        .map_err(|err| AdminError::Internal(err.to_string()))?
        .map_err(|err| AdminError::Internal(format!("lode: {err}")))
}

#[utoipa::path(
    get,
    path = "/admin/api/lode",
    tag = "lode",
    summary = "lode status",
    description = "`{\"supervised\":false}` unless `LODE_DIR` is set; otherwise lode's fields \
from `state.json` (all `null` before lode wrote it).",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Status", body = LodeStatus),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_lode(State(state): State<AdminState>) -> Result<Json<LodeStatus>, AdminError> {
    let Some(lode) = state.lode.clone() else {
        return Ok(Json(LodeStatus {
            supervised: false,
            state: None,
        }));
    };
    let st = run(lode, |lode| lode.read()).await?.unwrap_or_default();
    let status = st
        .status
        .and_then(|status| serde_json::to_value(status).ok())
        .and_then(|value| value.as_str().map(str::to_owned));
    Ok(Json(LodeStatus {
        supervised: true,
        state: Some(LodeState {
            status,
            current: st.current,
            available: st.available,
            last_good: st.last_good,
            last_check: st.last_check,
            last_error: st.last_error,
            history: st
                .history
                .into_iter()
                .map(|entry| LodeHistoryEntry {
                    version: entry.version,
                    at: entry.at,
                    result: entry.result,
                })
                .collect(),
        }),
    }))
}

#[utoipa::path(
    post,
    path = "/admin/api/lode/check",
    tag = "lode",
    summary = "Check for a newer version now",
    description = "Bumps `check_nonce`; lode reports the result in `available` or `check_error`. \
Audited as `lode_check`.",
    security(("adminSession" = [])),
    responses(
        (status = 202, description = "Requested"),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 503, description = "Not supervised by lode (`unavailable`)", body = Error),
    ),
)]
pub async fn lode_check(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
) -> Result<StatusCode, AdminError> {
    let result = match supervisor(&state) {
        Ok(lode) => run(lode, |lode| lode.request_check()).await,
        Err(err) => Err(err),
    };
    let detail = result
        .as_ref()
        .ok()
        .map(|nonce| format!("check_nonce {nonce}"));
    caller
        .audit(&state, "lode_check", None, &result, detail)
        .await;
    result.map(|_| StatusCode::ACCEPTED)
}

#[utoipa::path(
    post,
    path = "/admin/api/lode/update",
    tag = "lode",
    summary = "Update to a version",
    description = "Sets `target` to the version or `latest`. Audited as `lode_update` (target the \
version).",
    request_body = LodeUpdate,
    security(("adminSession" = [])),
    responses(
        (status = 202, description = "Requested"),
        (status = 400, description = "Malformed body or empty version (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 503, description = "Not supervised by lode (`unavailable`)", body = Error),
    ),
)]
pub async fn lode_update(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<LodeUpdate>, JsonRejection>,
) -> Result<StatusCode, AdminError> {
    let version = body
        .map_err(|err| AdminError::BadRequest(err.body_text()))
        .map(|Json(update)| update.version.trim().to_owned())
        .and_then(|version| {
            if version.is_empty() {
                Err(AdminError::BadRequest("version must not be empty".into()))
            } else {
                Ok(version)
            }
        });
    let target = version.as_ref().ok().cloned();
    let result = match (supervisor(&state), version) {
        (Err(err), _) | (_, Err(err)) => Err(err),
        (Ok(lode), Ok(version)) => run(lode, move |lode| lode.request_update(&version)).await,
    };
    caller
        .audit(&state, "lode_update", target, &result, None)
        .await;
    result.map(|()| StatusCode::ACCEPTED)
}

#[utoipa::path(
    post,
    path = "/admin/api/lode/restart",
    tag = "lode",
    summary = "Restart the hub",
    description = "Bumps `restart_nonce`; lode stops the hub gracefully and starts the current \
version again. Audited as `lode_restart`.",
    security(("adminSession" = [])),
    responses(
        (status = 202, description = "Requested"),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 503, description = "Not supervised by lode (`unavailable`)", body = Error),
    ),
)]
pub async fn lode_restart(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
) -> Result<StatusCode, AdminError> {
    let result = match supervisor(&state) {
        Ok(lode) => run(lode, |lode| lode.reboot()).await,
        Err(err) => Err(err),
    };
    let detail = result
        .as_ref()
        .ok()
        .map(|nonce| format!("restart_nonce {nonce}"));
    caller
        .audit(&state, "lode_restart", None, &result, detail)
        .await;
    result.map(|_| StatusCode::ACCEPTED)
}

#[utoipa::path(
    post,
    path = "/admin/api/lode/rollback",
    tag = "lode",
    summary = "Roll back",
    description = "Sets `target` to the given version, else to lode's `last_good`. Audited as \
`lode_rollback` (target the chosen version).",
    request_body(content = LodeRollback, description = "Optional", content_type = "application/json"),
    security(("adminSession" = [])),
    responses(
        (status = 202, description = "Requested"),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 409, description = "No version given and no `last_good` recorded (`conflict`)", body = Error),
        (status = 503, description = "Not supervised by lode (`unavailable`)", body = Error),
    ),
)]
pub async fn lode_rollback(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let request: Result<LodeRollback, AdminError> = optional_json(&body);
    let result = match (supervisor(&state), request) {
        (Err(err), _) | (_, Err(err)) => Err(err),
        (Ok(lode), Ok(LodeRollback { version })) => {
            let version = version.filter(|v| !v.trim().is_empty());
            let last_good = match &version {
                Some(_) => None,
                None => run(lode.clone(), |lode| lode.read())
                    .await?
                    .and_then(|st| st.last_good),
            };
            match version.or(last_good) {
                None => Err(AdminError::Conflict(
                    "no version given and no last_good recorded".into(),
                )),
                Some(version) => run(lode, move |lode| lode.rollback(Some(&version))).await,
            }
        }
    };
    let target = result.as_ref().ok().cloned();
    caller
        .audit(&state, "lode_rollback", target, &result, None)
        .await;
    result.map(|_| StatusCode::ACCEPTED)
}
