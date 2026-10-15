//! Pending Welcomes.

use axum::{
    extract::{rejection::QueryRejection, Path, Query, State},
    http::StatusCode,
    Json,
};
use gim_hub_db::welcomes;
use serde_json::{json, Value};

use crate::{
    auth::AuthDevice,
    dto::{Error, PendingWelcomeList, PendingWelcomesQuery},
    error::ApiError,
    state::AppState,
};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;

#[utoipa::path(
    get,
    path = "/v2/welcomes/pending",
    tag = "events",
    summary = "List unacknowledged Welcomes",
    description = "Welcomes addressed to the calling device that it has not acknowledged with \
POST /v2/welcomes/{gid}/ack, oldest first. Pending Welcomes are retained independently of event \
retention until acknowledged or the group is deleted, so after a 410 `cursor_expired` a client \
recovers group joins here instead of scanning history.",
    params(PendingWelcomesQuery),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Pending Welcomes", body = PendingWelcomeList),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_pending_welcomes(
    State(state): State<AppState>,
    auth: AuthDevice,
    query: Result<Query<PendingWelcomesQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::ValidationFailed("limit must be 1-200".into()));
    }
    let pending = state
        .db
        .read(move |conn| welcomes::list_pending(conn, &auth.user_id, &auth.device_id, limit))
        .await?;
    // Each item is the stored `welcome` event payload plus `created_at`.
    let welcomes = pending
        .into_iter()
        .map(|welcome| {
            let mut item: Value = serde_json::from_str(&welcome.payload).map_err(|err| {
                ApiError::Internal(format!("pending welcome {} payload: {err}", welcome.id))
            })?;
            let fields = item.as_object_mut().ok_or_else(|| {
                ApiError::Internal(format!("pending welcome {} is not an object", welcome.id))
            })?;
            fields.insert("created_at".into(), welcome.created_at.into());
            Ok(item)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(json!({ "welcomes": welcomes })))
}

#[utoipa::path(
    post,
    path = "/v2/welcomes/{gid}/ack",
    tag = "events",
    summary = "Acknowledge a Welcome",
    description = "Marks the pending Welcome(s) for `gid` as processed for the calling device; they \
are no longer returned by GET /v2/welcomes/pending. Idempotent: returns 204 also when nothing is \
pending for `gid` (already acknowledged, or the group was deleted).",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Acknowledged (or nothing pending for `gid`)"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn ack_welcome(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
) -> Result<StatusCode, ApiError> {
    let now = state.clock.now_ms();
    state
        .db
        .write(move |tx| welcomes::ack(tx, &auth.user_id, &auth.device_id, &gid, now))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
