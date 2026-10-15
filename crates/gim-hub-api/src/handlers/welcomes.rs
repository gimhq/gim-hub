//! Pending Welcomes.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{Error, PendingWelcomeList, PendingWelcomesQuery},
};

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
pub async fn list_pending_welcomes(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
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
pub async fn ack_welcome(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
