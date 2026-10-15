//! Optional per-hub handle directory.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{Error, Handle},
};

#[utoipa::path(
    put,
    path = "/v2/handles/{handle}",
    tag = "handles",
    summary = "Claim a handle for the calling user",
    description = "Optional per-hub directory mapping a handle to a user ID. Handles are never used \
as federation (DHT) keys. A user holds at most one handle per hub; claiming a new one releases \
the previous one. Re-claiming the caller's own handle is a no-op.",
    params(("handle" = String, Path, description = "Handle: 3-32 chars of a-z, 0-9, _", pattern = "^[a-z0-9_]{3,32}$", example = "alice")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Handle claimed", body = Handle),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 409, description = "Handle belongs to another user (`handle_taken`)", body = Error),
    ),
)]
pub async fn put_handle(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    delete,
    path = "/v2/handles/{handle}",
    tag = "handles",
    summary = "Release a handle",
    params(("handle" = String, Path, description = "Handle: 3-32 chars of a-z, 0-9, _", pattern = "^[a-z0-9_]{3,32}$", example = "alice")),
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Handle released"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Handle belongs to another user (`forbidden`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn delete_handle(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/handles/{handle}",
    tag = "handles",
    summary = "Look up a handle",
    params(("handle" = String, Path, description = "Handle: 3-32 chars of a-z, 0-9, _", pattern = "^[a-z0-9_]{3,32}$", example = "alice")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Directory entry", body = Handle),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_handle(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
