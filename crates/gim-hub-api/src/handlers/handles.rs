//! Optional per-hub handle directory.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use gim_hub_db::handles::{self, Claim};

use crate::{
    auth::AuthDevice,
    dto::{Error, Handle},
    error::ApiError,
    state::AppState,
};

/// `^[a-z0-9_]{3,32}$`.
fn validate(handle: &str) -> Result<(), ApiError> {
    let valid = (3..=32).contains(&handle.len())
        && handle
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(ApiError::ValidationFailed(
            "handle must be 3-32 characters of a-z, 0-9, _".into(),
        ))
    }
}

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
pub async fn put_handle(
    auth: AuthDevice,
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Json<Handle>, ApiError> {
    validate(&handle)?;
    let now = state.clock.now_ms();
    let (handle_, user_id) = (handle.clone(), auth.user_id.clone());
    match state
        .db
        .write(move |tx| handles::claim(tx, &handle_, &user_id, now))
        .await?
    {
        Claim::Claimed => Ok(Json(Handle {
            handle,
            user_id: auth.user_id,
        })),
        Claim::Taken => Err(ApiError::HandleTaken),
    }
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
pub async fn delete_handle(
    auth: AuthDevice,
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate(&handle)?;
    state
        .db
        .write(move |tx| match handles::owner(tx, &handle)? {
            None => Err(ApiError::NotFound),
            Some(owner) if owner != auth.user_id => {
                Err(ApiError::Forbidden("handle belongs to another user".into()))
            }
            Some(_) => {
                handles::release(tx, &handle)?;
                Ok(StatusCode::NO_CONTENT)
            }
        })
        .await
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
pub async fn get_handle(
    _auth: AuthDevice,
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Json<Handle>, ApiError> {
    validate(&handle)?;
    let handle_ = handle.clone();
    let user_id = state
        .db
        .read(move |conn| handles::owner(conn, &handle_))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(Handle { handle, user_id }))
}
