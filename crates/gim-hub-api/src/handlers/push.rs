//! Push registration and the test-only push log.

use axum::{
    extract::{rejection::JsonRejection, Query, State},
    http::StatusCode,
    Json,
};
use gim_hub_db::push::{self, Registration};
use serde::Deserialize;
use serde_json::{json, Value};

use super::identity::json_body;
use crate::{
    auth::AuthDevice,
    dto::{Error, PushRegistration},
    error::ApiError,
    state::AppState,
};

#[utoipa::path(
    put,
    path = "/v2/push/registration",
    tag = "push",
    summary = "Register the calling device for push",
    description = "Replaces the calling device's push registration. `provider`, `token`, `app_id`, `sandbox`, `p256dh` and `auth` are opaque to the hub and passed to the push server's webhook; `log` registrations are only recorded by the hub (tests).",
    request_body = PushRegistration,
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Registration stored"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn put_push_registration(
    auth: AuthDevice,
    State(state): State<AppState>,
    body: Result<Json<PushRegistration>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let body = json_body(body)?;
    gim_hub_push::validate_registration(&body.provider, &body.token, body.app_id.as_deref())
        .map_err(ApiError::ValidationFailed)?;
    let p256dh = gim_hub_push::decode_key("p256dh", body.p256dh.as_deref())
        .map_err(ApiError::ValidationFailed)?;
    let key_auth = gim_hub_push::decode_key("auth", body.auth.as_deref())
        .map_err(ApiError::ValidationFailed)?;
    let registration = Registration {
        user_id: auth.user_id,
        device_id: auth.device_id,
        provider: body.provider,
        token: body.token,
        app_id: body.app_id,
        sandbox: body.sandbox,
        p256dh,
        auth: key_auth,
        updated_at: state.clock.now_ms(),
    };
    state
        .db
        .write(move |tx| push::put(tx, &registration))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v2/push/registration",
    tag = "push",
    summary = "Remove the calling device's push registration",
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Registration removed (or none existed)"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn delete_push_registration(
    auth: AuthDevice,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    state
        .db
        .write(move |tx| push::delete(tx, &auth.user_id, &auth.device_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Query of `GET /v2/debug/push-log`.
#[derive(Debug, Deserialize)]
pub struct PushLogQuery {
    pub device_id: Option<String>,
}

/// Test-only: recent payloads sent by the `log` provider, optionally of one
/// device. Not part of the API contract; 404 unless
/// `GIM_HUB_PUSH_LOG_ENDPOINT=true` (see `docs/push.md`).
pub async fn get_push_log(
    State(state): State<AppState>,
    Query(query): Query<PushLogQuery>,
) -> Result<Json<Value>, ApiError> {
    if !state.config.push.log_endpoint {
        return Err(ApiError::NotFound);
    }
    let notifications = state.push.log().recent(query.device_id.as_deref());
    Ok(Json(json!({ "notifications": notifications })))
}
