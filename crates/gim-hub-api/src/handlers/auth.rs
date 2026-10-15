//! Device sign-in by signature challenge.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::dto::{AuthChallenge, AuthChallengeRequest, CreateSessionRequest, Error, Session};

#[utoipa::path(
    post,
    path = "/v2/auth/challenge",
    tag = "auth",
    summary = "Request a sign-in challenge",
    description = "Issues a single-use gim-core AuthChallenge for a device listed as active in the \
user's stored DeviceList. The device signs the challenge bytes and answers with \
POST /v2/auth/session before `expires_at`.",
    request_body = AuthChallengeRequest,
    responses(
        (status = 200, description = "Challenge issued", body = AuthChallenge),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 404, description = "No DeviceList stored for the user, or the device is not active in it (`not_found`)", body = Error),
    ),
)]
pub async fn create_auth_challenge() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    post,
    path = "/v2/auth/session",
    tag = "auth",
    summary = "Answer a challenge and obtain a device token",
    description = "Verifies the signature against the device key of the DeviceCert in the stored \
DeviceList and consumes the challenge. The device must still be active (not revoked) at this \
point. The token is revoked when a later DeviceList revokes the device.",
    request_body = CreateSessionRequest,
    responses(
        (status = 200, description = "Session created", body = Session),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Unknown, used or expired challenge (`invalid_challenge`) or bad signature (`invalid_signature`)", body = Error),
        (status = 403, description = "Device is no longer active in the DeviceList (`device_not_active`)", body = Error),
    ),
)]
pub async fn create_session() -> impl IntoResponse {
    not_implemented()
}
