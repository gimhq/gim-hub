//! Push registration.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{Error, PushRegistration},
};

#[utoipa::path(
    put,
    path = "/v2/push/registration",
    tag = "push",
    summary = "Register the calling device for push",
    description = "Replaces the calling device's push registration.",
    request_body = PushRegistration,
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Registration stored"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn put_push_registration(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
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
pub async fn delete_push_registration(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
