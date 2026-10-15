//! Users and their self-certifying DeviceLists.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{DeviceList, Error, Me, PutDeviceListRequest, User},
};

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Upload a signed DeviceList",
    description = "No authentication: the DeviceList is self-certifying. The hub verifies the root \
key signature and that the list's user ID matches `user_id` (derived from the root key). The first \
upload creates the user on this hub. A later upload with a higher `seq` replaces the stored list; \
re-uploading the identical list (same `seq`, same bytes) is idempotent and returns 200. Devices revoked by the new list lose their tokens; a `device_list.updated` event is emitted.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutDeviceListRequest,
    responses(
        (status = 200, description = "DeviceList replaced, or identical to the stored one", body = DeviceList),
        (status = 201, description = "User created with this DeviceList", body = DeviceList),
        (status = 400, description = "Malformed or invalid DeviceList, or user ID mismatch (`invalid_device_list`)", body = Error),
        (status = 409, description = "`seq` is lower than the stored DeviceList, or equal with different bytes (`stale_device_list`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn put_device_list() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Get a user's DeviceList",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Current DeviceList", body = DeviceList),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_device_list(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}",
    tag = "identity",
    summary = "Get a user",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "User", body = User),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_user(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/me",
    tag = "identity",
    summary = "Get the calling user and device",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Calling device", body = Me),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_me(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
