//! MLS KeyPackages.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{
        ClaimKeyPackagesRequest, ClaimKeyPackagesResponse, Error, KeyPackageCount,
        UploadKeyPackagesRequest,
    },
};

#[utoipa::path(
    post,
    path = "/v2/keypackages",
    tag = "keypackages",
    summary = "Upload KeyPackages for the calling device",
    description = "Adds one-time KeyPackages, or with `last_resort: true` replaces the device's \
last-resort KeyPackage (exactly one package). Each hub of a multi-homed user holds its own \
disjoint set.",
    request_body = UploadKeyPackagesRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Stock after the upload", body = KeyPackageCount),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn upload_key_packages(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/keypackages/count",
    tag = "keypackages",
    summary = "Count the calling device's KeyPackages",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "KeyPackage stock", body = KeyPackageCount),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn count_key_packages(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    post,
    path = "/v2/keypackages/claim",
    tag = "keypackages",
    summary = "Claim one KeyPackage per active device",
    description = "For each target, atomically removes and returns one one-time KeyPackage per \
active device of the user's DeviceList (or only the given device). The device's last-resort \
KeyPackage is returned (and kept) only when its one-time packages are exhausted. Emits \
`keypackages.low` to a device whose one-time count drops below the threshold.",
    request_body = ClaimKeyPackagesRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Claimed KeyPackages", body = ClaimKeyPackagesResponse),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn claim_key_packages(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
