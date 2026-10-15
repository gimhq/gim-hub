//! Link-bundle relay for adding a device.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{CreateLinkBundleRequest, Error, LinkBundle, LinkBundleCreated, LinkBundleQuery},
};

#[utoipa::path(
    post,
    path = "/v2/link-bundles",
    tag = "linking",
    summary = "Post a sealed link bundle",
    description = "Called by an existing device after scanning the new device's QR code. The \
bundle is relayed opaquely, kept for `expires_in` seconds (at most 600), and deleted on the \
first successful fetch. At most 262144 decoded bytes.",
    request_body = CreateLinkBundleRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Bundle stored", body = LinkBundleCreated),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 409, description = "`link_id` is already in use (`conflict`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn create_link_bundle(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/link-bundles/{link_id}",
    tag = "linking",
    summary = "Fetch a link bundle (new device)",
    description = "No authentication: the new device has no token yet; the bundle is sealed to its \
ephemeral key. With `wait > 0` and no bundle yet, the request is held open up to `wait` seconds. \
The bundle is deleted when returned; expired or already fetched bundles are 404.",
    params(
        ("link_id" = String, Path, description = "Link ID from the QR code", example = "wgy33neayyoqouya3g77pwolne"),
        LinkBundleQuery,
    ),
    responses(
        (status = 200, description = "Bundle (now deleted from the hub)", body = LinkBundle),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 404, description = "No bundle within the wait time (`not_found`)", body = Error),
        (status = 429, description = "Rate limited (`rate_limited`)", body = Error),
    ),
)]
pub async fn get_link_bundle() -> impl IntoResponse {
    not_implemented()
}
