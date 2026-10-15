//! Encrypted attachments.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{BlobCreated, Error, RawBytes},
};

#[utoipa::path(
    post,
    path = "/v2/blobs",
    tag = "blobs",
    summary = "Upload an encrypted blob",
    description = "Stores the request body verbatim. The client encrypts before upload and shares \
the blob ID and key inside MLS messages. Bodies larger than the hub limit (default 104857600 \
bytes) fail with 413.",
    request_body(content = inline(RawBytes), content_type = "application/octet-stream", description = "Raw encrypted bytes"),
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Blob stored", body = BlobCreated),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn upload_blob(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/blobs/{blob_id}",
    tag = "blobs",
    summary = "Download an encrypted blob",
    description = "Supports a single byte range (`Range: bytes=a-b`, `bytes=a-`, or `bytes=-n`).",
    params(
        ("blob_id" = String, Path, description = "Opaque blob ID", example = "b_Hk4dN7sL2pX9cV0mB5qT1g"),
        ("Range" = Option<String>, Header, description = "Single byte range", example = "bytes=0-1023"),
    ),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Whole blob", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 206, description = "Requested range", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 416, description = "Range not satisfiable (`range_not_satisfiable`)", body = Error),
    ),
)]
pub async fn download_blob(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
