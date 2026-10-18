//! Link-bundle relay for adding a device.

use std::time::Duration;

use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        Path, Query, State,
    },
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_db::links;
use tokio::time::{timeout_at, Instant};

use super::identity::{decode_base64, json_body};
use crate::{
    auth::AuthDevice,
    dto::{CreateLinkBundleRequest, Error, LinkBundle, LinkBundleCreated, LinkBundleQuery},
    error::ApiError,
    state::AppState,
};

/// Largest accepted bundle in decoded bytes.
const MAX_BUNDLE_BYTES: usize = 262_144;
/// Largest `expires_in` in seconds.
const MAX_EXPIRES_IN: u32 = 600;
/// Largest long-poll `wait` in seconds.
const MAX_WAIT: u32 = 30;
/// Notifier key standing in for a user ID: link waiters subscribe to
/// `(LINK_WAITERS, link_id)`. Never a valid user ID.
const LINK_WAITERS: &str = "link-bundle";

/// `^[A-Za-z0-9_-]{16,64}$`.
fn validate_link_id(link_id: &str) -> Result<(), ApiError> {
    let valid = (16..=64).contains(&link_id.len())
        && link_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(ApiError::ValidationFailed(
            "link_id must be 16-64 characters of A-Z, a-z, 0-9, _, -".into(),
        ))
    }
}

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
pub async fn create_link_bundle(
    _auth: AuthDevice,
    State(state): State<AppState>,
    body: Result<Json<CreateLinkBundleRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<LinkBundleCreated>), ApiError> {
    let body = json_body(body)?;
    validate_link_id(&body.link_id)?;
    if !(1..=MAX_EXPIRES_IN).contains(&body.expires_in) {
        return Err(ApiError::ValidationFailed(format!(
            "expires_in must be 1-{MAX_EXPIRES_IN}"
        )));
    }
    let bundle = decode_base64(&body.sealed_bundle)
        .ok_or_else(|| ApiError::ValidationFailed("sealed_bundle is not valid base64".into()))?;
    if bundle.is_empty() {
        return Err(ApiError::ValidationFailed("sealed_bundle is empty".into()));
    }
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    let now = state.clock.now_ms();
    let expires_at = now + i64::from(body.expires_in) * 1000;
    let link_id = body.link_id.clone();
    let inserted = state
        .db
        .write(move |tx| links::insert(tx, &link_id, &bundle, now, expires_at))
        .await?;
    if !inserted {
        return Err(ApiError::Conflict("link_id is already in use".into()));
    }
    state.notifier.notify(LINK_WAITERS, &body.link_id);
    Ok((
        StatusCode::CREATED,
        Json(LinkBundleCreated {
            link_id: body.link_id,
            expires_at,
        }),
    ))
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
pub async fn get_link_bundle(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    query: Result<Query<LinkBundleQuery>, QueryRejection>,
) -> Result<Json<LinkBundle>, ApiError> {
    validate_link_id(&link_id)?;
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    if query.wait > MAX_WAIT {
        return Err(ApiError::ValidationFailed(format!(
            "wait must be 0-{MAX_WAIT}"
        )));
    }
    let wait = query
        .wait
        .min(state.config.load().longpoll_max_wait_seconds);
    let deadline = Instant::now() + Duration::from_secs(u64::from(wait));
    // Subscribe before the first attempt so a bundle posted in between
    // still wakes this request.
    let mut wake = state.notifier.subscribe(LINK_WAITERS, &link_id);
    let bundle = loop {
        let now = state.clock.now_ms();
        let id = link_id.clone();
        if let Some(bundle) = state.db.write(move |tx| links::take(tx, &id, now)).await? {
            break Some(bundle);
        }
        if !matches!(timeout_at(deadline, wake.changed()).await, Ok(Ok(()))) {
            break None;
        }
    };
    // Lets the notifier drop the entry if no other request waits on it.
    drop(wake);
    state.notifier.notify(LINK_WAITERS, &link_id);
    let bundle = bundle.ok_or(ApiError::NotFound)?;
    Ok(Json(LinkBundle {
        link_id,
        sealed_bundle: STANDARD.encode(bundle),
    }))
}
