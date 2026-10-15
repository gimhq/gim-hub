//! Bearer-token authentication of devices.

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, Method},
};
use sha2::{Digest, Sha256};

use crate::{error::ApiError, state::AppState};

/// The authenticated calling device.
///
/// Extracted from `Authorization: Bearer <token>`: the token's SHA-256 must
/// match an unexpired session whose device is still active in the user's
/// DeviceList. Otherwise the request fails with 401 `unauthorized`.
///
/// Write gate (docs/multihoming.md §7.3): while the user is removed from this
/// hub (a newer hosting record stopped listing it), writes fail with 403
/// `hosting_record_required`; reads and `REMOVED_USER_WRITES` are served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDevice {
    pub user_id: String,
    pub device_id: String,
}

/// Authenticated writes a removed user may still make, as path segments
/// (`*` matches one segment): acknowledging Welcomes while draining, and
/// getting this hub's entry to list it again.
const REMOVED_USER_WRITES: &[&[&str]] = &[
    &["", "v2", "welcomes", "*", "ack"],
    &["", "v2", "users", "*", "hosting-entry"],
];

/// Whether the request is a write refused to a removed user.
fn gated_write(parts: &Parts) -> bool {
    if matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    let segments: Vec<&str> = parts.uri.path().split('/').collect();
    !REMOVED_USER_WRITES.iter().any(|pattern| {
        pattern.len() == segments.len()
            && pattern
                .iter()
                .zip(&segments)
                .all(|(expected, segment)| *expected == "*" || expected == segment)
    })
}

/// SHA-256 of a bearer token, as stored in the sessions table.
pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// SHA-256 of the `Authorization: Bearer` token, if the header carries one.
pub(crate) fn bearer_token_hash(headers: &HeaderMap) -> Option<[u8; 32]> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token_hash(token))
}

impl FromRequestParts<AppState> for AuthDevice {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let hash = bearer_token_hash(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let now = state.clock.now_ms();
        let session = state
            .db
            .read(move |conn| gim_hub_db::auth::lookup_session(conn, &hash, now))
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if gated_write(parts) {
            let user_id = session.user_id.clone();
            let removed = state
                .db
                .read(move |conn| gim_hub_db::hosting::removed_at(conn, &user_id))
                .await?;
            if removed.is_some() {
                return Err(ApiError::HostingRecordRequired);
            }
        }
        Ok(Self {
            user_id: session.user_id,
            device_id: session.device_id,
        })
    }
}
