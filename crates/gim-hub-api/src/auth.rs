//! Bearer-token authentication of devices.

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap},
};
use sha2::{Digest, Sha256};

use crate::{error::ApiError, state::AppState};

/// The authenticated calling device.
///
/// Extracted from `Authorization: Bearer <token>`: the token's SHA-256 must
/// match an unexpired session whose device is still active in the user's
/// DeviceList. Otherwise the request fails with 401 `unauthorized`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDevice {
    pub user_id: String,
    pub device_id: String,
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
        Ok(Self {
            user_id: session.user_id,
            device_id: session.device_id,
        })
    }
}
