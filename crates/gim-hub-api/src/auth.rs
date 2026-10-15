//! Bearer-token authentication of devices.

use axum::{extract::FromRequestParts, http::request::Parts};
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

fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

impl FromRequestParts<AppState> for AuthDevice {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let hash = token_hash(bearer_token(parts).ok_or(ApiError::Unauthorized)?);
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
