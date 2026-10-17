//! Liveness probe and hub identity.

use axum::{
    extract::{rejection::QueryRejection, Query, State},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

use crate::{
    dto::{Error, Health, HealthStatus, HubInfo, HubQuery},
    error::ApiError,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    summary = "Liveness probe",
    responses((status = 200, description = "Hub is up", body = Health)),
)]
pub async fn healthz(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: HealthStatus::Ok,
        version: state.config.release_version.clone(),
    })
}

#[utoipa::path(
    get,
    path = "/v2/hub",
    tag = "health",
    summary = "This hub's identity",
    description = "Unauthenticated. Lets a client check that a URL belongs to the `hub_id` \
listed in its hosting record before signing in. With `?nonce=` (32 random bytes, base64url \
without padding) the response also carries `proof`, the hub root key's Ed25519 signature over \
`\"gim-hub-proof-v1\" || 0x00 || nonce(32) || u16be(len(hub_id)) || hub_id || \
u16be(len(public_url)) || public_url` (UTF-8, lengths in bytes), base64url without padding; the client \
checks that `hub_id` derives from `hub_root_pubkey`, that `public_url` is the URL it called and \
verifies `proof` with `hub_root_pubkey`. A hub without a configured `public_url` cannot prove \
and answers a nonce with 400.",
    params(HubQuery),
    responses(
        (status = 200, description = "Hub identity", body = HubInfo),
        (status = 400, description = "Malformed nonce, or a nonce while this hub has no public URL (`validation_failed`)", body = Error),
    ),
)]
pub async fn get_hub(
    State(state): State<AppState>,
    query: Result<Query<HubQuery>, QueryRejection>,
) -> Result<Json<HubInfo>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let public_url = state.config.public_url.clone();
    let proof = match query.nonce {
        None => None,
        Some(nonce) => {
            let nonce: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&nonce)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    ApiError::ValidationFailed(
                        "nonce must be 32 bytes, base64url without padding".into(),
                    )
                })?;
            let url = public_url.as_deref().ok_or_else(|| {
                ApiError::ValidationFailed(
                    "proof unavailable: this hub has no public URL (GIM_HUB_PUBLIC_URL)".into(),
                )
            })?;
            let proof = state
                .hub
                .sign_proof(&nonce, url)
                .map_err(|err| ApiError::Internal(err.to_string()))?;
            Some(URL_SAFE_NO_PAD.encode(proof))
        }
    };
    Ok(Json(HubInfo {
        hub_id: state.hub.hub_id().to_string(),
        hub_root_pubkey: STANDARD.encode(state.hub.signing_key().verifying_key().as_bytes()),
        version: state.config.release_version.clone(),
        public_url,
        proof,
    }))
}
