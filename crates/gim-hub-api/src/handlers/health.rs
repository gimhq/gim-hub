//! Liveness probe and hub identity.

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::{
    dto::{Health, HealthStatus, HubInfo},
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    summary = "Liveness probe",
    responses((status = 200, description = "Hub is up", body = Health)),
)]
pub async fn healthz() -> Json<Health> {
    Json(Health {
        status: HealthStatus::Ok,
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

#[utoipa::path(
    get,
    path = "/v2/hub",
    tag = "health",
    summary = "This hub's identity",
    description = "Unauthenticated. Lets a client check that a URL belongs to the `hub_id` \
listed in its hosting record before signing in.",
    responses((status = 200, description = "Hub identity", body = HubInfo)),
)]
pub async fn get_hub(State(state): State<AppState>) -> Json<HubInfo> {
    Json(HubInfo {
        hub_id: state.hub.hub_id().to_string(),
        hub_root_pubkey: STANDARD.encode(state.hub.signing_key().verifying_key().as_bytes()),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}
