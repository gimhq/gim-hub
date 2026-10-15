//! Liveness probe.

use axum::Json;

use crate::dto::{Health, HealthStatus};

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
