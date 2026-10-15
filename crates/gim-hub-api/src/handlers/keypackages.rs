//! MLS KeyPackages.

use std::collections::HashSet;

use axum::{extract::rejection::JsonRejection, extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use gim_hub_db::{events, keypackages};

use super::groups::json_body;
use crate::{
    auth::AuthDevice,
    dto::{
        ClaimKeyPackagesRequest, ClaimKeyPackagesResponse, ClaimTarget, ClaimedKeyPackage, Error,
        KeyPackageCount, KeyPackagesLow, UploadKeyPackagesRequest,
    },
    error::ApiError,
    mls,
    state::AppState,
};

const MAX_UPLOAD: usize = 100;
const MAX_TARGETS: usize = 100;

fn count_of(stock: keypackages::Stock) -> KeyPackageCount {
    KeyPackageCount {
        available: stock.available,
        has_last_resort: stock.has_last_resort,
    }
}

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
pub async fn upload_key_packages(
    State(state): State<AppState>,
    auth: AuthDevice,
    body: Result<Json<UploadKeyPackagesRequest>, JsonRejection>,
) -> Result<Json<KeyPackageCount>, ApiError> {
    let body = json_body(body)?;
    if body.key_packages.is_empty() || body.key_packages.len() > MAX_UPLOAD {
        return Err(ApiError::ValidationFailed(format!(
            "key_packages must hold 1-{MAX_UPLOAD} packages"
        )));
    }
    if body.last_resort && body.key_packages.len() != 1 {
        return Err(ApiError::ValidationFailed(
            "a last-resort upload must hold exactly one package".into(),
        ));
    }
    let mut packages = Vec::with_capacity(body.key_packages.len());
    for encoded in &body.key_packages {
        let bytes = STANDARD
            .decode(&encoded.0)
            .map_err(|_| ApiError::ValidationFailed("key_packages must be base64".into()))?;
        if bytes.len() > state.config.max_message_bytes {
            return Err(ApiError::PayloadTooLarge);
        }
        let hash = mls::parse_key_package(&bytes)?;
        packages.push((bytes, hash));
    }

    let now = state.clock.now_ms();
    let last_resort = body.last_resort;
    let stock = state
        .db
        .write(move |tx| {
            for (bytes, hash) in &packages {
                if last_resort {
                    keypackages::replace_last_resort(
                        tx,
                        &auth.user_id,
                        &auth.device_id,
                        bytes,
                        hash,
                        now,
                    )?;
                } else {
                    keypackages::insert_one_time(
                        tx,
                        &auth.user_id,
                        &auth.device_id,
                        bytes,
                        hash,
                        now,
                    )?;
                }
            }
            keypackages::stock(tx, &auth.user_id, &auth.device_id)
        })
        .await
        .map_err(ApiError::from)?;
    Ok(Json(count_of(stock)))
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
pub async fn count_key_packages(
    State(state): State<AppState>,
    auth: AuthDevice,
) -> Result<Json<KeyPackageCount>, ApiError> {
    let stock = state
        .db
        .read(move |conn| keypackages::stock(conn, &auth.user_id, &auth.device_id))
        .await
        .map_err(ApiError::from)?;
    Ok(Json(count_of(stock)))
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
pub async fn claim_key_packages(
    State(state): State<AppState>,
    _auth: AuthDevice,
    body: Result<Json<ClaimKeyPackagesRequest>, JsonRejection>,
) -> Result<Json<ClaimKeyPackagesResponse>, ApiError> {
    let body = json_body(body)?;
    if body.targets.is_empty() || body.targets.len() > MAX_TARGETS {
        return Err(ApiError::ValidationFailed(format!(
            "targets must hold 1-{MAX_TARGETS} entries"
        )));
    }
    let now = state.clock.now_ms();
    let threshold = state.config.keypackage_low_threshold;
    let (response, low) = state
        .db
        .write(move |tx| {
            let mut response = ClaimKeyPackagesResponse {
                key_packages: Vec::new(),
                missing: Vec::new(),
            };
            let mut low = Vec::new();
            let mut seen = HashSet::new();
            for target in body.targets {
                let devices =
                    keypackages::active_devices(tx, &target.user_id, target.device_id.as_deref())?;
                if devices.is_empty() {
                    response.missing.push(target);
                    continue;
                }
                for device_id in devices {
                    if !seen.insert((target.user_id.clone(), device_id.clone())) {
                        continue;
                    }
                    let Some(claimed) = keypackages::claim(tx, &target.user_id, &device_id, now)?
                    else {
                        response.missing.push(ClaimTarget {
                            user_id: target.user_id.clone(),
                            device_id: Some(device_id),
                        });
                        continue;
                    };
                    if !claimed.last_resort {
                        let available =
                            keypackages::stock(tx, &target.user_id, &device_id)?.available;
                        if available < threshold {
                            let data = serde_json::to_string(&KeyPackagesLow { available })
                                .map_err(|err| ApiError::Internal(err.to_string()))?;
                            events::append(
                                tx,
                                &target.user_id,
                                &device_id,
                                "keypackages.low",
                                &data,
                                now,
                            )?;
                            low.push((target.user_id.clone(), device_id.clone()));
                        }
                    }
                    response.key_packages.push(ClaimedKeyPackage {
                        user_id: target.user_id.clone(),
                        device_id,
                        key_package: STANDARD.encode(&claimed.key_package),
                        last_resort: claimed.last_resort,
                    });
                }
            }
            Ok::<_, ApiError>((response, low))
        })
        .await?;
    for (user_id, device_id) in &low {
        state.notifier.notify(user_id, device_id);
    }
    Ok(Json(response))
}
