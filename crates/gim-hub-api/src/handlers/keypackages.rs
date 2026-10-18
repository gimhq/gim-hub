//! MLS KeyPackages.

use std::{collections::HashSet, sync::Arc};

use axum::{extract::rejection::JsonRejection, extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::future::join_all;
use gim_hub_db::{
    events, hosting, keypackages,
    remote_identity::{self, RemoteClaim},
    users, DbError,
};
use gim_hub_identity::{DeviceList, HubId, UserId};
use gim_hub_proto::s2s;
use gim_hub_s2s::{
    hosting::decode_stored, ops::claim::claim_remote, BoxFuture, ClaimOutcome, ClaimService,
    FederationService, HostingError, LocalClaims,
};

use super::identity::json_body;
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
disjoint set. Every leaf must carry the calling device's gim-core credential (type 0xF001), \
valid against the caller's stored DeviceList, with the certified device key as its signature \
key; otherwise the whole upload is rejected. A KeyPackage is uploaded to at most one hub, ever: \
an upload containing a KeyPackage this hub already claimed from another hub on a client's \
behalf is rejected as a whole.",
    request_body = UploadKeyPackagesRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Stock after the upload", body = KeyPackageCount),
        (status = 400, description = "Malformed or invalid KeyPackage, or invalid credential (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 409, description = "A KeyPackage was already claimed from another hub through this hub (`duplicate_key_package`)", body = Error),
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
        if bytes.len() > state.config.load().max_message_bytes {
            return Err(ApiError::PayloadTooLarge);
        }
        let (hash, leaf) = mls::parse_key_package(&bytes)?;
        packages.push((bytes, hash, leaf));
    }

    let now = state.clock.now_ms();
    let last_resort = body.last_resort;
    let stock = state
        .db
        .write(move |tx| {
            let device_list = users::get_device_list(tx, &auth.user_id)?;
            let device_list = device_list.as_ref().map(|list| list.device_list.as_slice());
            for (_, hash, leaf) in &packages {
                mls::check_leaf_credential(leaf, device_list, &auth.user_id, &auth.device_id)?;
                // Handed out by another hub already (multihoming.md §5.3).
                if remote_identity::get_claim(tx, hash)?.is_some() {
                    return Err(ApiError::DuplicateKeyPackage);
                }
            }
            for (bytes, hash, _) in &packages {
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
            Ok::<_, ApiError>(keypackages::stock(tx, &auth.user_id, &auth.device_id)?)
        })
        .await?;
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
`keypackages.low` to a device whose one-time count drops below the threshold.\n\n\
With federation, a target hosted on other hubs (per its hosting record) is claimed from its \
listed hubs in `(priority, hub_id)` order on the caller's behalf, moving to the next hub when one \
is unavailable or has no package; devices the first answering hub did not return are requested \
from the following hubs. Targets for which no hub answered and a hub could not be reached, \
refused or timed out are listed in `unavailable` (retryable). Targets for which no hub returned a \
package and a hub refused because its user policy does not admit the caller (S2S `UNAUTHORIZED`, \
`client_code` `user_not_admitted`) are listed in `not_admitted` (not retryable: the target's hub \
does not accept contacts from the caller). Claiming from another hub requires \
the caller to have a valid hosting record listing this hub. Claim and commit through the same \
hub.",
    request_body = ClaimKeyPackagesRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Claimed KeyPackages", body = ClaimKeyPackagesResponse),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "A target is on another hub and the caller has no valid hosting record listing this hub (`hosting_record_required`)", body = Error),
    ),
)]
pub async fn claim_key_packages(
    State(state): State<AppState>,
    auth: AuthDevice,
    body: Result<Json<ClaimKeyPackagesRequest>, JsonRejection>,
) -> Result<Json<ClaimKeyPackagesResponse>, ApiError> {
    let body = json_body(body)?;
    if body.targets.is_empty() || body.targets.len() > MAX_TARGETS {
        return Err(ApiError::ValidationFailed(format!(
            "targets must hold 1-{MAX_TARGETS} entries"
        )));
    }
    let mut local = Vec::new();
    let mut remote = Vec::new();
    let mut missing = Vec::new();
    let mut unavailable = Vec::new();
    for target in body.targets {
        match route(&state, &target.user_id).await? {
            Route::Local => local.push(target),
            Route::Remote(hubs) => {
                if !remote.iter().any(|(seen, _): &(ClaimTarget, Vec<HubId>)| {
                    seen.user_id == target.user_id && seen.device_id == target.device_id
                }) {
                    remote.push((target, hubs));
                }
            }
            Route::Missing => missing.push(target),
            Route::Unavailable => unavailable.push(target),
        }
    }
    // A hub acts in federation only for its hosted users (§3.7).
    if !remote.is_empty() {
        state.hosting.require_hosting_record(&auth.user_id).await?;
    }

    let claimed = claim_local(&state, local).await?;
    let mut response = ClaimKeyPackagesResponse {
        key_packages: claimed
            .claimed
            .into_iter()
            .map(|(user_id, device_id, claimed)| ClaimedKeyPackage {
                user_id,
                device_id,
                key_package: STANDARD.encode(&claimed.key_package),
                last_resort: claimed.last_resort,
            })
            .collect(),
        missing: claimed.missing,
        unavailable,
        not_admitted: Vec::new(),
    };
    response.missing.extend(missing);

    let outcomes = join_all(
        remote
            .iter()
            .map(|(target, hubs)| claim_routed(&state, &auth.user_id, target, hubs)),
    )
    .await;
    let now = state.clock.now_ms();
    let mut ledger = Vec::new();
    for ((target, _), outcome) in remote.into_iter().zip(outcomes) {
        if outcome.packages.is_empty() {
            if outcome.not_admitted {
                response.not_admitted.push(target);
            } else if outcome.unavailable {
                response.unavailable.push(target);
            } else {
                response.missing.push(target);
            }
            continue;
        }
        for (hub, package) in outcome.packages {
            let Ok((kp_ref, _)) = mls::parse_key_package(&package.key_package) else {
                tracing::warn!(%hub, user_id = %target.user_id, "dropping an invalid remote KeyPackage");
                response.missing.push(ClaimTarget {
                    user_id: target.user_id.clone(),
                    device_id: Some(package.device_id),
                });
                continue;
            };
            ledger.push(RemoteClaim {
                kp_ref: kp_ref.to_vec(),
                user_id: target.user_id.clone(),
                device_id: package.device_id.clone(),
                target_hub_id: hub.to_string(),
                claimed_by_user_id: auth.user_id.clone(),
                claimed_by_device_id: auth.device_id.clone(),
                claimed_at: now,
            });
            response.key_packages.push(ClaimedKeyPackage {
                user_id: target.user_id.clone(),
                device_id: package.device_id,
                key_package: STANDARD.encode(&package.key_package),
                last_resort: package.last_resort,
            });
        }
    }
    if !ledger.is_empty() {
        state
            .db
            .write(move |tx| {
                for claim in &ledger {
                    remote_identity::insert_claim(tx, claim)?;
                    // A copy stored here must never be handed out (§5.3).
                    if let Some((user_id, device_id)) = keypackages::burn(tx, &claim.kp_ref, now)? {
                        tracing::warn!(
                            %user_id,
                            %device_id,
                            target_hub_id = %claim.target_hub_id,
                            "burned a local KeyPackage claimed through another hub"
                        );
                    }
                }
                Ok::<_, DbError>(())
            })
            .await?;
    }
    Ok(Json(response))
}

/// Where a claim target's KeyPackages are claimed (multihoming.md §5.2).
enum Route {
    /// On this hub (also every target while federation is disabled).
    Local,
    /// From the target's listed hubs, in `(priority, hub_id)` order.
    Remote(Vec<HubId>),
    /// No valid hosting record is known.
    Missing,
    /// The hosting record could not be resolved: a peer did not answer.
    Unavailable,
}

async fn route(state: &AppState, user_id: &str) -> Result<Route, ApiError> {
    if !state.federation.is_enabled() {
        return Ok(Route::Local);
    }
    let own = state.hub.hub_id().clone();
    let key = user_id.to_owned();
    let (local, stored) = state
        .db
        .read(move |conn| {
            Ok::<_, DbError>((hosting::is_local(conn, &key)?, hosting::get(conn, &key)?))
        })
        .await?;
    let record = if local {
        // A local user is claimed here if its stored record lists this hub
        // or it has no record at all (single hub); a local user that is not
        // hosted here is routed by its record.
        let Some(stored) = stored else {
            return Ok(Route::Local);
        };
        if stored.hub_ids.iter().any(|hub_id| hub_id == own.as_str()) {
            return Ok(Route::Local);
        }
        match decode_stored(&stored.record) {
            Ok(record) => record,
            Err(err) => {
                tracing::warn!(%user_id, %err, "stored hosting record does not decode");
                return Ok(Route::Missing);
            }
        }
    } else {
        match state.hosting.resolve(user_id).await {
            Ok(record) => record,
            Err(HostingError::NotFound | HostingError::Required) => return Ok(Route::Missing),
            Err(HostingError::Unavailable(reason)) => {
                tracing::info!(%user_id, %reason, "claim target's hosting record unavailable");
                return Ok(Route::Unavailable);
            }
            Err(HostingError::Db(err)) => return Err(err.into()),
        }
    };
    if record.entry(&own).is_some() {
        // Lists this hub but never uploaded a DeviceList here.
        return Ok(Route::Local);
    }
    let mut entries: Vec<_> = record.hubs().iter().collect();
    entries.sort_by(|a, b| (a.priority(), a.hub_id()).cmp(&(b.priority(), b.hub_id())));
    if entries.is_empty() {
        return Ok(Route::Missing);
    }
    Ok(Route::Remote(
        entries
            .into_iter()
            .map(|entry| entry.hub_id().clone())
            .collect(),
    ))
}

/// Packages of one target claimed from its listed hubs.
struct Routed {
    /// `(hub, package)`, at most one per device.
    packages: Vec<(HubId, s2s::ClaimedKeyPackage)>,
    /// A hub was in the `unavailable` class (or refused).
    unavailable: bool,
    /// A hub refused because its user policy does not admit the requester.
    not_admitted: bool,
}

/// Claims `target` from `hubs` (multihoming.md §5.2 steps 2-4): the first
/// hub answering with packages serves the claim, then every active device it
/// did not return is requested from the following hubs, one request per
/// (device, hub), until a hub returns a package for it.
async fn claim_routed(
    state: &AppState,
    requester: &str,
    target: &ClaimTarget,
    hubs: &[HubId],
) -> Routed {
    let federation = state.federation.as_ref();
    let user_id = &target.user_id;
    let mut routed = Routed {
        packages: Vec::new(),
        unavailable: false,
        not_admitted: false,
    };
    let mut answered = None;
    for (index, hub) in hubs.iter().enumerate() {
        match claim_remote(
            federation,
            hub,
            requester,
            user_id,
            target.device_id.as_deref(),
        )
        .await
        {
            ClaimOutcome::Claimed(packages) => {
                answered = Some(index);
                let mut seen = HashSet::new();
                routed.packages.extend(
                    packages
                        .into_iter()
                        .filter(|package| seen.insert(package.device_id.clone()))
                        .map(|package| (hub.clone(), package)),
                );
                break;
            }
            ClaimOutcome::Missing => {}
            ClaimOutcome::Unavailable(reason) => {
                tracing::info!(%hub, %user_id, %reason, "remote claim failed, trying the next hub");
                routed.unavailable = true;
            }
            ClaimOutcome::NotAdmitted => {
                tracing::info!(%hub, %user_id, "remote claim refused by the user policy, trying the next hub");
                routed.not_admitted = true;
            }
            ClaimOutcome::Rejected(reason) => {
                tracing::info!(%hub, %user_id, %reason, "remote claim refused");
                routed.unavailable = true;
                break;
            }
        }
    }
    let Some(answered) = answered else {
        return routed;
    };
    let following = &hubs[answered + 1..];
    if target.device_id.is_some() || following.is_empty() {
        return routed;
    }
    let returned: HashSet<String> = routed
        .packages
        .iter()
        .map(|(_, package)| package.device_id.clone())
        .collect();
    for device_id in active_devices_of(state, user_id).await {
        if returned.contains(&device_id) {
            continue;
        }
        for hub in following {
            match claim_remote(federation, hub, requester, user_id, Some(&device_id)).await {
                ClaimOutcome::Claimed(packages) => {
                    if let Some(package) = packages
                        .into_iter()
                        .find(|package| package.device_id == device_id)
                    {
                        routed.packages.push((hub.clone(), package));
                        break;
                    }
                }
                ClaimOutcome::Missing => {}
                ClaimOutcome::Unavailable(reason) => {
                    tracing::info!(%hub, %user_id, %device_id, %reason, "device claim failed, trying the next hub");
                }
                ClaimOutcome::NotAdmitted => {
                    tracing::info!(%hub, %user_id, %device_id, "device claim refused by the user policy, trying the next hub");
                }
                ClaimOutcome::Rejected(reason) => {
                    tracing::info!(%hub, %user_id, %device_id, %reason, "device claim refused");
                    break;
                }
            }
        }
    }
    routed
}

/// Active devices of `user_id` per its DeviceList (`device_list_for`);
/// empty if no list can be obtained.
async fn active_devices_of(state: &AppState, user_id: &str) -> Vec<String> {
    let list = match state.device_lists.device_list_for(user_id).await {
        Ok(list) => list,
        Err(err) => {
            tracing::info!(%user_id, %err, "no DeviceList for the per-device claim follow-up");
            return Vec::new();
        }
    };
    let Ok(user) = UserId::parse(user_id) else {
        return Vec::new();
    };
    match DeviceList::verify(&list, &user) {
        Ok(list) => list
            .certs()
            .iter()
            .map(|cert| cert.device_id().to_string())
            .collect(),
        Err(err) => {
            tracing::warn!(%user_id, %err, "stored DeviceList does not verify");
            Vec::new()
        }
    }
}

/// Burns the stored, unclaimed copies of the KeyPackages a Commit adds
/// (multihoming.md §5.3). Called after the claim ledger was read, so a burn
/// never satisfies the ledger rule (§5.4).
pub(crate) async fn burn_added(
    state: &AppState,
    parsed: &mls::ParsedCommit,
) -> Result<(), ApiError> {
    let kp_refs: Vec<[u8; 32]> = parsed.added.iter().map(|(kp_ref, _)| *kp_ref).collect();
    if kp_refs.is_empty() {
        return Ok(());
    }
    let now = state.clock.now_ms();
    state
        .db
        .write(move |tx| {
            for kp_ref in &kp_refs {
                if let Some((user_id, device_id)) = keypackages::burn(tx, kp_ref, now)? {
                    tracing::warn!(
                        %user_id,
                        %device_id,
                        "burned a local KeyPackage added by a Commit without a claim here"
                    );
                }
            }
            Ok::<_, DbError>(())
        })
        .await?;
    Ok(())
}

/// KeyPackages claimed on this hub.
struct LocalClaimed {
    /// `(user_id, device_id, package)`.
    claimed: Vec<(String, String, keypackages::Claimed)>,
    missing: Vec<ClaimTarget>,
}

/// Claims for local `targets` in one transaction, emitting
/// `keypackages.low` where the stock drops below the threshold.
async fn claim_local(
    state: &AppState,
    targets: Vec<ClaimTarget>,
) -> Result<LocalClaimed, ApiError> {
    if targets.is_empty() {
        return Ok(LocalClaimed {
            claimed: Vec::new(),
            missing: Vec::new(),
        });
    }
    let now = state.clock.now_ms();
    let threshold = state.config.load().keypackage_low_threshold;
    let (result, low) = state
        .db
        .write(move |tx| {
            let mut result = LocalClaimed {
                claimed: Vec::new(),
                missing: Vec::new(),
            };
            let mut low = Vec::new();
            let mut seen = HashSet::new();
            for target in targets {
                let devices =
                    keypackages::active_devices(tx, &target.user_id, target.device_id.as_deref())?;
                if devices.is_empty() {
                    result.missing.push(target);
                    continue;
                }
                for device_id in devices {
                    if !seen.insert((target.user_id.clone(), device_id.clone())) {
                        continue;
                    }
                    let Some(claimed) = keypackages::claim(tx, &target.user_id, &device_id, now)?
                    else {
                        result.missing.push(ClaimTarget {
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
                    result
                        .claimed
                        .push((target.user_id.clone(), device_id, claimed));
                }
            }
            Ok::<_, ApiError>((result, low))
        })
        .await?;
    for (user_id, device_id) in &low {
        state.notifier.notify(user_id, device_id);
    }
    Ok(result)
}

/// Serves `ClaimKeyPackage` from other hubs with the local claim path.
struct StateClaims(AppState);

impl LocalClaims for StateClaims {
    fn claim(
        &self,
        target_user_id: String,
        device_id: Option<String>,
    ) -> BoxFuture<'_, Result<Vec<s2s::ClaimedKeyPackage>, DbError>> {
        Box::pin(async move {
            let target = ClaimTarget {
                user_id: target_user_id,
                device_id,
            };
            let claimed = claim_local(&self.0, vec![target])
                .await
                .map_err(|err| DbError::Task(err.to_string()))?;
            Ok(claimed
                .claimed
                .into_iter()
                .map(|(_, device_id, claimed)| s2s::ClaimedKeyPackage {
                    device_id,
                    key_package: claimed.key_package,
                    last_resort: claimed.last_resort,
                })
                .collect())
        })
    }
}

/// Registers the `ClaimKeyPackage` op handler, serving claims of remote
/// requesters from this hub's hosted users. Returns the handler, which the
/// caller keeps alive.
pub fn register_claim_op(state: &AppState, service: &FederationService) -> Arc<ClaimService> {
    let claims = ClaimService::new(
        state.hosting.clone(),
        Arc::new(StateClaims(state.clone())),
        state.clock.as_now(),
        admission(state),
    );
    claims.register(service);
    claims
}

/// The user policy of `state` for the S2S op handlers.
pub(crate) fn admission(state: &AppState) -> gim_hub_s2s::Admission {
    let policy = state.user_policy.clone();
    Arc::new(move |user_id: &str| policy.admitted(user_id))
}

/// Remote claims older than this are pruned (§5.2).
const REMOTE_CLAIM_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Deletes remote KeyPackage claims older than 7 days; returns how many.
pub async fn prune_remote_claims(state: &AppState) -> Result<usize, DbError> {
    let cutoff = state.clock.now_ms() - REMOTE_CLAIM_RETENTION_MS;
    state
        .db
        .write(move |tx| remote_identity::prune_claims(tx, cutoff))
        .await
}
