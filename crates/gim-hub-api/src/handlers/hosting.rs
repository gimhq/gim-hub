//! Hosting records (docs/federation.md §4): the hub's signed entry, record
//! upload and lookup, and the `hosting_record.expiring` check.

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::BTreeSet, sync::Arc};

use gim_hub_db::{events, hosting as store, outbox, remote_identity, users, DbError, Transaction};
use gim_hub_identity::{HostingEntry, HostingRecord, HubId, IdentityError, UserId};
use gim_hub_s2s::{
    hosting::{self as hosting, MAX_RECORD_BYTES},
    ops::hosting_record::{HostingRecordService, LocalHostingRecords},
    outbox::NewEntry,
    BoxFuture, FederationService, Hosting, OutboxSender,
};

use super::identity::{decode_base64, json_body};
use crate::{
    auth::AuthDevice,
    dto::{
        self, CreateHostingEntryRequest, Error, HostingRecordExpiring, HostingRecordHub,
        HostingRecordUpdated, PutHostingRecordRequest,
    },
    error::ApiError,
    ratelimit::ClientIp,
    state::AppState,
};

const HOSTING_RECORD_EXPIRING: &str = "hosting_record.expiring";
const HOSTING_RECORD_UPDATED: &str = "hosting_record.updated";
const HOUR_MS: i64 = 60 * 60 * 1000;
/// Accepted record lifetimes at upload (`expires_at - now`).
const MIN_LIFETIME_MS: i64 = HOUR_MS;
const MAX_LIFETIME_MS: i64 = 30 * 24 * HOUR_MS;
/// `hosting_record.expiring` is emitted when less than this remains...
const EXPIRING_WINDOW_MS: i64 = 48 * HOUR_MS;
/// ...at most once per this period per user.
const EXPIRING_RENOTIFY_MS: i64 = 24 * HOUR_MS;

fn record_dto(record: &gim_hub_identity::HostingRecord, hosted: bool) -> dto::HostingRecord {
    dto::HostingRecord {
        user_id: record.user_id().to_string(),
        hosting_record: STANDARD.encode(record.as_bytes()),
        seq: record.seq(),
        expires_at: record.expires_at(),
        hosted,
    }
}

#[utoipa::path(
    post,
    path = "/v2/users/{user_id}/hosting-entry",
    tag = "hosting",
    summary = "Get this hub's signed hosting entry for the caller",
    description = "The hub co-signs its `HostingEntry` for the caller's user with its root key. \
The client puts the entry into its `SignedHostingRecord`, signs the record with the user root key \
and uploads it with `PUT /v2/users/{user_id}/hosting-record`. Signing is deterministic: repeated \
calls return identical bytes.",
    params(("user_id" = String, Path, description = "The caller's user ID", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = CreateHostingEntryRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Signed entry", body = dto::HostingEntry),
        (status = 400, description = "`priority` out of 0..=255 or malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "`user_id` is not the caller's (`forbidden`)", body = Error),
    ),
)]
pub async fn create_hosting_entry(
    auth: AuthDevice,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    body: Result<Json<CreateHostingEntryRequest>, JsonRejection>,
) -> Result<Json<dto::HostingEntry>, ApiError> {
    if user_id != auth.user_id {
        return Err(ApiError::Forbidden(
            "can only get an entry for the caller's own user".into(),
        ));
    }
    let body = json_body(body)?;
    let priority = u8::try_from(body.priority)
        .map_err(|_| ApiError::ValidationFailed("priority must be 0..=255".into()))?;
    let user_id = UserId::parse(&user_id)
        .map_err(|err| ApiError::ValidationFailed(format!("user_id: {err}")))?;
    let entry = HostingEntry::sign(state.hub.signing_key(), &user_id, priority);
    Ok(Json(dto::HostingEntry {
        hub_id: entry.hub_id().to_string(),
        hub_root_pubkey: STANDARD.encode(entry.hub_root_pubkey().as_bytes()),
        priority,
        entry: STANDARD.encode(hosting::encode_entry(&entry)),
    }))
}

/// What a record upload did.
enum Upload {
    Created,
    Replaced,
    Unchanged,
}

/// Stores verified `record` of a local user (client `PUT` or
/// `NotifyHostingRecord`): the seq rules, then, when it supersedes the stored
/// record, in the same transaction, the hub-set hook (multihoming.md §4.3),
/// `hosting_record.updated` (§4.5), the removal or re-adding of this hub
/// (§7.3) and the `NotifyHostingRecord` queue (§4.2). Publishes a record
/// listing this hub to the DHT afterwards. `check_lifetime` applies the
/// upload lifetime bounds (client uploads only).
async fn store_local_record(
    state: &AppState,
    record: &HostingRecord,
    check_lifetime: bool,
) -> Result<Upload, ApiError> {
    let now = state.clock.now_ms();
    let hub_id = state.hub.hub_id().clone();
    let hosted = record.entry(&hub_id).is_some();
    let stored = hosting::stored_record(record, hosted, now)
        .map_err(|reason| ApiError::InvalidHostingRecord(reason.into()))?;
    let lifetime = stored.expires_at.saturating_sub(now);
    let received = record.clone();
    let (hosting, outbox) = (state.hosting.clone(), state.outbox.clone());
    let federation = state.federation.is_enabled();

    let (upload, notify) = state
        .db
        .write(move |tx| {
            // 2. A user of this hub.
            if !store::is_local(tx, &stored.user_id)? {
                return Err(ApiError::NotFound);
            }
            // 3. Lifetime.
            if check_lifetime && !(MIN_LIFETIME_MS..=MAX_LIFETIME_MS).contains(&lifetime) {
                return Err(ApiError::InvalidHostingRecord(
                    "invalid hosting record (lifetime_out_of_range)".into(),
                ));
            }
            // 4. Seq rules; the stored record was verified when stored.
            let current = store::get(tx, &stored.user_id)?;
            let previous = current
                .as_ref()
                .and_then(|current| hosting::decode_stored(&current.record).ok());
            let upload = match (&current, &previous) {
                (None, _) => Upload::Created,
                (Some(_), Some(previous)) => match received.supersedes(previous) {
                    Ok(true) => Upload::Replaced,
                    Ok(false) => return Ok((Upload::Unchanged, Vec::new())),
                    Err(_) => return Err(ApiError::StaleHostingRecord),
                },
                (Some(_), None) => Upload::Replaced,
            };
            store::put(tx, &stored)?;
            let notify = match &previous {
                Some(previous) => superseded(
                    tx,
                    &Superseded {
                        hub_id: &hub_id,
                        hosting: &hosting,
                        outbox: outbox.as_ref(),
                        federation,
                        now,
                    },
                    previous,
                    &received,
                )?,
                None => Vec::new(),
            };
            Ok::<_, ApiError>((upload, notify))
        })
        .await?;
    for device_id in &notify {
        state.notifier.notify(record.user_id().as_str(), device_id);
    }
    if hosted && !matches!(upload, Upload::Unchanged) {
        state.hosting.publish(record.clone());
    }
    Ok(upload)
}

/// Context of [`superseded`].
struct Superseded<'a> {
    hub_id: &'a HubId,
    hosting: &'a Hosting,
    outbox: &'a dyn OutboxSender,
    federation: bool,
    now: i64,
}

/// Effects of storing `record` of a local user over `previous`, in the
/// record-store transaction. Returns the devices to wake.
fn superseded(
    tx: &Transaction<'_>,
    ctx: &Superseded<'_>,
    previous: &HostingRecord,
    record: &HostingRecord,
) -> Result<Vec<String>, ApiError> {
    let user_id = record.user_id().as_str();
    ctx.hosting
        .superseded(tx, previous, record, true, ctx.now)?;
    let was_hosted = previous.entry(ctx.hub_id).is_some();
    let hosted = record.entry(ctx.hub_id).is_some();
    if hosted {
        // Listed again: the removal ends (§7.3).
        store::set_removed_at(tx, user_id, None)?;
    } else if was_hosted && ctx.federation {
        // §7.3: this hub was removed by the user.
        store::set_removed_at(tx, user_id, Some(ctx.now))?;
        let (key_packages, replicas) = store::remove_local_user(tx, user_id)?;
        outbox::delete_user_entries(tx, outbox::Kind::DeviceList, user_id)?;
        tracing::info!(
            %user_id,
            key_packages,
            replicas,
            "user removed this hub from their hosting record"
        );
    }
    if hosting::entries(previous) == hosting::entries(record) {
        return Ok(Vec::new());
    }
    // §4.5: the user's devices learn about the new hub list.
    let payload = serde_json::to_string(&HostingRecordUpdated {
        user_id: user_id.to_owned(),
        seq: record.seq(),
        expires_at: record.expires_at(),
        hosted,
        hubs: record
            .hubs()
            .iter()
            .map(|entry| HostingRecordHub {
                hub_id: entry.hub_id().to_string(),
                priority: entry.priority(),
            })
            .collect(),
    })
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    let devices = users::active_device_ids(tx, user_id)?;
    for device_id in &devices {
        events::append(
            tx,
            user_id,
            device_id,
            HOSTING_RECORD_UPDATED,
            &payload,
            ctx.now,
        )?;
    }
    // §4.2: hubs listed before or now, owners and member hubs; sent only by
    // a hub that hosts the user under either record.
    if was_hosted || hosted {
        let mut peers: BTreeSet<String> = previous
            .hubs()
            .iter()
            .chain(record.hubs())
            .map(|entry| entry.hub_id().to_string())
            .collect();
        peers.extend(remote_identity::device_list_peer_hubs(
            tx,
            user_id,
            ctx.hub_id.as_str(),
        )?);
        peers.remove(ctx.hub_id.as_str());
        for peer in peers {
            match HubId::parse(&peer) {
                Ok(peer) => {
                    ctx.outbox
                        .enqueue_in_tx(tx, &peer, NewEntry::HostingRecord { user_id })?
                }
                Err(err) => tracing::warn!(%peer, %err, "skipping an invalid peer hub_id"),
            }
        }
    }
    Ok(devices)
}

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/hosting-record",
    tag = "hosting",
    summary = "Upload the user's signed hosting record",
    description = "No authentication: the record is self-certifying. Checks, in order: the record \
verifies for `user_id` (gim-core \"Hosting record\" verification; 400 `invalid_hosting_record` \
naming the gim-core error code); `user_id` is a user of this hub (404); the lifetime \
`expires_at - now` is between 1 hour and 30 days (400 `invalid_hosting_record`, \
`lifetime_out_of_range`); the seq rules against the stored record: a lower `seq`, or the same \
`seq` with a different body, is 409 `stale_hosting_record`, the identical record is 200 \
unchanged. A record listing this hub is published to the federation DHT. A record that does not \
list this hub is stored too; the hub then stops acting for the user in federation. With \
federation, a record that changes the listed hubs or priorities emits `hosting_record.updated` \
to the user's devices and is propagated to the user's other hubs, removed hubs and the hubs \
sharing groups with the user; a record that stops listing this hub removes the user here (writes \
refused with 403 `hosting_record_required`, data purged after `GIM_HUB_UNHOSTED_GRACE_HOURS`) \
until a later record lists it again.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutHostingRecordRequest,
    responses(
        (status = 200, description = "Record replaced, or identical to the stored one", body = dto::HostingRecord),
        (status = 201, description = "First record of the user stored", body = dto::HostingRecord),
        (status = 400, description = "Invalid record, user ID mismatch or lifetime out of range (`invalid_hosting_record`), or malformed body (`validation_failed`)", body = Error),
        (status = 404, description = "Not a user of this hub (`not_found`)", body = Error),
        (status = 409, description = "`seq` is lower than the stored record, or equal with a different body (`stale_hosting_record`)", body = Error),
        (status = 413, description = "Record larger than 8192 bytes (`payload_too_large`)", body = Error),
    ),
)]
pub async fn put_hosting_record(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    body: Result<Json<PutHostingRecordRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<dto::HostingRecord>), ApiError> {
    let body = json_body(body)?;
    let invalid = |err: IdentityError| {
        ApiError::InvalidHostingRecord(format!("invalid hosting record ({})", err.code()))
    };
    let expected = UserId::parse(&user_id).map_err(invalid)?;
    let bytes = decode_base64(&body.hosting_record).ok_or_else(|| {
        ApiError::InvalidHostingRecord("hosting_record is not valid base64".into())
    })?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    // 1. Verification.
    let record = hosting::verify(&bytes, &expected, state.clock.now_ms()).map_err(invalid)?;
    let hosted = record.entry(state.hub.hub_id()).is_some();
    let upload = store_local_record(&state, &record, true).await?;
    let status = match upload {
        Upload::Created => StatusCode::CREATED,
        Upload::Replaced | Upload::Unchanged => StatusCode::OK,
    };
    Ok((status, Json(record_dto(&record, hosted))))
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/hosting-record",
    tag = "hosting",
    summary = "Get a user's hosting record",
    description = "No authentication. For a user of this hub, the stored record; for any other \
user, the newest valid record resolved through federation (cached, fetched from the user's hubs \
or from the DHT). Rate limited per client IP and per `user_id`, sharing the budget of the other \
unauthenticated user reads (`GET /v2/users/{user_id}` and its `device-list`).",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    responses(
        (status = 200, description = "Current record", body = dto::HostingRecord),
        (status = 404, description = "No record, or it expired (`not_found`)", body = Error),
        (status = 429, description = "Over the per-client-IP or per-user limit of unauthenticated reads (`rate_limited`); retry after `Retry-After` seconds", body = Error),
        (status = 503, description = "Resolution needed a peer hub that did not answer and the DHT had nothing (`peer_unavailable`, with `Retry-After` seconds)", body = Error),
    ),
)]
pub async fn get_hosting_record(
    client: ClientIp,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<dto::HostingRecord>, ApiError> {
    state
        .public_reads
        .check(client, &user_id, state.clock.now_ms())?;
    let user_id_ = user_id.clone();
    let local = state
        .db
        .read(move |conn| store::is_local(conn, &user_id_))
        .await?;
    let record = state.hosting.resolve(&user_id).await?;
    let hosted = local && record.entry(state.hub.hub_id()).is_some();
    Ok(Json(record_dto(&record, hosted)))
}

/// Hourly hosting record maintenance: expires records (§4.3) and emits
/// `hosting_record.expiring` to the active devices of hosted users with
/// less than 48 hours left, once per record `seq` and at most once per 24
/// hours per user. Returns `(expired rows, users notified)`.
pub async fn check_hosting_records(state: &AppState) -> Result<(usize, usize), ApiError> {
    let now = state.clock.now_ms();
    let (expired, notify, users) = state
        .db
        .write(move |tx| {
            let (deleted, unhosted) = store::expire(tx, now)?;
            let due = store::expiring(
                tx,
                now,
                now.saturating_add(EXPIRING_WINDOW_MS),
                now - EXPIRING_RENOTIFY_MS,
            )?;
            let mut notify = Vec::new();
            for row in &due {
                let payload = serde_json::to_string(&HostingRecordExpiring {
                    user_id: row.user_id.clone(),
                    expires_at: u64::try_from(row.expires_at).unwrap_or_default(),
                    seq: u64::try_from(row.seq).unwrap_or_default(),
                })
                .map_err(|err| ApiError::Internal(err.to_string()))?;
                for device_id in users::active_device_ids(tx, &row.user_id)? {
                    events::append(
                        tx,
                        &row.user_id,
                        &device_id,
                        HOSTING_RECORD_EXPIRING,
                        &payload,
                        now,
                    )?;
                    notify.push((row.user_id.clone(), device_id));
                }
                store::mark_expiring_notified(tx, &row.user_id, row.seq, now)?;
            }
            Ok::<_, ApiError>((deleted + unhosted, notify, due.len()))
        })
        .await?;
    for (user_id, device_id) in &notify {
        state.notifier.notify(user_id, device_id);
    }
    Ok((expired, users))
}

/// Applies records pushed with `NotifyHostingRecord` to local users.
struct StateHostingRecords(AppState);

impl LocalHostingRecords for StateHostingRecords {
    fn apply_local(&self, record: HostingRecord) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            match store_local_record(&self.0, &record, false).await {
                // Stale, or the user is gone: nothing to apply.
                Ok(_) | Err(ApiError::StaleHostingRecord | ApiError::NotFound) => Ok(()),
                Err(err) => Err(DbError::Task(err.to_string())),
            }
        })
    }
}

/// Registers the `NotifyHostingRecord` op handler (multihoming.md §4.2).
/// The returned service must be kept alive.
pub fn register_hosting_record_op(
    state: &AppState,
    service: &FederationService,
) -> Arc<HostingRecordService> {
    let records = HostingRecordService::new(
        state.db.clone(),
        state.hosting.clone(),
        Arc::new(StateHostingRecords(state.clone())),
        state.clock.as_now(),
    );
    records.register(service);
    records
}

/// Purges the data of users who removed this hub more than
/// `GIM_HUB_UNHOSTED_GRACE_HOURS` ago (multihoming.md §7.3), keeping their
/// hosting records as tombstones. Returns how many users were purged.
pub async fn purge_removed_users(state: &AppState) -> Result<usize, DbError> {
    let grace = i64::from(state.config.unhosted_grace_hours) * HOUR_MS;
    let cutoff = state.clock.now_ms().saturating_sub(grace);
    let purged = state
        .db
        .write(move |tx| store::purge_removed(tx, cutoff))
        .await?;
    for user_id in &purged {
        tracing::info!(%user_id, "removed user purged");
    }
    Ok(purged.len())
}
