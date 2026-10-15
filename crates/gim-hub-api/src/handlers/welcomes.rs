//! Pending Welcomes.

use axum::{
    extract::{rejection::QueryRejection, Path, Query, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use gim_hub_db::{events, groups, users, welcomes};
use gim_hub_proto::s2s::{CopyPendingWelcomesRequest, DeliverWelcomeRequest};
use serde_json::{json, Value};

use crate::{
    auth::AuthDevice,
    dto::{Error, PendingWelcomeList, PendingWelcomesQuery, Welcome},
    error::ApiError,
    mls,
    state::AppState,
};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;

#[utoipa::path(
    get,
    path = "/v2/welcomes/pending",
    tag = "events",
    summary = "List unacknowledged Welcomes",
    description = "Welcomes addressed to the calling device that it has not acknowledged with \
POST /v2/welcomes/{gid}/ack, oldest first. Pending Welcomes are retained independently of event \
retention until acknowledged or the group is deleted, so after a 410 `cursor_expired` a client \
recovers group joins here instead of scanning history.",
    params(PendingWelcomesQuery),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Pending Welcomes", body = PendingWelcomeList),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_pending_welcomes(
    State(state): State<AppState>,
    auth: AuthDevice,
    query: Result<Query<PendingWelcomesQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::ValidationFailed("limit must be 1-200".into()));
    }
    let pending = state
        .db
        .read(move |conn| welcomes::list_pending(conn, &auth.user_id, &auth.device_id, limit))
        .await?;
    // Each item is the stored `welcome` event payload plus `created_at`.
    let welcomes = pending
        .into_iter()
        .map(|welcome| {
            let mut item: Value = serde_json::from_str(&welcome.payload).map_err(|err| {
                ApiError::Internal(format!("pending welcome {} payload: {err}", welcome.id))
            })?;
            let fields = item.as_object_mut().ok_or_else(|| {
                ApiError::Internal(format!("pending welcome {} is not an object", welcome.id))
            })?;
            fields.insert("created_at".into(), welcome.created_at.into());
            Ok(item)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(json!({ "welcomes": welcomes })))
}

#[utoipa::path(
    post,
    path = "/v2/welcomes/{gid}/ack",
    tag = "events",
    summary = "Acknowledge a Welcome",
    description = "Marks the pending Welcome(s) for `gid` as processed for the calling device; they \
are no longer returned by GET /v2/welcomes/pending. Idempotent: returns 204 also when nothing is \
pending for `gid` (already acknowledged, or the group was deleted).",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Acknowledged (or nothing pending for `gid`)"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn ack_welcome(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
) -> Result<StatusCode, ApiError> {
    let now = state.clock.now_ms();
    state
        .db
        .write(move |tx| welcomes::ack(tx, &auth.user_id, &auth.device_id, &gid, now))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Stores a Welcome delivered by the owning hub for a hosted recipient
/// (§5.4, §6.6): for each recipient device that is an active device here,
/// the pending Welcome and the `welcome` event (deduplicated by the owner's
/// `message_id`). The first such Welcome creates the replica from the
/// snapshot; a replica without local members is replaced, one with local
/// members is kept.
///
/// The replica starts just before the Commit that produced the Welcome
/// (`last_seq = snapshot.seq - 1`, Resolved in H3-T5), so that Commit
/// arrives through `Deliver` and emits `group.member_added` here as on a
/// single hub.
pub(crate) async fn deliver_welcome(
    state: &AppState,
    request: DeliverWelcomeRequest,
) -> Result<(), ApiError> {
    mls::check_welcome(&request.welcome)?;
    let snapshot = request
        .group
        .clone()
        .ok_or_else(|| ApiError::ValidationFailed("missing group snapshot".into()))?;
    let data = serde_json::to_string(&Welcome {
        gid: request.gid.clone(),
        sender_user_id: request.sender_user_id.clone(),
        sender_device_id: request.sender_device_id.clone(),
        epoch: snapshot.epoch,
        seq: snapshot.seq,
        welcome: STANDARD.encode(&request.welcome),
        ratchet_tree: request
            .ratchet_tree
            .as_ref()
            .map(|tree| STANDARD.encode(tree)),
    })
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    let now = state.clock.now_ms();
    let wake = state
        .db
        .write(move |tx| {
            let active = users::active_device_ids(tx, &request.recipient_user_id)?;
            let devices: Vec<&String> = request
                .recipient_device_ids
                .iter()
                .filter(|device_id| active.contains(device_id))
                .collect();
            if devices.is_empty() {
                return Ok::<_, ApiError>(Vec::new());
            }
            let gid = &request.gid;
            let replace = groups::get(tx, gid)?.is_none()
                || groups::local_member_devices(tx, gid)?.is_empty();
            if replace {
                let members: Vec<(String, String)> = snapshot
                    .members
                    .iter()
                    .map(|m| (m.user_id.clone(), m.device_id.clone()))
                    .collect();
                groups::create_replica(
                    tx,
                    &groups::Group {
                        gid: gid.clone(),
                        kind: if snapshot.kind == "direct" {
                            "direct".into()
                        } else {
                            "group".into()
                        },
                        epoch: snapshot.epoch.saturating_sub(1),
                        last_seq: snapshot.seq.saturating_sub(1),
                        created_by_user_id: snapshot.created_by_user_id.clone(),
                        created_by_device_id: snapshot.created_by_device_id.clone(),
                        created_at: i64::try_from(snapshot.created_at).unwrap_or(i64::MAX),
                    },
                    &members,
                    now,
                )?;
            }
            let mut wake = Vec::new();
            for device_id in devices {
                let user_id = &request.recipient_user_id;
                if welcomes::insert_delivered(
                    tx,
                    user_id,
                    device_id,
                    gid,
                    &data,
                    &request.message_id,
                    now,
                )? {
                    events::append(tx, user_id, device_id, "welcome", &data, now)?;
                    wake.push((user_id.clone(), device_id.clone()));
                }
            }
            Ok(wake)
        })
        .await?;
    for (user_id, device_id) in &wake {
        state.notifier.notify(user_id, device_id);
    }
    Ok(())
}

/// Stores the pending Welcomes of a hosted user copied by a co-host
/// (multihoming.md §4.4): for each item whose device is an active device
/// here and whose payload is a JSON object with a valid `welcome` field
/// (base64 of an MLSMessage carrying a Welcome), the pending Welcome and the
/// `welcome` event, deduplicated by `(message_id, user_id, device_id)`. The
/// replica is not needed: it arrives with `SeedReplica` from the owner.
pub(crate) async fn copy_pending_welcomes(
    state: &AppState,
    request: CopyPendingWelcomesRequest,
) -> Result<(), ApiError> {
    let now = state.clock.now_ms();
    let user_id = request.user_id.clone();
    let wake = state
        .db
        .write(move |tx| {
            let user_id = &request.user_id;
            let active = users::active_device_ids(tx, user_id)?;
            let mut wake = Vec::new();
            for welcome in &request.welcomes {
                let valid = serde_json::from_str::<Value>(&welcome.payload_json)
                    .is_ok_and(|payload| valid_welcome_payload(&payload));
                if !valid
                    || welcome.message_id.is_empty()
                    || welcome.gid.is_empty()
                    || !active.contains(&welcome.device_id)
                {
                    continue;
                }
                if welcomes::insert_delivered(
                    tx,
                    user_id,
                    &welcome.device_id,
                    &welcome.gid,
                    &welcome.payload_json,
                    &welcome.message_id,
                    now,
                )? {
                    events::append(
                        tx,
                        user_id,
                        &welcome.device_id,
                        "welcome",
                        &welcome.payload_json,
                        now,
                    )?;
                    wake.push(welcome.device_id.clone());
                }
            }
            Ok::<_, ApiError>(wake)
        })
        .await?;
    for device_id in &wake {
        state.notifier.notify(&user_id, device_id);
    }
    Ok(())
}

/// Whether a copied `welcome` event payload is an object whose `welcome`
/// field is the base64 of an MLSMessage carrying a Welcome.
fn valid_welcome_payload(payload: &Value) -> bool {
    payload["welcome"]
        .as_str()
        .and_then(|welcome| STANDARD.decode(welcome).ok())
        .is_some_and(|welcome| mls::check_welcome(&welcome).is_ok())
}
