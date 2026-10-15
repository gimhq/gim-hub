//! MLS application messages.

use axum::{
    body::{to_bytes, Body},
    extract::{rejection::QueryRejection, Path, Query, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_db::{
    events, groups,
    messages::{self, Membership, NewMessage, StoredMessage},
    Transaction,
};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{self, ErrorCode};
use gim_hub_s2s::ops::{deliver::to_sequenced, submit};
use openmls::prelude::{ContentType, MlsMessageIn, WireFormat};
use tls_codec::Deserialize;

use super::groups::{
    apply_replica, forward_error, hubs_of, queue_deliver, remote_owner, resolve_hosting,
    roster_users, to_s2s_error, Sender,
};
use crate::{
    auth::AuthDevice,
    dto::{
        Error, Message, MessageKind, MessageList, MessagesQuery, SendMessageRequest,
        StaleEpochError,
    },
    error::ApiError,
    state::AppState,
};

const MAX_CLIENT_ID_CHARS: usize = 64;
const DEFAULT_LIST_LIMIT: u32 = 100;
const MAX_LIST_LIMIT: u32 = 500;
/// Room for the JSON envelope and `client_id` around the base64 message.
const REQUEST_OVERHEAD_BYTES: usize = 4096;

#[utoipa::path(
    post,
    path = "/v2/groups/{gid}/messages",
    tag = "messages",
    summary = "Send an application message",
    description = "Stores the opaque MLS message, assigns the next `seq` and emits a `message` event \
to every member device except the sender. The epoch is read from the MLS framing; a message for \
another epoch fails with 409 `stale_epoch`.\n\n\
Resending the same `client_id` from the same device returns the stored message with 200 and \
emits nothing. A decoded message larger than the hub limit (default 262144 bytes) fails with 413.\n\n\
For a group owned by another hub (federation), this hub forwards the message to the owning hub, \
which assigns the `seq`; the response is the sequenced message. This needs the caller's hosting \
record listing this hub (403 `hosting_record_required`); when the owning hub refuses the request \
the result is 502 `peer_refused`, when it cannot be reached 503 `peer_unavailable` with \
`Retry-After` (retry with the same `client_id`).",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    request_body = SendMessageRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Idempotent replay: the message stored earlier for this client_id", body = Message),
        (status = 201, description = "Message stored", body = Message),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`), or the group is owned by another hub and the caller has no valid hosting record listing this hub (`hosting_record_required`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 409, description = "Message epoch is not the group epoch (`stale_epoch`)", body = StaleEpochError),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
        (status = 502, description = "The owning hub of the group refused the request (`peer_refused`)", body = Error),
        (status = 503, description = "The owning hub of the group is unreachable (`peer_unavailable`); retry after `Retry-After` seconds", body = Error),
    ),
)]
pub async fn send_message(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
    body: Body,
) -> Result<(StatusCode, Json<Message>), ApiError> {
    let max = state.config.max_message_bytes;
    let body_limit = max
        .div_ceil(3)
        .saturating_mul(4)
        .saturating_add(REQUEST_OVERHEAD_BYTES);
    let body = to_bytes(body, body_limit)
        .await
        .map_err(|_| ApiError::PayloadTooLarge)?;
    let request: SendMessageRequest = serde_json::from_slice(&body)
        .map_err(|err| ApiError::ValidationFailed(format!("invalid request body: {err}")))?;
    let client_id = request.client_id;
    if client_id.is_empty() || client_id.chars().count() > MAX_CLIENT_ID_CHARS {
        return Err(ApiError::ValidationFailed(
            "client_id must be 1-64 characters".into(),
        ));
    }
    let payload = STANDARD
        .decode(request.mls_message.as_bytes())
        .map_err(|_| ApiError::ValidationFailed("mls_message is not valid base64".into()))?;
    if payload.len() > max {
        return Err(ApiError::PayloadTooLarge);
    }
    let epoch = application_message_epoch(&payload, &gid)?;
    let sender = Sender {
        user_id: auth.user_id,
        device_id: auth.device_id,
    };
    if let Some(owner) = remote_owner(&state, &gid) {
        return forward_message(&state, sender, owner, gid, client_id, payload).await;
    }
    Ok(
        match sequence_message(&state, sender, gid, client_id, payload, epoch).await? {
            Outcome::Created(stored) => (StatusCode::CREATED, Json(message_dto(stored))),
            Outcome::Replayed(stored) => (StatusCode::OK, Json(message_dto(stored))),
        },
    )
}

/// Sequences an application message of a group owned here: dedup by
/// `client_id`, epoch check, append, local events and the fan-out to member
/// hubs (§6.4, §6.5).
async fn sequence_message(
    state: &AppState,
    sender: Sender,
    gid: String,
    client_id: String,
    payload: Vec<u8>,
    epoch: u64,
) -> Result<Outcome, ApiError> {
    let epoch = i64::try_from(epoch)
        .map_err(|_| ApiError::ValidationFailed("epoch out of range".into()))?;
    let federated = state.federation.is_enabled();
    if federated {
        resolve_hosting(state, roster_users(state, &gid).await?).await;
    }
    let fan_out = federated.then(|| (state.hub.hub_id().clone(), state.outbox.clone()));
    let now = state.clock.now_ms();
    let message_id = new_message_id()?;
    let (outcome, recipients) = state
        .db
        .write(move |tx| {
            let current_epoch = groups::group_epoch(tx, &gid)?.ok_or(ApiError::NotFound)?;
            if !groups::is_member(tx, &gid, &sender.user_id, &sender.device_id)? {
                return Err(ApiError::NotMember);
            }
            if let Some(stored) =
                messages::find_by_client_id(tx, &gid, &sender.device_id, &client_id)?
            {
                if stored.sender_user_id != sender.user_id {
                    return Err(ApiError::Conflict(
                        "client_id is already used by another sender".into(),
                    ));
                }
                return Ok((Outcome::Replayed(stored), Vec::new()));
            }
            if epoch != current_epoch {
                return Err(ApiError::StaleEpoch {
                    current_epoch: u64::try_from(current_epoch).unwrap_or_default(),
                });
            }
            let stored = messages::append(
                tx,
                &NewMessage {
                    gid: &gid,
                    epoch,
                    kind: "application",
                    sender_user_id: &sender.user_id,
                    sender_device_id: &sender.device_id,
                    client_id: &client_id,
                    payload: &payload,
                    commit_hash: None,
                    message_id: &message_id,
                },
                now,
            )?;
            let recipients = emit_message_events(tx, &stored, now)?;
            if let Some((own, outbox)) = &fan_out {
                let members = groups::member_devices(tx, &gid)?;
                let peers = hubs_of(tx, members.iter().map(|(user_id, _)| user_id.as_str()), own)?;
                queue_deliver(tx, outbox.as_ref(), &peers, &stored)?;
            }
            Ok((Outcome::Created(stored), recipients))
        })
        .await?;

    for (user_id, device_id) in &recipients {
        state.notifier.notify(user_id, device_id);
    }
    Ok(outcome)
}

/// Forwards an application message for a remote-owned group to its owner
/// with `SubmitMessage` and applies the sequenced message to the replica
/// (§6.5). A `client_id` already in the replica is answered locally.
async fn forward_message(
    state: &AppState,
    sender: Sender,
    owner: HubId,
    gid: String,
    client_id: String,
    payload: Vec<u8>,
) -> Result<(StatusCode, Json<Message>), ApiError> {
    let (key, member, id) = (gid.clone(), sender.clone(), client_id.clone());
    let replayed = state
        .db
        .read(move |conn| {
            groups::group_epoch(conn, &key)?.ok_or(ApiError::NotFound)?;
            if !groups::is_member(conn, &key, &member.user_id, &member.device_id)? {
                return Err(ApiError::NotMember);
            }
            match messages::find_by_client_id(conn, &key, &member.device_id, &id)? {
                Some(stored) if stored.sender_user_id != member.user_id => Err(ApiError::Conflict(
                    "client_id is already used by another sender".into(),
                )),
                found => Ok(found),
            }
        })
        .await?;
    if let Some(stored) = replayed {
        return Ok((StatusCode::OK, Json(message_dto(stored))));
    }
    state
        .hosting
        .require_hosting_record(&sender.user_id)
        .await?;
    let request = s2s::SubmitMessageRequest {
        gid: gid.clone(),
        sender_user_id: sender.user_id,
        sender_device_id: sender.device_id,
        client_id,
        mls_message: payload,
    };
    let response = match submit::submit_message(state.federation.as_ref(), &owner, request).await {
        Ok(response) => response,
        Err(err) => return Err(forward_error(state, &owner, &gid, err).await),
    };
    let message = response
        .message
        .filter(|message| message.gid == gid)
        .ok_or_else(|| ApiError::PeerRefused("owning hub answered without the message".into()))?;
    let dto = sequenced_dto(&message);
    if let Err(err) = apply_replica(state, &owner, vec![message], true).await {
        tracing::error!(%err, gid, "applying the submitted message failed");
    }
    Ok((
        if response.duplicate {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(dto),
    ))
}

/// `SubmitMessage` on the owning hub, after authorization (§6.5).
pub(crate) async fn submit_from_peer(
    state: &AppState,
    request: s2s::SubmitMessageRequest,
) -> Result<s2s::SubmitMessageResponse, s2s::Error> {
    let stale = |err| to_s2s_error(err, ErrorCode::StaleEpoch);
    let client_id = request.client_id;
    if client_id.is_empty() || client_id.chars().count() > MAX_CLIENT_ID_CHARS {
        return Err(stale(ApiError::ValidationFailed(
            "client_id must be 1-64 characters".into(),
        )));
    }
    if request.mls_message.len() > state.config.max_message_bytes {
        return Err(stale(ApiError::PayloadTooLarge));
    }
    let epoch = application_message_epoch(&request.mls_message, &request.gid).map_err(stale)?;
    let sender = Sender {
        user_id: request.sender_user_id,
        device_id: request.sender_device_id,
    };
    let (stored, duplicate) = match sequence_message(
        state,
        sender,
        request.gid,
        client_id,
        request.mls_message,
        epoch,
    )
    .await
    .map_err(stale)?
    {
        Outcome::Created(stored) => (stored, false),
        Outcome::Replayed(stored) => (stored, true),
    };
    Ok(s2s::SubmitMessageResponse {
        seq: u64::try_from(stored.seq).unwrap_or_default(),
        epoch: u64::try_from(stored.epoch).unwrap_or_default(),
        duplicate,
        message: Some(to_sequenced(stored, Membership::default())),
    })
}

enum Outcome {
    Created(StoredMessage),
    Replayed(StoredMessage),
}

#[utoipa::path(
    get,
    path = "/v2/groups/{gid}/messages",
    tag = "messages",
    summary = "List group messages",
    description = "Commits and application messages with `seq >= from_seq`, ascending. For a \
group owned by another hub (federation), this hub serves its replica, which holds the log from \
the Commit that added this hub's first member on: a lower `from_seq` returns messages starting \
there.",
    params(
        ("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq%2Fhf4caruf7nbxzmwh5wvgefz6pa"),
        MessagesQuery,
    ),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Messages", body = MessageList),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn list_messages(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
    query: Result<Query<MessagesQuery>, QueryRejection>,
) -> Result<Json<MessageList>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let from_seq = query.from_seq.unwrap_or(1);
    let from_seq = i64::try_from(from_seq)
        .ok()
        .filter(|seq| *seq >= 1)
        .ok_or_else(|| ApiError::ValidationFailed("from_seq must be at least 1".into()))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(ApiError::ValidationFailed("limit must be 1-500".into()));
    }

    let mut stored = state
        .db
        .read(move |conn| {
            groups::group_epoch(conn, &gid)?.ok_or(ApiError::NotFound)?;
            if !groups::is_member(conn, &gid, &auth.user_id, &auth.device_id)? {
                return Err(ApiError::NotMember);
            }
            // A replica holds the log from the point its hub joined (§5.4).
            let from_seq = match groups::replica(conn, &gid)? {
                Some(replica) => from_seq.max(i64::try_from(replica.from_seq).unwrap_or(i64::MAX)),
                None => from_seq,
            };
            Ok(messages::list_from(conn, &gid, from_seq, limit + 1)?)
        })
        .await?;
    let has_more = stored.len() > limit as usize;
    stored.truncate(limit as usize);
    Ok(Json(MessageList {
        messages: stored.into_iter().map(message_dto).collect(),
        has_more,
    }))
}

/// Validates that `bytes` is an MLSMessage carrying a PrivateMessage
/// application message for `gid` and returns its epoch. The MLS group ID is
/// the UTF-8 bytes of the gid.
fn application_message_epoch(bytes: &[u8], gid: &str) -> Result<u64, ApiError> {
    let invalid = |msg: &str| ApiError::ValidationFailed(msg.to_owned());
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| invalid("mls_message is not a valid MLSMessage"))?;
    let message = message
        .try_into_protocol_message()
        .map_err(|_| invalid("mls_message must be a PrivateMessage"))?;
    if message.wire_format() != WireFormat::PrivateMessage {
        return Err(invalid(
            "mls_message must be a PrivateMessage; send Commits to /commits",
        ));
    }
    if message.content_type() != ContentType::Application {
        return Err(invalid(
            "mls_message must be an application message; send handshake messages to /commits",
        ));
    }
    if message.group_id().as_slice() != gid.as_bytes() {
        return Err(invalid("mls_message is for another group"));
    }
    Ok(message.epoch().as_u64())
}

fn new_message_id() -> Result<String, ApiError> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(hex::encode(raw))
}

/// API view of a stored message.
pub(crate) fn message_dto(stored: StoredMessage) -> Message {
    Message {
        kind: if stored.kind == "commit" {
            MessageKind::Commit
        } else {
            MessageKind::Application
        },
        mls_message: STANDARD.encode(&stored.payload),
        seq: u64::try_from(stored.seq).unwrap_or_default(),
        epoch: u64::try_from(stored.epoch).unwrap_or_default(),
        gid: stored.gid,
        sender_user_id: stored.sender_user_id,
        sender_device_id: stored.sender_device_id,
        client_id: stored.client_id,
        created_at: stored.created_at,
    }
}

/// API view of a message received from the owning hub.
fn sequenced_dto(message: &s2s::SequencedMessage) -> Message {
    Message {
        kind: if message.kind() == s2s::MessageKind::Commit {
            MessageKind::Commit
        } else {
            MessageKind::Application
        },
        mls_message: STANDARD.encode(&message.payload),
        seq: message.seq,
        epoch: message.epoch,
        gid: message.gid.clone(),
        sender_user_id: message.sender_user_id.clone(),
        sender_device_id: message.sender_device_id.clone(),
        client_id: message.client_id.clone(),
        created_at: i64::try_from(message.created_at).unwrap_or(i64::MAX),
    }
}

/// Appends a `message` event for every local member device of the
/// message's group except the sender. Returns the recipients to notify
/// after commit.
pub(crate) fn emit_message_events(
    tx: &Transaction<'_>,
    stored: &StoredMessage,
    now: i64,
) -> Result<Vec<(String, String)>, ApiError> {
    emit_message_events_except(tx, stored, &[], now)
}

/// [`emit_message_events`] without the devices in `except`.
pub(crate) fn emit_message_events_except(
    tx: &Transaction<'_>,
    stored: &StoredMessage,
    except: &[(String, String)],
    now: i64,
) -> Result<Vec<(String, String)>, ApiError> {
    let payload = serde_json::to_string(&message_dto(stored.clone()))
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let mut recipients = groups::local_member_devices(tx, &stored.gid)?;
    recipients.retain(|(user_id, device_id)| {
        (user_id, device_id) != (&stored.sender_user_id, &stored.sender_device_id)
            && !except.iter().any(|(u, d)| (u, d) == (user_id, device_id))
    });
    for (user_id, device_id) in &recipients {
        events::append(tx, user_id, device_id, "message", &payload, now)?;
    }
    Ok(recipients)
}
