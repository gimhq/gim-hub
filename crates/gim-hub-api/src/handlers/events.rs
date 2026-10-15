//! Per-device event stream (long-poll and WebSocket).

use std::time::Duration;

use axum::{
    extract::{
        rejection::QueryRejection,
        ws::{rejection::WebSocketUpgradeRejection, CloseFrame, Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::HeaderMap,
    response::Response,
    Json,
};
use gim_hub_db::{
    events::{self, StoredEvent},
    Connection,
};
use serde_json::{json, Value};

use crate::{
    auth::{bearer_token_hash, token_hash, AuthDevice},
    dto::{CursorExpiredError, Error, EventList, EventsQuery, StreamQuery},
    error::ApiError,
    state::AppState,
};

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 500;
const MAX_WAIT_SECONDS: u32 = 30;
/// Page size used when replaying the backlog over the WebSocket.
const STREAM_BATCH: u32 = 500;
const PING_INTERVAL: Duration = Duration::from_secs(30);
const CLOSE_UNAUTHORIZED: u16 = 4401;
const CLOSE_CURSOR_EXPIRED: u16 = 4410;
const CLOSE_INTERNAL: u16 = 1011;

#[utoipa::path(
    get,
    path = "/v2/events",
    tag = "events",
    summary = "Fetch events (optionally long-polling)",
    description = "Returns events addressed to the calling device with `cursor` greater than the \
given one, ascending. With `wait > 0` and no pending events the request is held open up to `wait` \
seconds until an event arrives.\n\n\
If events after `cursor` have been pruned the hub responds 410 `cursor_expired` with the current \
head `cursor`; the client must resync (GET /v2/groups, message history, DeviceLists) and continue \
from that cursor.\n\n\
After a wait the session is checked again: if it was deleted, expired or its device was revoked \
in the meantime the hub responds 401 `unauthorized` instead of returning events.",
    params(EventsQuery),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Events", body = EventList),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 410, description = "Cursor is older than the retention window (`cursor_expired`)", body = CursorExpiredError),
    ),
)]
pub async fn list_events(
    State(state): State<AppState>,
    auth: AuthDevice,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let cursor = query.cursor.unwrap_or(0);
    let wait = query.wait.unwrap_or(0);
    if wait > MAX_WAIT_SECONDS {
        return Err(ApiError::ValidationFailed("wait must be 0-30".into()));
    }
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::ValidationFailed("limit must be 1-500".into()));
    }

    // Subscribe before reading so an event committed in between wakes us.
    let mut wake = state.notifier.subscribe(&auth.user_id, &auth.device_id);
    let mut events = fetch_events(&state, &auth, cursor, limit).await?;
    let wait = wait.min(state.config.longpoll_max_wait_seconds);
    if events.is_empty() && wait > 0 {
        // A timeout simply returns the (empty) result.
        let _ = tokio::time::timeout(Duration::from_secs(wait.into()), wake.changed()).await;
        let fetched = fetch_events(&state, &auth, cursor, limit).await;
        // The session may have been revoked, deleted or expired meanwhile;
        // checked after the read so it covers every event the read saw.
        let hash = bearer_token_hash(&headers).ok_or(ApiError::Unauthorized)?;
        if authenticate(&state, hash).await?.is_none() {
            return Err(ApiError::Unauthorized);
        }
        events = fetched?;
    }
    let next_cursor = events.last().map_or(cursor, |(cursor, _)| *cursor);
    let events: Vec<Value> = events.into_iter().map(|(_, event)| event).collect();
    Ok(Json(
        json!({ "events": events, "next_cursor": next_cursor }),
    ))
}

#[utoipa::path(
    get,
    path = "/v2/stream",
    tag = "events",
    summary = "Event stream (WebSocket)",
    description = "WebSocket upgrade delivering the same events as GET /v2/events in real time. \
Authenticate with `Authorization: Bearer <token>` or, where headers cannot be set, `?token=`.\n\n\
After the upgrade the hub first replays every event after `cursor`, then pushes new ones. \
Server-to-client frames are JSON text frames:\n\n\
- `{\"type\":\"event\",\"event\":Event}` - one per event, ascending `cursor`.\n\
- `{\"type\":\"error\",\"error\":{\"code\":\"cursor_expired\",\"message\":\"...\"},\"cursor\":<head cursor>}` - \
sent when `cursor` is older than the retention window, followed by close code 4410. Resync, then \
reconnect with the given cursor.\n\n\
An invalid or missing token closes the connection with code 4401. The session is checked again \
with every batch of events and at least every 30 seconds; once it is deleted, expires or its \
device is revoked by a DeviceList update, no further events are sent and the connection is closed \
with code 4401. Client-to-server frames are ignored.",
    params(StreamQuery),
    security(("bearerAuth" = [])),
    responses(
        (status = 101, description = "Switching Protocols; frames as described above"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
    ),
)]
pub async fn stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<StreamQuery>, QueryRejection>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let upgrade = upgrade.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    // The header token first, then `?token=`; keep the hash to re-check.
    let mut auth = None;
    let hashes = [
        bearer_token_hash(&headers),
        query.token.as_deref().map(token_hash),
    ];
    for hash in hashes.into_iter().flatten() {
        if let Some(device) = authenticate(&state, hash).await? {
            auth = Some((device, hash));
            break;
        }
    }
    let cursor = query.cursor.unwrap_or(0);
    Ok(upgrade.on_upgrade(move |socket| run_stream(socket, state, auth, cursor)))
}

/// The device of the session with token hash `hash` if it has not expired
/// and its device is still active.
async fn authenticate(state: &AppState, hash: [u8; 32]) -> Result<Option<AuthDevice>, ApiError> {
    let now = state.clock.now_ms();
    let session = state
        .db
        .read(move |conn| gim_hub_db::auth::lookup_session(conn, &hash, now))
        .await?;
    Ok(session.map(|session| AuthDevice {
        user_id: session.user_id,
        device_id: session.device_id,
    }))
}

async fn run_stream(
    mut socket: WebSocket,
    state: AppState,
    auth: Option<(AuthDevice, [u8; 32])>,
    mut cursor: u64,
) {
    let Some((auth, hash)) = auth else {
        close(&mut socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    let mut wake = state.notifier.subscribe(&auth.user_id, &auth.device_id);
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    loop {
        // Drain everything after `cursor`; the subscription above catches
        // events committed while draining.
        loop {
            let batch = fetch_events(&state, &auth, cursor, STREAM_BATCH).await;
            // Checked after the read: an event it saw was committed after any
            // revocation it must not outlive.
            if !still_authorized(&mut socket, &state, hash).await {
                return;
            }
            let batch = match batch {
                Ok(batch) => batch,
                Err(ApiError::CursorExpired { cursor: head }) => {
                    let err = ApiError::CursorExpired { cursor: head };
                    let frame = json!({
                        "type": "error",
                        "error": { "code": err.code(), "message": err.to_string() },
                        "cursor": head,
                    });
                    if socket
                        .send(Message::Text(frame.to_string().into()))
                        .await
                        .is_ok()
                    {
                        close(&mut socket, CLOSE_CURSOR_EXPIRED, "cursor_expired").await;
                    }
                    return;
                }
                Err(err) => {
                    tracing::error!(%err, "event stream read failed");
                    close(&mut socket, CLOSE_INTERNAL, "internal").await;
                    return;
                }
            };
            let full = batch.len() == STREAM_BATCH as usize;
            for (event_cursor, event) in batch {
                let frame = json!({ "type": "event", "event": event });
                if socket
                    .send(Message::Text(frame.to_string().into()))
                    .await
                    .is_err()
                {
                    return;
                }
                cursor = event_cursor;
            }
            if !full {
                break;
            }
        }

        // Wait for a wake-up, answering pings and ignoring client frames.
        loop {
            tokio::select! {
                changed = wake.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    break;
                }
                frame = socket.recv() => match frame {
                    None | Some(Err(_) | Ok(Message::Close(_))) => return,
                    Some(Ok(_)) => {}
                },
                _ = ping.tick() => {
                    if !still_authorized(&mut socket, &state, hash).await {
                        return;
                    }
                    if socket.send(Message::Ping(Default::default())).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Re-checks the stream's session; closes the socket (4401, or 1011 on a
/// database error) and returns false if it is no longer valid.
async fn still_authorized(socket: &mut WebSocket, state: &AppState, hash: [u8; 32]) -> bool {
    match authenticate(state, hash).await {
        Ok(Some(_)) => true,
        Ok(None) => {
            close(socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
            false
        }
        Err(err) => {
            tracing::error!(%err, "event stream session check failed");
            close(socket, CLOSE_INTERNAL, "internal").await;
            false
        }
    }
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    // The peer may already be gone; nothing left to do then.
    let _ = socket.send(Message::Close(Some(frame))).await;
}

/// Events of the calling device after `cursor` as `(cursor, event JSON)`, or
/// 410 `cursor_expired` if events after `cursor` may have been pruned.
async fn fetch_events(
    state: &AppState,
    auth: &AuthDevice,
    cursor: u64,
    limit: u32,
) -> Result<Vec<(u64, Value)>, ApiError> {
    let (user_id, device_id) = (auth.user_id.clone(), auth.device_id.clone());
    let after = i64::try_from(cursor).unwrap_or(i64::MAX);
    state
        .db
        .read(move |conn| {
            if after < events::pruned_through(conn)? {
                let head = events::head_cursor(conn)?;
                return Err(ApiError::CursorExpired {
                    cursor: u64::try_from(head).unwrap_or_default(),
                });
            }
            events::list_after(conn, &user_id, &device_id, after, limit)?
                .into_iter()
                .map(|event| event_json(conn, event))
                .collect()
        })
        .await
}

/// Wire shape of an event: `{cursor, created_at, type, data}`. A `message`
/// event stored before `Message.message_id` existed gets it filled from the
/// message log, with the same value as the push `collapse_id`.
fn event_json(conn: &Connection, event: StoredEvent) -> Result<(u64, Value), ApiError> {
    let mut data: Value = serde_json::from_str(&event.payload)
        .map_err(|err| ApiError::Internal(format!("event {} payload: {err}", event.id)))?;
    if event.event_type == "message" && data.get("message_id").is_none() {
        if let (Some(gid), Some(seq)) = (data["gid"].as_str(), data["seq"].as_u64()) {
            let message_id = gim_hub_push::message_id(conn, gid, seq)?;
            data["message_id"] = message_id.into();
        }
    }
    let cursor = u64::try_from(event.id).unwrap_or_default();
    Ok((
        cursor,
        json!({
            "cursor": cursor,
            "created_at": event.created_at,
            "type": event.event_type,
            "data": data,
        }),
    ))
}
