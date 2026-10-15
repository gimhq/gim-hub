//! Per-device event stream (long-poll and WebSocket).

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{CursorExpiredError, Error, EventList, EventsQuery, StreamQuery},
};

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
from that cursor.",
    params(EventsQuery),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Events", body = EventList),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 410, description = "Cursor is older than the retention window (`cursor_expired`)", body = CursorExpiredError),
    ),
)]
pub async fn list_events(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
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
An invalid or missing token closes the connection with code 4401. Client-to-server frames are \
ignored.",
    params(StreamQuery),
    security(("bearerAuth" = [])),
    responses(
        (status = 101, description = "Switching Protocols; frames as described above"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
    ),
)]
pub async fn stream() -> impl IntoResponse {
    not_implemented()
}
