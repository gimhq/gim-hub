//! MLS application messages.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{Error, Message, MessageList, MessagesQuery, SendMessageRequest, StaleEpochError},
};

#[utoipa::path(
    post,
    path = "/v2/groups/{gid}/messages",
    tag = "messages",
    summary = "Send an application message",
    description = "Stores the opaque MLS message, assigns the next `seq` and emits a `message` event \
to every member device except the sender. The epoch is read from the MLS framing; a message for \
another epoch fails with 409 `stale_epoch`.\n\n\
Resending the same `client_id` from the same device returns the stored message with 200 and \
emits nothing. A decoded message larger than the hub limit (default 262144 bytes) fails with 413.",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    request_body = SendMessageRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Idempotent replay: the message stored earlier for this client_id", body = Message),
        (status = 201, description = "Message stored", body = Message),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 409, description = "Message epoch is not the group epoch (`stale_epoch`)", body = StaleEpochError),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn send_message(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/groups/{gid}/messages",
    tag = "messages",
    summary = "List group messages",
    description = "Commits and application messages with `seq >= from_seq`, ascending.",
    params(
        ("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa"),
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
pub async fn list_messages(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
