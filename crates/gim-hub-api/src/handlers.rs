//! Route handlers. Everything except `/healthz` is a stub returning
//! 501 Not Implemented until the hub logic lands; the `#[utoipa::path]`
//! annotations are the client API v2 contract.

use axum::{http::StatusCode, response::IntoResponse, Json};

use crate::dto::{
    AuthChallenge, AuthChallengeRequest, BlobCreated, ClaimKeyPackagesRequest,
    ClaimKeyPackagesResponse, CommitResult, CreateGroupRequest, CreateLinkBundleRequest,
    CreateSessionRequest, CursorExpiredError, DeviceList, Error, EventList, EventsQuery, Group,
    GroupList, Handle, Health, HealthStatus, KeyPackageCount, LinkBundle, LinkBundleCreated,
    LinkBundleQuery, Me, Message, MessageList, MessagesQuery, PushRegistration,
    PutDeviceListRequest, PutRecoveryBackupRequest, RawBytes, RecoveryBackup, SendMessageRequest,
    Session, StaleEpochError, StreamQuery, SubmitCommitRequest, UploadKeyPackagesRequest, User,
};

fn not_implemented() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(Error::new(
            "not_implemented",
            "endpoint not implemented yet",
        )),
    )
}

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

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/v2/auth/challenge",
    tag = "auth",
    summary = "Request a sign-in challenge",
    description = "Issues a single-use gim-core AuthChallenge for a device listed as active in the \
user's stored DeviceList. The device signs the challenge bytes and answers with \
POST /v2/auth/session before `expires_at`.",
    request_body = AuthChallengeRequest,
    responses(
        (status = 200, description = "Challenge issued", body = AuthChallenge),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 404, description = "No DeviceList stored for the user, or the device is not active in it (`not_found`)", body = Error),
    ),
)]
pub async fn create_auth_challenge() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    post,
    path = "/v2/auth/session",
    tag = "auth",
    summary = "Answer a challenge and obtain a device token",
    description = "Verifies the signature against the device key of the DeviceCert in the stored \
DeviceList and consumes the challenge. The device must still be active (not revoked) at this \
point. The token is revoked when a later DeviceList revokes the device.",
    request_body = CreateSessionRequest,
    responses(
        (status = 200, description = "Session created", body = Session),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Unknown, used or expired challenge (`invalid_challenge`) or bad signature (`invalid_signature`)", body = Error),
        (status = 403, description = "Device is no longer active in the DeviceList (`device_not_active`)", body = Error),
    ),
)]
pub async fn create_session() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Upload a signed DeviceList",
    description = "No authentication: the DeviceList is self-certifying. The hub verifies the root \
key signature and that the list's user ID matches `user_id` (derived from the root key). The first \
upload creates the user on this hub. A later upload with a higher `seq` replaces the stored list; \
re-uploading the identical list (same `seq`, same bytes) is idempotent and returns 200. Devices revoked by the new list lose their tokens; a `device_list.updated` event is emitted.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutDeviceListRequest,
    responses(
        (status = 200, description = "DeviceList replaced, or identical to the stored one", body = DeviceList),
        (status = 201, description = "User created with this DeviceList", body = DeviceList),
        (status = 400, description = "Malformed or invalid DeviceList, or user ID mismatch (`invalid_device_list`)", body = Error),
        (status = 409, description = "`seq` is lower than the stored DeviceList, or equal with different bytes (`stale_device_list`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn put_device_list() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Get a user's DeviceList",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Current DeviceList", body = DeviceList),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_device_list() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}",
    tag = "identity",
    summary = "Get a user",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "User", body = User),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_user() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/me",
    tag = "identity",
    summary = "Get the calling user and device",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Calling device", body = Me),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_me() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

#[utoipa::path(
    put,
    path = "/v2/handles/{handle}",
    tag = "handles",
    summary = "Claim a handle for the calling user",
    description = "Optional per-hub directory mapping a handle to a user ID. Handles are never used \
as federation (DHT) keys. A user holds at most one handle per hub; claiming a new one releases \
the previous one. Re-claiming the caller's own handle is a no-op.",
    params(("handle" = String, Path, description = "Handle: 3-32 chars of a-z, 0-9, _", pattern = "^[a-z0-9_]{3,32}$", example = "alice")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Handle claimed", body = Handle),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 409, description = "Handle belongs to another user (`handle_taken`)", body = Error),
    ),
)]
pub async fn put_handle() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    delete,
    path = "/v2/handles/{handle}",
    tag = "handles",
    summary = "Release a handle",
    params(("handle" = String, Path, description = "Handle: 3-32 chars of a-z, 0-9, _", pattern = "^[a-z0-9_]{3,32}$", example = "alice")),
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Handle released"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Handle belongs to another user (`forbidden`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn delete_handle() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/handles/{handle}",
    tag = "handles",
    summary = "Look up a handle",
    params(("handle" = String, Path, description = "Handle: 3-32 chars of a-z, 0-9, _", pattern = "^[a-z0-9_]{3,32}$", example = "alice")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Directory entry", body = Handle),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_handle() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Recovery backup
// ---------------------------------------------------------------------------

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/recovery-backup",
    tag = "recovery",
    summary = "Store the caller's recovery backup",
    description = "Replaces the stored backup. Only the caller's own `user_id` is accepted. The \
backup is opaque ciphertext (gim-core recovery backup CBOR) of at most 65536 decoded bytes.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutRecoveryBackupRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Backup stored", body = RecoveryBackup),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "`user_id` is not the caller's (`forbidden`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn put_recovery_backup() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/recovery-backup",
    tag = "recovery",
    summary = "Fetch a recovery backup",
    description = "No authentication: this is the restore path of a user who lost every device. \
The backup is only useful with the recovery code. Requests will be rate limited per client \
address and per `user_id` (429 `rate_limited` with `Retry-After`).",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    responses(
        (status = 200, description = "Stored backup", body = RecoveryBackup),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 429, description = "Rate limited (`rate_limited`)", body = Error),
    ),
)]
pub async fn get_recovery_backup() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Link bundles
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/v2/link-bundles",
    tag = "linking",
    summary = "Post a sealed link bundle",
    description = "Called by an existing device after scanning the new device's QR code. The \
bundle is relayed opaquely, kept for `expires_in` seconds (at most 600), and deleted on the \
first successful fetch. At most 262144 decoded bytes.",
    request_body = CreateLinkBundleRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Bundle stored", body = LinkBundleCreated),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 409, description = "`link_id` is already in use (`conflict`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn create_link_bundle() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/link-bundles/{link_id}",
    tag = "linking",
    summary = "Fetch a link bundle (new device)",
    description = "No authentication: the new device has no token yet; the bundle is sealed to its \
ephemeral key. With `wait > 0` and no bundle yet, the request is held open up to `wait` seconds. \
The bundle is deleted when returned; expired or already fetched bundles are 404.",
    params(
        ("link_id" = String, Path, description = "Link ID from the QR code", example = "wgy33neayyoqouya3g77pwolne"),
        LinkBundleQuery,
    ),
    responses(
        (status = 200, description = "Bundle (now deleted from the hub)", body = LinkBundle),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 404, description = "No bundle within the wait time (`not_found`)", body = Error),
        (status = 429, description = "Rate limited (`rate_limited`)", body = Error),
    ),
)]
pub async fn get_link_bundle() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// KeyPackages
// ---------------------------------------------------------------------------

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
pub async fn upload_key_packages() -> impl IntoResponse {
    not_implemented()
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
pub async fn count_key_packages() -> impl IntoResponse {
    not_implemented()
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
pub async fn claim_key_packages() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/v2/groups",
    tag = "groups",
    summary = "Create a group",
    description = "Assigns a new `gid = <owner_peer_id>/<random_128 base32>` (this hub's PeerID) at \
epoch 0 with the calling device as the only member. Further members are added by Commits.",
    request_body = CreateGroupRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Group created", body = Group),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn create_group() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/groups",
    tag = "groups",
    summary = "List groups the calling device is a member of",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Groups", body = GroupList),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_groups() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/groups/{gid}",
    tag = "groups",
    summary = "Get a group",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Group", body = Group),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_group() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    post,
    path = "/v2/groups/{gid}/commits",
    tag = "groups",
    summary = "Submit an MLS Commit",
    description = "`mls_message` is an MLS PublicMessage (Commit or Proposal), so the hub can parse \
it. The hub reads the epoch from the MLS framing (there is no client epoch field) and \
accepts the Commit only for the group's current epoch, advancing it by one. Membership changes \
are derived from the Add/Remove/Update proposals; each added member's gim-core credential \
(type 0xF001) is validated against their DeviceList, members are identified by user ID + device \
ID from their credentials, and `group.member_added` / `group.member_removed` events carry the `user_id`. The \
optional Welcome is delivered as a `welcome` event to `welcome_recipients`.\n\n\
Resubmitting the same Commit (same hash) returns the original result with `duplicate: true` \
and emits nothing. Any other Commit for a past epoch fails with 409 `stale_epoch`.",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    request_body = SubmitCommitRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Duplicate of an accepted Commit (`duplicate: true`)", body = CommitResult),
        (status = 201, description = "Commit accepted", body = CommitResult),
        (status = 400, description = "Not a PublicMessage Commit for this group, invalid credential of an added member, or Welcome fields inconsistent (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`), or group policy forbids the change (`forbidden`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 409, description = "Commit epoch is not the group epoch (`stale_epoch`)", body = StaleEpochError),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn submit_commit() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

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
pub async fn send_message() -> impl IntoResponse {
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
pub async fn list_messages() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

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
pub async fn list_events() -> impl IntoResponse {
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

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/v2/blobs",
    tag = "blobs",
    summary = "Upload an encrypted blob",
    description = "Stores the request body verbatim. The client encrypts before upload and shares \
the blob ID and key inside MLS messages. Bodies larger than the hub limit (default 104857600 \
bytes) fail with 413.",
    request_body(content = inline(RawBytes), content_type = "application/octet-stream", description = "Raw encrypted bytes"),
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Blob stored", body = BlobCreated),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn upload_blob() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/blobs/{blob_id}",
    tag = "blobs",
    summary = "Download an encrypted blob",
    description = "Supports a single byte range (`Range: bytes=a-b`, `bytes=a-`, or `bytes=-n`).",
    params(
        ("blob_id" = String, Path, description = "Opaque blob ID", example = "b_Hk4dN7sL2pX9cV0mB5qT1g"),
        ("Range" = Option<String>, Header, description = "Single byte range", example = "bytes=0-1023"),
    ),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Whole blob", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 206, description = "Requested range", body = inline(RawBytes), content_type = "application/octet-stream"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 416, description = "Range not satisfiable (`range_not_satisfiable`)", body = Error),
    ),
)]
pub async fn download_blob() -> impl IntoResponse {
    not_implemented()
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

#[utoipa::path(
    put,
    path = "/v2/push/registration",
    tag = "push",
    summary = "Register the calling device for push",
    description = "Replaces the calling device's push registration.",
    request_body = PushRegistration,
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Registration stored"),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn put_push_registration() -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    delete,
    path = "/v2/push/registration",
    tag = "push",
    summary = "Remove the calling device's push registration",
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Registration removed (or none existed)"),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn delete_push_registration() -> impl IntoResponse {
    not_implemented()
}
