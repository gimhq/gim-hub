//! Request and response bodies of the client API v2.
//!
//! JSON fields are snake_case, timestamps are integer milliseconds since the
//! Unix epoch and binary values are standard base64 strings. Identity objects
//! (DeviceList, AuthChallenge, recovery backup, link bundle) are gim-core CBOR
//! wire formats and are carried as opaque base64 strings, never re-modelled.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Example user ID (format owned by gim-core).
pub const USER_ID_EXAMPLE: &str = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa";
/// Example device ID (format owned by gim-core).
pub const DEVICE_ID_EXAMPLE: &str = "d54ta5gvdyzz26janc6rgmbeagy";
/// Example hub ID (format owned by gim-core).
pub const HUB_ID_EXAMPLE: &str = "hciqgrcknldyy6lbu2splf5frcdqeftipgfikjxbzeq6x6y55lggapay";
/// Example group ID: `<owner hub_id>/<random_128 base32lower>`.
pub const GID_EXAMPLE: &str =
    "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq/hf4caruf7nbxzmwh5wvgefz6pa";
/// Example link ID.
pub const LINK_ID_EXAMPLE: &str = "wgy33neayyoqouya3g77pwolne";
/// Example client idempotency key.
pub const CLIENT_ID_EXAMPLE: &str = "9f1c2a7e-0b44-4d0e-9a51-3c8f1e2d6b70";
/// Example message ID (opaque, assigned by the owning hub).
pub const MESSAGE_ID_EXAMPLE: &str = "5f0e9c1d7a2b4c3e8d6f1a0b9c8d7e6f";
/// Example timestamp.
pub const TIMESTAMP_EXAMPLE: i64 = 1_760_479_200_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    /// Machine-readable snake_case error code.
    #[schema(example = "not_found")]
    pub code: String,
    /// Human-readable description.
    pub message: String,
}

/// Body of every non-2xx JSON response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Error {
    pub error: ErrorBody,
}

impl Error {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

/// 409 `stale_epoch`: the MLS message is not for the group's current epoch.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StaleEpochError {
    pub error: ErrorBody,
    /// The group's current epoch.
    pub current_epoch: u64,
}

/// 410 `cursor_expired`: events after the given cursor have been pruned.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CursorExpiredError {
    pub error: ErrorBody,
    /// Current head cursor; resync state, then continue from here.
    pub cursor: u64,
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
}

/// Liveness probe result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Health {
    pub status: HealthStatus,
    /// Hub release version: the version the lode supervisor launched
    /// (`LODE_ACTIVE_VERSION`), else the package version.
    #[schema(example = "0.2.0")]
    pub version: String,
}

/// This hub's identity, so a client can check that a URL belongs to the
/// `hub_id` listed in its hosting record before signing in.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HubInfo {
    #[schema(example = json!(HUB_ID_EXAMPLE))]
    pub hub_id: String,
    /// The hub's 32-byte Ed25519 root public key, base64; `hub_id` is
    /// derived from it.
    #[schema(content_encoding = "base64")]
    pub hub_root_pubkey: String,
    /// Hub release version: the version the lode supervisor launched
    /// (`LODE_ACTIVE_VERSION`), else the package version.
    #[schema(example = "0.2.0")]
    pub version: String,
    /// The hub's canonical client-API base URL (`GIM_HUB_PUBLIC_URL`,
    /// normalized), if configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "https://hub.example.eu")]
    pub public_url: Option<String>,
    /// Only with `?nonce=`: Ed25519 signature by the hub root key
    /// (`hub_root_pubkey`) over `"gim-hub-proof-v1" || 0x00 || nonce(32) ||
    /// u16be(len(hub_id)) || hub_id || u16be(len(public_url)) || public_url`
    /// (UTF-8, lengths in bytes), base64url without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(content_encoding = "base64url")]
    pub proof: Option<String>,
}

/// Query of GET /v2/hub.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HubQuery {
    /// Client nonce for a proof of possession: 32 random bytes, base64url
    /// without padding (43 characters). Needs a configured `public_url`.
    #[param(pattern = "^[A-Za-z0-9_-]{43}$")]
    pub nonce: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Request a sign-in challenge for a device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthChallengeRequest {
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// Opaque device ID (format owned by gim-core).
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub device_id: String,
}

/// A sign-in challenge.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthChallenge {
    /// gim-core AuthChallenge CBOR, base64. The device signs these exact
    /// bytes into an AuthResponse as defined in gim-core docs/identity.md.
    #[schema(content_encoding = "base64")]
    pub challenge: String,
    /// When the challenge expires (ms since the Unix epoch, exclusive).
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub expires_at: i64,
    /// `hub_id` of this hub: the challenge's `audience`.
    #[schema(example = json!(HUB_ID_EXAMPLE))]
    pub hub_id: String,
}

/// Answer a sign-in challenge.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    /// gim-core AuthResponse CBOR, base64: the challenge bytes, user ID,
    /// device ID and the device signature.
    #[schema(content_encoding = "base64")]
    pub response: String,
}

/// A device session.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Session {
    /// Bearer token for this device. Returned once; store it securely.
    pub token: String,
    /// When the token expires (ms since the Unix epoch). Sign in again after.
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub expires_at: i64,
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Upload a signed DeviceList.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PutDeviceListRequest {
    /// gim-core DeviceList CBOR (`[tbs, sig]`, signed by the user root key), base64.
    #[schema(content_encoding = "base64")]
    pub device_list: String,
}

/// A user's current DeviceList.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceList {
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// gim-core DeviceList CBOR, base64.
    #[schema(content_encoding = "base64")]
    pub device_list: String,
}

/// A user as known to this hub.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// gim-core DeviceList CBOR, base64.
    #[schema(content_encoding = "base64")]
    pub device_list: String,
    /// Handle claimed in this hub's directory, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(pattern = "^[a-z0-9_]{3,32}$", example = "alice")]
    pub handle: Option<String>,
}

/// The calling device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Me {
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// Opaque device ID (format owned by gim-core).
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub device_id: String,
    /// Handle claimed in this hub's directory, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(pattern = "^[a-z0-9_]{3,32}$", example = "alice")]
    pub handle: Option<String>,
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/// A handle directory entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Handle {
    /// Handle: 3-32 chars of a-z, 0-9, _.
    #[schema(pattern = "^[a-z0-9_]{3,32}$", example = "alice")]
    pub handle: String,
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
}

// ---------------------------------------------------------------------------
// Recovery backup
// ---------------------------------------------------------------------------

/// Store the caller's recovery backup.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PutRecoveryBackupRequest {
    /// gim-core recovery backup CBOR (root key encrypted under the
    /// recovery-code key), base64. At most 65536 decoded bytes.
    #[schema(content_encoding = "base64")]
    pub backup: String,
}

/// A stored recovery backup.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecoveryBackup {
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// gim-core recovery backup CBOR, base64.
    #[schema(content_encoding = "base64")]
    pub backup: String,
    /// When the backup was last stored (ms since the Unix epoch).
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub updated_at: i64,
}

// ---------------------------------------------------------------------------
// Hosting records
// ---------------------------------------------------------------------------

/// Body of POST /v2/users/{user_id}/hosting-entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct CreateHostingEntryRequest {
    /// Priority of this hub in the record; lower is preferred.
    #[serde(default)]
    #[schema(minimum = 0, maximum = 255, default = 0)]
    pub priority: i64,
}

/// This hub's signed entry for the caller's hosting record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingEntry {
    #[schema(example = json!(HUB_ID_EXAMPLE))]
    pub hub_id: String,
    /// The hub's 32-byte Ed25519 root public key, base64.
    #[schema(content_encoding = "base64")]
    pub hub_root_pubkey: String,
    #[schema(minimum = 0, maximum = 255)]
    pub priority: u8,
    /// gim-core CBOR `HostingEntry` `[hub_root_pubkey, priority, hub_sig]`,
    /// base64; signing is deterministic, so repeated calls return identical
    /// bytes.
    #[schema(content_encoding = "base64")]
    pub entry: String,
}

/// Body of PUT /v2/users/{user_id}/hosting-record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PutHostingRecordRequest {
    /// gim-core CBOR `SignedHostingRecord`, base64, at most 8192 decoded
    /// bytes.
    #[schema(content_encoding = "base64")]
    pub hosting_record: String,
}

/// A user's hosting record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingRecord {
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// gim-core CBOR `SignedHostingRecord`, base64.
    #[schema(content_encoding = "base64")]
    pub hosting_record: String,
    pub seq: u64,
    /// Expiry of the record (ms since the Unix epoch, exclusive).
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub expires_at: u64,
    /// Whether the user is local to this hub and the record lists this hub.
    pub hosted: bool,
}

// ---------------------------------------------------------------------------
// Link bundles
// ---------------------------------------------------------------------------

/// Post a sealed link bundle for a new device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateLinkBundleRequest {
    /// Client-chosen random ID shared with the new device through the QR code
    /// (16-64 chars of A-Z, a-z, 0-9, _, -).
    #[schema(pattern = "^[A-Za-z0-9_-]{16,64}$", example = json!(LINK_ID_EXAMPLE))]
    pub link_id: String,
    /// gim-core link bundle CBOR sealed to the new device's ephemeral key,
    /// base64. At most 262144 decoded bytes.
    #[schema(content_encoding = "base64")]
    pub sealed_bundle: String,
    /// Time to live in seconds (1-600).
    #[schema(minimum = 1, maximum = 600, example = 300)]
    pub expires_in: u32,
}

/// A stored link bundle.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LinkBundleCreated {
    #[schema(example = json!(LINK_ID_EXAMPLE))]
    pub link_id: String,
    /// When the bundle is deleted unless fetched first (ms since the Unix epoch).
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub expires_at: i64,
}

/// A fetched link bundle.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LinkBundle {
    #[schema(example = json!(LINK_ID_EXAMPLE))]
    pub link_id: String,
    /// gim-core link bundle CBOR sealed to the new device's ephemeral key, base64.
    #[schema(content_encoding = "base64")]
    pub sealed_bundle: String,
}

/// Query of GET /v2/link-bundles/{link_id}.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LinkBundleQuery {
    /// Long-poll timeout in seconds (0-30).
    #[param(minimum = 0, maximum = 30, default = 0)]
    #[serde(default)]
    pub wait: u32,
}

// ---------------------------------------------------------------------------
// KeyPackages
// ---------------------------------------------------------------------------

/// Upload KeyPackages for the calling device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UploadKeyPackagesRequest {
    /// Serialized MLS KeyPackages (TLS encoding), base64 each (1-100).
    #[schema(min_items = 1, max_items = 100, inline)]
    pub key_packages: Vec<KeyPackageBytes>,
    /// When true, `key_packages` must hold exactly one package, which replaces
    /// the device's last-resort KeyPackage. Otherwise the packages are added
    /// to the device's one-time pool.
    #[serde(default)]
    #[schema(default = false)]
    pub last_resort: bool,
}

/// Serialized MLS KeyPackage (TLS encoding), base64.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, content_encoding = "base64")]
pub struct KeyPackageBytes(pub String);

/// KeyPackage stock of the calling device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyPackageCount {
    /// Unclaimed one-time KeyPackages.
    pub available: u32,
    /// Whether a last-resort KeyPackage is stored.
    pub has_last_resort: bool,
}

/// A user, or one device of a user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClaimTarget {
    /// Opaque user ID (format owned by gim-core).
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// Opaque device ID. Omit to target every active device in the user's DeviceList.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub device_id: Option<String>,
}

/// Claim KeyPackages.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClaimKeyPackagesRequest {
    /// Users or devices to claim one KeyPackage per active device for (1-100).
    #[schema(min_items = 1, max_items = 100)]
    pub targets: Vec<ClaimTarget>,
}

/// A claimed KeyPackage.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClaimedKeyPackage {
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub device_id: String,
    /// Serialized MLS KeyPackage (TLS encoding), base64.
    #[schema(content_encoding = "base64")]
    pub key_package: String,
    /// True if this is the device's (reused) last-resort KeyPackage.
    pub last_resort: bool,
}

/// Claimed KeyPackages.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClaimKeyPackagesResponse {
    pub key_packages: Vec<ClaimedKeyPackage>,
    /// Targets that are unknown, have no active device, or have no KeyPackage at all.
    pub missing: Vec<ClaimTarget>,
    /// Targets on another hub that could not be reached, refused, or timed out (retryable).
    pub unavailable: Vec<ClaimTarget>,
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Direct,
    Group,
}

/// A member device of a group.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GroupMember {
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub device_id: String,
}

/// Create a group.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub kind: GroupKind,
}

/// A group as tracked by its delivery service.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Group {
    /// Group ID `<owner hub_id>/<random_128 base32lower>`, assigned by the hub. Clients use its
    /// UTF-8 bytes as the MLS group ID.
    #[schema(example = json!(GID_EXAMPLE))]
    pub gid: String,
    pub kind: GroupKind,
    /// Current MLS epoch (advanced by accepted Commits).
    pub epoch: u64,
    /// Highest assigned per-group sequence number (0 before the first message).
    pub last_seq: u64,
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub created_by_user_id: String,
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub created_by_device_id: String,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    /// Member devices (delivery-service view of the roster).
    pub members: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GroupList {
    pub groups: Vec<Group>,
}

/// Submit an MLS Commit or Proposal.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SubmitCommitRequest {
    /// Sender-chosen idempotency key, unique per sending device and group (1-64 chars).
    #[schema(min_length = 1, max_length = 64, example = json!(CLIENT_ID_EXAMPLE))]
    pub client_id: String,
    /// MLSMessage carrying the Commit or Proposal as a PublicMessage (TLS encoding), base64.
    #[schema(content_encoding = "base64")]
    pub mls_message: String,
    /// TLS-encoded MLSMessage (wire_format = mls_welcome) carrying the Welcome for the devices
    /// added by this Commit, base64. Not allowed with a Proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(content_encoding = "base64")]
    pub welcome: Option<String>,
    /// Devices the Welcome is addressed to (1-500). Required with `welcome`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(min_items = 1, max_items = 500)]
    pub welcome_recipients: Option<Vec<GroupMember>>,
    /// Ratchet tree for the new members (TLS encoding), base64, when it is not
    /// carried in the Welcome as an extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(content_encoding = "base64")]
    pub ratchet_tree: Option<String>,
}

/// An accepted Commit or Proposal.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CommitResult {
    /// Per-group sequence number of the Commit or Proposal.
    pub seq: u64,
    /// Group epoch after the Commit; for a Proposal, the (unchanged) epoch it was sent in.
    pub epoch: u64,
    /// True if this exact Commit or Proposal had already been accepted (nothing was emitted again).
    pub duplicate: bool,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Commit,
    Application,
    Proposal,
}

/// Send an MLS application message.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SendMessageRequest {
    /// Sender-chosen idempotency key, unique per sending device and group (1-64 chars).
    #[schema(min_length = 1, max_length = 64, example = json!(CLIENT_ID_EXAMPLE))]
    pub client_id: String,
    /// MLSMessage carrying a PrivateMessage (TLS encoding), base64. Content is never inspected; the
    /// epoch is read from the framing.
    #[schema(content_encoding = "base64")]
    pub mls_message: String,
}

/// An entry of a group's message log.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Message {
    #[schema(example = json!(GID_EXAMPLE))]
    pub gid: String,
    /// Per-group sequence number assigned by the owning hub, starting at 1.
    #[schema(minimum = 1)]
    pub seq: u64,
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub sender_user_id: String,
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub sender_device_id: String,
    #[schema(min_length = 1, max_length = 64, example = json!(CLIENT_ID_EXAMPLE))]
    pub client_id: String,
    /// Opaque message ID assigned by the owning hub, identical on every hub that stores the
    /// message. Equals the push payload's `message_id` / `collapse_id`; the cross-hub dedup key.
    #[schema(example = json!(MESSAGE_ID_EXAMPLE))]
    pub message_id: String,
    pub kind: MessageKind,
    /// MLS epoch read from the message framing.
    pub epoch: u64,
    /// MLSMessage (TLS encoding), base64.
    #[schema(content_encoding = "base64")]
    pub mls_message: String,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MessageList {
    pub messages: Vec<Message>,
    /// True if more messages exist after the last returned one.
    pub has_more: bool,
}

/// Query of GET /v2/groups/{gid}/messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MessagesQuery {
    /// Return messages with `seq >= from_seq`.
    #[param(minimum = 1, default = 1)]
    pub from_seq: Option<u64>,
    /// Maximum number of messages (1-500).
    #[param(minimum = 1, maximum = 500, default = 100)]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Query of GET /v2/events.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventsQuery {
    /// Last cursor the client has processed.
    #[param(minimum = 0, default = 0)]
    pub cursor: Option<u64>,
    /// Long-poll timeout in seconds (0-30).
    #[param(minimum = 0, maximum = 30, default = 0)]
    pub wait: Option<u32>,
    /// Maximum number of events (1-500).
    #[param(minimum = 1, maximum = 500, default = 100)]
    pub limit: Option<u32>,
}

/// Query of GET /v2/stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StreamQuery {
    /// Last cursor the client has processed.
    #[param(minimum = 0, default = 0)]
    pub cursor: Option<u64>,
    /// Bearer token (alternative to the Authorization header).
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EventList {
    pub events: Vec<Event>,
    /// Pass as `cursor` in the next request (unchanged if no events were returned).
    pub next_cursor: u64,
}

/// An entry of the calling device's event stream, ordered by `cursor`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
#[schema(discriminator(property_name = "type", mapping(
    ("message" = "#/components/schemas/MessageEvent"),
    ("group.member_added" = "#/components/schemas/MemberAddedEvent"),
    ("group.member_removed" = "#/components/schemas/MemberRemovedEvent"),
    ("welcome" = "#/components/schemas/WelcomeEvent"),
    ("keypackages.low" = "#/components/schemas/KeyPackagesLowEvent"),
    ("device_list.updated" = "#/components/schemas/DeviceListUpdatedEvent"),
    ("hosting_record.expiring" = "#/components/schemas/HostingRecordExpiringEvent"),
    ("hosting_record.updated" = "#/components/schemas/HostingRecordUpdatedEvent"),
)))]
pub enum Event {
    Message(MessageEvent),
    MemberAdded(MemberAddedEvent),
    MemberRemoved(MemberRemovedEvent),
    Welcome(WelcomeEvent),
    KeyPackagesLow(KeyPackagesLowEvent),
    DeviceListUpdated(DeviceListUpdatedEvent),
    HostingRecordExpiring(HostingRecordExpiringEvent),
    HostingRecordUpdated(HostingRecordUpdatedEvent),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum MessageEventType {
    #[serde(rename = "message")]
    Tag,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum MemberAddedEventType {
    #[serde(rename = "group.member_added")]
    Tag,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum MemberRemovedEventType {
    #[serde(rename = "group.member_removed")]
    Tag,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum WelcomeEventType {
    #[serde(rename = "welcome")]
    Tag,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum KeyPackagesLowEventType {
    #[serde(rename = "keypackages.low")]
    Tag,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum DeviceListUpdatedEventType {
    #[serde(rename = "device_list.updated")]
    Tag,
}

/// A message (Commit or application) in a group the device is a member of.
/// Not delivered to the sending device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MessageEvent {
    /// Global event cursor of the receiving device.
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: MessageEventType,
    pub data: Message,
}

/// Devices of one user added to or removed from a group by a Commit.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MembershipChange {
    #[schema(example = json!(GID_EXAMPLE))]
    pub gid: String,
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    #[schema(min_items = 1)]
    pub device_ids: Vec<String>,
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub by_user_id: String,
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub by_device_id: String,
    /// Group epoch after the Commit.
    pub epoch: u64,
    /// Per-group sequence number of the Commit.
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MemberAddedEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: MemberAddedEventType,
    pub data: MembershipChange,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MemberRemovedEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: MemberRemovedEventType,
    pub data: MembershipChange,
}

/// An MLS Welcome addressed to the receiving device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Welcome {
    #[schema(example = json!(GID_EXAMPLE))]
    pub gid: String,
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub sender_user_id: String,
    #[schema(example = json!(DEVICE_ID_EXAMPLE))]
    pub sender_device_id: String,
    /// Group epoch the Welcome joins.
    pub epoch: u64,
    /// Per-group sequence number of the Commit that produced the Welcome;
    /// fetch messages from `seq + 1` after joining.
    pub seq: u64,
    /// TLS-encoded MLSMessage (wire_format = mls_welcome) carrying a Welcome, base64.
    #[schema(content_encoding = "base64")]
    pub welcome: String,
    /// Ratchet tree (TLS encoding), base64, if the sender supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(content_encoding = "base64")]
    pub ratchet_tree: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WelcomeEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: WelcomeEventType,
    pub data: Welcome,
}

/// Query of GET /v2/welcomes/pending.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PendingWelcomesQuery {
    /// Maximum number of Welcomes (1-200).
    #[param(minimum = 1, maximum = 200, default = 50)]
    pub limit: Option<u32>,
}

/// A Welcome addressed to the calling device that it has not acknowledged.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PendingWelcome {
    #[serde(flatten)]
    pub welcome: Welcome,
    /// When the hub stored the Welcome.
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PendingWelcomeList {
    /// Oldest first.
    pub welcomes: Vec<PendingWelcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyPackagesLow {
    /// Remaining one-time KeyPackages of the receiving device.
    pub available: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyPackagesLowEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: KeyPackagesLowEventType,
    pub data: KeyPackagesLow,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum HostingRecordExpiringEventType {
    #[serde(rename = "hosting_record.expiring")]
    Tag,
}

/// A newer DeviceList was stored for the receiving user or for a user sharing
/// a group with the receiving device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceListUpdatedEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: DeviceListUpdatedEventType,
    pub data: DeviceList,
}

/// The receiving user's hosting record expires soon.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingRecordExpiring {
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// When the stored record expires (ms since the Unix epoch).
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub expires_at: u64,
    /// `seq` of the stored record.
    pub seq: u64,
}

/// Emitted once per record `seq` (at most once per 24 hours per user) to the
/// user's active devices when less than 48 hours remain on the hosting
/// record listing this hub. Publish a renewed record (new `seq`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingRecordExpiringEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: HostingRecordExpiringEventType,
    pub data: HostingRecordExpiring,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum HostingRecordUpdatedEventType {
    #[serde(rename = "hosting_record.updated")]
    Tag,
}

/// A hub entry of a hosting record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingRecordHub {
    #[schema(example = json!(HUB_ID_EXAMPLE))]
    pub hub_id: String,
    /// Lower is preferred.
    #[schema(minimum = 0, maximum = 255)]
    pub priority: u8,
}

/// The receiving user's hosting record as stored by this hub.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingRecordUpdated {
    #[schema(example = json!(USER_ID_EXAMPLE))]
    pub user_id: String,
    /// `seq` of the stored record; dedup across hubs by it.
    pub seq: u64,
    /// When the stored record expires (ms since the Unix epoch).
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub expires_at: u64,
    /// Whether the record lists this hub.
    pub hosted: bool,
    /// The listed hubs.
    pub hubs: Vec<HostingRecordHub>,
}

/// Emitted to the user's active devices on this hub when a stored record
/// changes the listed hubs or their priorities (renewals with the same
/// entries emit nothing). Multi-homing (H4), emitted with federation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostingRecordUpdatedEvent {
    pub cursor: u64,
    #[schema(example = json!(TIMESTAMP_EXAMPLE))]
    pub created_at: i64,
    #[schema(inline)]
    pub r#type: HostingRecordUpdatedEventType,
    pub data: HostingRecordUpdated,
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlobCreated {
    /// Blob ID `<origin hub_id>/b_<random>`; percent-encode `/` in paths.
    #[schema(
        example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq/b_Hk4dN7sL2pX9cV0mB5qT1g"
    )]
    pub blob_id: String,
    /// Stored size in bytes.
    pub size: u64,
}

/// Raw encrypted bytes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct RawBytes(pub Vec<u8>);

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

/// Push registration of the calling device. Everything but `log` is opaque
/// to the hub and passed to the push server's webhook (`docs/push.md`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PushRegistration {
    /// Push platform name, interpreted by the push server (e.g. `apns`,
    /// `fcm`, `unifiedpush`). `log` is the hub's test provider and is never
    /// sent to the webhook.
    #[schema(pattern = "^[a-z0-9._-]{1,64}$", example = "apns")]
    pub provider: String,
    /// Platform token, opaque to the hub: 1-4096 bytes without control
    /// characters.
    #[schema(min_length = 1, max_length = 4096)]
    pub token: String,
    /// App identifier for the push server (e.g. bundle ID): 1-255
    /// characters of `A-Z a-z 0-9 . - _ :`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "im.g.apps")]
    pub app_id: Option<String>,
    /// Platform sandbox flag for the push server; absent if not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<bool>,
    /// Opaque key for the push server (e.g. a Web Push `p256dh`): base64url,
    /// padding optional, at most 256 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        min_length = 1,
        max_length = 256,
        example = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
    )]
    pub p256dh: Option<String>,
    /// Opaque secret for the push server (e.g. a Web Push `auth`):
    /// base64url, padding optional, at most 256 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(min_length = 1, max_length = 256, example = "BTBZMqHH6r4Tts7J_aSIgg")]
    pub auth: Option<String>,
}
