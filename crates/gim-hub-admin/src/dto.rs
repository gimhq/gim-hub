//! Request and response bodies of the admin API. Timestamps are integer
//! seconds since the Unix epoch, except lode's, which are passed through
//! from `state.json` verbatim.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// POST /admin/api/login body.
#[derive(Clone, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// The admin token from `GIM_HUB_ADMIN_TOKEN` or `GIM_HUB_ADMIN_TOKEN_FILE`.
    pub token: String,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// A new token session.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    /// Always `token`.
    pub actor: String,
    /// Send as `X-CSRF-Token` on every non-GET request.
    pub csrf_token: String,
    /// Absolute session expiry.
    pub expires_at: i64,
}

/// The current admin session.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionResponse {
    /// `token`, or `header:<identity>` for a trusted-proxy session.
    pub actor: String,
    /// `token` or `header`.
    pub auth: String,
    pub csrf_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Overview {
    /// The release version (`LODE_ACTIVE_VERSION` under lode).
    pub version: String,
    /// Build revision, `unknown` when not built from a checkout.
    pub revision: String,
    pub hub_id: String,
    pub public_url: Option<String>,
    pub started_at: i64,
    pub uptime_seconds: i64,
    pub storage: Storage,
    pub counts: Counts,
    pub push: PushCounters,
    pub event_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Storage {
    /// The database file plus its WAL.
    pub db_bytes: u64,
    /// Total size of the blob directory.
    pub blob_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Counts {
    pub users: i64,
    /// Active devices.
    pub devices: i64,
    pub groups: i64,
    pub blobs: i64,
}

/// Push dispatcher counters since the hub started.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PushCounters {
    pub enqueued: u64,
    pub coalesced: u64,
    pub upgraded: u64,
    pub dropped: u64,
    pub sent: u64,
    pub skipped: u64,
    pub invalid_token: u64,
    pub retried: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserList {
    pub items: Vec<UserItem>,
    /// Pass as `cursor` for the next page; `null` on the last page.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserItem {
    pub user_id: String,
    pub handle: Option<String>,
    pub suspended: bool,
    pub created_at: i64,
    /// Active devices.
    pub device_count: i64,
    /// Latest sign-in among the user's current sessions.
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserDetail {
    pub user_id: String,
    pub handle: Option<String>,
    pub suspended: bool,
    pub suspended_at: Option<i64>,
    pub created_at: i64,
    /// Hub IDs listed in the user's stored hosting record (empty without
    /// one).
    pub hosting_hubs: Vec<String>,
    pub devices: Vec<DeviceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceItem {
    pub device_id: String,
    pub created_at: i64,
    /// Latest sign-in among the device's current sessions.
    pub last_seen: Option<i64>,
    /// Active in the user's current DeviceList.
    pub active: bool,
    pub sessions: Vec<SessionItem>,
}

/// An unexpired device session.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionItem {
    /// The first 16 hex characters of the SHA-256 of the session token;
    /// never the token.
    pub session_ref: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// POST /admin/api/users/{user_id}/suspend body (optional).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SuspendRequest {
    /// Recorded in the audit log.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Revoked {
    /// Sessions deleted.
    pub revoked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FederationStatus {
    pub enabled: bool,
    /// libp2p PeerId of the runtime key.
    pub peer_id: Option<String>,
    pub listen_addrs: Vec<String>,
    /// Advertised addresses.
    pub external_addrs: Vec<String>,
    pub peers: Vec<PeerItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerItem {
    pub hub_id: String,
    /// Bound now (a verified, admitted connection).
    pub connected: bool,
    /// Queued S2S outbox entries.
    pub outbox_backlog: i64,
    /// Set while deliveries to the peer are failing.
    pub last_error: Option<String>,
    /// Last connection.
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Allowlist {
    /// `GIM_HUB_FEDERATION_ALLOWLIST`.
    pub path: String,
    /// The file contents.
    pub text: String,
    /// Parsed entries by hub ID (the own hub is skipped).
    pub entries: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AllowlistEntry {
    pub hub_id: String,
    /// Static multiaddrs.
    pub addrs: Vec<String>,
}

/// PUT /admin/api/federation/allowlist body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AllowlistUpdate {
    /// New file contents: one `hub_id [multiaddr ...]` per line, `#`
    /// comments.
    pub text: String,
}

/// lode status. Only `supervised` when the hub does not run under lode.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LodeStatus {
    pub supervised: bool,
    /// lode's fields from `state.json`; absent when not supervised.
    #[serde(flatten)]
    pub state: Option<LodeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LodeState {
    /// `starting`, `running`, `held`, `updating`, `rolling-back`,
    /// `stopping`, `stopped` or `error`.
    pub status: Option<String>,
    pub current: Option<String>,
    pub available: Option<String>,
    pub last_good: Option<String>,
    pub last_check: Option<String>,
    pub last_error: Option<String>,
    pub history: Vec<LodeHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LodeHistoryEntry {
    pub version: String,
    pub at: String,
    /// `good` or `bad`.
    pub result: String,
}

/// POST /admin/api/lode/update body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct LodeUpdate {
    /// A version, or `latest`.
    pub version: String,
}

/// POST /admin/api/lode/rollback body (optional).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct LodeRollback {
    /// Defaults to lode's `last_good`.
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigView {
    pub items: Vec<ConfigItem>,
}

/// One effective configuration value.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigItem {
    pub key: String,
    /// `null` when unset or redacted.
    pub value: Option<String>,
    /// A secret is configured but not shown.
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditList {
    /// Newest first.
    pub items: Vec<AuditItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditItem {
    pub id: i64,
    pub at: i64,
    /// `token`, `header:<identity>`, or `anonymous` for failed logins.
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub source_ip: String,
    /// `ok` or `error`.
    pub result: String,
    pub detail: Option<String>,
}
