//! Groups and MLS Commits.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use gim_hub_db::{
    events, groups, hosting as hosting_store, keypackages,
    messages::{self, Change, Membership, StoredMessage},
    remote_identity, users, welcomes, Connection, DbError, Transaction,
};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{self, ErrorCode};
use gim_hub_s2s::{
    ops::{
        deliver::{sequenced_message, to_sequenced},
        fetch_log,
        seed::Bootstrap,
        submit,
    },
    outbox::NewEntry,
    owner_of, BoxFuture, FederationService, GroupService, Groups, HostingError, OutboxSender,
    SubmitError,
};
use prost::Message as _;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    identity::json_body, keypackages as keypackage_handlers, messages as message_handlers,
    welcomes as welcome_handlers,
};
use crate::{
    auth::AuthDevice,
    dto::{
        CommitResult, CreateGroupRequest, Error, Group, GroupKind, GroupList, GroupMember,
        MembershipChange, StaleEpochError, SubmitCommitRequest, Welcome,
    },
    error::{ApiError, PEER_UNAVAILABLE_RETRY_AFTER},
    mls,
    state::AppState,
};

const MAX_CLIENT_ID_CHARS: usize = 64;
const MAX_WELCOME_RECIPIENTS: usize = 500;

/// RFC 4648 base32, lowercase, unpadded.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// 128 random bits, base32.
fn random_id() -> Result<String, ApiError> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(base32(&raw))
}

fn kind_name(kind: GroupKind) -> &'static str {
    match kind {
        GroupKind::Direct => "direct",
        GroupKind::Group => "group",
    }
}

fn to_dto(group: groups::Group, members: Vec<groups::Member>) -> Group {
    Group {
        gid: group.gid,
        kind: if group.kind == "direct" {
            GroupKind::Direct
        } else {
            GroupKind::Group
        },
        epoch: group.epoch,
        last_seq: group.last_seq,
        created_by_user_id: group.created_by_user_id,
        created_by_device_id: group.created_by_device_id,
        created_at: group.created_at,
        members: members
            .into_iter()
            .map(|m| GroupMember {
                user_id: m.user_id,
                device_id: m.device_id,
            })
            .collect(),
    }
}

fn is_member(members: &[groups::Member], user_id: &str, device_id: &str) -> bool {
    members
        .iter()
        .any(|m| m.user_id == user_id && m.device_id == device_id)
}

#[utoipa::path(
    post,
    path = "/v2/groups",
    tag = "groups",
    summary = "Create a group",
    description = "Assigns a new `gid = <owner hub_id>/<random_128 base32lower>` (this hub's \
`hub_id`, stable across runtime-key rotation) at epoch 0 with the calling device as the only member. Further members are added by Commits.",
    request_body = CreateGroupRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Group created", body = Group),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn create_group(
    State(state): State<AppState>,
    auth: AuthDevice,
    body: Result<Json<CreateGroupRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Group>), ApiError> {
    let body = json_body(body)?;
    let group = groups::Group {
        gid: format!("{}/{}", state.hub.hub_id().as_str(), random_id()?),
        kind: kind_name(body.kind).to_owned(),
        epoch: 0,
        last_seq: 0,
        created_by_user_id: auth.user_id,
        created_by_device_id: auth.device_id,
        created_at: state.clock.now_ms(),
    };
    let stored = group.clone();
    state
        .db
        .write(move |tx| groups::create(tx, &stored))
        .await?;
    let members = vec![groups::Member {
        user_id: group.created_by_user_id.clone(),
        device_id: group.created_by_device_id.clone(),
        leaf_index: Some(0),
    }];
    Ok((StatusCode::CREATED, Json(to_dto(group, members))))
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
pub async fn list_groups(
    State(state): State<AppState>,
    auth: AuthDevice,
) -> Result<Json<GroupList>, ApiError> {
    let list = state
        .db
        .read(move |conn| {
            groups::list_for_device(conn, &auth.user_id, &auth.device_id)?
                .into_iter()
                .map(|group| {
                    let members = groups::members(conn, &group.gid)?;
                    Ok(to_dto(group, members))
                })
                .collect::<Result<Vec<_>, gim_hub_db::DbError>>()
        })
        .await?;
    Ok(Json(GroupList { groups: list }))
}

#[utoipa::path(
    get,
    path = "/v2/groups/{gid}",
    tag = "groups",
    summary = "Get a group",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Group", body = Group),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_group(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
) -> Result<Json<Group>, ApiError> {
    let group = state
        .db
        .read(move |conn| {
            let group = groups::get(conn, &gid)?.ok_or(ApiError::NotFound)?;
            let members = groups::members(conn, &gid)?;
            if !is_member(&members, &auth.user_id, &auth.device_id) {
                return Err(ApiError::NotMember);
            }
            Ok(to_dto(group, members))
        })
        .await?;
    Ok(Json(group))
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
and emits nothing. Any other Commit for a past epoch fails with 409 `stale_epoch`.\n\n\
For a group owned by another hub (federation), this hub forwards the Commit to the owning hub, \
which sequences it; the response is the owner's result and the local replica already holds the \
Commit. Added members on other hubs get their Welcome through their own hub. This needs the \
caller's hosting record listing this hub (403 `hosting_record_required`); when the owning hub \
refuses the request the result is 502 `peer_refused`, when it cannot be reached 503 \
`peer_unavailable` with `Retry-After` (retry the same Commit: it is idempotent by hash).",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    request_body = SubmitCommitRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Duplicate of an accepted Commit (`duplicate: true`)", body = CommitResult),
        (status = 201, description = "Commit accepted", body = CommitResult),
        (status = 400, description = "Not a PublicMessage Commit for this group, invalid credential of an added member, or Welcome fields inconsistent (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`), group policy forbids the change (`forbidden`), or the group is owned by another hub and the caller has no valid hosting record listing this hub (`hosting_record_required`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 409, description = "Commit epoch is not the group epoch (`stale_epoch`)", body = StaleEpochError),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
        (status = 502, description = "The owning hub of the group refused the request (`peer_refused`)", body = Error),
        (status = 503, description = "The owning hub of the group is unreachable (`peer_unavailable`); retry after `Retry-After` seconds", body = Error),
    ),
)]
pub async fn submit_commit(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
    body: Result<Json<SubmitCommitRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CommitResult>), ApiError> {
    let body = json_body(body)?;
    let commit = CommitInput::validate(&state, gid, body)?;
    let sender = Sender {
        user_id: auth.user_id,
        device_id: auth.device_id,
    };
    if let Some(owner) = remote_owner(&state, &commit.gid) {
        return forward_commit(&state, sender, owner, commit).await;
    }
    let (seq, epoch, duplicate) =
        match sequence_commit(&state, sender, commit, Origin::Client).await? {
            CommitOutcome::Duplicate { seq, epoch } => (seq, epoch, true),
            CommitOutcome::Accepted { seq, epoch, .. } => (seq, epoch, false),
        };
    Ok((
        if duplicate {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(CommitResult {
            seq,
            epoch,
            duplicate,
        }),
    ))
}

/// The device a Commit or message is sequenced for.
#[derive(Debug, Clone)]
pub(crate) struct Sender {
    pub user_id: String,
    pub device_id: String,
}

/// Where a Commit reached the owning hub from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// A client of this hub.
    Client,
    /// A member hub (`SubmitCommit`): an added member's identity may come
    /// from the KeyPackage credential (§5.3).
    Peer,
}

/// The owning hub of `gid` if it is another hub and federation is enabled:
/// the group is then a replica here (§5.4). With federation disabled every
/// gid is handled locally, as on a single hub.
pub(crate) fn remote_owner(state: &AppState, gid: &str) -> Option<HubId> {
    if !state.federation.is_enabled() {
        return None;
    }
    owner_of(gid)
        .filter(|owner| *owner != state.hub.hub_id().as_str())
        .and_then(|owner| HubId::parse(owner).ok())
}

/// A Commit request checked as far as possible without the database.
struct CommitInput {
    gid: String,
    client_id: String,
    mls_message: Vec<u8>,
    parsed: mls::ParsedCommit,
    welcome: Option<WelcomeInput>,
}

struct WelcomeInput {
    welcome: Vec<u8>,
    ratchet_tree: Option<Vec<u8>>,
    recipients: Vec<Recipient>,
}

/// A Welcome recipient; member hubs name recipients by device only, the
/// owner matches them against the added members (§6.3).
struct Recipient {
    user_id: Option<String>,
    device_id: String,
}

impl CommitInput {
    fn validate(
        state: &AppState,
        gid: String,
        body: SubmitCommitRequest,
    ) -> Result<Self, ApiError> {
        let decode = |field: &str, value: &str| {
            STANDARD
                .decode(value)
                .map_err(|_| ApiError::ValidationFailed(format!("{field} must be base64")))
        };
        let mls_message = decode("mls_message", &body.mls_message)?;
        let welcome = match (body.welcome, body.welcome_recipients) {
            (None, None) => None,
            (Some(welcome), Some(recipients)) => Some(WelcomeInput {
                welcome: decode("welcome", &welcome)?,
                ratchet_tree: body
                    .ratchet_tree
                    .as_deref()
                    .map(|tree| decode("ratchet_tree", tree))
                    .transpose()?,
                recipients: recipients
                    .into_iter()
                    .map(|r| Recipient {
                        user_id: Some(r.user_id),
                        device_id: r.device_id,
                    })
                    .collect(),
            }),
            _ => return Err(invalid("welcome and welcome_recipients go together")),
        };
        if welcome.is_none() && body.ratchet_tree.is_some() {
            return Err(invalid("ratchet_tree requires welcome"));
        }
        Self::new(state, gid, body.client_id, mls_message, welcome)
    }

    /// A Commit forwarded by a member hub.
    fn from_peer(state: &AppState, request: s2s::SubmitCommitRequest) -> Result<Self, ApiError> {
        let welcome = match request.welcome {
            None if request.welcome_recipient_device_ids.is_empty() => {
                if request.ratchet_tree.is_some() {
                    return Err(invalid("ratchet_tree requires welcome"));
                }
                None
            }
            Some(welcome) if !request.welcome_recipient_device_ids.is_empty() => {
                Some(WelcomeInput {
                    welcome,
                    ratchet_tree: request.ratchet_tree,
                    recipients: request
                        .welcome_recipient_device_ids
                        .into_iter()
                        .map(|device_id| Recipient {
                            user_id: None,
                            device_id,
                        })
                        .collect(),
                })
            }
            _ => return Err(invalid("welcome and welcome_recipients go together")),
        };
        Self::new(
            state,
            request.gid,
            request.client_id,
            request.mls_message,
            welcome,
        )
    }

    fn new(
        state: &AppState,
        gid: String,
        client_id: String,
        mls_message: Vec<u8>,
        welcome: Option<WelcomeInput>,
    ) -> Result<Self, ApiError> {
        let client_id_chars = client_id.chars().count();
        if client_id_chars == 0 || client_id_chars > MAX_CLIENT_ID_CHARS {
            return Err(invalid("client_id must be 1-64 characters"));
        }
        if mls_message.len() > state.config.max_message_bytes {
            return Err(ApiError::PayloadTooLarge);
        }
        if let Some(welcome) = &welcome {
            if welcome.recipients.is_empty() || welcome.recipients.len() > MAX_WELCOME_RECIPIENTS {
                return Err(invalid("welcome_recipients must hold 1-500 devices"));
            }
            if welcome.welcome.len() + welcome.ratchet_tree.as_ref().map_or(0, Vec::len)
                > state.config.max_message_bytes
            {
                return Err(ApiError::PayloadTooLarge);
            }
        }
        let parsed = mls::parse_commit(&mls_message)?;
        if parsed.group_id != gid.as_bytes() {
            return Err(invalid("MLS group ID does not match the gid"));
        }
        Ok(Self {
            gid,
            client_id,
            mls_message,
            parsed,
            welcome,
        })
    }
}

fn invalid(message: &str) -> ApiError {
    ApiError::ValidationFailed(message.to_owned())
}

enum CommitOutcome {
    Duplicate {
        seq: u64,
        epoch: u64,
    },
    Accepted {
        seq: u64,
        epoch: u64,
        /// The stored Commit and its membership changes.
        message: Box<s2s::SequencedMessage>,
    },
}

fn event_data(data: &impl Serialize) -> Result<String, ApiError> {
    serde_json::to_string(data).map_err(|err| ApiError::Internal(err.to_string()))
}

/// Device IDs grouped by user.
fn by_user(devices: &[(String, String)]) -> BTreeMap<&str, Vec<String>> {
    let mut users: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (user_id, device_id) in devices {
        users.entry(user_id).or_default().push(device_id.clone());
    }
    users
}

/// The stored DeviceList of `user_id`: a local user's, else the cached
/// remote copy (§5.1).
fn stored_device_list(conn: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, ApiError> {
    if let Some(list) = users::get_device_list(conn, user_id)? {
        return Ok(Some(list.device_list));
    }
    Ok(remote_identity::get_device_list(conn, user_id)?.map(|list| list.device_list))
}

/// The expected identity of each added KeyPackage (§5.3): this hub's claim
/// ledger, then, for Commits from member hubs, the KeyPackage credential.
fn added_identities(
    conn: &Connection,
    parsed: &mls::ParsedCommit,
    origin: Origin,
) -> Result<Vec<Option<(String, String)>>, ApiError> {
    parsed
        .added
        .iter()
        .map(|(kp_hash, leaf)| {
            if let Some(owner) = keypackages::claimed_owner(conn, kp_hash)? {
                return Ok(Some(owner));
            }
            if let Some(claim) = remote_identity::get_claim(conn, kp_hash)? {
                return Ok(Some((claim.user_id, claim.device_id)));
            }
            Ok(match origin {
                Origin::Peer => mls::credential_identity(leaf),
                Origin::Client => None,
            })
        })
        .collect()
}

/// Brings the DeviceLists and hosting records a Commit needs up to date,
/// outside any transaction (§2, §5.3): the lists of the committer and the
/// added members (refetched once after a credential failure, §5.1) and the
/// hosting records of every member for the fan-out (§6.4).
async fn prepare_commit(
    state: &AppState,
    commit: &CommitInput,
    sender: &Sender,
    identities: &[Option<(String, String)>],
) -> Result<(), ApiError> {
    let mut checks: Vec<(String, String, mls::LeafCredential)> = Vec::new();
    for leaf in &commit.parsed.own_leaves {
        checks.push((
            sender.user_id.clone(),
            sender.device_id.clone(),
            leaf.clone(),
        ));
    }
    for (identity, (_, leaf)) in identities.iter().zip(&commit.parsed.added) {
        if let Some((user_id, device_id)) = identity {
            checks.push((user_id.clone(), device_id.clone(), leaf.clone()));
        }
    }
    let users: BTreeSet<String> = checks.iter().map(|(user, _, _)| user.clone()).collect();
    for user_id in &users {
        match state.device_lists.device_list_for(user_id).await {
            Err(HostingError::Unavailable(reason)) => {
                tracing::info!(%user_id, %reason, "DeviceList unavailable");
                return Err(ApiError::PeerUnavailable {
                    retry_after: PEER_UNAVAILABLE_RETRY_AFTER,
                });
            }
            Err(HostingError::Db(err)) => return Err(err.into()),
            Ok(_) | Err(_) => {}
        }
    }
    let failed = state
        .db
        .read(move |conn| {
            let mut failed = BTreeSet::new();
            for (user_id, device_id, leaf) in &checks {
                let list = stored_device_list(conn, user_id)?;
                if mls::check_leaf_credential(&leaf.clone(), list.as_deref(), user_id, device_id)
                    .is_err()
                {
                    failed.insert(user_id.clone());
                }
            }
            Ok::<_, ApiError>(failed)
        })
        .await?;
    for user_id in failed {
        if let Err(err) = state.device_lists.refetch_after_failure(&user_id).await {
            tracing::info!(%user_id, %err, "DeviceList refetch failed");
        }
    }
    let mut members = users;
    members.extend(roster_users(state, &commit.gid).await?);
    resolve_hosting(state, members).await;
    Ok(())
}

/// Users of the roster of `gid`.
pub(crate) async fn roster_users(
    state: &AppState,
    gid: &str,
) -> Result<BTreeSet<String>, ApiError> {
    let gid = gid.to_owned();
    Ok(state
        .db
        .read(move |conn| groups::member_devices(conn, &gid))
        .await?
        .into_iter()
        .map(|(user_id, _)| user_id)
        .collect())
}

/// Resolves (and caches) the hosting records of `users`, so the fan-out in
/// the sequencing transaction can read them (§6.4).
pub(crate) async fn resolve_hosting(state: &AppState, users: BTreeSet<String>) {
    for user_id in users {
        if let Err(err) = state.hosting.resolve(&user_id).await {
            tracing::debug!(%user_id, %err, "hosting record not resolved for the fan-out");
        }
    }
}

/// Every hub other than `own` listed in the stored hosting records of
/// `users` ("hubs of a user", §6.4).
pub(crate) fn hubs_of<'a>(
    conn: &Connection,
    users: impl IntoIterator<Item = &'a str>,
    own: &HubId,
) -> Result<BTreeSet<HubId>, ApiError> {
    let mut hubs = BTreeSet::new();
    for user_id in users {
        let Some(record) = hosting_store::get(conn, user_id)? else {
            continue;
        };
        for hub_id in record.hub_ids {
            if hub_id != own.as_str() {
                match HubId::parse(&hub_id) {
                    Ok(hub_id) => {
                        hubs.insert(hub_id);
                    }
                    Err(err) => tracing::warn!(%user_id, %hub_id, %err, "invalid hub_id"),
                }
            }
        }
    }
    Ok(hubs)
}

/// Queues `Deliver(gid, seq)` for every hub in `peers` (§6.4).
pub(crate) fn queue_deliver(
    tx: &Transaction<'_>,
    outbox: &dyn OutboxSender,
    peers: &BTreeSet<HubId>,
    stored: &StoredMessage,
) -> Result<(), ApiError> {
    let size = i64::try_from(stored.payload.len()).unwrap_or(i64::MAX);
    for peer in peers {
        outbox.enqueue_in_tx(
            tx,
            peer,
            NewEntry::Deliver {
                gid: &stored.gid,
                seq: stored.seq,
                size,
            },
        )?;
    }
    Ok(())
}

/// Sequences a Commit of a group owned here: credential checks of every
/// added member (local or remote, §5.3), then [`apply_commit`].
async fn sequence_commit(
    state: &AppState,
    sender: Sender,
    commit: CommitInput,
    origin: Origin,
) -> Result<CommitOutcome, ApiError> {
    let federated = state.federation.is_enabled();
    let parsed = commit.parsed.clone();
    let identities = state
        .db
        .read(move |conn| added_identities(conn, &parsed, origin))
        .await?;
    keypackage_handlers::burn_added(state, &commit.parsed).await?;
    if federated {
        prepare_commit(state, &commit, &sender, &identities).await?;
    }
    let context = CommitContext {
        sender,
        identities,
        message_id: random_id()?,
        now: state.clock.now_ms(),
        fan_out: federated.then(|| (state.hub.hub_id().clone(), state.outbox.clone())),
    };
    let (outcome, wake) = state
        .db
        .write(move |tx| apply_commit(tx, commit, context))
        .await?;
    for (user_id, device_id) in &wake {
        state.notifier.notify(user_id, device_id);
    }
    Ok(outcome)
}

struct CommitContext {
    sender: Sender,
    /// Expected identity of each added KeyPackage, `None` if unknown.
    identities: Vec<Option<(String, String)>>,
    message_id: String,
    now: i64,
    /// This hub and the outbox, when federation is enabled.
    fan_out: Option<(HubId, Arc<dyn OutboxSender>)>,
}

/// Sequences a Commit: appends it to the log, advances the epoch, updates the
/// roster, emits the Commit, membership and Welcome events to local devices
/// and queues the fan-out to member hubs. Returns the devices to wake.
fn apply_commit(
    tx: &Transaction<'_>,
    commit: CommitInput,
    context: CommitContext,
) -> Result<(CommitOutcome, BTreeSet<(String, String)>), ApiError> {
    let CommitInput {
        gid,
        client_id,
        mls_message,
        parsed,
        welcome,
    } = commit;
    let CommitContext {
        sender: auth,
        identities,
        message_id,
        now,
        fan_out,
    } = context;

    let group = groups::get(tx, &gid)?.ok_or(ApiError::NotFound)?;
    let members = groups::members(tx, &gid)?;
    let sender = members
        .iter()
        .find(|m| m.user_id == auth.user_id && m.device_id == auth.device_id)
        .ok_or(ApiError::NotMember)?;
    let commit_hash: [u8; 32] = Sha256::digest(&mls_message).into();
    if let Some((seq, epoch)) = messages::find_commit(tx, &gid, &commit_hash)? {
        return Ok((
            CommitOutcome::Duplicate {
                seq,
                epoch: epoch + 1,
            },
            BTreeSet::new(),
        ));
    }
    if parsed.epoch != group.epoch {
        return Err(ApiError::StaleEpoch {
            current_epoch: group.epoch,
        });
    }
    if sender.leaf_index != Some(parsed.sender_leaf) {
        return Err(invalid("Commit sender leaf is not the calling device"));
    }
    if messages::find_by_client_id(tx, &gid, &auth.device_id, &client_id)?.is_some() {
        return Err(invalid("client_id was already used in this group"));
    }

    // Removes first (RFC 9420 §12.3), then Adds into the leftmost blank leaves.
    let by_leaf: HashMap<u32, &groups::Member> = members
        .iter()
        .filter_map(|m| m.leaf_index.map(|leaf| (leaf, m)))
        .collect();
    let mut removed = Vec::new();
    let mut removed_leaves = HashSet::new();
    for leaf in &parsed.removed {
        let member = by_leaf
            .get(leaf)
            .ok_or_else(|| invalid("Remove proposal targets an empty leaf"))?;
        if !removed_leaves.insert(*leaf) {
            return Err(invalid("duplicate Remove proposal"));
        }
        if *leaf == parsed.sender_leaf {
            return Err(invalid("a Commit cannot remove its sender"));
        }
        removed.push((member.user_id.clone(), member.device_id.clone()));
    }
    let remaining: Vec<&groups::Member> = members
        .iter()
        .filter(|m| {
            m.leaf_index
                .is_none_or(|leaf| !removed_leaves.contains(&leaf))
        })
        .collect();

    // The committer's own leaves keep its identity.
    if !parsed.own_leaves.is_empty() {
        let device_list = stored_device_list(tx, &auth.user_id)?;
        for leaf in &parsed.own_leaves {
            mls::check_leaf_credential(
                leaf,
                device_list.as_deref(),
                &auth.user_id,
                &auth.device_id,
            )?;
        }
    }

    let mut added = Vec::new();
    for ((_, leaf), identity) in parsed.added.iter().zip(identities) {
        let (user_id, device_id) = identity.ok_or_else(|| invalid(mls::KP_NOT_CLAIMED))?;
        if remaining
            .iter()
            .any(|m| m.user_id == user_id && m.device_id == device_id)
            || added.contains(&(user_id.clone(), device_id.clone()))
        {
            return Err(invalid(
                "Add proposal for a device that is already a member",
            ));
        }
        let device_list = stored_device_list(tx, &user_id)?;
        mls::check_leaf_credential(leaf, device_list.as_deref(), &user_id, &device_id)?;
        added.push((user_id, device_id));
    }
    let occupied: BTreeSet<u32> = remaining.iter().filter_map(|m| m.leaf_index).collect();
    let leaves = mls::assign_leaves(&occupied, added.len());

    // Welcome recipients, resolved against the added devices.
    let mut recipients: Vec<(String, String)> = Vec::new();
    if let Some(welcome) = &welcome {
        for recipient in &welcome.recipients {
            let key = added
                .iter()
                .find(|(user_id, device_id)| {
                    *device_id == recipient.device_id
                        && recipient
                            .user_id
                            .as_ref()
                            .is_none_or(|user| user == user_id)
                })
                .filter(|key| !recipients.contains(key))
                .ok_or_else(|| {
                    invalid("welcome_recipients must be distinct devices added by this Commit")
                })?;
            recipients.push(key.clone());
        }
    }

    let framing_epoch =
        i64::try_from(parsed.epoch).map_err(|_| invalid("Commit epoch out of range"))?;
    let stored = messages::append(
        tx,
        &messages::NewMessage {
            gid: &gid,
            epoch: framing_epoch,
            kind: "commit",
            sender_user_id: &auth.user_id,
            sender_device_id: &auth.device_id,
            client_id: &client_id,
            payload: &mls_message,
            commit_hash: Some(&commit_hash),
            message_id: &message_id,
        },
        now,
    )?;
    let seq = group.last_seq + 1;
    let epoch = group.epoch + 1;
    let changes = MembershipChanges {
        added: added
            .iter()
            .zip(&leaves)
            .map(|((user_id, device_id), leaf)| (user_id.clone(), device_id.clone(), Some(*leaf)))
            .collect(),
        removed: removed.clone(),
    };
    let mut wake = record_commit(tx, &stored, &changes, now)?;

    let local_recipients: Vec<&(String, String)> = recipients
        .iter()
        .map(|key| Ok((key, hosting_store::is_local(tx, &key.0)?)))
        .collect::<Result<Vec<_>, gim_hub_db::DbError>>()?
        .into_iter()
        .filter_map(|(key, local)| local.then_some(key))
        .collect();
    if let Some(welcome) = &welcome {
        let data = event_data(&Welcome {
            gid: gid.clone(),
            sender_user_id: auth.user_id.clone(),
            sender_device_id: auth.device_id.clone(),
            epoch,
            seq,
            welcome: STANDARD.encode(&welcome.welcome),
            ratchet_tree: welcome
                .ratchet_tree
                .as_ref()
                .map(|tree| STANDARD.encode(tree)),
        })?;
        for (user_id, device_id) in &local_recipients {
            welcomes::insert_pending(tx, user_id, device_id, &gid, &data, now)?;
            events::append(tx, user_id, device_id, "welcome", &data, now)?;
            wake.insert((user_id.clone(), device_id.clone()));
        }
    }

    if let Some((own, outbox)) = &fan_out {
        // Welcomes go ahead of the Commit's Deliver for the same peer (§6.2).
        if let Some(welcome) = &welcome {
            let snapshot = s2s::GroupSnapshot {
                kind: group.kind.clone(),
                created_by_user_id: group.created_by_user_id.clone(),
                created_by_device_id: group.created_by_device_id.clone(),
                created_at: u64::try_from(group.created_at).unwrap_or_default(),
                epoch,
                seq,
                members: groups::member_devices(tx, &gid)?
                    .into_iter()
                    .map(|(user_id, device_id)| s2s::Member { user_id, device_id })
                    .collect(),
            };
            for (user_id, device_ids) in by_user(&recipients) {
                let request = s2s::DeliverWelcomeRequest {
                    gid: gid.clone(),
                    sender_user_id: auth.user_id.clone(),
                    recipient_user_id: user_id.to_owned(),
                    recipient_device_ids: device_ids,
                    welcome: welcome.welcome.clone(),
                    ratchet_tree: welcome.ratchet_tree.clone(),
                    message_id: message_id.clone(),
                    group: Some(snapshot.clone()),
                    sender_device_id: auth.device_id.clone(),
                }
                .encode_to_vec();
                for peer in hubs_of(tx, [user_id], own)? {
                    outbox.enqueue_in_tx(
                        tx,
                        &peer,
                        NewEntry::DeliverWelcome {
                            gid: &gid,
                            payload: &request,
                        },
                    )?;
                }
            }
        }
        // Roster before the Commit (which includes the removed members) and
        // the added members.
        let users: BTreeSet<&str> = members
            .iter()
            .map(|m| m.user_id.as_str())
            .chain(added.iter().map(|(user_id, _)| user_id.as_str()))
            .collect();
        let peers = hubs_of(tx, users, own)?;
        queue_deliver(tx, outbox.as_ref(), &peers, &stored)?;
    }

    let message = to_sequenced(stored, Membership { added, removed });
    Ok((
        CommitOutcome::Accepted {
            seq,
            epoch,
            message: Box::new(message),
        },
        wake,
    ))
}

/// Devices added (with their leaf index, unknown on replicas) and removed
/// by a Commit.
struct MembershipChanges {
    added: Vec<(String, String, Option<u32>)>,
    removed: Vec<(String, String)>,
}

/// Applies a stored Commit to the group, on the owner and on replicas
/// alike: the Commit goes to every previous local member except its sender
/// (new members join from the Welcome), the roster changes, membership
/// events go to the old and the new local roster, the changes are recorded
/// for `Deliver` / `FetchLog`, and the epoch advances. Returns the devices
/// that received events.
fn record_commit(
    tx: &Transaction<'_>,
    stored: &StoredMessage,
    changes: &MembershipChanges,
    now: i64,
) -> Result<BTreeSet<(String, String)>, ApiError> {
    let gid = &stored.gid;
    let seq = u64::try_from(stored.seq).unwrap_or_default();
    let epoch = u64::try_from(stored.epoch).unwrap_or_default() + 1;
    let added: Vec<(String, String)> = changes
        .added
        .iter()
        .map(|(user_id, device_id, _)| (user_id.clone(), device_id.clone()))
        .collect();
    // A replica created from a Welcome snapshot already lists the added
    // devices; they do not get the Commit either.
    let mut wake: BTreeSet<(String, String)> =
        message_handlers::emit_message_events_except(tx, stored, &added, now)?
            .into_iter()
            .collect();
    let mut audience: BTreeSet<(String, String)> =
        groups::local_member_devices(tx, gid)?.into_iter().collect();
    for (user_id, device_id) in &changes.removed {
        groups::remove_member(tx, gid, user_id, device_id)?;
        messages::insert_membership(tx, gid, stored.seq, Change::Removed, user_id, device_id)?;
    }
    for (user_id, device_id, leaf) in &changes.added {
        match leaf {
            Some(leaf) => groups::add_member(tx, gid, user_id, device_id, *leaf, now)?,
            None => groups::add_replica_member(tx, gid, user_id, device_id, now)?,
        }
        messages::insert_membership(tx, gid, stored.seq, Change::Added, user_id, device_id)?;
    }
    groups::set_epoch(tx, gid, epoch)?;
    audience.extend(groups::local_member_devices(tx, gid)?);

    for (event_type, devices) in [
        ("group.member_removed", &changes.removed),
        ("group.member_added", &added),
    ] {
        for (user_id, device_ids) in by_user(devices) {
            let data = event_data(&MembershipChange {
                gid: gid.clone(),
                user_id: user_id.to_owned(),
                device_ids,
                by_user_id: stored.sender_user_id.clone(),
                by_device_id: stored.sender_device_id.clone(),
                epoch,
                seq,
            })?;
            for (to_user, to_device) in &audience {
                events::append(tx, to_user, to_device, event_type, &data, now)?;
                wake.insert((to_user.clone(), to_device.clone()));
            }
        }
    }
    Ok(wake)
}

// ---------------------------------------------------------------------------
// Member hub: forwarding to the owner (§6.3)
// ---------------------------------------------------------------------------

/// How long a member hub catches up its replica before answering 409.
const CATCH_UP_TIMEOUT: Duration = Duration::from_secs(2);

/// Forwards a Commit for a remote-owned group to its owner with
/// `SubmitCommit` and applies the sequenced Commit to the replica.
async fn forward_commit(
    state: &AppState,
    sender: Sender,
    owner: HubId,
    commit: CommitInput,
) -> Result<(StatusCode, Json<CommitResult>), ApiError> {
    let gid = commit.gid.clone();
    let parsed = commit.parsed.clone();
    let member = sender.clone();
    let identities = state
        .db
        .read(move |conn| {
            groups::get(conn, &gid)?.ok_or(ApiError::NotFound)?;
            if !groups::is_member(conn, &gid, &member.user_id, &member.device_id)? {
                return Err(ApiError::NotMember);
            }
            added_identities(conn, &parsed, Origin::Client)
        })
        .await?;
    keypackage_handlers::burn_added(state, &commit.parsed).await?;
    if identities.iter().any(Option::is_none) {
        return Err(invalid(mls::KP_NOT_CLAIMED));
    }
    state
        .hosting
        .require_hosting_record(&sender.user_id)
        .await?;

    let (welcome, recipients, ratchet_tree) = match commit.welcome {
        Some(welcome) => (
            Some(welcome.welcome),
            welcome
                .recipients
                .into_iter()
                .map(|recipient| recipient.device_id)
                .collect(),
            welcome.ratchet_tree,
        ),
        None => (None, Vec::new(), None),
    };
    let request = s2s::SubmitCommitRequest {
        gid: commit.gid.clone(),
        sender_user_id: sender.user_id,
        sender_device_id: sender.device_id,
        client_id: commit.client_id,
        mls_message: commit.mls_message,
        welcome,
        welcome_recipient_device_ids: recipients,
        ratchet_tree,
    };
    let response = match submit::submit_commit(state.federation.as_ref(), &owner, request).await {
        Ok(response) => response,
        Err(err) => return Err(forward_error(state, &owner, &commit.gid, err).await),
    };
    if let Some(message) = response.message.filter(|message| message.gid == commit.gid) {
        // Read-your-writes: the replica holds the Commit before the client
        // hears back (§6.3).
        if let Err(err) = apply_replica(state, &owner, vec![message], true).await {
            tracing::error!(%err, gid = commit.gid, "applying the submitted Commit failed");
        }
    }
    Ok((
        if response.duplicate {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(CommitResult {
            seq: response.seq,
            epoch: response.epoch,
            duplicate: response.duplicate,
        }),
    ))
}

/// Maps a failed submit to the owner to the client error (§6.3 table). A
/// stale epoch first catches up the replica with `FetchLog`.
pub(crate) async fn forward_error(
    state: &AppState,
    owner: &HubId,
    gid: &str,
    err: SubmitError,
) -> ApiError {
    let unavailable = |reason: &str| {
        tracing::info!(%owner, gid, reason, "owning hub unavailable");
        ApiError::PeerUnavailable {
            retry_after: PEER_UNAVAILABLE_RETRY_AFTER,
        }
    };
    match err {
        SubmitError::Disabled => ApiError::NotFound,
        SubmitError::Refused(reason) => ApiError::PeerRefused(reason),
        SubmitError::Unavailable(reason) => unavailable(&reason),
        SubmitError::Rejected(err) => match err.code() {
            ErrorCode::Conflict | ErrorCode::StaleEpoch => {
                let _ = tokio::time::timeout(
                    CATCH_UP_TIMEOUT,
                    fill_gap(state.clone(), owner.clone(), gid.to_owned()),
                )
                .await;
                let current_epoch = match err.current_epoch {
                    Some(epoch) => epoch,
                    None => {
                        let gid = gid.to_owned();
                        state
                            .db
                            .read(move |conn| groups::get(conn, &gid))
                            .await
                            .ok()
                            .flatten()
                            .map_or(0, |group| group.epoch)
                    }
                };
                ApiError::StaleEpoch { current_epoch }
            }
            ErrorCode::Invalid => ApiError::ValidationFailed(err.message),
            ErrorCode::Unauthorized => match err.client_code.as_str() {
                "not_member" => ApiError::NotMember,
                "forbidden" => ApiError::Forbidden(err.message),
                _ => ApiError::PeerRefused(err.message),
            },
            ErrorCode::NotFound => ApiError::NotFound,
            code => unavailable(&format!("{code:?}: {}", err.message)),
        },
    }
}

// ---------------------------------------------------------------------------
// Member hub: replicas (§5.4, §6.6)
// ---------------------------------------------------------------------------

/// Applies messages sequenced by `owner` to the replicas, per gid in `seq`
/// order, in one transaction (§6.6): duplicates are skipped, the next seq
/// is applied with the same local events as on a single hub, and a gap
/// stops the gid (and, with `fill_gaps`, starts a `FetchLog` gap fill).
/// Returns one ack per gid.
pub(crate) async fn apply_replica(
    state: &AppState,
    owner: &HubId,
    batch: Vec<s2s::SequencedMessage>,
    fill_gaps: bool,
) -> Result<Vec<s2s::GroupAck>, ApiError> {
    // Every path (Deliver, submit responses, FetchLog pages) only applies
    // messages of groups `owner` owns, and never to groups owned here.
    if owner == state.hub.hub_id()
        || batch
            .iter()
            .any(|message| owner_of(&message.gid) != Some(owner.as_str()))
    {
        return Err(ApiError::PeerRefused(
            "message for a group the peer does not own".into(),
        ));
    }
    let now = state.clock.now_ms();
    let (acks, gaps, wake) = state
        .db
        .write(move |tx| {
            let mut by_gid: Vec<(String, Vec<s2s::SequencedMessage>)> = Vec::new();
            for message in batch {
                match by_gid.iter_mut().find(|(gid, _)| *gid == message.gid) {
                    Some((_, list)) => list.push(message),
                    None => by_gid.push((message.gid.clone(), vec![message])),
                }
            }
            let (mut acks, mut gaps, mut wake) = (Vec::new(), Vec::new(), BTreeSet::new());
            for (gid, mut list) in by_gid {
                list.sort_by_key(|message| message.seq);
                let Some(group) = groups::get(tx, &gid)? else {
                    acks.push(s2s::GroupAck {
                        gid,
                        highest_contiguous_seq: 0,
                    });
                    continue;
                };
                let mut last_seq = group.last_seq;
                let detached = groups::replica(tx, &gid)?.is_some_and(|replica| replica.detached);
                if !detached {
                    for message in list {
                        if message.seq <= last_seq {
                            continue;
                        }
                        if message.seq != last_seq + 1 {
                            gaps.push(gid.clone());
                            break;
                        }
                        wake.extend(apply_replicated(tx, &message, now)?);
                        last_seq = message.seq;
                    }
                }
                acks.push(s2s::GroupAck {
                    gid,
                    highest_contiguous_seq: last_seq,
                });
            }
            Ok::<_, ApiError>((acks, gaps, wake))
        })
        .await?;
    for (user_id, device_id) in &wake {
        state.notifier.notify(user_id, device_id);
    }
    if fill_gaps {
        for gid in gaps {
            spawn_gap_fill(state.clone(), owner.clone(), gid);
        }
    }
    Ok(acks)
}

/// Stores one message at the replica's next seq and emits its local events;
/// a Commit also updates roster and epoch, and detaches the replica when no
/// local member is left.
fn apply_replicated(
    tx: &Transaction<'_>,
    message: &s2s::SequencedMessage,
    now: i64,
) -> Result<BTreeSet<(String, String)>, ApiError> {
    let commit = message.kind() == s2s::MessageKind::Commit;
    let commit_hash: Option<[u8; 32]> = commit.then(|| Sha256::digest(&message.payload).into());
    let stored = messages::append(
        tx,
        &messages::NewMessage {
            gid: &message.gid,
            epoch: i64::try_from(message.epoch).map_err(|_| invalid("epoch out of range"))?,
            kind: if commit { "commit" } else { "application" },
            sender_user_id: &message.sender_user_id,
            sender_device_id: &message.sender_device_id,
            client_id: &message.client_id,
            payload: &message.payload,
            commit_hash: commit_hash.as_ref().map(|hash| hash.as_slice()),
            message_id: &message.message_id,
        },
        i64::try_from(message.created_at).unwrap_or(i64::MAX),
    )?;
    if !commit {
        return Ok(message_handlers::emit_message_events(tx, &stored, now)?
            .into_iter()
            .collect());
    }
    let changes = MembershipChanges {
        added: message
            .added_members
            .iter()
            .map(|m| (m.user_id.clone(), m.device_id.clone(), None))
            .collect(),
        removed: message
            .removed_members
            .iter()
            .map(|m| (m.user_id.clone(), m.device_id.clone()))
            .collect(),
    };
    let wake = record_commit(tx, &stored, &changes, now)?;
    if groups::local_member_devices(tx, &message.gid)?.is_empty() {
        groups::set_detached(tx, &message.gid, true)?;
    }
    Ok(wake)
}

/// Replicas with a gap fill in progress, as `<hub_id> <gid>` (one fill per
/// gid at a time, §6.6; keyed by hub because tests run several hubs in one
/// process).
static GAP_FILLS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Releases a [`GAP_FILLS`] slot.
struct GapFill(String);

impl Drop for GapFill {
    fn drop(&mut self) {
        GAP_FILLS.lock().expect("gap fills lock").remove(&self.0);
    }
}

fn spawn_gap_fill(state: AppState, owner: HubId, gid: String) {
    let fill: BoxFuture<'static, ()> = Box::pin(fill_gap(state, owner, gid));
    tokio::spawn(fill);
}

/// Fetches the replica's missing log suffix from the owner with `FetchLog`
/// pages until the log is complete (§6.6). Returns at once if a fill for
/// the gid is already running.
async fn fill_gap(state: AppState, owner: HubId, gid: String) {
    let key = format!("{} {gid}", state.hub.hub_id());
    if !GAP_FILLS
        .lock()
        .expect("gap fills lock")
        .insert(key.clone())
    {
        return;
    }
    let _slot = GapFill(key);
    loop {
        let key = gid.clone();
        let last_seq = match state.db.read(move |conn| groups::get(conn, &key)).await {
            Ok(Some(group)) => group.last_seq,
            Ok(None) => return,
            Err(err) => {
                tracing::error!(%err, gid, "gap fill: reading the replica failed");
                return;
            }
        };
        let page = match fetch_log::fetch(
            state.federation.as_ref(),
            &owner,
            &gid,
            last_seq + 1,
            fetch_log::MAX_LIMIT,
        )
        .await
        {
            Ok(page) => page,
            Err(err) => {
                tracing::info!(%owner, gid, %err, "gap fill: FetchLog failed");
                return;
            }
        };
        if page.messages.is_empty() {
            return;
        }
        if page.messages.iter().any(|message| message.gid != gid) {
            tracing::warn!(%owner, gid, "gap fill: FetchLog returned another group");
            return;
        }
        let acks = match apply_replica(&state, &owner, page.messages, false).await {
            Ok(acks) => acks,
            Err(err) => {
                tracing::error!(%err, gid, "gap fill: applying the log failed");
                return;
            }
        };
        let progressed = acks
            .iter()
            .any(|ack| ack.gid == gid && ack.highest_contiguous_seq > last_seq);
        if page.complete || !progressed {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// S2S ops (§3.7, §6)
// ---------------------------------------------------------------------------

/// The client-API side of the group ops.
struct StateGroups(AppState);

/// An S2S error for a failed sequencing on the owning hub (§9.1): stale
/// epochs carry `current_epoch`, client errors keep their code in
/// `client_code`.
pub(crate) fn to_s2s_error(err: ApiError, stale: ErrorCode) -> s2s::Error {
    let with = |code: ErrorCode, client_code: &str, message: String| s2s::Error {
        code: code as i32,
        message,
        current_epoch: None,
        client_code: client_code.to_owned(),
    };
    match err {
        ApiError::StaleEpoch { current_epoch } => s2s::Error {
            current_epoch: Some(current_epoch),
            ..with(stale, "stale_epoch", err.to_string())
        },
        ApiError::ValidationFailed(_) | ApiError::PayloadTooLarge | ApiError::Conflict(_) => {
            with(ErrorCode::Invalid, "validation_failed", err.to_string())
        }
        ApiError::NotMember => with(ErrorCode::Unauthorized, "not_member", err.to_string()),
        ApiError::Forbidden(_) => with(ErrorCode::Unauthorized, "forbidden", err.to_string()),
        ApiError::NotFound => with(ErrorCode::NotFound, "not_found", err.to_string()),
        ApiError::Internal(detail) => {
            tracing::error!(%detail, "sequencing for a member hub failed");
            with(ErrorCode::Internal, "", "internal error".into())
        }
        other => with(ErrorCode::Internal, "", other.to_string()),
    }
}

impl Groups for StateGroups {
    fn submit_commit(
        &self,
        request: s2s::SubmitCommitRequest,
    ) -> BoxFuture<'_, Result<s2s::SubmitCommitResponse, s2s::Error>> {
        Box::pin(async move {
            let state = &self.0;
            let stale = |err| to_s2s_error(err, ErrorCode::Conflict);
            let sender = Sender {
                user_id: request.sender_user_id.clone(),
                device_id: request.sender_device_id.clone(),
            };
            let commit = CommitInput::from_peer(state, request).map_err(stale)?;
            let gid = commit.gid.clone();
            match sequence_commit(state, sender, commit, Origin::Peer)
                .await
                .map_err(stale)?
            {
                CommitOutcome::Accepted {
                    seq,
                    epoch,
                    message,
                } => Ok(s2s::SubmitCommitResponse {
                    seq,
                    epoch,
                    duplicate: false,
                    message: Some(*message),
                }),
                CommitOutcome::Duplicate { seq, epoch } => {
                    let message = state
                        .db
                        .read(move |conn| {
                            sequenced_message(conn, &gid, i64::try_from(seq).unwrap_or(i64::MAX))
                        })
                        .await
                        .map_err(|err| stale(err.into()))?;
                    Ok(s2s::SubmitCommitResponse {
                        seq,
                        epoch,
                        duplicate: true,
                        message,
                    })
                }
            }
        })
    }

    fn submit_message(
        &self,
        request: s2s::SubmitMessageRequest,
    ) -> BoxFuture<'_, Result<s2s::SubmitMessageResponse, s2s::Error>> {
        Box::pin(message_handlers::submit_from_peer(&self.0, request))
    }

    fn deliver(
        &self,
        owner: HubId,
        messages: Vec<s2s::SequencedMessage>,
    ) -> BoxFuture<'_, Result<Vec<s2s::GroupAck>, DbError>> {
        Box::pin(async move {
            apply_replica(&self.0, &owner, messages, true)
                .await
                .map_err(|err| DbError::Task(err.to_string()))
        })
    }

    fn deliver_welcome(
        &self,
        request: s2s::DeliverWelcomeRequest,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            welcome_handlers::deliver_welcome(&self.0, request)
                .await
                .map_err(|err| DbError::Task(err.to_string()))
        })
    }

    fn seed_replica(&self, request: s2s::SeedReplicaRequest) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(seed_replica(&self.0, request))
    }

    fn copy_pending_welcomes(
        &self,
        request: s2s::CopyPendingWelcomesRequest,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            welcome_handlers::copy_pending_welcomes(&self.0, request)
                .await
                .map_err(|err| DbError::Task(err.to_string()))
        })
    }
}

/// Creates or replaces the replica of `gid` on a hub newly listed for a
/// member (multihoming.md §4.3): when there is none, it is detached or it
/// has no local members, the replica starts after the snapshot
/// (`last_seq = seq`, `replica_from_seq = seq + 1`). A live replica is kept.
/// No events: the member's devices joined through another hub.
async fn seed_replica(state: &AppState, request: s2s::SeedReplicaRequest) -> Result<(), DbError> {
    let Some(snapshot) = request.group else {
        return Ok(());
    };
    let gid = request.gid;
    let now = state.clock.now_ms();
    state
        .db
        .write(move |tx| {
            let live = groups::get(tx, &gid)?.is_some()
                && !groups::replica(tx, &gid)?.is_some_and(|replica| replica.detached)
                && !groups::local_member_devices(tx, &gid)?.is_empty();
            if live {
                return Ok(());
            }
            let members: Vec<(String, String)> = snapshot
                .members
                .into_iter()
                .map(|m| (m.user_id, m.device_id))
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
                    epoch: snapshot.epoch,
                    last_seq: snapshot.seq,
                    created_by_user_id: snapshot.created_by_user_id,
                    created_by_device_id: snapshot.created_by_device_id,
                    created_at: i64::try_from(snapshot.created_at).unwrap_or(i64::MAX),
                },
                &members,
                now,
            )
        })
        .await
}

/// Registers the group ops (`SubmitCommit`, `SubmitMessage`, `Deliver`,
/// `DeliverWelcome`, `FetchLog`, `SeedReplica`, `CopyPendingWelcomes`) with
/// handlers on `state` and installs the replica bootstrap hub-set hook
/// (multihoming.md §4.3, §4.4) on `state.hosting`, queueing to
/// `state.outbox`. Returns the service, which the caller keeps alive.
pub fn register_group_ops(state: &AppState, service: &FederationService) -> Arc<GroupService> {
    let groups = GroupService::new(
        state.db.clone(),
        state.hosting.clone(),
        Arc::new(StateGroups(state.clone())),
    );
    groups.register(service);
    state.hosting.set_hub_set_hook(Bootstrap::new(
        state.hub.hub_id().clone(),
        state.outbox.clone(),
    ));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replicas_only_accept_messages_of_the_owner() {
        let hub = crate::testing::TestHub::new();
        let own = hub.state.hub.hub_id().clone();
        let other = HubId::parse(crate::dto::GID_EXAMPLE.split_once('/').unwrap().0).unwrap();
        let message = |gid: String| s2s::SequencedMessage {
            gid,
            seq: 1,
            ..Default::default()
        };
        // A message of a group owned here, or by a hub other than the sender.
        for (owner, gid) in [(&other, format!("{own}/g1")), (&own, format!("{own}/g1"))] {
            let err = apply_replica(&hub.state, owner, vec![message(gid)], false)
                .await
                .unwrap_err();
            assert_eq!(err.code(), "peer_refused");
        }
        let acks = apply_replica(
            &hub.state,
            &other,
            vec![message(format!("{other}/g2"))],
            false,
        )
        .await
        .unwrap();
        assert_eq!(acks[0].highest_contiguous_seq, 0);
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
        assert_eq!(random_id().unwrap().len(), 26);
    }
}
