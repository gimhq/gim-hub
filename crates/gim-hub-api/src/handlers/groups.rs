//! Groups and MLS Commits.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use gim_hub_db::{events, groups, keypackages, messages, Transaction};
use gim_hub_identity::HubId;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{identity::json_body, messages as message_handlers};
use crate::{
    auth::AuthDevice,
    dto::{
        CommitResult, CreateGroupRequest, Error, Group, GroupKind, GroupList, GroupMember,
        MembershipChange, StaleEpochError, SubmitCommitRequest, Welcome,
    },
    error::ApiError,
    mls::{self, AcceptAllCredentials, AddedMember, CredentialPolicy},
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

/// This hub's ID (gim-core `HubId` of the hub key): the owner prefix of the
/// group IDs it assigns. Unlike a PeerID it does not change when the runtime
/// key rotates.
fn hub_id(state: &AppState) -> HubId {
    HubId::from_root_pubkey(&state.hub.signing_key().verifying_key())
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
pub async fn create_group(
    State(state): State<AppState>,
    auth: AuthDevice,
    body: Result<Json<CreateGroupRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Group>), ApiError> {
    let body = json_body(body)?;
    let group = groups::Group {
        gid: format!("{}/{}", hub_id(&state).as_str(), random_id()?),
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
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
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
pub async fn submit_commit(
    State(state): State<AppState>,
    auth: AuthDevice,
    Path(gid): Path<String>,
    body: Result<Json<SubmitCommitRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CommitResult>), ApiError> {
    let body = json_body(body)?;
    let commit = CommitInput::validate(&state, gid, body)?;
    let now = state.clock.now_ms();
    let message_id = random_id()?;
    let outcome = state
        .db
        .write(move |tx| apply_commit(tx, auth, commit, message_id, now))
        .await?;
    match outcome {
        CommitOutcome::Duplicate { seq, epoch } => Ok((
            StatusCode::OK,
            Json(CommitResult {
                seq,
                epoch,
                duplicate: true,
            }),
        )),
        CommitOutcome::Accepted { seq, epoch, wake } => {
            for (user_id, device_id) in &wake {
                state.notifier.notify(user_id, device_id);
            }
            Ok((
                StatusCode::CREATED,
                Json(CommitResult {
                    seq,
                    epoch,
                    duplicate: false,
                }),
            ))
        }
    }
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
    /// Re-encoded base64 of the Welcome and the optional ratchet tree.
    welcome: String,
    ratchet_tree: Option<String>,
    recipients: Vec<GroupMember>,
}

impl CommitInput {
    fn validate(
        state: &AppState,
        gid: String,
        body: SubmitCommitRequest,
    ) -> Result<Self, ApiError> {
        let invalid = |message: &str| ApiError::ValidationFailed(message.to_owned());
        let decode = |field: &str, value: &str| {
            STANDARD
                .decode(value)
                .map_err(|_| ApiError::ValidationFailed(format!("{field} must be base64")))
        };
        let client_id_chars = body.client_id.chars().count();
        if client_id_chars == 0 || client_id_chars > MAX_CLIENT_ID_CHARS {
            return Err(invalid("client_id must be 1-64 characters"));
        }
        let mls_message = decode("mls_message", &body.mls_message)?;
        if mls_message.len() > state.config.max_message_bytes {
            return Err(ApiError::PayloadTooLarge);
        }
        let welcome = match (body.welcome, body.welcome_recipients) {
            (None, None) => {
                if body.ratchet_tree.is_some() {
                    return Err(invalid("ratchet_tree requires welcome"));
                }
                None
            }
            (Some(welcome), Some(recipients)) => {
                if recipients.is_empty() || recipients.len() > MAX_WELCOME_RECIPIENTS {
                    return Err(invalid("welcome_recipients must hold 1-500 devices"));
                }
                let welcome = decode("welcome", &welcome)?;
                let ratchet_tree = body
                    .ratchet_tree
                    .map(|tree| decode("ratchet_tree", &tree))
                    .transpose()?;
                if welcome.len() + ratchet_tree.as_ref().map_or(0, Vec::len)
                    > state.config.max_message_bytes
                {
                    return Err(ApiError::PayloadTooLarge);
                }
                Some(WelcomeInput {
                    welcome: STANDARD.encode(welcome),
                    ratchet_tree: ratchet_tree.map(|tree| STANDARD.encode(tree)),
                    recipients,
                })
            }
            _ => return Err(invalid("welcome and welcome_recipients go together")),
        };
        let parsed = mls::parse_commit(&mls_message)?;
        if parsed.group_id != gid.as_bytes() {
            return Err(invalid("MLS group ID does not match the gid"));
        }
        Ok(Self {
            gid,
            client_id: body.client_id,
            mls_message,
            parsed,
            welcome,
        })
    }
}

enum CommitOutcome {
    Duplicate {
        seq: u64,
        epoch: u64,
    },
    Accepted {
        seq: u64,
        epoch: u64,
        /// Devices that received events.
        wake: BTreeSet<(String, String)>,
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

/// Sequences a Commit: appends it to the log, advances the epoch, updates the
/// roster and emits the Commit, membership and Welcome events.
fn apply_commit(
    tx: &Transaction<'_>,
    auth: AuthDevice,
    commit: CommitInput,
    message_id: String,
    now: i64,
) -> Result<CommitOutcome, ApiError> {
    let CommitInput {
        gid,
        client_id,
        mls_message,
        parsed,
        welcome,
    } = commit;
    let invalid = |message: &str| ApiError::ValidationFailed(message.to_owned());

    let group = groups::get(tx, &gid)?.ok_or(ApiError::NotFound)?;
    let members = groups::members(tx, &gid)?;
    let sender = members
        .iter()
        .find(|m| m.user_id == auth.user_id && m.device_id == auth.device_id)
        .ok_or(ApiError::NotMember)?;
    let commit_hash: [u8; 32] = Sha256::digest(&mls_message).into();
    if let Some((seq, epoch)) = messages::find_commit(tx, &gid, &commit_hash)? {
        return Ok(CommitOutcome::Duplicate {
            seq,
            epoch: epoch + 1,
        });
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

    let mut added = Vec::new();
    for kp_hash in &parsed.added {
        let (user_id, device_id) = keypackages::claimed_owner(tx, kp_hash)?
            .ok_or_else(|| invalid("Add proposal uses a KeyPackage not claimed on this hub"))?;
        if remaining
            .iter()
            .any(|m| m.user_id == user_id && m.device_id == device_id)
            || added.contains(&(user_id.clone(), device_id.clone()))
        {
            return Err(invalid(
                "Add proposal for a device that is already a member",
            ));
        }
        AcceptAllCredentials
            .check_added_member(&AddedMember {
                gid: &gid,
                user_id: &user_id,
                device_id: &device_id,
            })
            .map_err(ApiError::ValidationFailed)?;
        added.push((user_id, device_id));
    }
    let occupied: BTreeSet<u32> = remaining.iter().filter_map(|m| m.leaf_index).collect();
    let leaves = mls::assign_leaves(&occupied, added.len());

    if let Some(welcome) = &welcome {
        let mut seen = HashSet::new();
        for recipient in &welcome.recipients {
            let key = (recipient.user_id.clone(), recipient.device_id.clone());
            if !added.contains(&key) || !seen.insert(key) {
                return Err(invalid(
                    "welcome_recipients must be distinct devices added by this Commit",
                ));
            }
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
    groups::set_epoch(tx, &gid, epoch)?;
    // The Commit itself goes to every previous member except its sender,
    // including the removed ones; new members join from the Welcome.
    let mut wake: BTreeSet<(String, String)> =
        message_handlers::emit_message_events(tx, &stored, now)?
            .into_iter()
            .collect();
    for (user_id, device_id) in &removed {
        groups::remove_member(tx, &gid, user_id, device_id)?;
    }
    for ((user_id, device_id), leaf) in added.iter().zip(&leaves) {
        groups::add_member(tx, &gid, user_id, device_id, *leaf, now)?;
    }

    let mut emit = |user_id: &str, device_id: &str, event_type: &str, data: &str| {
        events::append(tx, user_id, device_id, event_type, data, now)?;
        wake.insert((user_id.to_owned(), device_id.to_owned()));
        Ok::<_, ApiError>(())
    };

    // Membership events go to the old and the new roster.
    let mut audience: BTreeSet<(String, String)> = members
        .iter()
        .map(|m| (m.user_id.clone(), m.device_id.clone()))
        .collect();
    audience.extend(added.iter().cloned());
    for (event_type, devices) in [
        ("group.member_removed", &removed),
        ("group.member_added", &added),
    ] {
        for (user_id, device_ids) in by_user(devices) {
            let data = event_data(&MembershipChange {
                gid: gid.clone(),
                user_id: user_id.to_owned(),
                device_ids,
                by_user_id: auth.user_id.clone(),
                by_device_id: auth.device_id.clone(),
                epoch,
                seq,
            })?;
            for (to_user, to_device) in &audience {
                emit(to_user, to_device, event_type, &data)?;
            }
        }
    }

    if let Some(welcome) = welcome {
        let data = event_data(&Welcome {
            gid: gid.clone(),
            sender_user_id: auth.user_id.clone(),
            sender_device_id: auth.device_id.clone(),
            epoch,
            seq,
            welcome: welcome.welcome,
            ratchet_tree: welcome.ratchet_tree,
        })?;
        for recipient in &welcome.recipients {
            groups::insert_pending_welcome(
                tx,
                &recipient.user_id,
                &recipient.device_id,
                &gid,
                &data,
                now,
            )?;
            emit(&recipient.user_id, &recipient.device_id, "welcome", &data)?;
        }
    }
    Ok(CommitOutcome::Accepted { seq, epoch, wake })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
        assert_eq!(random_id().unwrap().len(), 26);
    }
}
