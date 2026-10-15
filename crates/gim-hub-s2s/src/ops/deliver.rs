//! `Deliver` (docs/federation.md §6.4, §6.6, §7): the owning hub's fan-out
//! of sequenced messages to member hubs, and the outbox source that builds
//! them from the owner's log.

use std::collections::BTreeSet;

use gim_hub_db::{
    groups, hosting as hosting_store,
    messages::{self, Membership, StoredMessage},
    welcomes, Connection, DbError,
};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_response::Result as OpOutput, CopyPendingWelcomesRequest, DeliverRequest, DeliverResponse,
    ErrorCode, Member, MessageKind, PendingWelcome, SequencedMessage,
};

use super::{device_list::local_device_list, internal, owner_of, GroupService};
use crate::{
    federation::{error, OpResult},
    outbox::OutboxSource,
};

/// The wire form of a stored message and, for a Commit, its membership
/// changes.
pub fn to_sequenced(stored: StoredMessage, membership: Membership) -> SequencedMessage {
    let member = |(user_id, device_id): (String, String)| Member { user_id, device_id };
    let affected: BTreeSet<String> = membership
        .added
        .iter()
        .chain(&membership.removed)
        .map(|(user_id, _)| user_id.clone())
        .collect();
    let kind = if stored.kind == "commit" {
        MessageKind::Commit
    } else {
        MessageKind::Application
    };
    SequencedMessage {
        gid: stored.gid,
        seq: u64::try_from(stored.seq).unwrap_or_default(),
        epoch: u64::try_from(stored.epoch).unwrap_or_default(),
        kind: kind as i32,
        sender_user_id: stored.sender_user_id,
        sender_device_id: stored.sender_device_id,
        client_id: stored.client_id,
        payload: stored.payload,
        message_id: stored.message_id,
        created_at: u64::try_from(stored.created_at).unwrap_or_default(),
        affected_user_ids: affected.into_iter().collect(),
        added_members: membership.added.into_iter().map(member).collect(),
        removed_members: membership.removed.into_iter().map(member).collect(),
    }
}

/// The message `seq` of `gid` as a [`SequencedMessage`], if stored.
pub fn sequenced_message(
    conn: &Connection,
    gid: &str,
    seq: i64,
) -> Result<Option<SequencedMessage>, DbError> {
    let Some(stored) = messages::get(conn, gid, seq)? else {
        return Ok(None);
    };
    let membership = if stored.kind == "commit" {
        messages::membership(conn, gid, seq)?
    } else {
        Membership::default()
    };
    Ok(Some(to_sequenced(stored, membership)))
}

/// Payload bytes of the Welcomes in one `CopyPendingWelcomes`, well below
/// the transport frame limit; older Welcomes go first.
const MAX_COPY_BYTES: usize = 4 * 1024 * 1024;

/// The [`OutboxSource`] of a hub: `deliver` entries from the group log,
/// `device_list` entries from the `users` table, resync nudges for the
/// groups this hub owns, and `pending_welcomes` entries from the pending
/// Welcomes (multihoming.md §4.4).
#[derive(Debug, Clone)]
pub struct GroupSource {
    hub_id: HubId,
}

impl GroupSource {
    /// The source of the hub `hub_id`.
    pub fn new(hub_id: HubId) -> Self {
        Self { hub_id }
    }
}

impl OutboxSource for GroupSource {
    fn deliver_messages(
        &self,
        conn: &Connection,
        keys: &[(String, u64)],
    ) -> Result<Vec<Option<SequencedMessage>>, DbError> {
        keys.iter()
            .map(|(gid, seq)| match i64::try_from(*seq) {
                Ok(seq) => sequenced_message(conn, gid, seq),
                Err(_) => Ok(None),
            })
            .collect()
    }

    fn device_list(&self, conn: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, DbError> {
        local_device_list(conn, user_id)
    }

    fn resync_nudge(
        &self,
        conn: &Connection,
        peer: &HubId,
    ) -> Result<Vec<SequencedMessage>, DbError> {
        let mut nudge = Vec::new();
        for gid in groups::owned_with_member_on(conn, self.hub_id.as_str(), peer.as_str())? {
            if let Some(latest) = messages::latest(conn, &gid)? {
                let seq = latest.seq;
                nudge.extend(sequenced_message(conn, &gid, seq)?);
            }
        }
        Ok(nudge)
    }

    fn pending_welcomes(
        &self,
        conn: &Connection,
        user_id: &str,
        _: &HubId,
    ) -> Result<Option<CopyPendingWelcomesRequest>, DbError> {
        if !hosting_store::is_local(conn, user_id)? {
            return Ok(None);
        }
        let mut bytes = 0;
        let mut copied = Vec::new();
        for welcome in welcomes::pending_for_user(conn, user_id)? {
            bytes += welcome.payload.len();
            if !copied.is_empty() && bytes > MAX_COPY_BYTES {
                tracing::warn!(user_id, "pending Welcomes copy truncated");
                break;
            }
            copied.push(PendingWelcome {
                device_id: welcome.device_id,
                gid: welcome.gid,
                message_id: welcome.message_id,
                payload_json: welcome.payload,
                created_at: u64::try_from(welcome.created_at).unwrap_or_default(),
            });
        }
        if copied.is_empty() {
            return Ok(None);
        }
        Ok(Some(CopyPendingWelcomesRequest {
            user_id: user_id.to_owned(),
            welcomes: copied,
        }))
    }
}

/// `Deliver` on a member hub (§3.7): every message must belong to a group
/// the caller owns, otherwise the whole batch is refused.
pub(super) async fn handle(
    service: &GroupService,
    caller: HubId,
    request: DeliverRequest,
) -> OpResult {
    if request
        .messages
        .iter()
        .any(|message| owner_of(&message.gid) != Some(caller.as_str()))
    {
        return Err(error(
            ErrorCode::Unauthorized,
            "caller does not own every group in the batch",
        ));
    }
    let acks = service
        .groups
        .deliver(caller, request.messages)
        .await
        .map_err(|err| internal(&err))?;
    Ok(OpOutput::Deliver(DeliverResponse { acks }))
}
