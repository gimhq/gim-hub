//! Bootstrap of a hub newly listed for a user (docs/multihoming.md §4.3,
//! §4.4): the [`Bootstrap`] hub-set hook queues `SeedReplica` for the
//! groups this hub owns with the user in the roster and, on a hub hosting
//! the user, `CopyPendingWelcomes`; [`handle`] serves `SeedReplica` on the
//! added hub.

use std::sync::Arc;

use gim_hub_db::{groups, DbError, Transaction};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_response::Result as OpOutput, ErrorCode, GroupSnapshot, Member, SeedReplicaRequest,
    SeedReplicaResponse,
};
use prost::Message as _;

use super::{internal, owner_of, GroupService};
use crate::{
    federation::{error, OpResult},
    hosting::{HostingError, HubSetChange, HubSetHook},
    outbox::{NewEntry, OutboxSender},
};

/// The [`HubSetHook`] of the replica bootstrap, queueing in the
/// record-store transaction to every added hub other than this one:
///
/// - a `NotifyHostingRecord` first, when this hub hosts the user under
///   either record, so the added hub stores the record before it handles
///   the entries below (per-peer FIFO; the later queueing by the record
///   store coalesces with it);
/// - `SeedReplica` for every group this hub owns that has the user in its
///   roster, as of the group's current seq (§4.3);
/// - `CopyPendingWelcomes` when this hub hosts the user under the new
///   record (§4.4).
pub struct Bootstrap {
    hub_id: HubId,
    outbox: Arc<dyn OutboxSender>,
}

impl Bootstrap {
    pub fn new(hub_id: HubId, outbox: Arc<dyn OutboxSender>) -> Arc<Self> {
        Arc::new(Self { hub_id, outbox })
    }
}

impl HubSetHook for Bootstrap {
    fn hub_set_changed(
        &self,
        tx: &Transaction<'_>,
        change: &HubSetChange<'_>,
    ) -> Result<(), DbError> {
        let peers: Vec<&HubId> = change
            .added
            .iter()
            .filter(|hub| **hub != self.hub_id)
            .collect();
        if peers.is_empty() {
            return Ok(());
        }
        let user_id = change.user_id;
        let was_hosted = change.local && change.previous.entry(&self.hub_id).is_some();
        if change.hosted || was_hosted {
            for peer in &peers {
                self.outbox
                    .enqueue_in_tx(tx, peer, NewEntry::HostingRecord { user_id })?;
            }
        }
        for gid in groups::owned_with_user(tx, self.hub_id.as_str(), user_id)? {
            let Some(group) = groups::get(tx, &gid)? else {
                continue;
            };
            let request = SeedReplicaRequest {
                gid: gid.clone(),
                user_id: user_id.to_owned(),
                group: Some(GroupSnapshot {
                    kind: group.kind,
                    created_by_user_id: group.created_by_user_id,
                    created_by_device_id: group.created_by_device_id,
                    created_at: u64::try_from(group.created_at).unwrap_or_default(),
                    epoch: group.epoch,
                    seq: group.last_seq,
                    members: groups::member_devices(tx, &gid)?
                        .into_iter()
                        .map(|(user_id, device_id)| Member { user_id, device_id })
                        .collect(),
                }),
            }
            .encode_to_vec();
            for peer in &peers {
                self.outbox.enqueue_in_tx(
                    tx,
                    peer,
                    NewEntry::SeedReplica {
                        gid: &gid,
                        payload: &request,
                    },
                )?;
            }
        }
        if change.hosted {
            for peer in &peers {
                self.outbox
                    .enqueue_in_tx(tx, peer, NewEntry::PendingWelcomes { user_id })?;
            }
        }
        Ok(())
    }
}

/// `SeedReplica` on the added hub (§4.3): the caller owns the gid, this hub
/// hosts the user and the user is in the snapshot's roster; then
/// [`super::Groups::seed_replica`]. A gid owned here is ignored.
pub(super) async fn handle(
    service: &GroupService,
    caller: &HubId,
    request: SeedReplicaRequest,
) -> OpResult {
    if owner_of(&request.gid) != Some(caller.as_str()) {
        return Err(error(
            ErrorCode::Unauthorized,
            "caller does not own the group",
        ));
    }
    let Some(snapshot) = request.group else {
        return Err(error(ErrorCode::Invalid, "missing group snapshot"));
    };
    if !snapshot
        .members
        .iter()
        .any(|member| member.user_id == request.user_id)
    {
        return Err(error(ErrorCode::Invalid, "user is not in the group"));
    }
    match service
        .hosting
        .require_hosting_record(&request.user_id)
        .await
    {
        Ok(_) => {}
        Err(HostingError::Db(err)) => return Err(internal(&err)),
        Err(_) => return Err(error(ErrorCode::NotFound, "user is not hosted here")),
    }
    if service.owns(&request.gid) {
        return Ok(ok());
    }
    service
        .groups
        .seed_replica(SeedReplicaRequest {
            group: Some(snapshot),
            ..request
        })
        .await
        .map_err(|err| internal(&err))?;
    Ok(ok())
}

fn ok() -> OpOutput {
    OpOutput::SeedReplica(SeedReplicaResponse {})
}
