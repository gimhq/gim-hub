//! S2S op handlers and the client side of synchronous S2S requests.
//!
//! - [`device_list`]: remote DeviceLists (§5.1): the cache, `GetDeviceList`
//!   and `NotifyDeviceList`.
//! - [`claim`]: cross-hub KeyPackage claims (§5.2, §6.1).
//! - [`submit`], [`deliver`], [`welcome`], [`fetch_log`]: group federation
//!   (§5.3, §5.4, §6.2-§6.6), served by [`GroupService`].
//!
//! The multi-homing ops `NotifyHostingRecord`, `SeedReplica` and
//! `CopyPendingWelcomes` (multihoming.md §4.2-§4.4) have no handler yet:
//! [`MULTIHOMING_OPS`] fall through to the dispatcher's `INTERNAL`
//! "not implemented" answer until their subtasks register one.

pub mod claim;
pub mod deliver;
pub mod device_list;
pub mod fetch_log;
pub mod submit;
pub mod welcome;

use std::sync::Arc;

use gim_hub_db::{Db, DbError};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_request::Op, DeliverWelcomeRequest, Error as S2sError, ErrorCode, GroupAck,
    SequencedMessage, SubmitCommitRequest, SubmitCommitResponse, SubmitMessageRequest,
    SubmitMessageResponse,
};

use crate::{
    federation::{error, BoxFuture, FederationService, OpResult},
    hosting::{Hosting, HostingError, Purpose},
    policy::OpKind,
};

/// Multi-homing ops without a registered handler (stubs).
pub const MULTIHOMING_OPS: [OpKind; 3] = [
    OpKind::NotifyHostingRecord,
    OpKind::SeedReplica,
    OpKind::CopyPendingWelcomes,
];

fn request_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("random request id");
    hex::encode(bytes)
}

/// The owning hub's `hub_id` of a gid (`<owner hub_id>/<random>`).
pub fn owner_of(gid: &str) -> Option<&str> {
    gid.split_once('/').map(|(owner, _)| owner)
}

/// Group state owned by the client API: sequencing on the owning hub and
/// replicas on member hubs. Called after the op was authorized (§3.7).
pub trait Groups: Send + Sync + 'static {
    /// Sequences a Commit of a group owned here, exactly as a local Commit
    /// (§6.3). Errors carry `client_code` / `current_epoch` (§9.1).
    fn submit_commit(
        &self,
        request: SubmitCommitRequest,
    ) -> BoxFuture<'_, Result<SubmitCommitResponse, S2sError>>;

    /// Sequences an application message of a group owned here (§6.5).
    fn submit_message(
        &self,
        request: SubmitMessageRequest,
    ) -> BoxFuture<'_, Result<SubmitMessageResponse, S2sError>>;

    /// Applies messages sequenced by `owner` to the replicas (§6.6) and
    /// returns one ack per gid present in `messages`.
    fn deliver(
        &self,
        owner: HubId,
        messages: Vec<SequencedMessage>,
    ) -> BoxFuture<'_, Result<Vec<GroupAck>, DbError>>;

    /// Stores a Welcome for a hosted recipient and creates the replica
    /// (§5.4, §6.6).
    fn deliver_welcome(&self, request: DeliverWelcomeRequest)
        -> BoxFuture<'_, Result<(), DbError>>;
}

/// The group ops `SubmitCommit`, `SubmitMessage`, `Deliver`,
/// `DeliverWelcome` and `FetchLog`: authorization (§3.7), then [`Groups`]
/// or the owner's log.
pub struct GroupService {
    db: Db,
    hosting: Hosting,
    groups: Arc<dyn Groups>,
}

impl GroupService {
    pub fn new(db: Db, hosting: Hosting, groups: Arc<dyn Groups>) -> Arc<Self> {
        Arc::new(Self {
            db,
            hosting,
            groups,
        })
    }

    /// Registers the group op handlers on `service`. The handlers hold a
    /// weak reference: the caller keeps the returned service alive.
    pub fn register(self: &Arc<Self>, service: &FederationService) {
        for op in [
            OpKind::SubmitCommit,
            OpKind::SubmitMessage,
            OpKind::Deliver,
            OpKind::DeliverWelcome,
            OpKind::FetchLog,
        ] {
            let weak = Arc::downgrade(self);
            service.register(
                op,
                Arc::new(
                    move |caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                        let weak = weak.clone();
                        Box::pin(async move {
                            let Some(service) = weak.upgrade() else {
                                return Err(error(ErrorCode::Internal, "shutting down"));
                            };
                            service.handle(caller, op).await
                        })
                    },
                ),
            );
        }
    }

    /// Serves one group op from `caller`.
    pub async fn handle(&self, caller: HubId, op: Op) -> OpResult {
        match op {
            Op::SubmitCommit(request) => submit::handle_commit(self, &caller, request).await,
            Op::SubmitMessage(request) => submit::handle_message(self, &caller, request).await,
            Op::Deliver(request) => deliver::handle(self, caller, request).await,
            Op::DeliverWelcome(request) => welcome::handle(self, &caller, request).await,
            Op::FetchLog(request) => fetch_log::handle(self, &caller, request).await,
            _ => Err(error(ErrorCode::Invalid, "unexpected op")),
        }
    }

    fn owns(&self, gid: &str) -> bool {
        owner_of(gid) == Some(self.hosting.hub_id().as_str())
    }
}

/// Whether `caller` is listed in the hosting record of `user_id` (§3.7),
/// refreshing a cached record once if it does not list the caller.
async fn caller_listed(hosting: &Hosting, user_id: &str, caller: &HubId) -> Result<bool, S2sError> {
    match hosting
        .resolve_for(user_id, Purpose::Authorize(caller.clone()))
        .await
    {
        Ok(record) => Ok(record.entry(caller).is_some()),
        Err(HostingError::NotFound | HostingError::Required) => Ok(false),
        Err(HostingError::Unavailable(reason)) => Err(error(ErrorCode::Internal, &reason)),
        Err(HostingError::Db(err)) => Err(internal(&err)),
    }
}

fn internal(err: &DbError) -> S2sError {
    tracing::error!(%err, "group op failed");
    error(ErrorCode::Internal, "internal error")
}
