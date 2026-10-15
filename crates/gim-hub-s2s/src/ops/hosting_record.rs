//! The `NotifyHostingRecord` op (docs/multihoming.md §4.2): a hub of a user
//! pushes the user's new hosting record to co-hosts, removed hubs, owners
//! and member hubs.
//!
//! Sending is queued by the record-store transaction of the client API
//! (`hosting_record` outbox entries, the record is read at send time with
//! [`local_hosting_record`]).

use std::sync::Arc;

use gim_hub_db::{hosting as store, Connection, Db, DbError};
use gim_hub_identity::{HostingRecord, HubId, UserId};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, ErrorCode, NotifyHostingRecordResponse,
};

use crate::{
    federation::{error, BoxFuture, FederationService, OpResult},
    hosting::{self, Hosting, Now},
    policy::OpKind,
};

/// The stored hosting record (CBOR) of local user `user_id`, if any. This is
/// the `OutboxSource::hosting_record` of `NotifyHostingRecord` entries.
pub fn local_hosting_record(conn: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, DbError> {
    if !store::is_local(conn, user_id)? {
        return Ok(None);
    }
    Ok(store::get(conn, user_id)?.map(|row| row.record))
}

/// Record changes of local users, owned by the client API.
pub trait LocalHostingRecords: Send + Sync + 'static {
    /// Applies verified `record` of a local user as the client
    /// `PUT .../hosting-record` does (seq rules, `hosted`, DHT publish, hub-set
    /// hook, `hosting_record.updated`, removal and propagation), without the
    /// upload lifetime check. A stale or identical record is a no-op.
    fn apply_local(&self, record: HostingRecord) -> BoxFuture<'_, Result<(), DbError>>;
}

/// Serves `NotifyHostingRecord`.
pub struct HostingRecordService {
    db: Db,
    hosting: Hosting,
    local: Arc<dyn LocalHostingRecords>,
    now: Now,
}

impl HostingRecordService {
    pub fn new(
        db: Db,
        hosting: Hosting,
        local: Arc<dyn LocalHostingRecords>,
        now: Now,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            hosting,
            local,
            now,
        })
    }

    /// Registers the op handler on `service`. The handler holds a weak
    /// reference: the caller keeps the returned service alive.
    pub fn register(self: &Arc<Self>, service: &FederationService) {
        let weak = Arc::downgrade(self);
        service.register(
            OpKind::NotifyHostingRecord,
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

    /// `NotifyHostingRecord` from `caller`: verifies the record, then
    /// applies it to a local user or the remote cache with the seq rules.
    /// The caller must be listed in the record or in the stored record it
    /// supersedes; a record that would not change anything (stale or
    /// identical) is answered `{}` without that check (Q9: a resend of a
    /// genuine record is harmless).
    pub async fn handle(&self, caller: HubId, op: Op) -> OpResult {
        let Op::NotifyHostingRecord(request) = op else {
            return Err(error(ErrorCode::Invalid, "unexpected op"));
        };
        let user_id = UserId::parse(&request.user_id)
            .map_err(|_| error(ErrorCode::Invalid, "invalid user_id"))?;
        let now = (self.now)();
        let record = hosting::verify(&request.hosting_record_cbor, &user_id, now).map_err(|err| {
            error(
                ErrorCode::Invalid,
                &format!("invalid hosting record ({})", err.code()),
            )
        })?;
        if hosting::stored_record(&record, false, now).is_err() {
            return Err(error(ErrorCode::Invalid, "seq is out of range"));
        }
        let key = user_id.to_string();
        let (local, stored) = self
            .db
            .read(move |conn| Ok::<_, DbError>((store::is_local(conn, &key)?, store::get(conn, &key)?)))
            .await
            .map_err(|err| internal(&err))?;
        let previous = stored.and_then(|row| hosting::decode_stored(&row.record).ok());
        if let Some(previous) = &previous {
            if record.supersedes(previous) != Ok(true) {
                return Ok(ok());
            }
        }
        let listed = |record: &HostingRecord| record.entry(&caller).is_some();
        if !listed(&record) && !previous.as_ref().is_some_and(listed) {
            return Err(error(
                ErrorCode::Unauthorized,
                "caller is not listed for the user",
            ));
        }
        if local {
            self.local.apply_local(record).await
        } else {
            let hosting = self.hosting.clone();
            self.db
                .write(move |tx| hosting.store_remote_in_tx(tx, &record, now).map(drop))
                .await
        }
        .map_err(|err| internal(&err))?;
        Ok(ok())
    }
}

fn ok() -> OpOutput {
    OpOutput::NotifyHostingRecord(NotifyHostingRecordResponse {})
}

fn internal(err: &DbError) -> gim_hub_proto::s2s::Error {
    tracing::error!(%err, "NotifyHostingRecord failed");
    error(ErrorCode::Internal, "internal error")
}
