//! Remote DeviceLists (docs/federation.md §5.1): the cache of remote users'
//! DeviceLists with refresh, the `GetDeviceList` op (serving local users)
//! and the `NotifyDeviceList` op (receiving pushed updates).
//!
//! The hub reads every DeviceList through [`DeviceLists::device_list_for`]:
//! the `users` row of a local user, otherwise the cached remote copy.

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use gim_hub_db::{
    hosting as hosting_store,
    remote_identity::{self as store, StoredRemoteDeviceList},
    users, Connection, Db, DbError, Transaction,
};
use gim_hub_identity::{DeviceList, HostingEntry, HubId, UserId};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, ErrorCode, GetDeviceListRequest,
    GetDeviceListResponse, NotifyDeviceListResponse, S2sRequest,
};

use crate::{
    federation::{error, BoxFuture, Disabled, Federation, FederationService, OpResult},
    hosting::{Hosting, HostingError, Now, Purpose},
    policy::OpKind,
};

/// A cached copy younger than this is not refetched after a credential
/// check failure (§5.1).
pub const REFETCH_MIN_AGE: Duration = Duration::from_secs(60);

/// Default `GIM_HUB_DEVICE_LIST_CACHE_HOURS`.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Effects of DeviceList changes owned by the client API: events and the
/// local upload path.
pub trait DeviceListEvents: Send + Sync + 'static {
    /// Called in the write transaction that replaced the cached DeviceList
    /// of remote user `user_id` with a higher seq: appends
    /// `device_list.updated` for the local devices that must re-verify the
    /// user's credentials and returns them.
    fn replaced(
        &self,
        tx: &Transaction<'_>,
        user_id: &str,
        device_list: &[u8],
        now: i64,
    ) -> Result<Vec<(String, String)>, DbError>;

    /// Wakes `devices` after the transaction committed.
    fn wake(&self, devices: &[(String, String)]);

    /// Applies `list` (verified, pushed by a hub listed for the user) to a
    /// user that is local here, as if uploaded.
    fn apply_local(&self, list: DeviceList) -> BoxFuture<'_, Result<(), DbError>>;
}

/// The DeviceList (CBOR) of local user `user_id`, if any. This is the
/// `OutboxSource::device_list` of `NotifyDeviceList` entries.
pub fn local_device_list(conn: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, DbError> {
    Ok(users::get_device_list(conn, user_id)?.map(|list| list.device_list))
}

/// DeviceLists of local and remote users. Cheap to clone.
#[derive(Clone)]
pub struct DeviceLists {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    federation: Arc<dyn Federation>,
    hosting: Hosting,
    cache_ttl: RwLock<Duration>,
    now: Now,
    events: Arc<dyn DeviceListEvents>,
}

impl std::fmt::Debug for DeviceLists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceLists")
            .field("cache_ttl", &self.cache_ttl())
            .finish_non_exhaustive()
    }
}

impl DeviceLists {
    /// DeviceLists fetched through `federation`, locating users with
    /// `hosting`; cached copies older than `cache_ttl` are refreshed on use.
    pub fn new(
        db: Db,
        federation: Arc<dyn Federation>,
        hosting: Hosting,
        cache_ttl: Duration,
        now: Now,
        events: Arc<dyn DeviceListEvents>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                federation,
                hosting,
                cache_ttl: RwLock::new(cache_ttl),
                now,
                events,
            }),
        }
    }

    /// DeviceLists without federation: local users and the stored cache.
    pub fn local(db: Db, hosting: Hosting, now: Now, events: Arc<dyn DeviceListEvents>) -> Self {
        Self::new(
            db,
            Arc::new(Disabled),
            hosting,
            DEFAULT_CACHE_TTL,
            now,
            events,
        )
    }

    /// The same DeviceLists, fetching through `federation` and `hosting`
    /// with cache lifetime `cache_ttl` (`GIM_HUB_DEVICE_LIST_CACHE_HOURS`).
    pub fn with_federation(
        &self,
        federation: Arc<dyn Federation>,
        hosting: Hosting,
        cache_ttl: Duration,
    ) -> Self {
        Self::new(
            self.inner.db.clone(),
            federation,
            hosting,
            cache_ttl,
            self.inner.now.clone(),
            self.inner.events.clone(),
        )
    }

    fn now(&self) -> i64 {
        (self.inner.now)()
    }

    /// Freshness of cached remote DeviceLists
    /// (`GIM_HUB_DEVICE_LIST_CACHE_HOURS`).
    pub fn cache_ttl(&self) -> Duration {
        *self.inner.cache_ttl.read().expect("cache ttl lock")
    }

    /// Changes the freshness of cached remote DeviceLists; applies to the
    /// next lookup.
    pub fn set_cache_ttl(&self, cache_ttl: Duration) {
        *self.inner.cache_ttl.write().expect("cache ttl lock") = cache_ttl;
    }

    /// The DeviceList (CBOR) of `user_id`: a local user's stored list, else
    /// the cached remote copy, fetched from the user's hub when missing or
    /// older than the cache lifetime. A stale copy is returned when the
    /// user's hub cannot be reached; `Unavailable` only without any copy.
    pub async fn device_list_for(&self, user_id: &str) -> Result<Vec<u8>, HostingError> {
        let max_age = i64::try_from(self.cache_ttl().as_millis()).unwrap_or(i64::MAX);
        self.get(user_id, max_age).await
    }

    /// Like [`Self::device_list_for`] after a credential check against the
    /// user's list failed with `no_device_list`, `unknown_device` or
    /// `revoked_device`: refetches a remote copy older than
    /// [`REFETCH_MIN_AGE`] once (§5.1). The caller then decides on the
    /// returned list.
    pub async fn refetch_after_failure(&self, user_id: &str) -> Result<Vec<u8>, HostingError> {
        self.get(user_id, REFETCH_MIN_AGE.as_millis() as i64).await
    }

    async fn get(&self, user_id: &str, max_age_ms: i64) -> Result<Vec<u8>, HostingError> {
        let key = user_id.to_owned();
        let (local, cached) = self
            .inner
            .db
            .read(move |conn| {
                Ok::<_, DbError>((
                    local_device_list(conn, &key)?,
                    store::get_device_list(conn, &key)?,
                ))
            })
            .await?;
        if let Some(local) = local {
            return Ok(local);
        }
        let now = self.now();
        if let Some(cached) = &cached {
            if now.saturating_sub(cached.fetched_at) < max_age_ms {
                return Ok(cached.device_list.clone());
            }
        }
        let user_id = UserId::parse(user_id).map_err(|_| HostingError::NotFound)?;
        let fallback = |err: HostingError| match &cached {
            Some(cached) => Ok(cached.device_list.clone()),
            None => Err(err),
        };
        if !self.inner.federation.is_enabled() {
            return fallback(HostingError::NotFound);
        }
        let record = match self.inner.hosting.resolve(user_id.as_str()).await {
            Ok(record) => record,
            Err(HostingError::Db(err)) => return Err(err.into()),
            Err(err) => return fallback(err),
        };
        let mut entries: Vec<&HostingEntry> = record.hubs().iter().collect();
        entries.sort_by(|a, b| (a.priority(), a.hub_id()).cmp(&(b.priority(), b.hub_id())));
        let mut unavailable = None;
        for entry in entries {
            let hub = entry.hub_id();
            if hub == self.inner.hosting.hub_id() {
                continue;
            }
            match self.fetch_from(hub, &user_id).await {
                Ok(Some(list)) => return Ok(self.store(list).await?),
                Ok(None) => {}
                Err(reason) => unavailable = Some(format!("{hub}: {reason}")),
            }
        }
        fallback(match unavailable {
            Some(reason) => HostingError::Unavailable(reason),
            None => HostingError::NotFound,
        })
    }

    /// `GetDeviceList(user_id)` to `hub`: `Ok(None)` if the hub has no valid
    /// list, `Err` if it did not answer.
    async fn fetch_from(
        &self,
        hub: &HubId,
        user_id: &UserId,
    ) -> Result<Option<DeviceList>, String> {
        let request = S2sRequest {
            request_id: super::request_id(),
            op: Some(Op::GetDeviceList(GetDeviceListRequest {
                user_id: user_id.to_string(),
            })),
        };
        let response = self
            .inner
            .federation
            .send(hub, request)
            .await
            .map_err(|err| err.to_string())?;
        match (response.result, response.error) {
            (Some(OpOutput::GetDeviceList(response)), _) => {
                match verify(&response.device_list_cbor, user_id) {
                    Ok(list) => Ok(Some(list)),
                    Err(err) => {
                        tracing::warn!(%hub, %user_id, %err, "invalid DeviceList from peer");
                        Ok(None)
                    }
                }
            }
            (_, Some(err)) if err.code() == ErrorCode::NotFound => Ok(None),
            (_, Some(err)) => Err(format!("{:?}: {}", err.code(), err.message)),
            (_, None) => Err("unexpected response".into()),
        }
    }

    /// Stores a verified remote `list` with the seq rules: a higher seq
    /// replaces the cached copy (emitting `device_list.updated` to local
    /// peers when a copy existed), the identical list refreshes
    /// `fetched_at`, a lower seq or a conflict keeps the cached copy.
    /// Returns the current list (the `users` row if the user is local).
    async fn store(&self, list: DeviceList) -> Result<Vec<u8>, DbError> {
        let now = self.now();
        // Callers verified the list with `verify`, which bounds `seq`.
        let seq = i64::try_from(list.seq()).unwrap_or(i64::MAX);
        let row = StoredRemoteDeviceList {
            user_id: list.user_id().to_string(),
            root_pubkey: list.root_pubkey().as_bytes().to_vec(),
            device_list: list.as_bytes().to_vec(),
            seq,
            fetched_at: now,
            updated_at: now,
        };
        let events = self.inner.events.clone();
        let (stored, wake) = self
            .inner
            .db
            .write(move |tx| {
                if let Some(local) = local_device_list(tx, &row.user_id)? {
                    return Ok((local, Vec::new()));
                }
                let Some(current) = store::get_device_list(tx, &row.user_id)? else {
                    store::put_device_list(tx, &row)?;
                    return Ok((row.device_list, Vec::new()));
                };
                if row.seq > current.seq {
                    store::put_device_list(tx, &row)?;
                    let wake = events.replaced(tx, &row.user_id, &row.device_list, now)?;
                    return Ok((row.device_list, wake));
                }
                if row.seq == current.seq && row.device_list == current.device_list {
                    store::touch_fetched(tx, &row.user_id, row.seq, now)?;
                } else if row.seq == current.seq {
                    tracing::warn!(user_id = %row.user_id, seq = row.seq, "DeviceList seq conflict; keeping the cached copy");
                }
                Ok::<_, DbError>((current.device_list, Vec::new()))
            })
            .await?;
        self.inner.events.wake(&wake);
        Ok(stored)
    }

    /// Registers the `GetDeviceList` and `NotifyDeviceList` op handlers on
    /// `service`.
    pub fn register(&self, service: &FederationService) {
        let weak = Arc::downgrade(&self.inner);
        service.register(
            OpKind::GetDeviceList,
            Arc::new(
                move |_caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                    let weak = weak.clone();
                    Box::pin(async move {
                        let Some(inner) = weak.upgrade() else {
                            return Err(error(ErrorCode::Internal, "shutting down"));
                        };
                        DeviceLists { inner }.get_device_list(op).await
                    })
                },
            ),
        );
        let weak = Arc::downgrade(&self.inner);
        service.register(
            OpKind::NotifyDeviceList,
            Arc::new(
                move |caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                    let weak = weak.clone();
                    Box::pin(async move {
                        let Some(inner) = weak.upgrade() else {
                            return Err(error(ErrorCode::Internal, "shutting down"));
                        };
                        DeviceLists { inner }.notify_device_list(caller, op).await
                    })
                },
            ),
        );
    }

    /// The `GetDeviceList` op: the stored list of a local user (§3.7: no
    /// check beyond binding and policy). Cached remote copies are never
    /// passed on.
    pub async fn get_device_list(&self, op: Op) -> OpResult {
        let Op::GetDeviceList(request) = op else {
            return Err(error(ErrorCode::Invalid, "unexpected op"));
        };
        let user_id = request.user_id;
        match self
            .inner
            .db
            .read(move |conn| local_device_list(conn, &user_id))
            .await
        {
            Ok(Some(device_list_cbor)) if !device_list_cbor.is_empty() => {
                Ok(OpOutput::GetDeviceList(GetDeviceListResponse {
                    device_list_cbor,
                }))
            }
            Ok(_) => Err(error(ErrorCode::NotFound, "unknown user")),
            Err(err) => Err(internal(&err)),
        }
    }

    /// The `NotifyDeviceList` op (§3.7: the caller is listed for the user):
    /// verifies the pushed list and applies the seq rules to the cache, or
    /// to the `users` row of a local user as if uploaded.
    pub async fn notify_device_list(&self, caller: HubId, op: Op) -> OpResult {
        let Op::NotifyDeviceList(request) = op else {
            return Err(error(ErrorCode::Invalid, "unexpected op"));
        };
        let user_id = UserId::parse(&request.user_id)
            .map_err(|_| error(ErrorCode::Invalid, "invalid user_id"))?;
        match self
            .inner
            .hosting
            .resolve_for(user_id.as_str(), Purpose::Authorize(caller.clone()))
            .await
        {
            Ok(record) if record.entry(&caller).is_some() => {}
            Ok(_) | Err(HostingError::NotFound | HostingError::Required) => {
                return Err(error(
                    ErrorCode::Unauthorized,
                    "caller is not listed for the user",
                ))
            }
            Err(HostingError::Unavailable(reason)) => {
                return Err(error(ErrorCode::Internal, &reason))
            }
            Err(HostingError::Db(err)) => return Err(internal(&err)),
        }
        let list = verify(&request.device_list_cbor, &user_id)
            .map_err(|err| error(ErrorCode::Invalid, &format!("invalid DeviceList: {err}")))?;
        let key = user_id.to_string();
        let local = self
            .inner
            .db
            .read(move |conn| hosting_store::is_local(conn, &key))
            .await
            .map_err(|err| internal(&err))?;
        if local {
            self.inner.events.apply_local(list).await
        } else {
            self.store(list).await.map(|_| ())
        }
        .map_err(|err| internal(&err))?;
        Ok(OpOutput::NotifyDeviceList(NotifyDeviceListResponse {}))
    }
}

/// Verifies received DeviceList bytes for `user_id`; `seq` must fit the
/// database.
fn verify(bytes: &[u8], user_id: &UserId) -> Result<DeviceList, String> {
    let list = DeviceList::verify(bytes, user_id).map_err(|err| err.to_string())?;
    if i64::try_from(list.seq()).is_err() {
        return Err("seq is out of range".into());
    }
    Ok(list)
}

fn internal(err: &DbError) -> gim_hub_proto::s2s::Error {
    tracing::error!(%err, "DeviceList op failed");
    error(ErrorCode::Internal, "internal error")
}
