//! Hosting records (docs/federation.md §4): DHT publication and republish,
//! the `/gim/user/` record validator, resolution with a cache, the
//! `GetHostingRecord` op, and the helpers other subtasks authorize with.
//!
//! The client endpoints live in `gim-hub-api` (`handlers/hosting.rs`); they
//! store records through `gim_hub_db::hosting` and call [`Hosting::publish`].
//!
//! Every code path that stores a record superseding the stored one calls
//! [`Hosting::superseded`] in its write transaction, which runs the
//! [`HubSetHook`] when the listed hubs changed (docs/multihoming.md §4.3).

#[cfg(feature = "testing")]
pub mod testing;
mod validator;

#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::Duration,
};

use gim_hub_db::{
    hosting::{self as store, StoredHostingRecord},
    Db, DbError, Transaction,
};
use gim_hub_identity::{HostingEntry, HostingRecord, HubId, IdentityError, UserId};
use gim_hub_proto::{
    s2s::{
        s2s_request::Op, s2s_response::Result as OpOutput, ErrorCode, GetHostingRecordRequest,
        GetHostingRecordResponse, S2sRequest,
    },
    USER_RECORD_KEY_PREFIX,
};
use tokio::{sync::broadcast, task::JoinHandle};

pub use validator::UserRecordValidator;

use crate::{
    config::FederationConfig,
    federation::{error, BoxFuture, Disabled, Federation, FederationService, OpResult},
    policy::OpKind,
    transport::{PeerEvent, SendError, Transport},
};

/// Largest accepted `SignedHostingRecord`, in bytes (§4.2, §4.4).
pub const MAX_RECORD_BYTES: usize = 8192;
/// How long a DHT lookup collects records (§4.5 step 4).
const DHT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Distinct valid records after which a DHT lookup stops (§4.5 step 4).
const DHT_LOOKUP_RECORDS: usize = 3;

/// Current time in milliseconds since the Unix epoch.
pub type Now = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Failure to find a usable hosting record.
#[derive(Debug, thiserror::Error)]
pub enum HostingError {
    /// No valid record is known (none, or expired).
    #[error("no valid hosting record")]
    NotFound,
    /// The user has no valid record listing this hub; the client API maps
    /// it to 403 `hosting_record_required`.
    #[error("no valid hosting record lists this hub")]
    Required,
    /// Resolution needed a peer that did not answer and the DHT had nothing;
    /// the client API maps it to 503 `peer_unavailable`.
    #[error("peer unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Why a record is resolved (§4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    Lookup,
    /// Authorizing a request from `caller` (§3.7): if a fresh cached record
    /// does not list the caller, it is refreshed once, asking the caller
    /// first.
    Authorize(HubId),
}

/// Hosting settings, from [`FederationConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingSettings {
    /// `GIM_HUB_HOSTING_CACHE_SECONDS`.
    pub cache_ttl: Duration,
    /// `GIM_HUB_DHT_REPUBLISH_HOURS`.
    pub republish_interval: Duration,
}

impl HostingSettings {
    pub fn from_config(config: &FederationConfig) -> Self {
        Self {
            cache_ttl: Duration::from_secs(config.hosting_cache_seconds.into()),
            republish_interval: Duration::from_secs(u64::from(config.dht_republish_hours) * 3600),
        }
    }
}

impl Default for HostingSettings {
    fn default() -> Self {
        Self::from_config(&FederationConfig::disabled(std::path::Path::new("")))
    }
}

/// A change of the hubs listed for a user, seen in the write transaction
/// that stores `record` over `previous` (docs/multihoming.md §4.3).
#[derive(Debug, Clone, Copy)]
pub struct HubSetChange<'a> {
    pub user_id: &'a str,
    /// The record just stored.
    pub record: &'a HostingRecord,
    /// The stored record it superseded.
    pub previous: &'a HostingRecord,
    /// Hubs listed by `record` and not by `previous`, sorted; may include
    /// this hub.
    pub added: &'a [HubId],
    /// Hubs listed by `previous` and not by `record`, sorted; may include
    /// this hub.
    pub removed: &'a [HubId],
    /// `user_id` is a local user of this hub (else `record` is a cached
    /// record of a remote user).
    pub local: bool,
    /// `local` and `record` lists this hub.
    pub hosted: bool,
    /// Time of the store, unix ms.
    pub now: i64,
}

/// The hub-set diff hook (docs/multihoming.md §4.3, §4.4, §12): called
/// inside the write transaction that stores a record superseding the stored
/// one, when the set of listed hubs changed (`added` or `removed` not
/// empty). Paths: the client `PUT .../hosting-record`, `NotifyHostingRecord`
/// (local users and the remote cache) and a resolution that stores a newer
/// record of a remote user ([`Hosting::resolve_for`]). Priority-only changes
/// and the first record of a user do not call it.
///
/// The hook may queue outbox entries in `tx` (they commit with the record);
/// an error rolls the record store back. Install it with
/// [`Hosting::set_hub_set_hook`].
pub trait HubSetHook: Send + Sync + 'static {
    fn hub_set_changed(
        &self,
        tx: &Transaction<'_>,
        change: &HubSetChange<'_>,
    ) -> Result<(), DbError>;
}

/// Hosting records of this hub. Cheap to clone.
#[derive(Clone)]
pub struct Hosting {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    hub_id: HubId,
    federation: Arc<dyn Federation>,
    dht: Option<Transport>,
    settings: HostingSettings,
    now: Now,
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    publish_failures: AtomicU64,
    hub_set_hook: RwLock<Option<Arc<dyn HubSetHook>>>,
}

impl std::fmt::Debug for Hosting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hosting")
            .field("hub_id", &self.inner.hub_id)
            .finish_non_exhaustive()
    }
}

impl Hosting {
    /// Hosting records of hub `hub_id`, resolving remote records through
    /// `federation` and, if given, the DHT of `dht`.
    pub fn new(
        db: Db,
        hub_id: HubId,
        federation: Arc<dyn Federation>,
        dht: Option<Transport>,
        settings: HostingSettings,
        now: Now,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                hub_id,
                federation,
                dht,
                settings,
                now,
                flights: Mutex::default(),
                publish_failures: AtomicU64::new(0),
                hub_set_hook: RwLock::default(),
            }),
        }
    }

    /// Hosting without federation: local records and the stored cache only.
    pub fn local(db: Db, hub_id: HubId, now: Now) -> Self {
        Self::new(
            db,
            hub_id,
            Arc::new(Disabled),
            None,
            HostingSettings::default(),
            now,
        )
    }

    pub fn hub_id(&self) -> &HubId {
        &self.inner.hub_id
    }

    /// Installs the [`HubSetHook`], replacing any previous one.
    pub fn set_hub_set_hook(&self, hook: Arc<dyn HubSetHook>) {
        *self.inner.hub_set_hook.write().expect("hook lock") = Some(hook);
    }

    /// To be called in the write transaction `tx` that stored `record` of
    /// `user_id` over `previous` (both verified): runs the [`HubSetHook`]
    /// when the listed hubs changed. `local`: the user is a local user.
    pub fn superseded(
        &self,
        tx: &Transaction<'_>,
        previous: &HostingRecord,
        record: &HostingRecord,
        local: bool,
        now: i64,
    ) -> Result<(), DbError> {
        let hook = self.inner.hub_set_hook.read().expect("hook lock").clone();
        let Some(hook) = hook else {
            return Ok(());
        };
        let (added, removed) = hub_diff(previous, record);
        if added.is_empty() && removed.is_empty() {
            return Ok(());
        }
        hook.hub_set_changed(
            tx,
            &HubSetChange {
                user_id: record.user_id().as_str(),
                record,
                previous,
                added: &added,
                removed: &removed,
                local,
                hosted: local && record.entry(self.hub_id()).is_some(),
                now,
            },
        )
    }

    /// Stores verified `record` of a remote user in the cache with the seq
    /// rules (fed §4.5 step 5) in `tx`: a superseding record replaces the
    /// cached one (running [`Self::superseded`]), the identical record
    /// refreshes `fetched_at`, an older or conflicting one is ignored. Does
    /// nothing for a local user. Returns whether `record` was stored.
    pub fn store_remote_in_tx(
        &self,
        tx: &Transaction<'_>,
        record: &HostingRecord,
        now: i64,
    ) -> Result<bool, DbError> {
        let Ok(stored) = stored_record(record, false, now) else {
            return Ok(false);
        };
        if store::is_local(tx, &stored.user_id)? {
            return Ok(false);
        }
        let Some(current) = store::get(tx, &stored.user_id)? else {
            store::put(tx, &stored)?;
            return Ok(true);
        };
        if current.record == stored.record {
            store::touch_fetched(tx, &stored.user_id, stored.seq, now)?;
            return Ok(false);
        }
        match decode_stored(&current.record) {
            Ok(previous) if record.supersedes(&previous) != Ok(true) => Ok(false),
            Ok(previous) => {
                store::put(tx, &stored)?;
                self.superseded(tx, &previous, record, false, now)?;
                Ok(true)
            }
            Err(_) => {
                store::put(tx, &stored)?;
                Ok(true)
            }
        }
    }

    /// DHT puts that failed so far (retried on the next republish).
    pub fn publish_failures(&self) -> u64 {
        self.inner.publish_failures.load(Ordering::Relaxed)
    }

    fn now(&self) -> i64 {
        (self.inner.now)()
    }

    /// Registers the `/gim/user/` DHT validator and the `GetHostingRecord`
    /// op handler on `service`.
    pub fn register(&self, service: &FederationService) {
        service
            .transport()
            .register_record_validator(USER_RECORD_KEY_PREFIX, Arc::new(UserRecordValidator));
        let weak = Arc::downgrade(&self.inner);
        service.register(
            OpKind::GetHostingRecord,
            Arc::new(
                move |_caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                    let weak = weak.clone();
                    Box::pin(async move { get_hosting_record(weak, op).await })
                },
            ),
        );
    }

    /// The valid record of local user `user_id` that lists this hub: the
    /// precondition of every federated action on the user's behalf (§3.7).
    pub async fn require_hosting_record(
        &self,
        user_id: &str,
    ) -> Result<HostingRecord, HostingError> {
        let record = self
            .local_record(user_id)
            .await?
            .ok_or(HostingError::Required)?;
        match record.entry(self.hub_id()) {
            Some(_) => Ok(record),
            None => Err(HostingError::Required),
        }
    }

    /// The stored, unexpired record of local user `user_id`, if any.
    pub async fn local_record(&self, user_id: &str) -> Result<Option<HostingRecord>, DbError> {
        let user_id = user_id.to_owned();
        let row = self
            .inner
            .db
            .read(move |conn| {
                Ok::<_, DbError>(if store::is_local(conn, &user_id)? {
                    store::get(conn, &user_id)?
                } else {
                    None
                })
            })
            .await?;
        let now = self.now();
        Ok(row
            .and_then(|row| decode_stored(&row.record).ok())
            .filter(|record| unexpired(record, now)))
    }

    /// The newest valid record of `user_id` known (§4.5, purpose lookup).
    pub async fn resolve(&self, user_id: &str) -> Result<HostingRecord, HostingError> {
        self.resolve_for(user_id, Purpose::Lookup).await
    }

    /// The newest valid record of `user_id` known (§4.5): local record,
    /// fresh cache, `GetHostingRecord` from listed hubs, then the DHT.
    /// Concurrent resolutions of one user are coalesced.
    pub async fn resolve_for(
        &self,
        user_id: &str,
        purpose: Purpose,
    ) -> Result<HostingRecord, HostingError> {
        let user_id = UserId::parse(user_id).map_err(|_| HostingError::NotFound)?;
        let flight = self
            .inner
            .flights
            .lock()
            .expect("flights lock")
            .entry(user_id.to_string())
            .or_default()
            .clone();
        let result = {
            let _guard = flight.lock().await;
            self.resolve_once(&user_id, &purpose).await
        };
        let mut flights = self.inner.flights.lock().expect("flights lock");
        if Arc::strong_count(&flight) == 2 {
            flights.remove(user_id.as_str());
        }
        result
    }

    async fn resolve_once(
        &self,
        user_id: &UserId,
        purpose: &Purpose,
    ) -> Result<HostingRecord, HostingError> {
        let now = self.now();
        let key = user_id.to_string();
        let (local, row) = self
            .inner
            .db
            .read(move |conn| {
                Ok::<_, DbError>((store::is_local(conn, &key)?, store::get(conn, &key)?))
            })
            .await?;
        let cached = row.as_ref().and_then(|row| decode_stored(&row.record).ok());
        let valid_cached = cached.clone().filter(|record| unexpired(record, now));
        // 1. Local user: no network.
        if local {
            return valid_cached.ok_or(HostingError::NotFound);
        }
        // 2. Fresh cache, unless it does not list the authorizing caller.
        let caller = match purpose {
            Purpose::Lookup => None,
            Purpose::Authorize(caller) => Some(caller),
        };
        if let (Some(row), Some(record)) = (&row, &valid_cached) {
            let age = now.saturating_sub(row.fetched_at);
            let fresh =
                u128::try_from(age).unwrap_or(0) < self.inner.settings.cache_ttl.as_millis();
            if fresh && caller.is_none_or(|caller| record.entry(caller).is_some()) {
                return Ok(record.clone());
            }
        }
        if !self.inner.federation.is_enabled() {
            return valid_cached.ok_or(HostingError::NotFound);
        }

        // 3. Ask the caller, then the cached record's hubs, primary first.
        let mut hubs: Vec<HubId> = caller.into_iter().cloned().collect();
        if let Some(record) = &cached {
            let mut entries: Vec<&HostingEntry> = record.hubs().iter().collect();
            entries.sort_by(|a, b| (a.priority(), a.hub_id()).cmp(&(b.priority(), b.hub_id())));
            hubs.extend(entries.into_iter().map(|entry| entry.hub_id().clone()));
        }
        let mut seen = HashSet::new();
        hubs.retain(|hub| hub != self.hub_id() && seen.insert(hub.clone()));
        let mut found = Vec::new();
        let mut unavailable = None;
        for hub in &hubs {
            match self.fetch_from(hub, user_id, now).await {
                Ok(Some(record)) => {
                    found.push(record);
                    break;
                }
                Ok(None) => {}
                Err(err) => unavailable = Some(format!("{hub}: {err}")),
            }
        }
        // 4. The DHT.
        if found.is_empty() {
            found = self.fetch_from_dht(user_id, now).await;
        }

        // A record from the network never replaces a cached one with a
        // higher seq, nor a conflicting one.
        let mut winner = valid_cached.clone();
        for record in &found {
            winner = match winner {
                Some(current) if record.supersedes(&current) != Ok(true) => Some(current),
                _ => Some(record.clone()),
            };
        }
        let Some(winner) = winner else {
            return Err(match unavailable {
                Some(reason) => HostingError::Unavailable(reason),
                None => HostingError::NotFound,
            });
        };
        // 5. Store the winner, or note that the network confirmed the cache.
        let confirmed = found.iter().any(|record| record == &winner);
        if confirmed {
            // Re-checked in the transaction: the user may have become local,
            // or another record may have been stored.
            let (hosting, record) = (self.clone(), winner.clone());
            self.inner
                .db
                .write(move |tx| hosting.store_remote_in_tx(tx, &record, now))
                .await?;
        }
        Ok(winner)
    }

    /// `GetHostingRecord(user_id)` to `hub`: `Ok(None)` if the hub has no
    /// valid record, `Err` if it did not answer.
    async fn fetch_from(
        &self,
        hub: &HubId,
        user_id: &UserId,
        now: i64,
    ) -> Result<Option<HostingRecord>, SendError> {
        let request = S2sRequest {
            request_id: request_id(),
            op: Some(Op::GetHostingRecord(GetHostingRecordRequest {
                user_id: user_id.to_string(),
            })),
        };
        let response = self.inner.federation.send(hub, request).await?;
        let Some(OpOutput::GetHostingRecord(response)) = response.result else {
            return Ok(None);
        };
        match verify(&response.hosting_record_cbor, user_id, now) {
            Ok(record) => Ok(Some(record)),
            Err(err) => {
                tracing::warn!(%hub, %user_id, %err, "invalid hosting record from peer");
                Ok(None)
            }
        }
    }

    /// Valid records of `user_id` in the DHT.
    async fn fetch_from_dht(&self, user_id: &UserId, now: i64) -> Vec<HostingRecord> {
        let Some(dht) = &self.inner.dht else {
            return Vec::new();
        };
        let key = user_record_key(user_id.as_str());
        let lookup = dht.dht_get(&key, DHT_LOOKUP_RECORDS);
        let values = match tokio::time::timeout(DHT_LOOKUP_TIMEOUT, lookup).await {
            Ok(Ok(values)) => values,
            Ok(Err(err)) => {
                tracing::debug!(%user_id, %err, "hosting record lookup failed");
                return Vec::new();
            }
            Err(_) => {
                tracing::debug!(%user_id, "hosting record lookup timed out");
                return Vec::new();
            }
        };
        values
            .iter()
            .filter_map(|value| verify(value, user_id, now).ok())
            .collect()
    }

    /// Publishes `record` to the DHT in the background (no-op without
    /// federation); failures are retried by the republish task.
    pub fn publish(&self, record: HostingRecord) {
        if self.inner.dht.is_none() {
            return;
        }
        let hosting = self.clone();
        tokio::spawn(async move {
            hosting.publish_one(&record).await;
        });
    }

    /// Puts `record` into the DHT and records the publication. Returns
    /// whether the put succeeded.
    async fn publish_one(&self, record: &HostingRecord) -> bool {
        let Some(dht) = &self.inner.dht else {
            return false;
        };
        let key = user_record_key(record.user_id().as_str());
        match dht
            .dht_put(&key, record.as_bytes().to_vec(), Some(record.expires_at()))
            .await
        {
            Ok(()) => {
                let (user_id, seq, now) = (record.user_id().to_string(), record.seq(), self.now());
                let seq = i64::try_from(seq).unwrap_or(i64::MAX);
                if let Err(err) = self
                    .inner
                    .db
                    .write(move |tx| store::mark_published(tx, &user_id, seq, now))
                    .await
                {
                    tracing::error!(%err, "recording a hosting record publication failed");
                }
                true
            }
            Err(err) => {
                self.inner.publish_failures.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(user_id = %record.user_id(), %err, "hosting record not published");
                false
            }
        }
    }

    /// Publishes every hosted, unexpired record (only those not published
    /// yet with `unpublished_only`). Returns `(published, failed)`.
    pub async fn republish(&self, unpublished_only: bool) -> (usize, usize) {
        let now = self.now();
        let rows = match self
            .inner
            .db
            .read(move |conn| store::hosted(conn, now, unpublished_only))
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                tracing::error!(%err, "loading hosted records failed");
                return (0, 0);
            }
        };
        let (mut published, mut failed) = (0, 0);
        for row in rows {
            let Ok(record) = decode_stored(&row.record) else {
                continue;
            };
            if self.publish_one(&record).await {
                published += 1;
            } else {
                failed += 1;
            }
        }
        (published, failed)
    }

    /// Starts the republish task (§4.4): every hosted record now and then
    /// every `GIM_HUB_DHT_REPUBLISH_HOURS`, plus the unpublished ones
    /// whenever a peer hub comes up. `None` without a DHT.
    pub fn spawn_republisher(&self) -> Option<JoinHandle<()>> {
        let dht = self.inner.dht.as_ref()?;
        let mut events = Some(dht.subscribe());
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        let mut interval = tokio::time::interval(self.inner.settings.republish_interval);
        Some(tokio::spawn(async move {
            loop {
                let all = tokio::select! {
                    _ = interval.tick() => true,
                    event = next_event(&mut events) => match event {
                        Some(PeerEvent::Up(_)) => false,
                        _ => continue,
                    },
                };
                let Some(inner) = weak.upgrade() else { return };
                let (published, failed) = Hosting { inner }.republish(!all).await;
                if published + failed > 0 {
                    tracing::info!(published, failed, "hosting records republished");
                }
            }
        }))
    }
}

/// The next peer event; pends forever once the channel is closed.
async fn next_event(events: &mut Option<broadcast::Receiver<PeerEvent>>) -> Option<PeerEvent> {
    let Some(receiver) = events else {
        return std::future::pending().await;
    };
    match receiver.recv().await {
        Ok(event) => Some(event),
        Err(broadcast::error::RecvError::Lagged(_)) => None,
        Err(broadcast::error::RecvError::Closed) => {
            *events = None;
            None
        }
    }
}

/// The `GetHostingRecord` op: the stored record of a local user (§3.7: no
/// check beyond binding and policy).
async fn get_hosting_record(hosting: Weak<Inner>, op: Op) -> OpResult {
    let Some(inner) = hosting.upgrade() else {
        return Err(error(ErrorCode::Internal, "shutting down"));
    };
    let Op::GetHostingRecord(request) = op else {
        return Err(error(ErrorCode::Invalid, "unexpected op"));
    };
    match (Hosting { inner }).local_record(&request.user_id).await {
        Ok(Some(record)) => Ok(OpOutput::GetHostingRecord(GetHostingRecordResponse {
            hosting_record_cbor: record.as_bytes().to_vec(),
        })),
        Ok(None) => Err(error(ErrorCode::NotFound, "no hosting record")),
        Err(err) => {
            tracing::error!(%err, "loading a hosting record failed");
            Err(error(ErrorCode::Internal, "internal error"))
        }
    }
}

/// DHT key of a user's hosting record: `/gim/user/<user_id>`.
pub fn user_record_key(user_id: &str) -> String {
    format!("{USER_RECORD_KEY_PREFIX}{user_id}")
}

/// Verifies received record bytes for `user_id` at `now` (size limit
/// included).
pub fn verify(bytes: &[u8], user_id: &UserId, now: i64) -> Result<HostingRecord, IdentityError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(IdentityError::Malformed(format!(
            "hosting record exceeds {MAX_RECORD_BYTES} bytes"
        )));
    }
    HostingRecord::verify(bytes, user_id, u64::try_from(now).unwrap_or(0))
}

/// Decodes stored record bytes. They were verified when stored, so only
/// expiry may have changed since: the caller compares `expires_at` itself.
pub fn decode_stored(bytes: &[u8]) -> Result<HostingRecord, IdentityError> {
    HostingRecord::verify_claimed(bytes, 0)
}

/// Whether `record` is unexpired at `now`.
pub fn unexpired(record: &HostingRecord, now: i64) -> bool {
    u64::try_from(now).is_ok_and(|now| now < record.expires_at())
}

/// The storage row of a verified `record` received at `now`. Fails if `seq`
/// does not fit the database.
pub fn stored_record(
    record: &HostingRecord,
    hosted: bool,
    now: i64,
) -> Result<StoredHostingRecord, &'static str> {
    Ok(StoredHostingRecord {
        user_id: record.user_id().to_string(),
        record: record.as_bytes().to_vec(),
        seq: i64::try_from(record.seq()).map_err(|_| "seq is out of range")?,
        expires_at: i64::try_from(record.expires_at()).unwrap_or(i64::MAX),
        hosted,
        hub_ids: record
            .hubs()
            .iter()
            .map(|entry| entry.hub_id().to_string())
            .collect(),
        fetched_at: now,
        published_at: None,
        updated_at: now,
    })
}

/// `(hub_id, priority)` of the entries of `record`, sorted by `hub_id`.
pub fn entries(record: &HostingRecord) -> Vec<(HubId, u8)> {
    let mut entries: Vec<(HubId, u8)> = record
        .hubs()
        .iter()
        .map(|entry| (entry.hub_id().clone(), entry.priority()))
        .collect();
    entries.sort();
    entries
}

/// Hubs listed by `record` and not by `previous`, and the reverse; sorted.
pub fn hub_diff(previous: &HostingRecord, record: &HostingRecord) -> (Vec<HubId>, Vec<HubId>) {
    let ids = |record: &HostingRecord| -> std::collections::BTreeSet<HubId> {
        record
            .hubs()
            .iter()
            .map(|entry| entry.hub_id().clone())
            .collect()
    };
    let (before, after) = (ids(previous), ids(record));
    (
        after.difference(&before).cloned().collect(),
        before.difference(&after).cloned().collect(),
    )
}

/// CBOR of a `HostingEntry`: `[hub_root_pubkey, priority, hub_sig]`.
pub fn encode_entry(entry: &HostingEntry) -> Vec<u8> {
    encode_cbor(&entry_value(entry))
}

fn entry_value(entry: &HostingEntry) -> ciborium::Value {
    use ciborium::Value;
    Value::Array(vec![
        Value::Bytes(entry.hub_root_pubkey().as_bytes().to_vec()),
        Value::Integer(entry.priority().into()),
        Value::Bytes(entry.hub_sig().to_vec()),
    ])
}

fn encode_cbor(value: &ciborium::Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding to memory");
    out
}

fn request_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("random request id");
    hex::encode(bytes)
}
