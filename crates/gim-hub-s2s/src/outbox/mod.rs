//! Durable outbound queue for owner → member traffic (`Deliver`,
//! `DeliverWelcome`) and `NotifyDeviceList` (docs/federation.md §7).
//!
//! Writers queue entries with [`OutboxSender::enqueue_in_tx`] inside the
//! write transaction that sequences the message (or replaces the
//! DeviceList). The [`Outbox`] worker drains each peer's queue in `id`
//! order with at most one request in flight per peer, removes entries on
//! acknowledgement, backs off per peer on failure, and sends a resync nudge
//! once a peer that lost entries (cap or TTL) has drained.
//!
//! What an entry turns into on the wire comes from an [`OutboxSource`]
//! (messages and DeviceLists live in tables owned by other modules).

mod worker;

#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use gim_hub_db::{outbox, Connection, Db, DbError, Transaction};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::SequencedMessage;
use tokio::{
    sync::{broadcast, Notify},
    task::JoinHandle,
};

pub use gim_hub_db::outbox::NewEntry;

use crate::{
    config::FederationConfig,
    federation::{BoxFuture, Disabled, Federation},
    transport::{now_ms, PeerEvent},
};

/// Queues S2S traffic durably. Used by the group and identity code paths.
pub trait OutboxSender: Send + Sync + 'static {
    /// Queues `entry` for `peer` in the caller's write transaction `tx`
    /// (enforcing the backlog cap) and wakes the worker; the entry is sent
    /// once `tx` commits and dropped with it on rollback.
    fn enqueue_in_tx(
        &self,
        tx: &Transaction<'_>,
        peer: &HubId,
        entry: NewEntry<'_>,
    ) -> Result<(), DbError>;
}

/// Without federation there are no peers to queue for.
impl OutboxSender for Disabled {
    fn enqueue_in_tx(
        &self,
        _: &Transaction<'_>,
        _: &HubId,
        _: NewEntry<'_>,
    ) -> Result<(), DbError> {
        Ok(())
    }
}

/// Builds the wire form of queued entries. Errors are retried with the
/// peer's backoff.
pub trait OutboxSource: Send + Sync + 'static {
    /// The sequenced messages `(gid, seq)` of `deliver` entries, in the
    /// order of `keys`; `None` for a message that no longer exists (its
    /// entry is dropped).
    fn deliver_messages(
        &self,
        conn: &Connection,
        keys: &[(String, u64)],
    ) -> Result<Vec<Option<SequencedMessage>>, DbError>;

    /// The current DeviceList (CBOR) of the hosted user `user_id`; `None`
    /// when there is none (the entry is dropped).
    fn device_list(&self, conn: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, DbError>;

    /// The resync nudge for `peer` (§7.6): the newest message of every gid
    /// this hub owns with a member hosted on `peer`.
    fn resync_nudge(
        &self,
        conn: &Connection,
        peer: &HubId,
    ) -> Result<Vec<SequencedMessage>, DbError>;

    /// Called once when `peer` answers `UNAUTHORIZED`, before the entry is
    /// retried (§7.4): refresh the hosting records involved.
    fn refresh_peer(&self, peer: &HubId) -> BoxFuture<'_, ()> {
        let _ = peer;
        Box::pin(async {})
    }
}

/// Placeholder until the group and identity code provide the real source:
/// every build fails, so queued entries wait (and eventually expire).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSource;

impl OutboxSource for NoSource {
    fn deliver_messages(
        &self,
        _: &Connection,
        _: &[(String, u64)],
    ) -> Result<Vec<Option<SequencedMessage>>, DbError> {
        Err(DbError::Task("no outbox source".into()))
    }

    fn device_list(&self, _: &Connection, _: &str) -> Result<Option<Vec<u8>>, DbError> {
        Err(DbError::Task("no outbox source".into()))
    }

    fn resync_nudge(&self, _: &Connection, _: &HubId) -> Result<Vec<SequencedMessage>, DbError> {
        Err(DbError::Task("no outbox source".into()))
    }
}

/// Outbox settings (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxConfig {
    pub ttl: Duration,
    pub max_entries_per_peer: u64,
    pub max_bytes_per_peer: u64,
    pub backoff_max: Duration,
    /// How often expired entries are deleted.
    pub sweep_interval: Duration,
}

impl From<&FederationConfig> for OutboxConfig {
    fn from(config: &FederationConfig) -> Self {
        Self {
            ttl: Duration::from_secs(u64::from(config.outbox_ttl_hours) * 3600),
            max_entries_per_peer: config.outbox_max_entries_per_peer,
            max_bytes_per_peer: config.outbox_max_bytes_per_peer,
            backoff_max: Duration::from_secs(config.outbox_backoff_max_seconds.into()),
            sweep_interval: Duration::from_secs(60),
        }
    }
}

impl OutboxConfig {
    fn limits(&self) -> outbox::Limits {
        let clamp = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        outbox::Limits {
            ttl_ms: clamp(self.ttl.as_millis() as u64),
            max_entries: clamp(self.max_entries_per_peer),
            max_bytes: clamp(self.max_bytes_per_peer),
        }
    }
}

/// Wall clock in unix milliseconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Why entries were dropped without delivery
/// (`s2s_outbox_dropped_total{peer,reason}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// Evicted by the backlog cap.
    Evicted,
    /// TTL reached.
    Expired,
    /// The peer answered with a permanent error.
    Rejected,
    /// The entry could not be built (message or DeviceList gone, bad payload).
    Unbuildable,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evicted => "evicted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Unbuildable => "unbuildable",
        }
    }
}

/// Interval of the over-80 % backlog alert per peer.
const ALERT_INTERVAL_MS: i64 = 60 * 60 * 1000;

/// The durable outbox and its worker. Cheap to clone.
#[derive(Clone)]
pub struct Outbox {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    federation: Arc<dyn Federation>,
    source: Arc<dyn OutboxSource>,
    config: OutboxConfig,
    clock: Clock,
    wake: Notify,
    /// Peers with a running drain task.
    active: Mutex<HashSet<String>>,
    /// Last over-80 % alert per peer.
    alerts: Mutex<HashMap<String, i64>>,
    dropped: Mutex<HashMap<(String, DropReason), u64>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().expect("tasks lock").drain(..) {
            task.abort();
        }
    }
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Outbox {
    /// An outbox sending through `federation`; call [`Outbox::start`] to
    /// run the worker.
    pub fn new(
        db: Db,
        federation: Arc<dyn Federation>,
        source: Arc<dyn OutboxSource>,
        config: OutboxConfig,
    ) -> Self {
        Self::with_clock(db, federation, source, config, Arc::new(|| now_ms() as i64))
    }

    /// [`Outbox::new`] with an explicit clock.
    pub fn with_clock(
        db: Db,
        federation: Arc<dyn Federation>,
        source: Arc<dyn OutboxSource>,
        config: OutboxConfig,
        clock: Clock,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                federation,
                source,
                config,
                clock,
                wake: Notify::new(),
                active: Mutex::default(),
                alerts: Mutex::default(),
                dropped: Mutex::default(),
                tasks: Mutex::default(),
            }),
        }
    }

    /// Starts the worker. `peer_events` (the transport's
    /// [`crate::Transport::subscribe`]) resets a peer's backoff when it
    /// connects.
    pub fn start(&self, peer_events: Option<broadcast::Receiver<PeerEvent>>) {
        let supervisor = tokio::spawn(worker::supervise(self.clone()));
        let mut tasks = self.inner.tasks.lock().expect("tasks lock");
        tasks.push(supervisor);
        if let Some(mut events) = peer_events {
            let outbox = self.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(PeerEvent::Up(hub_id)) => {
                            if let Err(err) = outbox.peer_up(&hub_id).await {
                                tracing::error!(%err, peer = %hub_id, "outbox peer-up update failed");
                            }
                        }
                        Ok(PeerEvent::Down(_)) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => outbox.wake(),
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
        }
    }

    /// Stops the worker. Queued entries stay in the database.
    pub fn shutdown(&self) {
        for task in self.inner.tasks.lock().expect("tasks lock").drain(..) {
            task.abort();
        }
    }

    /// `peer` connected (§7.6): reset its backoff and drain its queue now.
    pub async fn peer_up(&self, peer: &HubId) -> Result<(), DbError> {
        let peer = peer.as_str().to_owned();
        let now = self.now();
        self.inner
            .db
            .write(move |tx| outbox::record_connected(tx, &peer, now))
            .await?;
        self.wake();
        Ok(())
    }

    /// Wakes the worker to look for due peers.
    pub fn wake(&self) {
        self.inner.wake.notify_one();
    }

    /// Entries of `peer` dropped for `reason` since start.
    pub fn dropped_total(&self, peer: &HubId, reason: DropReason) -> u64 {
        self.inner
            .dropped
            .lock()
            .expect("dropped lock")
            .get(&(peer.as_str().to_owned(), reason))
            .copied()
            .unwrap_or_default()
    }

    fn now(&self) -> i64 {
        (self.inner.clock)()
    }

    fn count_dropped(&self, peer: &str, reason: DropReason, count: u64) {
        if count == 0 {
            return;
        }
        *self
            .inner
            .dropped
            .lock()
            .expect("dropped lock")
            .entry((peer.to_owned(), reason))
            .or_default() += count;
        tracing::warn!(
            peer,
            reason = reason.as_str(),
            count,
            "s2s_outbox_dropped_total"
        );
    }

    /// Logs `error` at most hourly per peer while its backlog is over 80 %
    /// of either cap.
    fn check_backlog(&self, peer: &str, backlog: outbox::Backlog, now: i64) {
        let limits = self.inner.config.limits();
        let over = |value: i64, max: i64| value.saturating_mul(5) > max.saturating_mul(4);
        if !over(backlog.entries, limits.max_entries) && !over(backlog.bytes, limits.max_bytes) {
            return;
        }
        let mut alerts = self.inner.alerts.lock().expect("alerts lock");
        let last = alerts.entry(peer.to_owned()).or_insert(i64::MIN);
        if now.saturating_sub(*last) >= ALERT_INTERVAL_MS {
            *last = now;
            tracing::error!(
                peer,
                s2s_outbox_entries = backlog.entries,
                s2s_outbox_bytes = backlog.bytes,
                max_entries = limits.max_entries,
                max_bytes = limits.max_bytes,
                "outbox backlog over 80% of the cap"
            );
        }
    }
}

impl OutboxSender for Outbox {
    fn enqueue_in_tx(
        &self,
        tx: &Transaction<'_>,
        peer: &HubId,
        entry: NewEntry<'_>,
    ) -> Result<(), DbError> {
        let now = self.now();
        let peer = peer.as_str();
        let enqueued = outbox::enqueue(tx, peer, entry, &self.inner.config.limits(), now)?;
        self.count_dropped(peer, DropReason::Evicted, enqueued.evicted as u64);
        self.check_backlog(peer, enqueued.backlog, now);
        // The worker reads through the same `Db`, so it sees the entry once
        // the caller's transaction has committed.
        self.wake();
        Ok(())
    }
}
