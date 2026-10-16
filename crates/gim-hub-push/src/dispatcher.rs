//! Tails the event path and delivers pushes through a bounded queue.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use gim_hub_db::{events, push, Connection, Db, DbError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{sync::Notify, task::JoinHandle};

use crate::{
    PushConfig, PushError, PushKind, PushLog, PushNotification, PushProvider, Registration,
};

/// Events read per database round trip while tailing.
const BATCH: u32 = 500;
/// Longest honoured `Retry-After`.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Dispatcher tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatcherSettings {
    /// Also push membership events.
    pub member_events: bool,
    /// Send minimal wake-up payloads (see [`PushNotification::minimal`]).
    pub minimal: bool,
    /// Most devices with a queued push.
    pub queue_capacity: usize,
    /// How often the event path is tailed.
    pub poll_interval: Duration,
    /// Concurrent sends.
    pub workers: usize,
    /// Attempts per notification, including the first.
    pub max_attempts: u32,
    /// Delay before the first retry; doubles per attempt.
    pub retry_base: Duration,
}

impl Default for DispatcherSettings {
    fn default() -> Self {
        Self {
            member_events: false,
            minimal: false,
            queue_capacity: 10_000,
            poll_interval: Duration::from_millis(500),
            workers: 4,
            max_attempts: 5,
            retry_base: Duration::from_secs(1),
        }
    }
}

impl From<&PushConfig> for DispatcherSettings {
    fn from(config: &PushConfig) -> Self {
        Self {
            member_events: config.member_events,
            minimal: config.minimal,
            queue_capacity: config.queue_capacity,
            ..Self::default()
        }
    }
}

/// Decides whether this hub pushes to a device `(user_id, device_id)`.
/// Multi-homing installs one that admits only users whose primary hub this
/// is; the default admits everyone (duplicates collapse on `collapse_id`).
pub type PushGate = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Counters of the dispatcher.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Notifications queued.
    pub enqueued: u64,
    /// Queued notifications replaced by a newer one for the same device.
    pub coalesced: u64,
    /// Notifications dropped because the queue was full.
    pub dropped: u64,
    /// Notifications delivered to a provider.
    pub sent: u64,
    /// Notifications without a provider (no webhook configured).
    pub skipped: u64,
    /// Registrations deleted after the push server rejected them.
    pub invalid_token: u64,
    /// Retries scheduled.
    pub retried: u64,
    /// Notifications given up on (permanent error or out of attempts).
    pub failed: u64,
}

#[derive(Default)]
struct Metrics {
    enqueued: AtomicU64,
    coalesced: AtomicU64,
    dropped: AtomicU64,
    sent: AtomicU64,
    skipped: AtomicU64,
    invalid_token: AtomicU64,
    retried: AtomicU64,
    failed: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

type DeviceKey = (String, String);

#[derive(Debug, Clone)]
struct Job {
    registration: Registration,
    notification: PushNotification,
    attempt: u32,
}

impl Job {
    fn key(&self) -> DeviceKey {
        (
            self.registration.user_id.clone(),
            self.registration.device_id.clone(),
        )
    }
}

/// Pending pushes, at most one per device, in arrival order.
#[derive(Default)]
struct Queue {
    order: VecDeque<DeviceKey>,
    pending: HashMap<DeviceKey, Job>,
}

struct Inner {
    db: Db,
    providers: Vec<Arc<dyn PushProvider>>,
    settings: DispatcherSettings,
    log: PushLog,
    gate: RwLock<Option<PushGate>>,
    queue: Mutex<Queue>,
    wake: Notify,
    /// Last event id read from the event path.
    cursor: tokio::sync::Mutex<i64>,
    metrics: Metrics,
}

/// The push dispatcher (cheap to clone).
#[derive(Clone)]
pub struct Dispatcher {
    inner: Arc<Inner>,
}

impl Dispatcher {
    /// A dispatcher delivering through the first of `providers` that
    /// [handles](PushProvider::handles) a registration, that will tail
    /// events after `start_after`.
    /// `log` is the sink of the `log` provider. Nothing runs until
    /// [`Dispatcher::start`].
    pub fn new(
        db: Db,
        providers: Vec<Arc<dyn PushProvider>>,
        log: PushLog,
        settings: DispatcherSettings,
        start_after: i64,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                providers,
                settings,
                log,
                gate: RwLock::new(None),
                queue: Mutex::new(Queue::default()),
                wake: Notify::new(),
                cursor: tokio::sync::Mutex::new(start_after),
                metrics: Metrics::default(),
            }),
        }
    }

    /// Installs the multi-homing gate (see [`PushGate`]).
    pub fn set_gate(&self, gate: PushGate) {
        *self
            .inner
            .gate
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(gate);
    }

    /// The `log` provider's sink.
    pub fn log(&self) -> &PushLog {
        &self.inner.log
    }

    /// Current counters.
    pub fn metrics(&self) -> MetricsSnapshot {
        let m = &self.inner.metrics;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        MetricsSnapshot {
            enqueued: get(&m.enqueued),
            coalesced: get(&m.coalesced),
            dropped: get(&m.dropped),
            sent: get(&m.sent),
            skipped: get(&m.skipped),
            invalid_token: get(&m.invalid_token),
            retried: get(&m.retried),
            failed: get(&m.failed),
        }
    }

    /// Spawns the tailing loop and the send workers; abort the returned
    /// tasks to stop.
    pub fn start(&self) -> Vec<JoinHandle<()>> {
        let mut tasks = Vec::new();
        let tail = self.clone();
        tasks.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(tail.inner.settings.poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if let Err(err) = tail.poll_once().await {
                    tracing::error!(%err, "push: reading events failed");
                }
            }
        }));
        for _ in 0..self.inner.settings.workers.max(1) {
            let inner = self.inner.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let job = inner.next_job().await;
                    inner.deliver(job).await;
                }
            }));
        }
        tasks
    }

    /// Reads new events and queues their pushes; returns how many were
    /// queued (or replaced a queued one).
    pub async fn poll_once(&self) -> Result<usize, DbError> {
        let mut cursor = self.inner.cursor.lock().await;
        let mut queued = 0;
        loop {
            let after = *cursor;
            let (member_events, minimal) = (
                self.inner.settings.member_events,
                self.inner.settings.minimal,
            );
            let (last, read, jobs) = self
                .inner
                .db
                .read(move |conn| collect_jobs(conn, after, member_events, minimal))
                .await?;
            *cursor = last;
            for job in jobs {
                if self.inner.admits(&job) && self.inner.enqueue(job, false) {
                    queued += 1;
                }
            }
            if read < BATCH as usize {
                return Ok(queued);
            }
        }
    }

    /// Sends every queued push in the calling task (tests); retries are
    /// still scheduled in the background. Returns the number processed.
    pub async fn run_pending(&self) -> usize {
        let mut processed = 0;
        while let Some(job) = self.inner.pop() {
            self.inner.deliver(job).await;
            processed += 1;
        }
        processed
    }
}

impl Inner {
    fn admits(&self, job: &Job) -> bool {
        let gate = self.gate.read().unwrap_or_else(PoisonError::into_inner);
        gate.as_ref()
            .is_none_or(|gate| gate(&job.registration.user_id, &job.registration.device_id))
    }

    /// Queues `job`, replacing a queued push for the same device. A retry
    /// never replaces a newer queued push. Returns whether it was queued.
    fn enqueue(&self, job: Job, retry: bool) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let key = job.key();
        if let Some(pending) = queue.pending.get_mut(&key) {
            bump(&self.metrics.coalesced);
            if retry {
                return false;
            }
            *pending = job;
            return true;
        }
        if queue.pending.len() >= self.settings.queue_capacity {
            bump(&self.metrics.dropped);
            tracing::warn!(
                user_id = %key.0,
                device_id = %key.1,
                capacity = self.settings.queue_capacity,
                "push: queue full, notification dropped"
            );
            return false;
        }
        queue.order.push_back(key.clone());
        queue.pending.insert(key, job);
        drop(queue);
        bump(&self.metrics.enqueued);
        self.wake.notify_one();
        true
    }

    fn pop(&self) -> Option<Job> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(key) = queue.order.pop_front() {
            if let Some(job) = queue.pending.remove(&key) {
                return Some(job);
            }
        }
        None
    }

    async fn next_job(&self) -> Job {
        loop {
            if let Some(job) = self.pop() {
                return job;
            }
            self.wake.notified().await;
        }
    }

    async fn deliver(self: &Arc<Self>, mut job: Job) {
        if job.attempt == 0 {
            job.notification.sent_at = now_ms();
        }
        let registration = &job.registration;
        let Some(provider) = self
            .providers
            .iter()
            .find(|p| p.handles(&registration.provider))
        else {
            bump(&self.metrics.skipped);
            tracing::info!(
                provider = %registration.provider,
                user_id = %registration.user_id,
                device_id = %registration.device_id,
                "push skipped: provider not configured"
            );
            return;
        };
        match provider.send(registration, &job.notification).await {
            Ok(()) => bump(&self.metrics.sent),
            Err(PushError::InvalidToken(reason)) => {
                bump(&self.metrics.invalid_token);
                tracing::info!(
                    provider = %registration.provider,
                    user_id = %registration.user_id,
                    device_id = %registration.device_id,
                    %reason,
                    "push registration rejected; removed"
                );
                let r = registration.clone();
                let removed = self
                    .db
                    .write(move |tx| {
                        push::delete_token(tx, &r.user_id, &r.device_id, &r.provider, &r.token)
                    })
                    .await;
                if let Err(err) = removed {
                    tracing::error!(%err, "push: removing registration failed");
                }
            }
            Err(PushError::Retryable(reason, retry_after))
                if job.attempt + 1 < self.settings.max_attempts =>
            {
                bump(&self.metrics.retried);
                let backoff = self.settings.retry_base * 2u32.saturating_pow(job.attempt);
                let delay =
                    retry_after.map_or(backoff, |after| backoff.max(after.min(MAX_RETRY_AFTER)));
                tracing::warn!(
                    provider = %registration.provider,
                    device_id = %registration.device_id,
                    %reason,
                    attempt = job.attempt + 1,
                    ?delay,
                    "push failed; retrying"
                );
                let inner = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    inner.enqueue(
                        Job {
                            attempt: job.attempt + 1,
                            ..job
                        },
                        true,
                    );
                });
            }
            Err(err) => {
                bump(&self.metrics.failed);
                tracing::warn!(
                    provider = %registration.provider,
                    device_id = %registration.device_id,
                    %err,
                    "push failed"
                );
            }
        }
    }
}

/// Reads events after `after`: returns the last id read, how many events were
/// read and the pushes they produce.
fn collect_jobs(
    conn: &Connection,
    after: i64,
    member_events: bool,
    minimal: bool,
) -> Result<(i64, usize, Vec<Job>), DbError> {
    let events = events::list_all_after(conn, after, BATCH)?;
    let last = events.last().map_or(after, |e| e.event.id);
    let mut jobs = Vec::new();
    for addressed in &events {
        let Some(kind) = PushKind::from_event_type(&addressed.event.event_type) else {
            continue;
        };
        if !kind.is_alert() && !member_events {
            continue;
        }
        // MLS Proposals change nothing until a Commit covers them.
        if matches!(kind, PushKind::Message) && is_proposal(&addressed.event.payload) {
            continue;
        }
        let Some(registration) = push::get_active(conn, &addressed.user_id, &addressed.device_id)?
        else {
            continue;
        };
        match notification(conn, kind, &addressed.event.payload, minimal)? {
            Some(notification) => jobs.push(Job {
                registration,
                notification,
                attempt: 0,
            }),
            None => tracing::warn!(
                event_id = addressed.event.id,
                "push: malformed event payload"
            ),
        }
    }
    Ok((last, events.len(), jobs))
}

/// Whether a `message` event carries an MLS Proposal.
fn is_proposal(payload: &str) -> bool {
    serde_json::from_str::<Value>(payload).is_ok_and(|data| data["kind"] == "proposal")
}

/// The notification for an event's data.
fn notification(
    conn: &Connection,
    kind: PushKind,
    payload: &str,
    minimal: bool,
) -> Result<Option<PushNotification>, DbError> {
    let Ok(data) = serde_json::from_str::<Value>(payload) else {
        return Ok(None);
    };
    let (Some(gid), Some(seq)) = (data["gid"].as_str(), data["seq"].as_u64()) else {
        return Ok(None);
    };
    let mls_message = match kind {
        PushKind::Message => data["mls_message"].as_str(),
        // A Welcome is only usable inline without a separate ratchet tree.
        PushKind::Welcome if data["ratchet_tree"].is_null() => data["welcome"].as_str(),
        _ => None,
    };
    let message_id = message_id(conn, gid, seq)?;
    Ok(Some(PushNotification {
        kind,
        gid: gid.to_owned(),
        seq,
        message_id,
        mls_message: mls_message.map(str::to_owned),
        minimal,
        delivery_id: delivery_id(),
        sent_at: 0,
    }))
}

/// A fresh random delivery id: 128 bits, lowercase hex.
fn delivery_id() -> String {
    let mut bytes = [0u8; 16];
    // The system RNG does not fail on supported platforms; a zero id is
    // still delivered.
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The push `message_id` / `collapse_id` of `(gid, seq)`: the stored
/// message's ID, else a deterministic stand-in.
pub fn message_id(conn: &Connection, gid: &str, seq: u64) -> Result<String, DbError> {
    Ok(
        match push::message_id_at(conn, gid, i64::try_from(seq).unwrap_or(i64::MAX))? {
            Some(id) => id,
            None => fallback_message_id(gid, seq),
        },
    )
}

/// Deterministic stand-in when `(gid, seq)` is not stored here.
fn fallback_message_id(gid: &str, seq: u64) -> String {
    let digest = Sha256::new()
        .chain_update(gid.as_bytes())
        .chain_update([0])
        .chain_update(seq.to_be_bytes())
        .finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use gim_hub_db::users::{self, Device, StoredDeviceList};

    use super::*;

    /// Answers with the queued results (then `Ok`) and records sends.
    struct Fake {
        name: &'static str,
        results: StdMutex<VecDeque<Result<(), PushError>>>,
        sent: StdMutex<Vec<(String, PushNotification)>>,
    }

    impl Fake {
        fn new(name: &'static str, results: Vec<Result<(), PushError>>) -> Arc<Self> {
            Arc::new(Self {
                name,
                results: StdMutex::new(results.into()),
                sent: StdMutex::new(Vec::new()),
            })
        }

        fn sent(&self) -> Vec<(String, PushNotification)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PushProvider for Fake {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn send(&self, r: &Registration, n: &PushNotification) -> Result<(), PushError> {
            self.sent
                .lock()
                .unwrap()
                .push((r.device_id.clone(), n.clone()));
            self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
    }

    async fn db_with_devices(devices: &[(&str, &str, &str)]) -> Db {
        let db = Db::open_in_memory().unwrap();
        let devices: Vec<(String, String, String)> = devices
            .iter()
            .map(|(u, d, p)| ((*u).into(), (*d).into(), (*p).into()))
            .collect();
        db.write(move |tx| {
            for (user_id, device_id, provider) in &devices {
                if users::get_device_list(tx, user_id)?.is_none() {
                    users::put_device_list(
                        tx,
                        &StoredDeviceList {
                            user_id: user_id.clone(),
                            root_pubkey: vec![0; 32],
                            device_list: Vec::new(),
                            seq: 0,
                            updated_at: 0,
                        },
                    )?;
                }
                users::put_device(
                    tx,
                    &Device {
                        user_id: user_id.clone(),
                        device_id: device_id.clone(),
                        sig_pubkey: vec![0; 32],
                        active: true,
                    },
                    0,
                )?;
                push::put(
                    tx,
                    &Registration {
                        user_id: user_id.clone(),
                        device_id: device_id.clone(),
                        provider: provider.clone(),
                        token: format!("tok-{device_id}"),
                        app_id: None,
                        sandbox: None,
                        p256dh: None,
                        auth: None,
                        updated_at: 0,
                    },
                )?;
            }
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        db
    }

    async fn append(db: &Db, device: &str, event_type: &str, data: Value) {
        let (device, event_type) = (device.to_owned(), event_type.to_owned());
        db.write(move |tx| events::append(tx, "u2", &device, &event_type, &data.to_string(), 0))
            .await
            .unwrap();
    }

    fn message(seq: u64) -> Value {
        serde_json::json!({
            "gid": "g1", "seq": seq, "sender_user_id": "u1", "mls_message": "AAAA",
        })
    }

    fn dispatcher(
        db: &Db,
        providers: Vec<Arc<dyn PushProvider>>,
        settings: DispatcherSettings,
    ) -> Dispatcher {
        Dispatcher::new(db.clone(), providers, PushLog::default(), settings, 0)
    }

    #[tokio::test]
    async fn message_events_become_pushes_and_coalesce_per_device() {
        let db = db_with_devices(&[("u2", "d1", "fcm"), ("u2", "d2", "fcm")]).await;
        let fake = Fake::new("fcm", Vec::new());
        let d = dispatcher(&db, vec![fake.clone()], DispatcherSettings::default());
        append(&db, "d1", "message", message(1)).await;
        append(&db, "d1", "message", message(2)).await;
        append(&db, "d2", "keypackages.low", serde_json::json!({})).await;
        append(&db, "d3", "message", message(2)).await;
        assert_eq!(d.poll_once().await.unwrap(), 2);
        assert_eq!(d.poll_once().await.unwrap(), 0);
        assert_eq!(d.run_pending().await, 1);
        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "d1");
        assert_eq!(sent[0].1.seq, 2);
        assert_eq!(sent[0].1.message_id, fallback_message_id("g1", 2));
        assert_eq!(sent[0].1.mls_message.as_deref(), Some("AAAA"));
        let m = d.metrics();
        assert_eq!((m.enqueued, m.coalesced, m.sent), (1, 1, 1));
    }

    #[tokio::test]
    async fn proposals_are_not_pushed() {
        let db = db_with_devices(&[("u2", "d1", "fcm")]).await;
        let fake = Fake::new("fcm", Vec::new());
        let d = dispatcher(&db, vec![fake.clone()], DispatcherSettings::default());
        let mut proposal = message(1);
        proposal["kind"] = "proposal".into();
        append(&db, "d1", "message", proposal).await;
        assert_eq!(d.poll_once().await.unwrap(), 0);
        let mut commit = message(2);
        commit["kind"] = "commit".into();
        append(&db, "d1", "message", commit).await;
        assert_eq!(d.poll_once().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn member_events_are_opt_in_and_welcomes_inline_without_tree() {
        let db = db_with_devices(&[("u2", "d1", "fcm")]).await;
        let member = serde_json::json!({
            "gid": "g1", "seq": 3, "user_id": "u3", "device_ids": ["d9"],
            "by_user_id": "u1", "by_device_id": "d1", "epoch": 2,
        });
        append(&db, "d1", "group.member_added", member.clone()).await;
        let fake = Fake::new("fcm", Vec::new());
        let off = dispatcher(&db, vec![fake.clone()], DispatcherSettings::default());
        assert_eq!(off.poll_once().await.unwrap(), 0);
        let on = dispatcher(
            &db,
            vec![fake.clone()],
            DispatcherSettings {
                member_events: true,
                ..DispatcherSettings::default()
            },
        );
        assert_eq!(on.poll_once().await.unwrap(), 1);
        on.run_pending().await;
        assert_eq!(fake.sent()[0].1.kind, PushKind::MemberAdded);
        assert!(fake.sent()[0]
            .1
            .payload(true)
            .get("sender_user_id")
            .is_none());

        let welcome = serde_json::json!({
            "gid": "g1", "seq": 3, "sender_user_id": "u1", "sender_device_id": "d1",
            "epoch": 2, "welcome": "V0VMQw==",
        });
        append(&db, "d1", "welcome", welcome.clone()).await;
        let mut with_tree = welcome;
        with_tree["ratchet_tree"] = "VFJFRQ==".into();
        append(&db, "d1", "welcome", with_tree).await;
        let d = dispatcher(&db, vec![fake.clone()], DispatcherSettings::default());
        d.poll_once().await.unwrap();
        d.run_pending().await;
        // Coalesced to the second Welcome, which has a tree: not inlined.
        let last = fake.sent().pop().unwrap().1;
        assert_eq!(last.kind, PushKind::Welcome);
        assert_eq!(last.mls_message, None);
    }

    #[tokio::test]
    async fn minimal_mode_sends_wake_ups() {
        let db = db_with_devices(&[("u2", "d1", "fcm")]).await;
        let fake = Fake::new("fcm", Vec::new());
        let d = dispatcher(
            &db,
            vec![fake.clone()],
            DispatcherSettings {
                minimal: true,
                ..DispatcherSettings::default()
            },
        );
        append(&db, "d1", "message", message(1)).await;
        d.poll_once().await.unwrap();
        d.run_pending().await;
        let sent = fake.sent().pop().unwrap().1;
        assert!(sent.minimal);
        assert_eq!(sent.kind, PushKind::Message);
        assert_eq!(
            sent.payload(true),
            serde_json::json!({ "v": 1, "type": "wake", "collapse_id": sent.message_id }),
        );
    }

    #[tokio::test]
    async fn invalid_token_removes_registration() {
        let db = db_with_devices(&[("u2", "d1", "fcm")]).await;
        let fake = Fake::new("fcm", vec![Err(PushError::InvalidToken("gone".into()))]);
        let d = dispatcher(&db, vec![fake], DispatcherSettings::default());
        append(&db, "d1", "message", message(1)).await;
        d.poll_once().await.unwrap();
        d.run_pending().await;
        assert_eq!(d.metrics().invalid_token, 1);
        assert!(db
            .read(|conn| push::get_active(conn, "u2", "d1"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn retryable_errors_are_retried_with_backoff() {
        let db = db_with_devices(&[("u2", "d1", "fcm")]).await;
        let fake = Fake::new(
            "fcm",
            vec![
                Err(PushError::Retryable("503".into(), None)),
                Err(PushError::Retryable("503".into(), None)),
            ],
        );
        let d = dispatcher(
            &db,
            vec![fake.clone()],
            DispatcherSettings {
                retry_base: Duration::from_millis(1),
                ..DispatcherSettings::default()
            },
        );
        append(&db, "d1", "message", message(1)).await;
        d.poll_once().await.unwrap();
        for _ in 0..200 {
            d.run_pending().await;
            if d.metrics().sent == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let m = d.metrics();
        assert_eq!((m.retried, m.sent, m.failed), (2, 1, 0));
        assert_eq!(fake.sent().len(), 3);
        // One delivery: the same id and first-attempt time on every retry.
        let sent = fake.sent();
        let first = &sent[0].1;
        assert!(first.sent_at > 0 && first.delivery_id.len() == 32);
        assert!(sent
            .iter()
            .all(|(_, n)| (&n.delivery_id, n.sent_at) == (&first.delivery_id, first.sent_at)));

        let fake = Fake::new("fcm", vec![Err(PushError::Permanent("400".into()))]);
        let d = dispatcher(&db, vec![fake], DispatcherSettings::default());
        append(&db, "d1", "message", message(2)).await;
        d.poll_once().await.unwrap();
        d.run_pending().await;
        assert_eq!(d.metrics().failed, 1);
    }

    #[tokio::test]
    async fn overflow_drops_and_unconfigured_providers_skip() {
        let db = db_with_devices(&[("u2", "d1", "apns"), ("u2", "d2", "apns")]).await;
        let d = dispatcher(
            &db,
            Vec::new(),
            DispatcherSettings {
                queue_capacity: 1,
                ..DispatcherSettings::default()
            },
        );
        append(&db, "d1", "message", message(1)).await;
        append(&db, "d2", "message", message(1)).await;
        assert_eq!(d.poll_once().await.unwrap(), 1);
        assert_eq!(d.run_pending().await, 1);
        let m = d.metrics();
        assert_eq!((m.dropped, m.skipped, m.sent), (1, 1, 0));
    }

    #[tokio::test]
    async fn gate_filters_devices_and_start_runs_workers() {
        let db = db_with_devices(&[("u2", "d1", "fcm"), ("u2", "d2", "fcm")]).await;
        let fake = Fake::new("fcm", Vec::new());
        let d = dispatcher(
            &db,
            vec![fake.clone()],
            DispatcherSettings {
                poll_interval: Duration::from_millis(5),
                ..DispatcherSettings::default()
            },
        );
        d.set_gate(Arc::new(|_, device_id| device_id == "d2"));
        let tasks = d.start();
        append(&db, "d1", "message", message(1)).await;
        append(&db, "d2", "message", message(1)).await;
        for _ in 0..200 {
            if d.metrics().sent == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for task in tasks {
            task.abort();
        }
        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "d2");
    }
}
