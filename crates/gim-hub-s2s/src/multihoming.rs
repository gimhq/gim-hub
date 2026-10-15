//! Multi-homing push gate (docs/multihoming.md §8): which of a user's hubs
//! pushes to the user's devices.
//!
//! The push dispatcher asks the gate synchronously for every queued push, so
//! [`PushGate::should_push`] never touches the database or the network: it
//! reads an in-memory view of the hosted users' hub lists, reloaded from the
//! database every [`REFRESH_INTERVAL`], and the transport's [`Liveness`]. A
//! record change is therefore seen by the gate up to one interval late.
//! The same loop keeps a connection open to every co-host, so the libp2p
//! pings that drive [`Liveness`] keep flowing.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use gim_hub_db::{hosting as store, Db, DbError};
use gim_hub_identity::{HostingRecord, HubId};
use tokio::task::JoinHandle;

use crate::{
    hosting::{decode_stored, Now},
    transport::{liveness::PING_INTERVAL, Liveness, Transport},
};

/// How often the hosted-user view is reloaded and co-host connections are
/// checked.
pub const REFRESH_INTERVAL: Duration = PING_INTERVAL;

/// Reachability of peer hubs as the push rule sees it.
pub trait PeerLiveness: Send + Sync + 'static {
    /// Whether `hub_id` is down (§8).
    fn is_down(&self, hub_id: &HubId) -> bool;

    /// The co-hosts of the hosted users, before the gate starts using them.
    fn track(&self, _hubs: &[HubId]) {}
}

impl PeerLiveness for Liveness {
    fn is_down(&self, hub_id: &HubId) -> bool {
        Liveness::is_down(self, hub_id)
    }

    fn track(&self, hubs: &[HubId]) {
        Liveness::track(self, hubs);
    }
}

/// A hosted user's listed hubs.
#[derive(Debug, Clone)]
struct Hosted {
    seq: u64,
    /// Unix ms, exclusive.
    expires_at: u64,
    /// In `(priority, hub_id)` order; the primary first.
    hubs: Vec<HubId>,
}

impl Hosted {
    /// `None` if `record` does not list `hub_id`.
    fn from_record(record: &HostingRecord, hub_id: &HubId) -> Option<Self> {
        record.entry(hub_id)?;
        let mut hubs: Vec<_> = record
            .hubs()
            .iter()
            .map(|entry| (entry.priority(), entry.hub_id().clone()))
            .collect();
        hubs.sort();
        Some(Self {
            seq: record.seq(),
            expires_at: record.expires_at(),
            hubs: hubs.into_iter().map(|(_, hub)| hub).collect(),
        })
    }
}

/// The push gate of a federated hub. Cheap to clone.
#[derive(Clone)]
pub struct PushGate {
    inner: Arc<Inner>,
}

struct Inner {
    hub_id: HubId,
    liveness: Arc<dyn PeerLiveness>,
    /// Wall clock (unix ms) for record expiry.
    now: Now,
    users: RwLock<HashMap<String, Hosted>>,
}

impl std::fmt::Debug for PushGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushGate")
            .field("hub_id", &self.inner.hub_id)
            .finish_non_exhaustive()
    }
}

impl PushGate {
    /// A gate for hub `hub_id` with an empty view; `now` is the wall clock in
    /// unix ms.
    pub fn new(hub_id: HubId, liveness: Arc<dyn PeerLiveness>, now: Now) -> Self {
        Self {
            inner: Arc::new(Inner {
                hub_id,
                liveness,
                now,
                users: RwLock::default(),
            }),
        }
    }

    /// Starts the gate of a federated hub: loads the view from `db` once,
    /// then reloads it and keeps the co-host connections open every
    /// [`REFRESH_INTERVAL`] in the returned task.
    pub async fn start(db: Db, transport: &Transport, now: Now) -> (Self, JoinHandle<()>) {
        let gate = Self::new(transport.hub_id().clone(), transport.liveness(), now);
        if let Err(err) = gate.refresh(&db).await {
            tracing::error!(%err, "push gate: loading hosted users failed");
        }
        let task = {
            let gate = gate.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(REFRESH_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval.tick().await;
                loop {
                    let co_hosts = gate.co_hosts();
                    futures::future::join_all(co_hosts.iter().map(|hub_id| {
                        let transport = transport.clone();
                        async move {
                            if let Err(err) = transport.keep_connected(hub_id).await {
                                tracing::debug!(%hub_id, %err, "co-host unreachable");
                            }
                        }
                    }))
                    .await;
                    interval.tick().await;
                    if let Err(err) = gate.refresh(&db).await {
                        tracing::error!(%err, "push gate: reloading hosted users failed");
                    }
                }
            })
        };
        (gate, task)
    }

    /// The §8 rule for local user `user_id`:
    /// 1. not hosted here (no valid record listing this hub, or removed) →
    ///    `false`; a single listed hub that is this hub → `true`;
    /// 2. this hub is the primary → `true`;
    /// 3. otherwise `true` only if every hub before this one in
    ///    `(priority, hub_id)` order is down.
    ///
    /// Without federation the gate is not installed and every user is
    /// pushed to.
    pub fn should_push(&self, user_id: &str) -> bool {
        let users = self.inner.users.read().expect("push gate lock");
        let Some(hosted) = users.get(user_id) else {
            return false;
        };
        let now = u64::try_from((self.inner.now)()).unwrap_or(0);
        if now >= hosted.expires_at {
            return false;
        }
        let Some(position) = hosted.hubs.iter().position(|hub| *hub == self.inner.hub_id) else {
            return false;
        };
        hosted.hubs[..position]
            .iter()
            .all(|hub| self.inner.liveness.is_down(hub))
    }

    /// Updates the view with `record` of a local user: hosted if it lists
    /// this hub, else not.
    pub fn set_record(&self, record: &HostingRecord) {
        let user_id = record.user_id().to_string();
        let mut users = self.inner.users.write().expect("push gate lock");
        match Hosted::from_record(record, &self.inner.hub_id) {
            Some(hosted) => {
                users.insert(user_id, hosted);
            }
            None => {
                users.remove(&user_id);
            }
        }
    }

    /// The other hubs listed for the hosted users, sorted.
    pub fn co_hosts(&self) -> Vec<HubId> {
        co_hosts(
            &self.inner.users.read().expect("push gate lock"),
            &self.inner.hub_id,
        )
    }

    /// Reloads the view from the hosted, unexpired records in `db`; records
    /// whose `seq` did not change are not decoded again.
    pub async fn refresh(&self, db: &Db) -> Result<(), DbError> {
        let now = (self.inner.now)();
        let rows = db.read(move |conn| store::hosted(conn, now, false)).await?;
        let users = {
            let current = self.inner.users.read().expect("push gate lock");
            let mut users = HashMap::with_capacity(rows.len());
            for row in rows {
                let seq = u64::try_from(row.seq).unwrap_or(0);
                let hosted = match current.get(&row.user_id) {
                    Some(hosted) if hosted.seq == seq => Some(hosted.clone()),
                    _ => decode_stored(&row.record)
                        .ok()
                        .and_then(|record| Hosted::from_record(&record, &self.inner.hub_id)),
                };
                if let Some(hosted) = hosted {
                    users.insert(row.user_id, hosted);
                }
            }
            users
        };
        // New co-hosts get the full failover delay before they count as down.
        self.inner
            .liveness
            .track(&co_hosts(&users, &self.inner.hub_id));
        *self.inner.users.write().expect("push gate lock") = users;
        Ok(())
    }
}

fn co_hosts(users: &HashMap<String, Hosted>, hub_id: &HubId) -> Vec<HubId> {
    let mut hubs: Vec<HubId> = users
        .values()
        .flat_map(|hosted| hosted.hubs.iter())
        .filter(|hub| *hub != hub_id)
        .cloned()
        .collect();
    hubs.sort();
    hubs.dedup();
    hubs
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use gim_hub_identity::SigningKey;

    use super::*;
    use crate::hosting::{stored_record, testing::sign_record};

    const FAILOVER: Duration = Duration::from_secs(30);
    const EXPIRES: u64 = 10_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn hub(seed: u8) -> HubId {
        HubId::from_root_pubkey(&key(seed).verifying_key())
    }

    fn record(user: u8, seq: u64, hubs: &[(u8, u8)]) -> HostingRecord {
        let keys: Vec<_> = hubs.iter().map(|(seed, p)| (key(*seed), *p)).collect();
        let refs: Vec<_> = keys.iter().map(|(k, p)| (k, *p)).collect();
        let bytes = sign_record(&key(user), seq, EXPIRES, &refs);
        HostingRecord::verify_claimed(&bytes, 0).unwrap()
    }

    /// A manual clock in ms, shared by the gate and the liveness view.
    struct Clock(Arc<AtomicI64>);

    impl Clock {
        fn new() -> Self {
            Self(Arc::new(AtomicI64::new(1_000)))
        }

        fn now(&self) -> Now {
            let clock = self.0.clone();
            Arc::new(move || clock.load(Ordering::SeqCst))
        }

        fn advance(&self, by: Duration) {
            self.0.fetch_add(by.as_millis() as i64, Ordering::SeqCst);
        }
    }

    /// Gate of hub `this` over liveness with the manual clock.
    fn gate(this: u8, clock: &Clock) -> (PushGate, Arc<Liveness>) {
        let liveness = Arc::new(Liveness::new(FAILOVER, clock.now()));
        (
            PushGate::new(hub(this), liveness.clone(), clock.now()),
            liveness,
        )
    }

    // Hubs 1 (priority 0, primary), 2 (priority 1), 3 (priority 1).
    const THREE: &[(u8, u8)] = &[(1, 0), (2, 1), (3, 1)];

    #[test]
    fn primary_pushes_fallback_waits_for_failover_and_stops_on_recovery() {
        let clock = Clock::new();
        let (primary, _) = gate(1, &clock);
        let (fallback, liveness) = gate(2, &clock);
        let r = record(100, 1, THREE);
        let user = r.user_id().to_string();
        primary.set_record(&r);
        fallback.set_record(&r);
        liveness.track(&fallback.co_hosts());

        assert!(primary.should_push(&user));
        assert!(!fallback.should_push(&user), "primary is up");

        clock.advance(FAILOVER - Duration::from_secs(1));
        liveness.alive(&hub(1));
        clock.advance(FAILOVER - Duration::from_secs(1));
        assert!(!fallback.should_push(&user), "a ping kept the primary up");

        clock.advance(Duration::from_secs(1));
        assert!(fallback.should_push(&user), "primary down after the delay");

        liveness.alive(&hub(1));
        assert!(!fallback.should_push(&user), "primary recovered");
        assert!(primary.should_push(&user));
    }

    #[test]
    fn third_hub_pushes_only_when_every_preceding_hub_is_down() {
        let clock = Clock::new();
        let (third, liveness) = gate(3, &clock);
        let r = record(100, 1, THREE);
        let user = r.user_id().to_string();
        third.set_record(&r);
        liveness.track(&third.co_hosts());
        assert_eq!(third.co_hosts(), {
            let mut hubs = vec![hub(1), hub(2)];
            hubs.sort();
            hubs
        });

        clock.advance(FAILOVER);
        liveness.alive(&hub(2));
        assert!(!third.should_push(&user), "hub 2 precedes and is up");
        clock.advance(FAILOVER);
        assert!(third.should_push(&user));
        liveness.alive(&hub(1));
        assert!(!third.should_push(&user));
    }

    #[test]
    fn equal_priority_orders_by_hub_id() {
        let clock = Clock::new();
        let (a, la) = gate(2, &clock);
        let (b, lb) = gate(3, &clock);
        let r = record(100, 1, &[(2, 0), (3, 0)]);
        let user = r.user_id().to_string();
        a.set_record(&r);
        b.set_record(&r);
        la.track(&a.co_hosts());
        lb.track(&b.co_hosts());
        let first = hub(2).min(hub(3));
        let (primary, fallback) = if first == hub(2) { (a, b) } else { (b, a) };
        assert!(primary.should_push(&user));
        assert!(!fallback.should_push(&user));
    }

    #[test]
    fn unhosted_removed_and_expired_users_are_not_pushed() {
        let clock = Clock::new();
        let (gate, _) = gate(2, &clock);
        assert!(!gate.should_push("unknown"));

        let r = record(100, 1, &[(1, 0), (2, 1)]);
        let user = r.user_id().to_string();
        gate.set_record(&r);
        clock.advance(FAILOVER * 2);
        assert!(gate.should_push(&user), "primary never seen: down");

        gate.set_record(&record(100, 2, &[(1, 0)]));
        assert!(!gate.should_push(&user), "removed");

        let single = record(101, 1, &[(2, 5)]);
        gate.set_record(&single);
        let single_user = single.user_id().to_string();
        assert!(gate.should_push(&single_user));
        clock.0.store(EXPIRES as i64, Ordering::SeqCst);
        assert!(!gate.should_push(&single_user), "expired");
    }

    #[test]
    fn single_listed_hub_always_pushes() {
        let clock = Clock::new();
        let (gate, _) = gate(1, &clock);
        let r = record(100, 1, &[(1, 3)]);
        gate.set_record(&r);
        assert!(gate.co_hosts().is_empty());
        assert!(gate.should_push(r.user_id().as_str()));
    }

    #[tokio::test]
    async fn refresh_loads_hosted_records_and_drops_removed_users() {
        let clock = Clock::new();
        let (gate, liveness) = gate(2, &clock);
        let db = Db::open_in_memory().unwrap();
        let hosted = record(100, 1, &[(1, 0), (2, 1)]);
        let single = record(101, 1, &[(2, 0)]);
        let put = |records: Vec<(HostingRecord, bool)>| {
            let db = db.clone();
            async move {
                db.write(move |tx| {
                    for (record, hosted) in &records {
                        store::put(tx, &stored_record(record, *hosted, 1_000).unwrap())?;
                    }
                    Ok::<_, DbError>(())
                })
                .await
                .unwrap();
            }
        };
        put(vec![(hosted.clone(), true), (single.clone(), true)]).await;
        gate.refresh(&db).await.unwrap();
        assert!(gate.should_push(single.user_id().as_str()));
        assert!(!gate.should_push(hosted.user_id().as_str()));
        assert_eq!(gate.co_hosts(), vec![hub(1)]);

        // Tracked at refresh: hub 1 gets the full delay from now.
        clock.advance(FAILOVER - Duration::from_secs(1));
        assert!(!liveness.is_down(&hub(1)));

        let removed = record(100, 2, &[(1, 0)]);
        put(vec![(removed, false)]).await;
        gate.refresh(&db).await.unwrap();
        assert!(!gate.should_push(hosted.user_id().as_str()));
        assert!(gate.co_hosts().is_empty());
    }
}
