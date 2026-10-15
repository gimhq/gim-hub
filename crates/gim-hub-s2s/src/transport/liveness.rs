//! Peer hub liveness for the multi-homing push rule (docs/multihoming.md
//! §8): a hub is down after the failover delay without a successful ping or
//! S2S exchange, and up again on the next success.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use gim_hub_identity::HubId;

use crate::hosting::Now;

/// How often connected peers are pinged.
pub const PING_INTERVAL: Duration = Duration::from_secs(10);

/// The ping interval for `failover`: [`PING_INTERVAL`], shortened so that
/// at least three pings fit into a short failover delay (tests).
pub fn ping_interval(failover: Duration) -> Duration {
    PING_INTERVAL
        .min(failover / 3)
        .max(Duration::from_millis(50))
}

/// A monotonic clock in milliseconds since its creation.
pub fn monotonic() -> Now {
    let start = Instant::now();
    Arc::new(move || i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX))
}

/// Last successful contact per hub, on an injectable clock.
pub struct Liveness {
    failover_ms: i64,
    now: Now,
    /// Hubs are measured from here until their first success.
    created: i64,
    last: Mutex<HashMap<HubId, i64>>,
}

impl std::fmt::Debug for Liveness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Liveness")
            .field("failover_ms", &self.failover_ms)
            .finish_non_exhaustive()
    }
}

impl Liveness {
    /// Liveness with failover delay `failover`, reading time from `now`
    /// (milliseconds, monotonic in production: see [`monotonic`]).
    pub fn new(failover: Duration, now: Now) -> Self {
        let created = now();
        Self {
            failover_ms: i64::try_from(failover.as_millis()).unwrap_or(i64::MAX),
            now,
            created,
            last: Mutex::default(),
        }
    }

    /// Records a successful ping or S2S exchange with `hub_id`.
    pub fn alive(&self, hub_id: &HubId) {
        let now = (self.now)();
        self.last
            .lock()
            .expect("liveness lock")
            .insert(hub_id.clone(), now);
    }

    /// Sets the hubs whose state matters: a hub not seen before is measured
    /// from now (it gets the full failover delay to answer); hubs not in
    /// `hubs` are forgotten.
    pub fn track(&self, hubs: &[HubId]) {
        let now = (self.now)();
        let mut last = self.last.lock().expect("liveness lock");
        last.retain(|hub, _| hubs.contains(hub));
        for hub in hubs {
            last.entry(hub.clone()).or_insert(now);
        }
    }

    /// Whether `hub_id` had no success for the failover delay. A hub never
    /// seen nor tracked is measured from the creation of `self`.
    pub fn is_down(&self, hub_id: &HubId) -> bool {
        let now = (self.now)();
        let last = self
            .last
            .lock()
            .expect("liveness lock")
            .get(hub_id)
            .copied()
            .unwrap_or(self.created);
        now.saturating_sub(last) >= self.failover_ms
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;

    fn hub(n: u8) -> HubId {
        HubId::from_root_pubkey(&gim_hub_identity::SigningKey::from_bytes(&[n; 32]).verifying_key())
    }

    #[test]
    fn down_after_failover_and_up_on_next_success() {
        let clock = Arc::new(AtomicI64::new(1_000));
        let now: Now = {
            let clock = clock.clone();
            Arc::new(move || clock.load(Ordering::SeqCst))
        };
        let liveness = Liveness::new(Duration::from_secs(30), now);
        let (a, b) = (hub(1), hub(2));
        assert!(!liveness.is_down(&a), "measured from creation");
        clock.fetch_add(29_999, Ordering::SeqCst);
        liveness.alive(&a);
        clock.fetch_add(1, Ordering::SeqCst);
        assert!(!liveness.is_down(&a));
        assert!(liveness.is_down(&b), "never seen for 30 s");

        liveness.track(&[a.clone(), b.clone()]);
        assert!(
            !liveness.is_down(&b),
            "newly tracked hub gets the full delay"
        );
        clock.fetch_add(30_000, Ordering::SeqCst);
        assert!(liveness.is_down(&a));
        assert!(liveness.is_down(&b));
        liveness.alive(&a);
        assert!(!liveness.is_down(&a));

        liveness.track(std::slice::from_ref(&a));
        assert!(liveness.is_down(&b), "forgotten hub falls back to creation");
    }

    #[test]
    fn ping_interval_fits_short_failover() {
        assert_eq!(ping_interval(Duration::from_secs(30)), PING_INTERVAL);
        assert_eq!(ping_interval(Duration::from_secs(300)), PING_INTERVAL);
        assert_eq!(
            ping_interval(Duration::from_secs(3)),
            Duration::from_secs(1)
        );
    }
}
