//! Shared application state.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use gim_hub_db::Db;
use gim_hub_push::{Dispatcher, DispatcherSettings, LogProvider, PushLog};
use gim_hub_s2s::{DeviceLists, Disabled, Federation, Hosting, OutboxSender};

use crate::{
    config::Config, handlers::IdentityEvents, hub::HubIdentity, notifier::Notifier,
    ratelimit::PublicReadLimits,
};

/// State shared by all handlers (cheap to clone).
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    pub hub: HubIdentity,
    pub notifier: Notifier,
    pub clock: Clock,
    /// Hub-to-hub federation; [`Disabled`] unless `GIM_HUB_FEDERATION=true`.
    pub federation: Arc<dyn Federation>,
    /// Durable S2S outbound queue; [`Disabled`] (a no-op) unless federation
    /// is enabled.
    pub outbox: Arc<dyn OutboxSender>,
    /// Hosting records: local records, the remote cache and resolution.
    pub hosting: Hosting,
    /// DeviceLists of local users and the cache of remote users' lists.
    pub device_lists: DeviceLists,
    /// Push dispatcher. [`AppState::new`] installs one with only the `log`
    /// provider that is not started; the binary replaces it with the
    /// configured providers and starts it.
    pub push: Dispatcher,
    /// Rate limits of the unauthenticated user reads, from the config.
    pub public_reads: PublicReadLimits,
    /// Rate limits of the unauthenticated recovery backup reads.
    pub recovery_reads: PublicReadLimits,
    /// One lock per remote blob being fetched from its origin, so
    /// concurrent downloads fetch it once.
    pub blob_fetches: BlobFetches,
}

/// Per-blob locks of in-flight remote blob fetches, keyed by blob id.
pub type BlobFetches = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

impl AppState {
    /// State with federation disabled.
    pub fn new(db: Db, config: Config, hub: HubIdentity, clock: Clock) -> Self {
        let hosting = Hosting::local(db.clone(), hub.hub_id().clone(), clock.as_now());
        let notifier = Notifier::default();
        let device_lists = DeviceLists::local(
            db.clone(),
            hosting.clone(),
            clock.as_now(),
            Arc::new(IdentityEvents::new(
                db.clone(),
                clock.clone(),
                notifier.clone(),
            )),
        );
        let push_log = PushLog::default();
        let push = Dispatcher::new(
            db.clone(),
            vec![Arc::new(LogProvider::new(push_log.clone()))],
            push_log,
            DispatcherSettings::from(&config.push),
            0,
        );
        let public_reads = PublicReadLimits::new(
            config.public_read_per_ip_per_min,
            config.public_read_per_user_per_min,
            config.trust_forwarded_for,
        );
        let recovery_reads = PublicReadLimits::new(
            config.recovery_read_per_ip_per_min,
            config.recovery_read_per_user_per_min,
            config.trust_forwarded_for,
        );
        Self {
            db,
            config: Arc::new(config),
            hub,
            notifier,
            clock,
            federation: Arc::new(Disabled),
            outbox: Arc::new(Disabled),
            hosting,
            device_lists,
            push,
            public_reads,
            recovery_reads,
            blob_fetches: BlobFetches::default(),
        }
    }
}

/// Source of the current time in milliseconds since the Unix epoch. Tests
/// use a manual clock to control expiry and retention.
#[derive(Debug, Clone, Default)]
pub struct Clock {
    manual: Option<Arc<AtomicI64>>,
}

impl Clock {
    /// The system clock.
    pub fn system() -> Self {
        Self::default()
    }

    /// A clock that stays at `now_ms` until advanced.
    pub fn manual(now_ms: i64) -> Self {
        Self {
            manual: Some(Arc::new(AtomicI64::new(now_ms))),
        }
    }

    /// Current time in milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> i64 {
        match &self.manual {
            Some(now) => now.load(Ordering::Relaxed),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
        }
    }

    /// This clock as a hosting-record time source.
    pub fn as_now(&self) -> gim_hub_s2s::hosting::Now {
        let clock = self.clone();
        Arc::new(move || clock.now_ms())
    }

    /// Moves a manual clock forward by `ms`.
    ///
    /// # Panics
    ///
    /// Panics on the system clock.
    pub fn advance(&self, ms: i64) {
        self.manual
            .as_ref()
            .expect("only a manual clock can be advanced")
            .fetch_add(ms, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let clock = Clock::manual(1_000);
        let copy = clock.clone();
        clock.advance(500);
        assert_eq!(copy.now_ms(), 1_500);
    }

    #[test]
    fn system_clock_is_after_2025() {
        assert!(Clock::system().now_ms() > 1_735_689_600_000);
    }
}
