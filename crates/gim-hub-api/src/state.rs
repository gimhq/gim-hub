//! Shared application state.

use std::{
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use gim_hub_db::Db;

use crate::{config::Config, hub::HubIdentity, notifier::Notifier};

/// State shared by all handlers (cheap to clone).
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    pub hub: HubIdentity,
    pub notifier: Notifier,
    pub clock: Clock,
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
