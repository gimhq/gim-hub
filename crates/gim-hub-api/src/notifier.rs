//! Per-device wake-ups for long-poll and WebSocket delivery.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use tokio::sync::watch;

type DeviceKey = (String, String);

/// Wakes waiters of a device after new events were committed for it.
///
/// Subscribe before reading events, then wait on the receiver's `changed()`:
/// a notification sent in between is not lost.
#[derive(Clone, Default)]
pub struct Notifier {
    devices: Arc<Mutex<HashMap<DeviceKey, watch::Sender<()>>>>,
}

impl Notifier {
    /// Subscribes to wake-ups of one device.
    pub fn subscribe(&self, user_id: &str, device_id: &str) -> watch::Receiver<()> {
        let mut devices = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        devices
            .entry((user_id.to_owned(), device_id.to_owned()))
            .or_insert_with(|| watch::channel(()).0)
            .subscribe()
    }

    /// Wakes every current subscriber of one device.
    pub fn notify(&self, user_id: &str, device_id: &str) {
        let mut devices = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (user_id.to_owned(), device_id.to_owned());
        if let Some(sender) = devices.get(&key) {
            if sender.receiver_count() == 0 {
                devices.remove(&key);
            } else {
                sender.send_replace(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn notify_wakes_only_that_device() {
        let notifier = Notifier::default();
        let mut d1 = notifier.subscribe("u1", "d1");
        let d2 = notifier.subscribe("u1", "d2");
        notifier.notify("u1", "d1");
        tokio::time::timeout(Duration::from_secs(1), d1.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(!d2.has_changed().unwrap());
    }

    #[test]
    fn idle_devices_are_dropped() {
        let notifier = Notifier::default();
        drop(notifier.subscribe("u1", "d1"));
        notifier.notify("u1", "d1");
        assert!(notifier.devices.lock().unwrap().is_empty());
    }
}
