//! Log-only provider: a structured log line plus an in-memory record.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::{encode_within, PushError, PushNotification, PushProvider, Registration};

/// Payload limit of the log provider (as for APNs), so tests see the same
/// inline/omit decision as real devices.
pub const LOG_MAX_PAYLOAD: usize = 4096;
/// Entries kept by [`PushLog`].
const CAPACITY: usize = 256;

/// A notification recorded by the log provider.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LoggedPush {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
    /// The contract payload as delivered.
    pub payload: Value,
    /// Wall-clock time of the send, ms since the Unix epoch.
    pub sent_at: i64,
}

/// The most recent [`LoggedPush`]es (cheap to clone).
#[derive(Debug, Clone, Default)]
pub struct PushLog {
    entries: Arc<Mutex<VecDeque<LoggedPush>>>,
}

impl PushLog {
    fn record(&self, entry: LoggedPush) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() == CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Recorded pushes, oldest first, optionally of one device ID only.
    pub fn recent(&self, device_id: Option<&str>) -> Vec<LoggedPush> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|entry| device_id.is_none_or(|id| entry.device_id == id))
            .cloned()
            .collect()
    }
}

/// The `log` provider.
pub struct LogProvider {
    log: PushLog,
}

impl LogProvider {
    pub fn new(log: PushLog) -> Self {
        Self { log }
    }
}

#[async_trait]
impl PushProvider for LogProvider {
    fn name(&self) -> &'static str {
        "log"
    }

    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError> {
        let (bytes, inlined) = encode_within(notification, LOG_MAX_PAYLOAD, |payload| {
            serde_json::to_vec(&payload).unwrap_or_default()
        });
        let payload: Value =
            serde_json::from_slice(&bytes).map_err(|err| PushError::Permanent(err.to_string()))?;
        tracing::info!(
            target: "gim_hub_push::log",
            user_id = %registration.user_id,
            device_id = %registration.device_id,
            r#type = notification.kind.as_str(),
            gid = %notification.gid,
            seq = notification.seq,
            message_id = %notification.message_id,
            inlined,
            bytes = bytes.len(),
            "push"
        );
        self.log.record(LoggedPush {
            user_id: registration.user_id.clone(),
            device_id: registration.device_id.clone(),
            token: registration.token.clone(),
            payload,
            sent_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::sample;

    #[tokio::test]
    async fn records_bounded_entries_per_device() {
        let log = PushLog::default();
        let provider = LogProvider::new(log.clone());
        let mut registration = Registration {
            user_id: "u1".into(),
            device_id: "d1".into(),
            provider: "log".into(),
            token: "t".into(),
            app_id: None,
            sandbox: false,
            p256dh: None,
            auth: None,
            updated_at: 0,
        };
        for i in 0..CAPACITY + 1 {
            registration.device_id = if i == 0 { "first" } else { "d1" }.into();
            provider.send(&registration, &sample(4)).await.unwrap();
        }
        assert!(log.recent(Some("first")).is_empty());
        assert_eq!(log.recent(Some("d1")).len(), CAPACITY);
        assert_eq!(log.recent(None)[0].payload, sample(4).payload(true));

        provider.send(&registration, &sample(5000)).await.unwrap();
        let last = log.recent(None).pop().unwrap();
        assert!(last.payload.get("mls_message").is_none());
    }
}
