//! Push gateway of the gim hub.
//!
//! The [`Dispatcher`] tails the central event path (the `events` table) and
//! turns `message` and `welcome` events (optionally membership events) into
//! [`PushNotification`]s for every addressed device with an active push
//! registration. A [`PushProvider`] delivers them: `log` (structured log line
//! plus an in-memory [`PushLog`], for tests) or the [`webhook`] provider,
//! which sends every other registration as one signed webhook to an external
//! push server that owns platform delivery. The contract is normative in
//! `docs/push.md`.
//!
//! A push is only a wake-up hint: clients always sync their event stream
//! afterwards, and push failures never affect the request that produced the
//! event.

use std::time::Duration;

mod config;
mod dispatcher;
pub mod http;
mod log;
mod payload;
mod validate;
pub mod webhook;

use async_trait::async_trait;

pub use config::{build_providers, PushConfig};
pub use dispatcher::{message_id, Dispatcher, DispatcherSettings, MetricsSnapshot, PushGate};
pub use gim_hub_db::push::Registration;
pub use log::{LogProvider, LoggedPush, PushLog, LOG_MAX_PAYLOAD};
pub use payload::{encode_within, PushKind, PushNotification};
pub use validate::{decode_key, validate_registration};
pub use webhook::{WebhookConfig, WebhookProvider};

/// Why a provider did not deliver a notification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    /// The registration is invalid for good; it is deleted.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// Transient failure (network, throttling, push server outage); retried
    /// with backoff, but not before the optional `Retry-After` delay.
    #[error("retryable: {0}")]
    Retryable(String, Option<Duration>),
    /// Any other failure; the notification is dropped.
    #[error("permanent: {0}")]
    Permanent(String),
}

/// A push provider.
#[async_trait]
pub trait PushProvider: Send + Sync {
    /// Name of the provider (for logs).
    fn name(&self) -> &'static str;

    /// Whether this provider delivers registrations of `provider` (the
    /// opaque string stored in the registration).
    fn handles(&self, provider: &str) -> bool {
        provider == self.name()
    }

    /// Delivers `notification` to the device of `registration`.
    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError>;
}
