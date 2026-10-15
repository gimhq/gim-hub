//! Push gateway of the gim hub.
//!
//! The [`Dispatcher`] tails the central event path (the `events` table) and
//! turns `message` and `welcome` events (optionally membership events) into
//! [`PushNotification`]s for every addressed device with an active push
//! registration. A [`PushProvider`] delivers them: `log` (structured log line
//! plus an in-memory [`PushLog`], for tests), `apns`, `fcm` and
//! `unifiedpush` (RFC 8291 encrypted, see [`webpush`]). The payload contract is normative in `docs/push.md`.
//!
//! A push is only a wake-up hint: clients always sync their event stream
//! afterwards, and push failures never affect the request that produced the
//! event.

pub mod apns;
mod config;
mod dispatcher;
pub mod fcm;
pub mod http;
mod jwt;
mod log;
mod payload;
pub mod unifiedpush;
mod validate;
pub mod webpush;

use async_trait::async_trait;

pub use config::{build_providers, ApnsConfig, FcmConfig, PushConfig};
pub use dispatcher::{Dispatcher, DispatcherSettings, MetricsSnapshot, PushGate};
pub use gim_hub_db::push::Registration;
pub use log::{LogProvider, LoggedPush, PushLog, LOG_MAX_PAYLOAD};
pub use payload::{encode_within, PushKind, PushNotification};
pub use validate::{validate_registration, validate_webpush_keys};

/// Why a provider did not deliver a notification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    /// The provider rejected the device token for good; the registration is
    /// deleted.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// Transient failure (network, throttling, provider outage); retried
    /// with backoff.
    #[error("retryable: {0}")]
    Retryable(String),
    /// Any other failure; the notification is dropped.
    #[error("permanent: {0}")]
    Permanent(String),
}

/// A push provider.
#[async_trait]
pub trait PushProvider: Send + Sync {
    /// Provider name as stored in registrations (`apns`, `fcm`,
    /// `unifiedpush`, `log`).
    fn name(&self) -> &'static str;

    /// Delivers `notification` to the device of `registration`.
    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError>;
}
