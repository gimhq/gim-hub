//! Push configuration and provider construction.

use std::sync::Arc;

use crate::{
    http::ReqwestClient, LogProvider, PushLog, PushProvider, WebhookConfig, WebhookProvider,
};

/// Push settings (`GIM_HUB_PUSH_*`, see `docs/operations.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushConfig {
    /// Also push `group.member_added` / `group.member_removed` events.
    pub member_events: bool,
    /// Send minimal wake-up payloads only (`GIM_HUB_PUSH_MINIMAL`).
    pub minimal: bool,
    /// Most devices with a queued push; more are dropped.
    pub queue_capacity: usize,
    /// Serve the test-only `GET /v2/debug/push-log`.
    pub log_endpoint: bool,
    /// The push server; when `None`, every push that is not for the `log`
    /// provider is skipped.
    pub webhook: Option<WebhookConfig>,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            member_events: false,
            minimal: false,
            queue_capacity: 10_000,
            log_endpoint: false,
            webhook: None,
        }
    }
}

/// The providers enabled by `config`: always `log` (recording into `log`),
/// plus the webhook (sending as `hub_id`) when configured.
pub fn build_providers(
    config: &PushConfig,
    log: PushLog,
    hub_id: &str,
) -> Result<Vec<Arc<dyn PushProvider>>, String> {
    let mut providers: Vec<Arc<dyn PushProvider>> = vec![Arc::new(LogProvider::new(log))];
    if let Some(webhook) = &config.webhook {
        let http = Arc::new(ReqwestClient::new(webhook.timeout)?);
        providers.push(Arc::new(WebhookProvider::new(webhook, hub_id, http)));
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn names(providers: &[Arc<dyn PushProvider>]) -> Vec<&'static str> {
        providers.iter().map(|p| p.name()).collect()
    }

    #[test]
    fn webhook_is_added_when_configured() {
        let providers = build_providers(&PushConfig::default(), PushLog::default(), "h1").unwrap();
        assert_eq!(names(&providers), ["log"]);
        let config = PushConfig {
            webhook: Some(
                WebhookConfig::new(
                    "http://push:8080/hook",
                    Some(&"s".repeat(32)),
                    Duration::from_secs(10),
                )
                .unwrap(),
            ),
            ..PushConfig::default()
        };
        let providers = build_providers(&config, PushLog::default(), "h1").unwrap();
        assert_eq!(names(&providers), ["log", "webhook"]);
        assert!(providers[1].handles("apns") && providers[1].handles("x.y-z"));
        assert!(!providers[1].handles("log"));
    }
}
