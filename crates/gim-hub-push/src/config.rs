//! Push configuration and provider construction.

use std::{path::PathBuf, sync::Arc};

use crate::{
    apns::ApnsProvider,
    fcm::FcmProvider,
    http::{HttpClient, ReqwestClient},
    unifiedpush::UnifiedPushProvider,
    LogProvider, PushLog, PushProvider,
};

/// APNs token-based authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsConfig {
    /// Apple developer team ID (JWT `iss`).
    pub team_id: String,
    /// ID of the `.p8` key (JWT `kid`).
    pub key_id: String,
    /// Path of the `.p8` key.
    pub key_path: PathBuf,
    /// Default `apns-topic` (app bundle ID) when a registration has no
    /// `app_id`.
    pub topic: String,
    /// Send every push through the sandbox environment.
    pub sandbox: bool,
}

/// FCM HTTP v1 authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcmConfig {
    /// Path of the service account JSON key.
    pub service_account_path: PathBuf,
    /// Firebase project ID; defaults to the service account's.
    pub project_id: Option<String>,
}

/// Push settings (`GIM_HUB_PUSH_*`, see `docs/operations.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushConfig {
    /// Also push `group.member_added` / `group.member_removed` events.
    pub member_events: bool,
    /// Most devices with a queued push; more are dropped.
    pub queue_capacity: usize,
    /// Serve the test-only `GET /v2/debug/push-log`.
    pub log_endpoint: bool,
    /// APNs; inert (sends skipped) when `None`.
    pub apns: Option<ApnsConfig>,
    /// FCM; inert (sends skipped) when `None`.
    pub fcm: Option<FcmConfig>,
    /// Deliver to UnifiedPush endpoints; inert (sends skipped) when off.
    pub unifiedpush: bool,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            member_events: false,
            queue_capacity: 10_000,
            log_endpoint: false,
            apns: None,
            fcm: None,
            unifiedpush: false,
        }
    }
}

/// The providers enabled by `config`: always `log` (recording into `log`),
/// plus APNs, FCM and UnifiedPush when configured. Fails on unreadable or
/// invalid credentials.
pub fn build_providers(
    config: &PushConfig,
    log: PushLog,
) -> Result<Vec<Arc<dyn PushProvider>>, String> {
    let mut providers: Vec<Arc<dyn PushProvider>> = vec![Arc::new(LogProvider::new(log))];
    if config.apns.is_none() && config.fcm.is_none() && !config.unifiedpush {
        return Ok(providers);
    }
    let http: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new()?);
    if let Some(apns) = &config.apns {
        providers.push(Arc::new(ApnsProvider::new(apns.clone(), http.clone())?));
    }
    if let Some(fcm) = &config.fcm {
        providers.push(Arc::new(FcmProvider::new(fcm, http.clone())?));
    }
    if config.unifiedpush {
        providers.push(Arc::new(UnifiedPushProvider::new(Arc::new(
            ReqwestClient::public_only()?,
        ))));
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::tests::p256_pem;

    fn names(providers: &[Arc<dyn PushProvider>]) -> Vec<&'static str> {
        providers.iter().map(|p| p.name()).collect()
    }

    #[test]
    fn only_log_by_default() {
        let providers = build_providers(&PushConfig::default(), PushLog::default()).unwrap();
        assert_eq!(names(&providers), ["log"]);
    }

    #[test]
    fn configured_providers_load_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("AuthKey.p8");
        std::fs::write(&key_path, p256_pem()).unwrap();
        let account_path = dir.path().join("service-account.json");
        let account = serde_json::json!({
            "client_email": "push@example-project.iam.gserviceaccount.com",
            "private_key": include_str!("../testdata/test-rsa-key.pem"),
            "token_uri": "https://oauth2.googleapis.com/token",
            "project_id": "example-project",
        });
        std::fs::write(&account_path, account.to_string()).unwrap();
        let mut config = PushConfig {
            apns: Some(ApnsConfig {
                team_id: "TEAM123456".into(),
                key_id: "KEY1234567".into(),
                key_path: key_path.clone(),
                topic: "im.g.apps".into(),
                sandbox: true,
            }),
            fcm: Some(FcmConfig {
                service_account_path: account_path,
                project_id: None,
            }),
            unifiedpush: true,
            ..PushConfig::default()
        };
        let providers = build_providers(&config, PushLog::default()).unwrap();
        assert_eq!(names(&providers), ["log", "apns", "fcm", "unifiedpush"]);

        std::fs::write(&key_path, "not a key").unwrap();
        assert!(build_providers(&config, PushLog::default()).is_err());
        config.apns = None;
        config.fcm.as_mut().unwrap().service_account_path = dir.path().join("missing.json");
        assert!(build_providers(&config, PushLog::default()).is_err());
    }
}
