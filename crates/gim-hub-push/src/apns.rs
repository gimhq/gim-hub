//! Apple Push Notification service, token-based (`.p8` key, ES256 JWT).

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use ring::signature::EcdsaKeyPair;
use serde_json::{json, Value};

use crate::{
    config::ApnsConfig,
    encode_within,
    http::{HttpClient, HttpRequest, HttpResponse},
    jwt, PushError, PushNotification, PushProvider, Registration,
};

/// Largest APNs payload (whole JSON body), in bytes.
pub const APNS_MAX_PAYLOAD: usize = 4096;
const PRODUCTION_HOST: &str = "https://api.push.apple.com";
const SANDBOX_HOST: &str = "https://api.sandbox.push.apple.com";
/// Provider tokens are valid for an hour and must not be refreshed more than
/// every 20 minutes; reuse one for 50.
const TOKEN_REUSE_SECS: u64 = 50 * 60;

/// APNs provider.
pub struct ApnsProvider {
    config: ApnsConfig,
    key: EcdsaKeyPair,
    http: Arc<dyn HttpClient>,
    /// Cached provider token and its `iat`.
    token: Mutex<Option<(String, u64)>>,
}

impl ApnsProvider {
    /// Loads the `.p8` key named by `config`.
    pub fn new(config: ApnsConfig, http: Arc<dyn HttpClient>) -> Result<Self, String> {
        let pem = std::fs::read_to_string(&config.key_path)
            .map_err(|err| format!("cannot read {}: {err}", config.key_path.display()))?;
        Self::from_pem(config, &pem, http)
    }

    /// A provider with the `.p8` key `pem`.
    pub fn from_pem(
        config: ApnsConfig,
        pem: &str,
        http: Arc<dyn HttpClient>,
    ) -> Result<Self, String> {
        let key = jwt::es256_key(&jwt::pem_to_der(pem)?)?;
        Ok(Self {
            config,
            key,
            http,
            token: Mutex::new(None),
        })
    }

    /// Provider token (JWT) issued at `iat` (seconds since the Unix epoch).
    pub fn provider_token(&self, iat: u64) -> Result<String, String> {
        jwt::sign_es256(
            &self.key,
            &json!({ "alg": "ES256", "kid": self.config.key_id }),
            &json!({ "iss": self.config.team_id, "iat": iat }),
        )
    }

    fn cached_token(&self) -> Result<String, PushError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut cached = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((token, iat)) = cached.as_ref() {
            if now.saturating_sub(*iat) < TOKEN_REUSE_SECS {
                return Ok(token.clone());
            }
        }
        let token = self.provider_token(now).map_err(PushError::Permanent)?;
        *cached = Some((token.clone(), now));
        Ok(token)
    }

    /// The request delivering `notification` to `registration`.
    pub fn request(
        &self,
        registration: &Registration,
        notification: &PushNotification,
        provider_token: &str,
    ) -> HttpRequest {
        let host = if self.config.sandbox || registration.sandbox {
            SANDBOX_HOST
        } else {
            PRODUCTION_HOST
        };
        let topic = registration
            .app_id
            .clone()
            .unwrap_or_else(|| self.config.topic.clone());
        let alert = notification.kind.is_alert();
        HttpRequest {
            url: format!("{host}/3/device/{}", registration.token),
            headers: vec![
                ("authorization", format!("bearer {provider_token}")),
                ("apns-topic", topic),
                (
                    "apns-push-type",
                    if alert { "alert" } else { "background" }.into(),
                ),
                ("apns-priority", if alert { "10" } else { "5" }.into()),
                ("apns-collapse-id", notification.collapse_id().to_owned()),
                ("content-type", "application/json".into()),
            ],
            body: body(notification),
        }
    }
}

/// The APNs JSON body: `aps` plus the contract payload under `gim`.
pub fn body(notification: &PushNotification) -> Vec<u8> {
    let aps = if notification.kind.is_alert() {
        json!({
            "alert": {
                "title": "gim",
                "body": if notification.kind == crate::PushKind::Welcome {
                    "New conversation"
                } else {
                    "New message"
                },
            },
            "mutable-content": 1,
        })
    } else {
        json!({ "content-available": 1 })
    };
    encode_within(notification, APNS_MAX_PAYLOAD, |payload| {
        serde_json::to_vec(&json!({ "aps": aps, "gim": payload })).unwrap_or_default()
    })
    .0
}

/// Maps an APNs response to the error classes.
fn classify(response: &HttpResponse) -> Result<(), PushError> {
    let reason = serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| body["reason"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let detail = format!("APNs {}: {reason}", response.status);
    match (response.status, reason.as_str()) {
        (200, _) => Ok(()),
        (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
            Err(PushError::InvalidToken(detail))
        }
        (403, "ExpiredProviderToken" | "InvalidProviderToken") | (429 | 500 | 503, _) => {
            Err(PushError::Retryable(detail))
        }
        _ => Err(PushError::Permanent(detail)),
    }
}

#[async_trait]
impl PushProvider for ApnsProvider {
    fn name(&self) -> &'static str {
        "apns"
    }

    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError> {
        let token = self.cached_token()?;
        let response = self
            .http
            .post(self.request(registration, notification, &token))
            .await
            .map_err(PushError::Retryable)?;
        let result = classify(&response);
        if response.status == 403 {
            // Force a fresh provider token on the retry.
            *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        jwt::tests::{decode, p256_pem},
        payload::sample,
        PushKind,
    };

    struct NoHttp;

    #[async_trait]
    impl HttpClient for NoHttp {
        async fn post(&self, _: HttpRequest) -> Result<HttpResponse, String> {
            Err("no network in tests".into())
        }
    }

    fn provider() -> ApnsProvider {
        let config = ApnsConfig {
            team_id: "TEAM123456".into(),
            key_id: "KEY1234567".into(),
            key_path: PathBuf::from("unused.p8"),
            topic: "im.g.apps".into(),
            sandbox: false,
        };
        ApnsProvider::from_pem(config, &p256_pem(), Arc::new(NoHttp)).unwrap()
    }

    fn registration(sandbox: bool, app_id: Option<&str>) -> Registration {
        Registration {
            user_id: "u2".into(),
            device_id: "d1".into(),
            provider: "apns".into(),
            token: "ab".repeat(32),
            app_id: app_id.map(str::to_owned),
            sandbox,
            p256dh: None,
            auth: None,
            updated_at: 0,
        }
    }

    #[test]
    fn provider_token_claims() {
        let jwt = provider().provider_token(1_760_479_200).unwrap();
        let (header, claims, _, signature) = decode(&jwt);
        assert_eq!(header, json!({"alg": "ES256", "kid": "KEY1234567"}));
        assert_eq!(claims, json!({"iss": "TEAM123456", "iat": 1_760_479_200}));
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn request_headers_and_body() {
        let p = provider();
        let request = p.request(&registration(false, None), &sample(8), "JWT");
        assert_eq!(
            request.url,
            format!("https://api.push.apple.com/3/device/{}", "ab".repeat(32))
        );
        assert_eq!(request.header("authorization"), Some("bearer JWT"));
        assert_eq!(request.header("apns-topic"), Some("im.g.apps"));
        assert_eq!(request.header("apns-push-type"), Some("alert"));
        assert_eq!(request.header("apns-priority"), Some("10"));
        assert_eq!(request.header("apns-collapse-id"), Some("m7"));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body,
            json!({
                "aps": {"alert": {"title": "gim", "body": "New message"}, "mutable-content": 1},
                "gim": sample(8).payload(true),
            })
        );

        let request = p.request(&registration(true, Some("im.g.other")), &sample(0), "JWT");
        assert!(request
            .url
            .starts_with("https://api.sandbox.push.apple.com/3/device/"));
        assert_eq!(request.header("apns-topic"), Some("im.g.other"));
    }

    #[test]
    fn membership_pushes_are_background() {
        let mut n = sample(0);
        n.kind = PushKind::MemberAdded;
        let request = provider().request(&registration(false, None), &n, "JWT");
        assert_eq!(request.header("apns-push-type"), Some("background"));
        assert_eq!(request.header("apns-priority"), Some("5"));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["aps"], json!({"content-available": 1}));
    }

    #[test]
    fn large_messages_are_not_inlined() {
        let body = body(&sample(4000));
        assert!(body.len() <= APNS_MAX_PAYLOAD);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body["gim"].get("mls_message").is_none());
        let body: Value = serde_json::from_slice(&super::body(&sample(3000))).unwrap();
        assert!(body["gim"].get("mls_message").is_some());
    }

    #[test]
    fn responses_are_classified() {
        let response = |status: u16, reason: &str| HttpResponse {
            status,
            body: json!({ "reason": reason }).to_string().into_bytes(),
        };
        assert_eq!(classify(&response(200, "")), Ok(()));
        for (status, reason) in [
            (410, "Unregistered"),
            (400, "BadDeviceToken"),
            (400, "DeviceTokenNotForTopic"),
        ] {
            assert!(matches!(
                classify(&response(status, reason)),
                Err(PushError::InvalidToken(_))
            ));
        }
        for (status, reason) in [
            (403, "ExpiredProviderToken"),
            (429, "TooManyRequests"),
            (503, "ServiceUnavailable"),
        ] {
            assert!(matches!(
                classify(&response(status, reason)),
                Err(PushError::Retryable(_))
            ));
        }
        assert!(matches!(
            classify(&response(400, "PayloadTooLarge")),
            Err(PushError::Permanent(_))
        ));
    }
}
