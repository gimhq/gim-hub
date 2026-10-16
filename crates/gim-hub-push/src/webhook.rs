//! Webhook provider: every push leaves the hub as one signed `POST` to an
//! external push server, which owns platform delivery (`docs/push.md`).

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use serde_json::{json, Value};

use crate::{
    encode_within,
    http::{HttpClient, HttpRequest, HttpResponse},
    PushError, PushNotification, PushProvider, Registration,
};

/// Largest `payload` object (JSON bytes) with `mls_message` inlined, leaving
/// room for the push server's platform envelope.
pub const MAX_PAYLOAD: usize = 3072;
/// `ttl` of every push, seconds.
pub const TTL_SECONDS: u32 = 86_400;
/// Shortest accepted signing secret, bytes.
pub const MIN_SECRET_LEN: usize = 32;
/// Signature header: `t=<unix seconds>,v1=<hex HMAC-SHA256>`.
pub const SIGNATURE_HEADER: &str = "x-gim-signature";
/// Delivery id header, equal to the body's `delivery_id`.
pub const DELIVERY_HEADER: &str = "x-gim-delivery";

/// Push server endpoint (`GIM_HUB_PUSH_WEBHOOK_*`).
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookConfig {
    /// `http` or `https` URL every push is POSTed to.
    pub url: String,
    /// HMAC-SHA256 signing secret, at least [`MIN_SECRET_LEN`] bytes.
    pub secret: String,
    /// Request timeout.
    pub timeout: Duration,
}

impl WebhookConfig {
    /// Validated settings; the error is the reason.
    pub fn new(url: &str, secret: Option<&str>, timeout: Duration) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(url).map_err(|err| format!("invalid URL: {err}"))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err("must be an http or https URL".into());
        }
        let secret = secret.ok_or("GIM_HUB_PUSH_WEBHOOK_SECRET is required with the URL")?;
        if secret.len() < MIN_SECRET_LEN {
            return Err(format!(
                "GIM_HUB_PUSH_WEBHOOK_SECRET must be at least {MIN_SECRET_LEN} bytes"
            ));
        }
        Ok(Self {
            url: url.to_owned(),
            secret: secret.to_owned(),
            timeout,
        })
    }
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &self.url)
            .field("secret", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// `X-Gim-Signature` of `body` sent at `timestamp` (unix seconds):
/// `t=<timestamp>,v1=<lowercase hex HMAC-SHA256(secret, "<timestamp>." || body)>`.
pub fn signature(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(format!("{timestamp}.").as_bytes());
    ctx.update(body);
    format!("t={timestamp},v1={}", hex(ctx.sign().as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The webhook provider: delivers every registration whose provider is not
/// `log`.
pub struct WebhookProvider {
    url: String,
    secret: Vec<u8>,
    hub_id: String,
    http: Arc<dyn HttpClient>,
}

impl WebhookProvider {
    pub fn new(
        config: &WebhookConfig,
        hub_id: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            url: config.url.clone(),
            secret: config.secret.as_bytes().to_vec(),
            hub_id: hub_id.into(),
            http,
        }
    }

    /// The webhook body of a push.
    pub fn body(&self, registration: &Registration, notification: &PushNotification) -> Value {
        let (payload, _) = encode_within(notification, MAX_PAYLOAD, |payload| {
            serde_json::to_vec(&payload).unwrap_or_default()
        });
        let payload: Value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
        let mut target = json!({
            "provider": registration.provider,
            "token": registration.token,
        });
        if let Some(app_id) = &registration.app_id {
            target["app_id"] = json!(app_id);
        }
        if let Some(sandbox) = registration.sandbox {
            target["sandbox"] = json!(sandbox);
        }
        if let Some(p256dh) = &registration.p256dh {
            target["p256dh"] = json!(URL_SAFE_NO_PAD.encode(p256dh));
        }
        if let Some(auth) = &registration.auth {
            target["auth"] = json!(URL_SAFE_NO_PAD.encode(auth));
        }
        json!({
            "v": 1,
            "hub_id": self.hub_id,
            "delivery_id": notification.delivery_id,
            "sent_at": notification.sent_at,
            "registration": target,
            "priority": notification.priority(),
            "collapse_id": notification.collapse_id(),
            "ttl": TTL_SECONDS,
            "payload": payload,
        })
    }

    /// The signed request of a push sent at `timestamp` (unix seconds).
    pub fn request(
        &self,
        registration: &Registration,
        notification: &PushNotification,
        timestamp: u64,
    ) -> HttpRequest {
        let body = serde_json::to_vec(&self.body(registration, notification)).unwrap_or_default();
        HttpRequest {
            url: self.url.clone(),
            headers: vec![
                ("content-type", "application/json".into()),
                (SIGNATURE_HEADER, signature(&self.secret, timestamp, &body)),
                (DELIVERY_HEADER, notification.delivery_id.clone()),
            ],
            body,
        }
    }
}

/// Maps the push server's response to the dispatcher outcome.
fn outcome(response: &HttpResponse) -> Result<(), PushError> {
    let reason = || {
        let body = String::from_utf8_lossy(&response.body);
        format!("push server answered {}: {:.200}", response.status, body)
    };
    match response.status {
        200..=299 => Ok(()),
        404 | 410 => Err(PushError::InvalidToken(reason())),
        429 | 500..=599 => Err(PushError::Retryable(reason(), response.retry_after)),
        _ => Err(PushError::Permanent(reason())),
    }
}

#[async_trait]
impl PushProvider for WebhookProvider {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn handles(&self, provider: &str) -> bool {
        provider != "log"
    }

    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let request = self.request(registration, notification, now);
        let response = self
            .http
            .post(request)
            .await
            .map_err(|err| PushError::Retryable(err, None))?;
        outcome(&response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{payload::sample, PushKind};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn registration() -> Registration {
        Registration {
            user_id: "u1".into(),
            device_id: "d1".into(),
            provider: "apns".into(),
            token: "tok".into(),
            app_id: Some("im.g.apps".into()),
            sandbox: Some(true),
            p256dh: Some(vec![4; 3]),
            auth: None,
            updated_at: 0,
        }
    }

    fn provider() -> WebhookProvider {
        struct Never;
        #[async_trait]
        impl HttpClient for Never {
            async fn post(&self, _: HttpRequest) -> Result<HttpResponse, String> {
                Err("unused".into())
            }
        }
        let config = WebhookConfig::new(
            "http://push:8080/hook",
            Some(SECRET),
            Duration::from_secs(1),
        )
        .unwrap();
        WebhookProvider::new(&config, "h1", Arc::new(Never))
    }

    #[test]
    fn config_requires_http_url_and_long_secret() {
        let t = Duration::from_secs(10);
        assert!(WebhookConfig::new("https://push.example.eu/v1", Some(SECRET), t).is_ok());
        assert!(WebhookConfig::new("ftp://push.example.eu/v1", Some(SECRET), t).is_err());
        assert!(WebhookConfig::new("not a url", Some(SECRET), t).is_err());
        assert!(WebhookConfig::new("http://push:8080", None, t).is_err());
        assert!(WebhookConfig::new("http://push:8080", Some(&SECRET[1..]), t).is_err());
        let debug = format!(
            "{:?}",
            WebhookConfig::new("http://p", Some(SECRET), t).unwrap()
        );
        assert!(!debug.contains(SECRET));
    }

    #[test]
    fn signature_matches_known_vector() {
        // HMAC-SHA256("key", "1.{}"), computed with Python's hmac module.
        assert_eq!(
            signature(b"key", 1, b"{}"),
            "t=1,v1=1ba6b8171186efc613e8bcc0cbdab2748f24984d7c5a84faa2637afa0e40d224"
        );
    }

    #[test]
    fn body_follows_contract() {
        let mut n = sample(4);
        n.delivery_id = "del1".into();
        n.sent_at = 1234;
        let body = provider().body(&registration(), &n);
        assert_eq!(
            body,
            json!({
                "v": 1, "hub_id": "h1", "delivery_id": "del1", "sent_at": 1234,
                "registration": {
                    "provider": "apns", "token": "tok", "app_id": "im.g.apps",
                    "sandbox": true, "p256dh": "BAQE",
                },
                "priority": "high", "collapse_id": "m7", "ttl": 86400,
                "payload": n.payload(true),
            })
        );
        n.kind = PushKind::MemberAdded;
        n.alert = false;
        assert_eq!(provider().body(&registration(), &n)["priority"], "normal");
        let big = provider().body(&registration(), &sample(MAX_PAYLOAD));
        assert!(big["payload"].get("mls_message").is_none());

        let request = provider().request(&registration(), &n, 99);
        assert_eq!(request.header("x-gim-delivery"), Some("del1"));
        assert_eq!(
            request.header("x-gim-signature").unwrap(),
            signature(SECRET.as_bytes(), 99, &request.body)
        );
    }

    #[test]
    fn responses_map_to_outcomes() {
        let response = |status, retry_after| HttpResponse {
            status,
            retry_after,
            body: Vec::new(),
        };
        let retry = Some(Duration::from_secs(3));
        assert_eq!(outcome(&response(204, None)), Ok(()));
        for status in [404, 410] {
            assert!(matches!(
                outcome(&response(status, None)),
                Err(PushError::InvalidToken(_))
            ));
        }
        for status in [429, 500, 503] {
            assert!(matches!(
                outcome(&response(status, retry)),
                Err(PushError::Retryable(_, r)) if r == retry
            ));
        }
        for status in [301, 400, 401, 413] {
            assert!(matches!(
                outcome(&response(status, None)),
                Err(PushError::Permanent(_))
            ));
        }
    }
}
