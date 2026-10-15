//! UnifiedPush: POST the payload to the endpoint URL registered as token.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    encode_within,
    http::{HttpClient, HttpRequest, HttpResponse},
    PushError, PushNotification, PushProvider, Registration,
};

/// Largest UnifiedPush message body, in bytes.
pub const UNIFIEDPUSH_MAX_BODY: usize = 4096;
/// Seconds a push server keeps an undelivered message.
const TTL_SECS: &str = "86400";

/// UnifiedPush provider.
pub struct UnifiedPushProvider {
    http: Arc<dyn HttpClient>,
}

impl UnifiedPushProvider {
    pub fn new(http: Arc<dyn HttpClient>) -> Self {
        Self { http }
    }
}

/// Whether `id` is a valid Web Push `Topic` (at most 32 base64url chars).
fn is_topic(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The request delivering `notification` to the endpoint `registration.token`.
pub fn request(registration: &Registration, notification: &PushNotification) -> HttpRequest {
    let (body, _) = encode_within(notification, UNIFIEDPUSH_MAX_BODY, |payload| {
        serde_json::to_vec(&payload).unwrap_or_default()
    });
    let urgency = if notification.kind.is_alert() {
        "high"
    } else {
        "normal"
    };
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("ttl", TTL_SECS.to_owned()),
        ("urgency", urgency.to_owned()),
    ];
    if is_topic(notification.collapse_id()) {
        headers.push(("topic", notification.collapse_id().to_owned()));
    }
    HttpRequest {
        url: registration.token.clone(),
        headers,
        body,
    }
}

fn classify(response: &HttpResponse) -> Result<(), PushError> {
    let detail = format!("UnifiedPush {}", response.status);
    match response.status {
        200..=299 => Ok(()),
        404 | 410 => Err(PushError::InvalidToken(detail)),
        429 | 500..=599 => Err(PushError::Retryable(detail)),
        _ => Err(PushError::Permanent(detail)),
    }
}

#[async_trait]
impl PushProvider for UnifiedPushProvider {
    fn name(&self) -> &'static str {
        "unifiedpush"
    }

    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError> {
        let response = self
            .http
            .post(request(registration, notification))
            .await
            .map_err(PushError::Retryable)?;
        classify(&response)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::{payload::sample, PushKind};

    fn registration() -> Registration {
        Registration {
            user_id: "u2".into(),
            device_id: "d1".into(),
            provider: "unifiedpush".into(),
            token: "https://push.example.eu/up/abc".into(),
            app_id: None,
            sandbox: false,
            updated_at: 0,
        }
    }

    #[test]
    fn request_posts_payload_to_endpoint() {
        let r = request(&registration(), &sample(8));
        assert_eq!(r.url, "https://push.example.eu/up/abc");
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.header("ttl"), Some("86400"));
        assert_eq!(r.header("urgency"), Some("high"));
        assert_eq!(r.header("topic"), Some("m7"));
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body, sample(8).payload(true));

        let mut n = sample(5000);
        n.kind = PushKind::MemberRemoved;
        n.message_id = "x".repeat(40);
        let r = request(&registration(), &n);
        assert_eq!(r.header("urgency"), Some("normal"));
        assert_eq!(r.header("topic"), None);
        assert!(r.body.len() <= UNIFIEDPUSH_MAX_BODY);
    }

    #[test]
    fn responses_are_classified() {
        let response = |status| HttpResponse {
            status,
            body: Vec::new(),
        };
        assert_eq!(classify(&response(201)), Ok(()));
        assert!(matches!(
            classify(&response(410)),
            Err(PushError::InvalidToken(_))
        ));
        assert!(matches!(
            classify(&response(502)),
            Err(PushError::Retryable(_))
        ));
        assert!(matches!(
            classify(&response(413)),
            Err(PushError::Permanent(_))
        ));
    }
}
