//! UnifiedPush: POST the payload, encrypted with RFC 8291 Web Push message
//! encryption (`aes128gcm`), to the endpoint URL registered as token.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    encode_within,
    http::{HttpClient, HttpRequest, HttpResponse},
    webpush, PushError, PushNotification, PushProvider, Registration,
};

/// Largest UnifiedPush message body (after encryption), in bytes.
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

/// The request delivering `notification` to the endpoint `registration.token`,
/// encrypted for the registration's `p256dh` and `auth`. The MLS message is
/// inlined only if the encrypted body stays within [`UNIFIEDPUSH_MAX_BODY`].
pub fn request(
    registration: &Registration,
    notification: &PushNotification,
) -> Result<HttpRequest, PushError> {
    let (Some(p256dh), Some(auth)) = (&registration.p256dh, &registration.auth) else {
        return Err(PushError::Permanent(
            "UnifiedPush registration has no p256dh/auth".into(),
        ));
    };
    let limit = UNIFIEDPUSH_MAX_BODY - webpush::OVERHEAD;
    let (plaintext, _) = encode_within(notification, limit, |payload| {
        serde_json::to_vec(&payload).unwrap_or_default()
    });
    let body = webpush::encrypt(p256dh, auth, &plaintext).map_err(PushError::Permanent)?;
    let urgency = if notification.kind.is_alert() {
        "high"
    } else {
        "normal"
    };
    let mut headers = vec![
        ("content-type", "application/octet-stream".to_owned()),
        ("content-encoding", "aes128gcm".to_owned()),
        ("ttl", TTL_SECS.to_owned()),
        ("urgency", urgency.to_owned()),
    ];
    if is_topic(notification.collapse_id()) {
        headers.push(("topic", notification.collapse_id().to_owned()));
    }
    Ok(HttpRequest {
        url: registration.token.clone(),
        headers,
        body,
    })
}

fn classify(response: &HttpResponse) -> Result<(), PushError> {
    let detail = format!("UnifiedPush {}", response.status);
    match response.status {
        200..=299 => Ok(()),
        // Redirects are not followed (the endpoint must be final).
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
            .post(request(registration, notification)?)
            .await
            .map_err(PushError::Retryable)?;
        classify(&response)
    }
}

#[cfg(test)]
mod tests {
    use ring::{
        agreement::{EphemeralPrivateKey, ECDH_P256},
        rand::SystemRandom,
    };
    use serde_json::Value;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{http::ReqwestClient, payload::sample, PushKind};

    /// A registration for `url` with a fresh user agent key.
    fn registration(url: &str) -> (Registration, EphemeralPrivateKey) {
        let ua_private = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()).unwrap();
        let p256dh = ua_private.compute_public_key().unwrap().as_ref().to_vec();
        let registration = Registration {
            user_id: "u2".into(),
            device_id: "d1".into(),
            provider: "unifiedpush".into(),
            token: url.into(),
            app_id: None,
            sandbox: false,
            p256dh: Some(p256dh),
            auth: Some(vec![9; 16]),
            updated_at: 0,
        };
        (registration, ua_private)
    }

    fn decrypt(ua_private: EphemeralPrivateKey, body: &[u8]) -> Value {
        serde_json::from_slice(&webpush::decrypt(ua_private, &[9; 16], body).unwrap()).unwrap()
    }

    #[test]
    fn request_posts_encrypted_payload_to_endpoint() {
        let (reg, ua_private) = registration("https://push.example.eu/up/abc");
        let r = request(&reg, &sample(8)).unwrap();
        assert_eq!(r.url, "https://push.example.eu/up/abc");
        assert_eq!(r.header("content-encoding"), Some("aes128gcm"));
        assert_eq!(r.header("content-type"), Some("application/octet-stream"));
        assert_eq!(r.header("ttl"), Some("86400"));
        assert_eq!(r.header("urgency"), Some("high"));
        assert_eq!(r.header("topic"), Some("m7"));
        assert_eq!(decrypt(ua_private, &r.body), sample(8).payload(true));

        let (reg, _) = registration("https://push.example.eu/up/abc");
        let mut n = sample(5000);
        n.kind = PushKind::MemberRemoved;
        n.message_id = "x".repeat(40);
        let r = request(&reg, &n).unwrap();
        assert_eq!(r.header("urgency"), Some("normal"));
        assert_eq!(r.header("topic"), None);
        assert!(r.body.len() <= UNIFIEDPUSH_MAX_BODY);

        let no_keys = Registration {
            p256dh: None,
            ..reg
        };
        assert!(matches!(
            request(&no_keys, &sample(8)),
            Err(PushError::Permanent(_))
        ));
    }

    #[test]
    fn inlining_accounts_for_encryption_overhead() {
        let plain_len = |mls_len| {
            serde_json::to_vec(&sample(mls_len).payload(true))
                .unwrap()
                .len()
        };
        let fits = (0..4096)
            .rev()
            .find(|&n| plain_len(n) + webpush::OVERHEAD <= UNIFIEDPUSH_MAX_BODY)
            .unwrap();
        for (mls_len, inlined) in [(fits, true), (fits + 1, false)] {
            let (reg, ua_private) = registration("https://push.example.eu/up/abc");
            let r = request(&reg, &sample(mls_len)).unwrap();
            assert!(r.body.len() <= UNIFIEDPUSH_MAX_BODY);
            let payload = decrypt(ua_private, &r.body);
            assert_eq!(payload.get("mls_message").is_some(), inlined, "{mls_len}");
        }
        assert_eq!(
            request(&registration("https://e.eu/").0, &sample(fits))
                .unwrap()
                .body
                .len(),
            UNIFIEDPUSH_MAX_BODY
        );
    }

    /// Accepts one HTTP/1.1 POST and answers 201; returns the raw request
    /// head and body.
    async fn receive_one(listener: TcpListener) -> (String, Vec<u8>) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0; 8192];
        let head_end = loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed early");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8(buf[..head_end].to_vec())
            .unwrap()
            .to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        while buf.len() < head_end + length {
            let n = stream.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        (head, buf[head_end..head_end + length].to_vec())
    }

    #[tokio::test]
    async fn sends_decryptable_body_to_mock_receiver() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/up/abc", listener.local_addr().unwrap());
        let receiver = tokio::spawn(receive_one(listener));
        // The unrestricted client: the mock receiver is on loopback.
        let provider = UnifiedPushProvider::new(Arc::new(ReqwestClient::new().unwrap()));
        let (reg, ua_private) = registration(&url);
        provider.send(&reg, &sample(8)).await.unwrap();
        let (head, body) = receiver.await.unwrap();
        assert!(head.starts_with("post /up/abc "), "{head}");
        assert!(head.contains("content-encoding: aes128gcm\r\n"), "{head}");
        let payload = decrypt(ua_private, &body);
        assert_eq!(payload, sample(8).payload(true));
        assert!(payload.get("sender_user_id").is_none());
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
