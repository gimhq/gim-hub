//! Firebase Cloud Messaging, HTTP v1 API with a service account.

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use ring::signature::RsaKeyPair;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    config::FcmConfig,
    encode_within,
    http::{HttpClient, HttpRequest, HttpResponse},
    jwt, PushError, PushNotification, PushProvider, Registration,
};

/// Largest FCM `data` payload (keys plus values), in bytes.
pub const FCM_MAX_DATA: usize = 4000;
/// The `data` key holding the contract payload as a JSON string.
pub const DATA_KEY: &str = "gim";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Refresh access tokens this long before they expire.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);

/// The fields of a Google service account JSON key file used here.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    #[serde(default)]
    pub project_id: Option<String>,
}

/// FCM provider.
pub struct FcmProvider {
    project_id: String,
    client_email: String,
    token_uri: String,
    key: RsaKeyPair,
    http: Arc<dyn HttpClient>,
    access_token: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl FcmProvider {
    /// Loads the service account named by `config`.
    pub fn new(config: &FcmConfig, http: Arc<dyn HttpClient>) -> Result<Self, String> {
        let path = &config.service_account_path;
        let json = std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let account: ServiceAccount = serde_json::from_str(&json)
            .map_err(|err| format!("invalid service account {}: {err}", path.display()))?;
        Self::from_account(account, config.project_id.clone(), http)
    }

    /// A provider for `account`; `project_id` defaults to the account's.
    pub fn from_account(
        account: ServiceAccount,
        project_id: Option<String>,
        http: Arc<dyn HttpClient>,
    ) -> Result<Self, String> {
        let project_id = project_id
            .or(account.project_id)
            .ok_or("FCM project id is not configured")?;
        Ok(Self {
            project_id,
            client_email: account.client_email,
            token_uri: account.token_uri,
            key: jwt::rs256_key(&jwt::pem_to_der(&account.private_key)?)?,
            http,
            access_token: tokio::sync::Mutex::new(None),
        })
    }

    /// The OAuth token request (JWT bearer grant) issued at `iat`.
    pub fn token_request(&self, iat: u64) -> Result<HttpRequest, String> {
        let assertion = jwt::sign_rs256(
            &self.key,
            &json!({ "alg": "RS256", "typ": "JWT" }),
            &json!({
                "iss": self.client_email,
                "scope": SCOPE,
                "aud": self.token_uri,
                "iat": iat,
                "exp": iat + 3600,
            }),
        )?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", GRANT_TYPE)
            .append_pair("assertion", &assertion)
            .finish();
        Ok(HttpRequest {
            url: self.token_uri.clone(),
            headers: vec![("content-type", "application/x-www-form-urlencoded".into())],
            body: body.into_bytes(),
        })
    }

    async fn access_token(&self) -> Result<String, PushError> {
        let mut cached = self.access_token.lock().await;
        if let Some((token, expires)) = cached.as_ref() {
            if Instant::now() + TOKEN_MARGIN < *expires {
                return Ok(token.clone());
            }
        }
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let request = self.token_request(iat).map_err(PushError::Permanent)?;
        let response = self
            .http
            .post(request)
            .await
            .map_err(PushError::Retryable)?;
        if response.status != 200 {
            return Err(PushError::Retryable(format!(
                "FCM OAuth token request failed with {}",
                response.status
            )));
        }
        let body: Value = serde_json::from_slice(&response.body)
            .map_err(|err| PushError::Retryable(format!("FCM OAuth response: {err}")))?;
        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| PushError::Retryable("FCM OAuth response has no token".into()))?
            .to_owned();
        let lifetime = Duration::from_secs(body["expires_in"].as_u64().unwrap_or(3600));
        *cached = Some((token.clone(), Instant::now() + lifetime));
        Ok(token)
    }

    /// The `messages:send` request delivering `notification`.
    pub fn request(
        &self,
        registration: &Registration,
        notification: &PushNotification,
        access_token: &str,
    ) -> HttpRequest {
        let payload = data_payload(notification);
        let priority = if notification.kind.is_alert() {
            "HIGH"
        } else {
            "NORMAL"
        };
        let body = json!({
            "message": {
                "token": registration.token,
                "data": { DATA_KEY: payload },
                "android": {
                    "priority": priority,
                    "collapse_key": notification.collapse_id(),
                },
            }
        });
        HttpRequest {
            url: format!(
                "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                self.project_id
            ),
            headers: vec![
                ("authorization", format!("Bearer {access_token}")),
                ("content-type", "application/json; charset=UTF-8".into()),
            ],
            body: serde_json::to_vec(&body).unwrap_or_default(),
        }
    }
}

/// The contract payload as the JSON string carried in `data.gim`, with the
/// MLS message inlined only if `data` stays within [`FCM_MAX_DATA`].
pub fn data_payload(notification: &PushNotification) -> String {
    let limit = FCM_MAX_DATA - DATA_KEY.len();
    let (bytes, _) = encode_within(notification, limit, |payload| {
        serde_json::to_vec(&payload).unwrap_or_default()
    });
    String::from_utf8(bytes).unwrap_or_default()
}

/// Maps an FCM response to the error classes, using the `errorCode` of the
/// error details (falling back to the error status).
fn classify(response: &HttpResponse) -> Result<(), PushError> {
    let body: Value = serde_json::from_slice(&response.body).unwrap_or_default();
    let code = body["error"]["details"]
        .as_array()
        .and_then(|details| details.iter().find_map(|d| d["errorCode"].as_str()))
        .or_else(|| body["error"]["status"].as_str())
        .unwrap_or_default();
    let detail = format!("FCM {}: {code}", response.status);
    match (response.status, code) {
        (200, _) => Ok(()),
        (404, _) | (_, "UNREGISTERED" | "SENDER_ID_MISMATCH") => {
            Err(PushError::InvalidToken(detail))
        }
        (401 | 429 | 500..=599, _) => Err(PushError::Retryable(detail)),
        _ => Err(PushError::Permanent(detail)),
    }
}

#[async_trait]
impl PushProvider for FcmProvider {
    fn name(&self) -> &'static str {
        "fcm"
    }

    async fn send(
        &self,
        registration: &Registration,
        notification: &PushNotification,
    ) -> Result<(), PushError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .post(self.request(registration, notification, &token))
            .await
            .map_err(PushError::Retryable)?;
        if response.status == 401 {
            *self.access_token.lock().await = None;
        }
        classify(&response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ring::signature::{KeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

    use super::*;
    use crate::{jwt::tests::decode, payload::sample};

    /// Throwaway RSA key generated for these tests only.
    const TEST_KEY: &str = include_str!("../testdata/test-rsa-key.pem");

    /// Answers the OAuth request, then `status` for sends; records requests.
    struct FakeHttp {
        status: u16,
        requests: Mutex<Vec<HttpRequest>>,
    }

    #[async_trait]
    impl HttpClient for FakeHttp {
        async fn post(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            let is_oauth = request.url.contains("oauth2");
            self.requests.lock().unwrap().push(request);
            Ok(if is_oauth {
                HttpResponse {
                    status: 200,
                    body: br#"{"access_token":"ya29.test","expires_in":3599}"#.to_vec(),
                }
            } else {
                HttpResponse {
                    status: self.status,
                    body: if self.status < 500 {
                        br#"{"error":{"details":[{"errorCode":"UNREGISTERED"}]}}"#.to_vec()
                    } else {
                        Vec::new()
                    },
                }
            })
        }
    }

    fn account() -> ServiceAccount {
        ServiceAccount {
            client_email: "push@example-project.iam.gserviceaccount.com".into(),
            private_key: TEST_KEY.into(),
            token_uri: "https://oauth2.googleapis.com/token".into(),
            project_id: Some("example-project".into()),
        }
    }

    fn provider(status: u16) -> (FcmProvider, Arc<FakeHttp>) {
        let http = Arc::new(FakeHttp {
            status,
            requests: Mutex::new(Vec::new()),
        });
        (
            FcmProvider::from_account(account(), None, http.clone()).unwrap(),
            http,
        )
    }

    fn registration() -> Registration {
        Registration {
            user_id: "u2".into(),
            device_id: "d1".into(),
            provider: "fcm".into(),
            token: "fcm-token:APA91b".into(),
            app_id: None,
            sandbox: false,
            updated_at: 0,
        }
    }

    #[test]
    fn token_request_is_a_signed_jwt_bearer_grant() {
        let (p, _) = provider(200);
        let request = p.token_request(1_760_479_200).unwrap();
        assert_eq!(request.url, "https://oauth2.googleapis.com/token");
        assert_eq!(
            request.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect();
        assert_eq!(form[0], ("grant_type".into(), GRANT_TYPE.into()));
        assert_eq!(form[1].0, "assertion");
        let (header, claims, input, signature) = decode(&form[1].1);
        assert_eq!(header, json!({"alg": "RS256", "typ": "JWT"}));
        assert_eq!(
            claims,
            json!({
                "iss": "push@example-project.iam.gserviceaccount.com",
                "scope": SCOPE,
                "aud": "https://oauth2.googleapis.com/token",
                "iat": 1_760_479_200,
                "exp": 1_760_482_800,
            })
        );
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, p.key.public_key().as_ref())
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn send_request_is_data_only_high_priority() {
        let (p, _) = provider(200);
        let request = p.request(&registration(), &sample(8), "ya29.test");
        assert_eq!(
            request.url,
            "https://fcm.googleapis.com/v1/projects/example-project/messages:send"
        );
        assert_eq!(request.header("authorization"), Some("Bearer ya29.test"));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body,
            json!({
                "message": {
                    "token": "fcm-token:APA91b",
                    "data": { "gim": sample(8).payload(true).to_string() },
                    "android": { "priority": "HIGH", "collapse_key": "m7" },
                }
            })
        );
    }

    #[test]
    fn data_respects_the_limit() {
        let fits = data_payload(&sample(3700));
        assert!(fits.contains("mls_message"));
        let omitted = data_payload(&sample(3990));
        assert!(!omitted.contains("mls_message"));
        assert!(DATA_KEY.len() + omitted.len() <= FCM_MAX_DATA);
    }

    #[tokio::test]
    async fn send_fetches_token_once_and_classifies() {
        let (p, http) = provider(200);
        p.send(&registration(), &sample(0)).await.unwrap();
        p.send(&registration(), &sample(0)).await.unwrap();
        let urls: Vec<String> = http
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.url.clone())
            .collect();
        assert_eq!(urls.len(), 3);
        assert!(urls[0].contains("oauth2"));

        let (p, _) = provider(404);
        assert!(matches!(
            p.send(&registration(), &sample(0)).await,
            Err(PushError::InvalidToken(_))
        ));
        let (p, _) = provider(503);
        assert!(matches!(
            p.send(&registration(), &sample(0)).await,
            Err(PushError::Retryable(_))
        ));
        let (p, _) = provider(400);
        assert!(matches!(
            p.send(&registration(), &sample(0)).await,
            Err(PushError::InvalidToken(_))
        ));
    }
}
