//! Push registration endpoints and log-provider delivery of message pushes.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};
use tower::ServiceExt;

use gim_hub_api::{dto::GID_EXAMPLE, testing::TestHub};
use gim_hub_db::push::{self, Registration};
use gim_hub_push::{Dispatcher, DispatcherSettings, LogProvider, PushLog};

/// RFC 8291 Appendix A user agent public key and authentication secret.
const P256DH: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";

async fn call(
    hub: &TestHub,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = hub
        .router()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn register(hub: &TestHub, token: &str, body: Value) -> (StatusCode, Value) {
    call(
        hub,
        Method::PUT,
        "/v2/push/registration",
        Some(token),
        Some(body),
    )
    .await
}

async fn stored(hub: &TestHub, user_id: &str, device_id: &str) -> Option<Registration> {
    let (user_id, device_id) = (user_id.to_owned(), device_id.to_owned());
    hub.state
        .db
        .read(move |conn| push::get_active(conn, &user_id, &device_id))
        .await
        .unwrap()
}

#[tokio::test]
async fn registration_validates_replaces_and_deletes() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;

    let apns = "AB".repeat(32);
    let (status, _) = register(
        &hub,
        &token,
        json!({ "provider": "apns", "token": apns, "app_id": "im.g.apps", "sandbox": true }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let registration = stored(&hub, "u1", "d1").await.unwrap();
    assert_eq!(registration.provider, "apns");
    assert_eq!(registration.token, "ab".repeat(32));
    assert_eq!(registration.app_id.as_deref(), Some("im.g.apps"));
    assert!(registration.sandbox);

    // One registration per device: a new one replaces it.
    assert_eq!((registration.p256dh, registration.auth), (None, None));
    let (status, _) = register(
        &hub,
        &token,
        json!({
            "provider": "unifiedpush", "token": "https://push.example.eu/up/abc",
            "p256dh": P256DH, "auth": AUTH,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let registration = stored(&hub, "u1", "d1").await.unwrap();
    assert_eq!(registration.provider, "unifiedpush");
    assert!(!registration.sandbox);
    assert_eq!(registration.p256dh.as_ref().map(Vec::len), Some(65));
    assert_eq!(registration.auth.as_ref().map(Vec::len), Some(16));

    let up = "https://push.example.eu/up/abc";
    for body in [
        json!({ "provider": "unifiedpush", "token": up }),
        json!({ "provider": "unifiedpush", "token": up, "p256dh": P256DH }),
        json!({ "provider": "unifiedpush", "token": up, "auth": AUTH }),
        json!({ "provider": "unifiedpush", "token": up, "p256dh": &P256DH[..86], "auth": AUTH }),
        json!({ "provider": "unifiedpush", "token": up, "p256dh": P256DH, "auth": &AUTH[..20] }),
        json!({ "provider": "unifiedpush", "token": up, "p256dh": "!!", "auth": AUTH }),
        json!({ "provider": "apns", "token": "not-hex" }),
        json!({ "provider": "fcm", "token": "short" }),
        json!({ "provider": "unifiedpush", "token": "http://push.example.eu/up" }),
        json!({ "provider": "unifiedpush", "token": "https://127.0.0.1/up" }),
        json!({ "provider": "log", "token": "" }),
        json!({ "provider": "smoke", "token": "x" }),
        json!({ "token": "x" }),
    ] {
        let (status, error) = register(&hub, &token, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(error["error"]["code"], "validation_failed");
    }
    assert_eq!(
        stored(&hub, "u1", "d1").await.unwrap().provider,
        "unifiedpush"
    );

    for _ in 0..2 {
        let (status, _) = call(
            &hub,
            Method::DELETE,
            "/v2/push/registration",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    assert!(stored(&hub, "u1", "d1").await.is_none());
}

#[tokio::test]
async fn webpush_keys_are_ignored_for_other_providers() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let (status, _) = register(
        &hub,
        &token,
        json!({ "provider": "log", "token": "t", "p256dh": "bad", "auth": AUTH }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let registration = stored(&hub, "u1", "d1").await.unwrap();
    assert_eq!((registration.p256dh, registration.auth), (None, None));
}

#[tokio::test]
async fn registration_requires_auth() {
    let hub = TestHub::new();
    let body = json!({ "provider": "log", "token": "t" });
    for (method, body) in [(Method::PUT, Some(body)), (Method::DELETE, None)] {
        let (status, error) = call(&hub, method, "/v2/push/registration", None, body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error["error"]["code"], "unauthorized");
        let (status, _) = call(
            &hub,
            Method::PUT,
            "/v2/push/registration",
            Some("bogus"),
            body,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

/// The sender's side of an MLS group with group ID `gid`.
struct MlsSender {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl MlsSender {
    fn new(gid: &str) -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(gid.as_bytes()),
            credential,
        )
        .unwrap();
        Self {
            provider,
            signer,
            group,
        }
    }

    fn application(&mut self, text: &[u8]) -> Vec<u8> {
        self.group
            .create_message(&self.provider, &self.signer, text)
            .unwrap()
            .to_bytes()
            .unwrap()
    }
}

async fn seed_group(hub: &TestHub, gid: &str, members: &[(&str, &str)]) {
    let gid = gid.to_owned();
    let members: Vec<(String, String)> = members
        .iter()
        .map(|(u, d)| ((*u).to_owned(), (*d).to_owned()))
        .collect();
    hub.state
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO groups (gid, kind, epoch, created_by_user_id, created_by_device_id, \
                 created_at) VALUES (?1, 'group', 0, 'u1', 'd1', 0)",
                [gid.as_str()],
            )
            .map_err(gim_hub_db::DbError::from)?;
            for (user_id, device_id) in &members {
                tx.execute(
                    "INSERT INTO group_members (gid, user_id, device_id, added_at) \
                     VALUES (?1, ?2, ?3, 0)",
                    [gid.as_str(), user_id, device_id],
                )
                .map_err(gim_hub_db::DbError::from)?;
            }
            Ok::<_, gim_hub_db::DbError>(())
        })
        .await
        .unwrap();
}

async fn send_message(hub: &TestHub, token: &str, client_id: &str, mls: &[u8]) -> Value {
    let (status, message) = call(
        hub,
        Method::POST,
        &format!("/v2/groups/{}/messages", GID_EXAMPLE.replace('/', "%2F")),
        Some(token),
        Some(json!({ "client_id": client_id, "mls_message": STANDARD.encode(mls) })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    message
}

async fn message_id(hub: &TestHub, seq: i64) -> String {
    hub.state
        .db
        .read(move |conn| push::message_id_at(conn, GID_EXAMPLE, seq))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn messages_push_to_other_members_with_inline_payload_by_size() {
    let mut hub = TestHub::new();
    let alice = hub.create_session("u1", "d1").await;
    let bob = hub.create_session("u2", "d1").await;
    let _carol = hub.create_session("u3", "d1").await;
    seed_group(
        &hub,
        GID_EXAMPLE,
        &[("u1", "d1"), ("u2", "d1"), ("u3", "d1")],
    )
    .await;
    for token in [&alice, &bob] {
        let (status, _) = register(
            &hub,
            token,
            json!({ "provider": "log", "token": "log-token" }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let mut mls = MlsSender::new(GID_EXAMPLE);

    // Small message: inlined. Carol has no registration; Alice is the sender.
    let small = mls.application(b"hi");
    let message = send_message(&hub, &alice, "c1", &small).await;
    assert_eq!(hub.deliver_pushes().await, 1);
    let log = hub.state.push.log().recent(None);
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].user_id.as_str(), log[0].device_id.as_str()),
        ("u2", "d1")
    );
    let id = message_id(&hub, 1).await;
    assert_eq!(
        log[0].payload,
        json!({
            "v": 1,
            "type": "message",
            "gid": GID_EXAMPLE,
            "seq": 1,
            "message_id": id,
            "collapse_id": id,
            "mls_message": message["mls_message"],
        })
    );

    // Large message: omitted, the client fetches by (gid, seq).
    let large = mls.application(&[7u8; 5000]);
    send_message(&hub, &alice, "c2", &large).await;
    assert_eq!(hub.deliver_pushes().await, 1);
    let last = hub.state.push.log().recent(Some("d1")).pop().unwrap();
    assert_eq!(last.payload["seq"], 2);
    assert_eq!(last.payload["message_id"], message_id(&hub, 2).await);
    assert!(last.payload.get("mls_message").is_none());

    // The debug endpoint is off by default and test-only when enabled.
    let (status, _) = call(
        &hub,
        Method::GET,
        "/v2/debug/push-log?device_id=d1",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let mut config = (*hub.state.config).clone();
    config.push.log_endpoint = true;
    hub.state.config = Arc::new(config);
    let (status, body) = call(
        &hub,
        Method::GET,
        "/v2/debug/push-log?device_id=d1",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let notifications = body["notifications"].as_array().unwrap();
    assert_eq!(notifications.len(), 2);
    assert_eq!(notifications[0]["payload"], log[0].payload);
    let (_, body) = call(
        &hub,
        Method::GET,
        "/v2/debug/push-log?device_id=d9",
        None,
        None,
    )
    .await;
    assert_eq!(body["notifications"], json!([]));
}

#[tokio::test]
async fn minimal_mode_pushes_only_wake_ups() {
    let mut hub = TestHub::new();
    let log = PushLog::default();
    hub.state.push = Dispatcher::new(
        hub.state.db.clone(),
        vec![Arc::new(LogProvider::new(log.clone()))],
        log.clone(),
        DispatcherSettings {
            minimal: true,
            ..DispatcherSettings::default()
        },
        0,
    );
    let alice = hub.create_session("u1", "d1").await;
    let bob = hub.create_session("u2", "d1").await;
    seed_group(&hub, GID_EXAMPLE, &[("u1", "d1"), ("u2", "d1")]).await;
    let (status, _) = register(&hub, &bob, json!({ "provider": "log", "token": "t" })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let mut mls = MlsSender::new(GID_EXAMPLE);
    send_message(&hub, &alice, "c1", &mls.application(b"hi")).await;
    assert_eq!(hub.deliver_pushes().await, 1);
    let pushes = log.recent(Some("d1"));
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        pushes[0].payload,
        json!({ "v": 1, "type": "wake", "collapse_id": message_id(&hub, 1).await })
    );
}
