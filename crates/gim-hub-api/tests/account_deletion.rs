//! DELETE /v2/users/{user_id}: account deletion with a root-signed request.

mod identity_support;

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use gim_hub_api::testing::{TestHub, TEST_NOW};
use gim_hub_identity::ROOT_REQUEST_CONTEXT;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use identity_support::{code, device_id, device_list, key, put_device_list, send, user_id};

/// Sends DELETE `path` signed by `root` at `timestamp_ms`.
async fn signed_delete(
    hub: &TestHub,
    root: &SigningKey,
    path: &str,
    timestamp_ms: i64,
) -> (StatusCode, Value) {
    let tbs = format!(
        "DELETE\n{path}\n{timestamp_ms}\n{}",
        hex::encode(Sha256::digest(b""))
    );
    let message = [ROOT_REQUEST_CONTEXT, &[0], tbs.as_bytes()].concat();
    let signature = root.sign(&message).to_bytes();
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(path)
        .header(
            "gim-key",
            URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()),
        )
        .header("gim-timestamp", timestamp_ms.to_string())
        .header("gim-signature", URL_SAFE_NO_PAD.encode(signature))
        .body(Body::empty())
        .unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

#[tokio::test]
async fn a_root_signed_request_deletes_the_account() {
    let hub = TestHub::new();
    let user = user_id(1);
    let (status, _) = put_device_list(&hub, &user, &device_list(1, 1, &[11], &[])).await;
    assert_eq!(status, StatusCode::CREATED);
    let token = hub.create_session(&user, &device_id(11)).await;
    let (status, _) = send(
        &hub,
        Method::PUT,
        &format!("/v2/users/{user}/recovery-backup"),
        Some(&token),
        Some(json!({ "backup": "AQID" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let path = format!("/v2/users/{user}");
    let (status, body) = signed_delete(&hub, &key(1), &path, TEST_NOW).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Gone: the public lookups, the backup and the session.
    let (status, _) = send(&hub, Method::GET, &path, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &hub,
        Method::GET,
        &format!("{path}/recovery-backup"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&hub, Method::GET, "/v2/me", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A replay finds nothing left.
    let (status, body) = signed_delete(&hub, &key(1), &path, TEST_NOW).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
}

#[tokio::test]
async fn only_the_users_root_key_within_the_window_deletes() {
    let hub = TestHub::new();
    let user = user_id(1);
    put_device_list(&hub, &user, &device_list(1, 1, &[11], &[])).await;
    let path = format!("/v2/users/{user}");

    // Another user's key, signing this path.
    let (status, body) = signed_delete(&hub, &key(2), &path, TEST_NOW).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "forbidden");
    // Too old, too far ahead.
    for at in [TEST_NOW - 5 * 60 * 1000 - 1, TEST_NOW + 5 * 60 * 1000 + 1] {
        let (status, body) = signed_delete(&hub, &key(1), &path, at).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code(&body), "invalid_signature");
    }
    // Signed for another path, or not signed at all.
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(&path)
        .body(Body::empty())
        .unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (status, _) = send(&hub, Method::GET, &path, None, None).await;
    assert_eq!(status, StatusCode::OK);
}
