//! Recovery backups: authenticated store, unauthenticated fetch.

mod identity_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::{TestHub, TEST_NOW};
use serde_json::json;

use identity_support::{b64, code, send};

#[tokio::test]
async fn store_and_fetch() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let uri = "/v2/users/u1/recovery-backup";

    let (status, body) = send(&hub, Method::GET, uri, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");

    let backup = b64(b"ciphertext");
    let (status, body) = send(
        &hub,
        Method::PUT,
        uri,
        Some(&token),
        Some(json!({ "backup": backup })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "user_id": "u1", "backup": backup, "updated_at": TEST_NOW })
    );

    hub.state.clock.advance(1_000);
    let replaced = b64(&[7; 65_536]);
    let (status, _) = send(
        &hub,
        Method::PUT,
        uri,
        Some(&token),
        Some(json!({ "backup": replaced })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(&hub, Method::GET, uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "user_id": "u1", "backup": replaced, "updated_at": TEST_NOW + 1_000 })
    );
}

#[tokio::test]
async fn store_is_restricted_and_validated() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    hub.create_session("u2", "d2").await;
    let body = json!({ "backup": b64(b"ciphertext") });

    let (status, value) = send(
        &hub,
        Method::PUT,
        "/v2/users/u1/recovery-backup",
        None,
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&value), "unauthorized");

    let (status, value) = send(
        &hub,
        Method::PUT,
        "/v2/users/u2/recovery-backup",
        Some(&token),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&value), "forbidden");

    let uri = "/v2/users/u1/recovery-backup";
    for (backup, expected, expected_code) in [
        (
            b64(&[7; 65_537]),
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        ),
        (
            "not base64!".to_owned(),
            StatusCode::BAD_REQUEST,
            "validation_failed",
        ),
        (String::new(), StatusCode::BAD_REQUEST, "validation_failed"),
    ] {
        let (status, value) = send(
            &hub,
            Method::PUT,
            uri,
            Some(&token),
            Some(json!({ "backup": backup })),
        )
        .await;
        assert_eq!(status, expected);
        assert_eq!(code(&value), expected_code);
    }
    assert_eq!(
        send(&hub, Method::GET, uri, None, None).await.0,
        StatusCode::NOT_FOUND
    );
}
