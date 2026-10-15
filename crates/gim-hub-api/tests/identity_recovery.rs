//! Recovery backups: authenticated store, unauthenticated fetch.

mod identity_support;

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use gim_hub_api::{
    ratelimit::PublicReadLimits,
    testing::{TestHub, TEST_NOW},
};
use serde_json::json;
use tower::ServiceExt;

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

/// Unauthenticated GET of `user_id`'s backup from `peer`: the status and
/// `Retry-After`.
async fn fetch(hub: &TestHub, user_id: &str, peer: &str) -> (StatusCode, Option<u64>) {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(format!("/v2/users/{user_id}/recovery-backup"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    let response = hub.router().oneshot(request).await.unwrap();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().unwrap().parse().unwrap());
    (response.status(), retry_after)
}

#[tokio::test]
async fn fetch_is_rate_limited_per_address_and_per_user() {
    let mut hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let (status, _) = send(
        &hub,
        Method::PUT,
        "/v2/users/u1/recovery-backup",
        Some(&token),
        Some(json!({ "backup": b64(b"ciphertext") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    hub.state.recovery_reads = PublicReadLimits::new(2, 2, false);
    let limited = |secs| (StatusCode::TOO_MANY_REQUESTS, Some(secs));

    // 2 per minute per address and per user (one token every 30 s), the
    // address first; checked before the lookup, so missing backups count.
    let (a, b, c) = ("203.0.113.7:1", "198.51.100.1:1", "192.0.2.1:1");
    assert_eq!(fetch(&hub, "u1", a).await, (StatusCode::OK, None));
    assert_eq!(fetch(&hub, "u2", a).await, (StatusCode::NOT_FOUND, None));
    assert_eq!(fetch(&hub, "u1", a).await, limited(30));
    assert_eq!(fetch(&hub, "u1", b).await, (StatusCode::OK, None));
    assert_eq!(fetch(&hub, "u1", c).await, limited(30));
    assert_eq!(fetch(&hub, "u2", c).await, (StatusCode::NOT_FOUND, None));
    // The public user reads have their own budget.
    let (status, _) = send(&hub, Method::GET, "/v2/users/u1", None, None).await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);

    hub.state.clock.advance(20_000);
    assert_eq!(fetch(&hub, "u1", a).await, limited(10));
    assert_eq!(fetch(&hub, "u1", b).await, limited(10));
    hub.state.clock.advance(10_000);
    assert_eq!(fetch(&hub, "u1", b).await, (StatusCode::OK, None));
}
