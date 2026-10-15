//! Link-bundle relay: post, fetch once, long-poll, expiry.

mod identity_support;

use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::{TestHub, TEST_NOW};
use serde_json::{json, Value};

use identity_support::{b64, code, send};

const LINK_ID: &str = "wgy33neayyoqouya3g77pwolne";

async fn post(hub: &TestHub, token: &str, body: Value) -> (StatusCode, Value) {
    send(
        hub,
        Method::POST,
        "/v2/link-bundles",
        Some(token),
        Some(body),
    )
    .await
}

fn bundle(link_id: &str, expires_in: u32) -> Value {
    json!({ "link_id": link_id, "sealed_bundle": b64(b"sealed"), "expires_in": expires_in })
}

async fn fetch(hub: &TestHub, link_id: &str, wait: u32) -> (StatusCode, Value) {
    let uri = format!("/v2/link-bundles/{link_id}?wait={wait}");
    send(hub, Method::GET, &uri, None, None).await
}

#[tokio::test]
async fn post_then_fetch_once() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;

    let (status, body) = send(
        &hub,
        Method::POST,
        "/v2/link-bundles",
        None,
        Some(bundle(LINK_ID, 300)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&body), "unauthorized");

    let (status, body) = post(&hub, &token, bundle(LINK_ID, 300)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body,
        json!({ "link_id": LINK_ID, "expires_at": TEST_NOW + 300_000 })
    );
    let (status, body) = post(&hub, &token, bundle(LINK_ID, 300)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&body), "conflict");

    let (status, body) = fetch(&hub, LINK_ID, 0).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "link_id": LINK_ID, "sealed_bundle": b64(b"sealed") })
    );
    let (status, body) = fetch(&hub, LINK_ID, 0).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
}

#[tokio::test]
async fn expired_bundles_are_gone() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    assert_eq!(
        post(&hub, &token, bundle(LINK_ID, 1)).await.0,
        StatusCode::CREATED
    );
    hub.state.clock.advance(1_000);
    assert_eq!(fetch(&hub, LINK_ID, 0).await.0, StatusCode::NOT_FOUND);

    // An expired bundle no longer blocks its link_id.
    assert_eq!(
        post(&hub, &token, bundle(LINK_ID, 1)).await.0,
        StatusCode::CREATED
    );
    hub.state.clock.advance(1_000);
    assert_eq!(
        post(&hub, &token, bundle(LINK_ID, 5)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(fetch(&hub, LINK_ID, 0).await.0, StatusCode::OK);
}

#[tokio::test]
async fn long_poll_wakes_on_post() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let started = Instant::now();
    let (fetched, posted) = tokio::join!(fetch(&hub, LINK_ID, 20), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        post(&hub, &token, bundle(LINK_ID, 300)).await
    });
    assert_eq!(posted.0, StatusCode::CREATED);
    assert_eq!(fetched.0, StatusCode::OK);
    assert_eq!(fetched.1["sealed_bundle"], b64(b"sealed"));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn long_poll_times_out() {
    let hub = TestHub::new();
    let started = Instant::now();
    let (status, body) = fetch(&hub, LINK_ID, 1).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn invalid_requests_are_rejected() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let invalid_posts = [
        bundle("short", 300),
        bundle("has a space in the link id", 300),
        bundle(&"a".repeat(65), 300),
        bundle(LINK_ID, 0),
        bundle(LINK_ID, 601),
        json!({ "link_id": LINK_ID, "sealed_bundle": "%%", "expires_in": 60 }),
        json!({ "link_id": LINK_ID, "sealed_bundle": "", "expires_in": 60 }),
        json!({ "link_id": LINK_ID }),
    ];
    for body in invalid_posts {
        let (status, value) = post(&hub, &token, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(code(&value), "validation_failed");
    }
    let too_large = json!({
        "link_id": LINK_ID,
        "sealed_bundle": b64(&[1; 262_145]),
        "expires_in": 60,
    });
    let (status, value) = post(&hub, &token, too_large).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(code(&value), "payload_too_large");

    for uri in [
        format!("/v2/link-bundles/{LINK_ID}?wait=31"),
        format!("/v2/link-bundles/{LINK_ID}?wait=soon"),
        "/v2/link-bundles/short".to_owned(),
    ] {
        let (status, value) = send(&hub, Method::GET, &uri, None, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(code(&value), "validation_failed");
    }
}
