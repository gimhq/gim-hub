//! Unauthenticated GET /v2/users/{user_id} and GET
//! /v2/users/{user_id}/device-list, rate limited per client IP and per user.

mod identity_support;

use std::net::SocketAddr;

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use gim_hub_api::{ratelimit::PublicReadLimits, testing::TestHub};
use serde_json::{json, Value};
use tower::ServiceExt;

use identity_support::{b64, code, device_id, device_list, put_device_list, send, user_id};

/// GET `uri` without a token, from `peer` (no ConnectInfo when `None`),
/// with an optional `X-Forwarded-For`; returns the status, `Retry-After`
/// and the JSON body.
async fn get(
    hub: &TestHub,
    uri: &str,
    peer: Option<&str>,
    forwarded_for: Option<&str>,
) -> (StatusCode, Option<u64>, Value) {
    let mut request = Request::builder().method(Method::GET).uri(uri);
    if let Some(value) = forwarded_for {
        request = request.header("x-forwarded-for", value);
    }
    let mut request = request.body(Body::empty()).unwrap();
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    }
    let response = hub.router().oneshot(request).await.unwrap();
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().unwrap().parse().unwrap());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        retry_after,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

fn assert_limited(response: &(StatusCode, Option<u64>, Value)) {
    let (status, retry_after, body) = response;
    assert_eq!(*status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code(body), "rate_limited");
    assert!(retry_after.is_some_and(|secs| secs >= 1), "{retry_after:?}");
}

async fn hub_with_user(root_seed: u8) -> (TestHub, String, Vec<u8>) {
    let hub = TestHub::new();
    let user = user_id(root_seed);
    let list = device_list(root_seed, 1, &[2], &[]);
    assert_eq!(
        put_device_list(&hub, &user, &list).await.0,
        StatusCode::CREATED
    );
    (hub, user, list)
}

#[tokio::test]
async fn local_user_is_readable_without_auth() {
    let (hub, user, list) = hub_with_user(1).await;

    let (status, _, body) = get(&hub, &format!("/v2/users/{user}/device-list"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "user_id": user, "device_list": b64(&list) }));

    let (status, _, body) = get(&hub, &format!("/v2/users/{user}"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "user_id": user, "device_list": b64(&list) }));

    // With a handle: exactly user_id, device_list and handle.
    let token = hub.create_session(&user, &device_id(2)).await;
    let (status, _) = send(&hub, Method::PUT, "/v2/handles/alice", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = get(&hub, &format!("/v2/users/{user}"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "user_id": user, "device_list": b64(&list), "handle": "alice" })
    );
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["device_list", "handle", "user_id"]);

    let missing = user_id(5);
    for uri in [
        format!("/v2/users/{missing}"),
        format!("/v2/users/{missing}/device-list"),
    ] {
        let (status, _, body) = get(&hub, &uri, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(code(&body), "not_found");
    }
}

#[tokio::test]
async fn per_ip_limit_is_shared_by_both_endpoints() {
    let (mut hub, user, _) = hub_with_user(1).await;
    hub.state.public_reads = PublicReadLimits::new(2, 100, false);
    let peer = Some("203.0.113.7:4000");

    let user_uri = format!("/v2/users/{user}");
    let list_uri = format!("/v2/users/{user}/device-list");
    assert_eq!(get(&hub, &user_uri, peer, None).await.0, StatusCode::OK);
    assert_eq!(get(&hub, &list_uri, peer, None).await.0, StatusCode::OK);
    assert_limited(&get(&hub, &list_uri, peer, None).await);
    // Checked before the lookup: unknown users are limited too.
    assert_limited(&get(&hub, &format!("/v2/users/{}", user_id(5)), peer, None).await);

    // Another address, and another IPv6 /64, have their own budget; the
    // same /64 shares one.
    assert_eq!(
        get(&hub, &user_uri, Some("198.51.100.1:1"), None).await.0,
        StatusCode::OK
    );
    for _ in 0..2 {
        assert_eq!(
            get(&hub, &user_uri, Some("[2001:db8:0:1::a]:1"), None)
                .await
                .0,
            StatusCode::OK
        );
    }
    assert_limited(&get(&hub, &user_uri, Some("[2001:db8:0:1::b]:1"), None).await);
    assert_eq!(
        get(&hub, &user_uri, Some("[2001:db8:0:2::a]:1"), None)
            .await
            .0,
        StatusCode::OK
    );

    // X-Forwarded-For is ignored unless trusted.
    assert_limited(&get(&hub, &user_uri, peer, Some("192.0.2.1")).await);
}

#[tokio::test]
async fn trusted_forwarded_for_keys_by_the_left_most_address() {
    let (mut hub, user, _) = hub_with_user(1).await;
    hub.state.public_reads = PublicReadLimits::new(1, 100, true);
    let proxy = Some("10.0.0.1:1");
    let uri = format!("/v2/users/{user}/device-list");

    assert_eq!(
        get(&hub, &uri, proxy, Some("192.0.2.1, 10.0.0.1")).await.0,
        StatusCode::OK
    );
    assert_limited(&get(&hub, &uri, proxy, Some("192.0.2.1")).await);
    assert_eq!(
        get(&hub, &uri, proxy, Some("192.0.2.2")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn per_user_limit_spares_other_targets() {
    let (mut hub, alice, _) = hub_with_user(1).await;
    let bob = user_id(3);
    put_device_list(&hub, &bob, &device_list(3, 1, &[4], &[])).await;
    hub.state.public_reads = PublicReadLimits::new(100, 2, false);

    // Two clients share Alice's budget.
    let alice_uri = format!("/v2/users/{alice}");
    assert_eq!(
        get(&hub, &alice_uri, Some("203.0.113.7:1"), None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        get(
            &hub,
            &format!("/v2/users/{alice}/device-list"),
            Some("198.51.100.1:1"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_limited(&get(&hub, &alice_uri, Some("192.0.2.1:1"), None).await);

    let (status, _, body) = get(&hub, &format!("/v2/users/{bob}"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], bob);
}
