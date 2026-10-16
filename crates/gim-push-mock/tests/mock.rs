//! Router-level tests of the mock push server.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use gim_push_mock::{router, sign, verify_signature, Config, MockState, SignatureError};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn app() -> Router {
    router(MockState::new(&Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        secret: SECRET.to_vec(),
        max_skew_seconds: 300,
    }))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn body(delivery_id: &str, provider: &str, token: &str) -> Value {
    json!({
        "v": 1,
        "hub_id": "hub",
        "delivery_id": delivery_id,
        "sent_at": 1_700_000_000_000u64,
        "registration": { "provider": provider, "token": token, "app_id": "cc.gim.app" },
        "priority": "high",
        "collapse_id": "m1",
        "ttl": 86400,
        "payload": { "v": 1, "type": "message", "gid": "g", "seq": 1, "message_id": "m1", "collapse_id": "m1" },
    })
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, value)
}

fn push_request(body: &Value, signature: Option<String>) -> Request<Body> {
    let raw = serde_json::to_vec(body).unwrap();
    let mut request = Request::post("/push")
        .header("content-type", "application/json")
        .header("x-gim-delivery", body["delivery_id"].as_str().unwrap_or(""));
    if let Some(signature) = signature {
        request = request.header("x-gim-signature", signature);
    }
    request.body(Body::from(raw)).unwrap()
}

async fn push(app: &Router, body: &Value) -> StatusCode {
    let signature = sign(SECRET, now(), &serde_json::to_vec(body).unwrap());
    send(app, push_request(body, Some(signature))).await.0
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    send(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

fn seqs(list: &Value) -> Vec<u64> {
    list["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["seq"].as_u64().unwrap())
        .collect()
}

#[test]
fn signature_roundtrip_and_rejections() {
    let t = 1_700_000_000;
    let header = sign(SECRET, t, b"{}");
    assert!(header.starts_with("t=1700000000,v1="));
    assert_eq!(verify_signature(SECRET, &header, b"{}", t, 300), Ok(()));
    assert_eq!(
        verify_signature(SECRET, &header, b"{}", t + 300, 300),
        Ok(())
    );

    assert_eq!(
        verify_signature(SECRET, &header, b"{ }", t, 300),
        Err(SignatureError::BadMac)
    );
    assert_eq!(
        verify_signature(b"another secret", &header, b"{}", t, 300),
        Err(SignatureError::BadMac)
    );
    assert_eq!(
        verify_signature(SECRET, &header, b"{}", t + 301, 300),
        Err(SignatureError::Skew)
    );
    assert_eq!(
        verify_signature(SECRET, &header, b"{}", t - 301, 300),
        Err(SignatureError::Skew)
    );

    let mac = header.split_once(",v1=").unwrap().1;
    for malformed in [
        String::new(),
        "garbage".into(),
        format!("v1={mac},t={t}"),
        format!("t={t}"),
        format!("t=,v1={mac}"),
        format!("t=-1,v1={mac}"),
        format!("t={t},v1={}", mac.to_uppercase()),
        format!("t={t},v1={}", &mac[..62]),
        format!("t={t},v1={mac},v2=00"),
    ] {
        assert_eq!(
            verify_signature(SECRET, &malformed, b"{}", t, 300),
            Err(SignatureError::Malformed),
            "{malformed:?}"
        );
    }
}

#[tokio::test]
async fn push_rejects_bad_signatures_with_401() {
    let app = app();
    let body = body("d1", "mock-android", "t-1");
    let raw = serde_json::to_vec(&body).unwrap();

    for signature in [
        None,
        Some("t=1,v1=zz".to_owned()),
        Some(sign(b"wrong secret", now(), &raw)),
        Some(sign(SECRET, now() - 1000, &raw)),
    ] {
        let (status, _) = send(&app, push_request(&body, signature)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (_, stats) = get(&app, "/stats").await;
    assert_eq!(stats["counters"]["unauthorized"], 4);
    assert_eq!(stats["deliveries"], 0);
}

#[tokio::test]
async fn push_rejects_invalid_bodies_with_400() {
    let app = app();
    let mut wrong_version = body("d1", "mock-android", "t-1");
    wrong_version["v"] = json!(2);
    let mut no_registration = body("d2", "mock-android", "t-1");
    no_registration["registration"] = json!({});
    for invalid in [wrong_version, no_registration, json!({ "v": 1 })] {
        assert_eq!(push(&app, &invalid).await, StatusCode::BAD_REQUEST);
    }

    // X-Gim-Delivery must equal the body's delivery_id.
    let body = body("d3", "mock-android", "t-1");
    let raw = serde_json::to_vec(&body).unwrap();
    let request = Request::post("/push")
        .header("x-gim-delivery", "other")
        .header("x-gim-signature", sign(SECRET, now(), &raw))
        .body(Body::from(raw))
        .unwrap();
    assert_eq!(send(&app, request).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn push_records_once_per_delivery_id() {
    let app = app();
    let first = body("d1", "mock-android", "t-1");
    assert_eq!(push(&app, &first).await, StatusCode::OK);
    assert_eq!(push(&app, &first).await, StatusCode::OK);

    let (status, list) = get(&app, "/deliveries").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seqs(&list), [1]);
    let delivery = &list["deliveries"][0];
    assert_eq!(delivery["delivery_id"], "d1");
    assert_eq!(delivery["body"], first);
    assert!(delivery["received_at"].as_u64().unwrap() > 1_700_000_000_000);
    assert!(delivery.get("simctl").is_none());
    assert_eq!(list["next"], 1);

    let (_, stats) = get(&app, "/stats").await;
    assert_eq!(stats["counters"]["delivered"], 1);
    assert_eq!(stats["counters"]["duplicates"], 1);
}

#[tokio::test]
async fn token_prefixes_select_the_response() {
    let app = app();
    for (token, status) in [
        ("gone-1", StatusCode::GONE),
        ("fail-1", StatusCode::INTERNAL_SERVER_ERROR),
        ("bad-1", StatusCode::BAD_REQUEST),
        ("t-1", StatusCode::OK),
    ] {
        let id = format!("d-{token}");
        assert_eq!(push(&app, &body(&id, "mock-android", token)).await, status);
    }
    // A retry of a failed push fails again: only 2xx deliveries are recorded.
    assert_eq!(
        push(&app, &body("d-fail-1", "mock-android", "fail-1")).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let (_, stats) = get(&app, "/stats").await;
    let counters = &stats["counters"];
    assert_eq!(
        (
            &counters["gone"],
            &counters["failed"],
            &counters["bad"],
            &counters["delivered"]
        ),
        (&json!(1), &json!(2), &json!(1), &json!(1))
    );
    let (_, list) = get(&app, "/deliveries").await;
    assert_eq!(list["deliveries"][0]["delivery_id"], "d-t-1");
}

#[tokio::test]
async fn deliveries_filter_by_token_provider_and_since() {
    let app = app();
    push(&app, &body("d1", "mock-android", "t-a")).await;
    push(&app, &body("d2", "mock-ios-sim", "t-b")).await;
    push(&app, &body("d3", "mock-android", "t-b")).await;
    push(&app, &body("d4", "mock-android", "t-a")).await;

    let (_, list) = get(&app, "/deliveries?token=t-a").await;
    assert_eq!(seqs(&list), [1, 4]);
    let (_, list) = get(&app, "/deliveries?provider=mock-android&token=t-b").await;
    assert_eq!(seqs(&list), [3]);
    let (_, list) = get(&app, "/deliveries?provider=mock-android&since=1").await;
    assert_eq!(seqs(&list), [3, 4]);
    assert_eq!(list["next"], 4);
    let (_, list) = get(&app, "/deliveries?since=4").await;
    assert_eq!(seqs(&list), Vec::<u64>::new());
    assert_eq!(list["next"], 4);
    let (_, list) = get(&app, "/deliveries?token=&provider=").await;
    assert_eq!(seqs(&list), [1, 2, 3, 4]);
    let (status, _) = get(&app, "/deliveries?since=x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn long_poll_wakes_on_a_matching_delivery() {
    let app = app();
    push(&app, &body("d1", "mock-android", "t-a")).await;

    let poll = tokio::spawn({
        let app = app.clone();
        async move { get(&app, "/deliveries?token=t-a&since=1&wait=10").await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A non-matching delivery does not end the wait.
    push(&app, &body("d2", "mock-android", "t-other")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!poll.is_finished());

    push(&app, &body("d3", "mock-android", "t-a")).await;
    let (status, list) = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seqs(&list), [3]);
    assert_eq!(list["next"], 3);
}

#[tokio::test]
async fn long_poll_times_out_empty() {
    let app = app();
    let started = std::time::Instant::now();
    let (status, list) = get(&app, "/deliveries?token=t-a&wait=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list, json!({ "deliveries": [], "next": 0 }));
    assert!(started.elapsed() >= Duration::from_millis(900));
}

#[tokio::test]
async fn reset_clears_deliveries_and_counters_but_keeps_seq() {
    let app = app();
    push(&app, &body("d1", "mock-android", "t-a")).await;
    push(&app, &body("d2", "mock-android", "gone-a")).await;

    let (status, _) = send(&app, Request::post("/reset").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = get(&app, "/deliveries").await;
    assert_eq!(seqs(&list), Vec::<u64>::new());
    let (_, stats) = get(&app, "/stats").await;
    assert_eq!(stats["counters"]["delivered"], 0);
    assert_eq!(stats["counters"]["gone"], 0);

    // The same delivery_id is recorded again, with a fresh seq.
    assert_eq!(
        push(&app, &body("d1", "mock-android", "t-a")).await,
        StatusCode::OK
    );
    let (_, list) = get(&app, "/deliveries").await;
    assert_eq!(seqs(&list), [2]);
}

#[tokio::test]
async fn ios_sim_deliveries_carry_a_simctl_view() {
    let app = app();
    let body = body("d1", "mock-ios-sim", "sim-1");
    push(&app, &body).await;

    let (_, list) = get(&app, "/deliveries?provider=mock-ios-sim").await;
    assert_eq!(
        list["deliveries"][0]["simctl"],
        json!({
            "bundle_id": "cc.gim.app",
            "payload": {
                "aps": { "alert": { "title": "gim", "body": "New message" }, "mutable-content": 1 },
                "gim": body["payload"],
            },
        })
    );
}

#[tokio::test]
async fn healthz_is_ok() {
    let (status, value) = get(&app(), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"], "ok");
}
