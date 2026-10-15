//! KeyPackage upload, count and claim.

mod mls_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use serde_json::json;

use mls_support::{b64, code, send, Client};

#[tokio::test]
async fn upload_count_and_claim_with_last_resort() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let bob = Client::new(&hub, "ubob", "db1").await;

    let body = bob.upload_key_packages(&hub, 2).await;
    assert_eq!(body, json!({ "available": 2, "has_last_resort": false }));
    let (status, body) = send(
        &hub,
        Method::POST,
        "/v2/keypackages",
        &bob.token,
        Some(json!({ "key_packages": [b64(&bob.key_package())], "last_resort": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "available": 2, "has_last_resort": true }));

    let claim = json!({ "targets": [{ "user_id": "ubob" }, { "user_id": "unknown" }] });
    let mut last_resort = Vec::new();
    for _ in 0..3 {
        let (status, body) = send(
            &hub,
            Method::POST,
            "/v2/keypackages/claim",
            &alice.token,
            Some(claim.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["missing"], json!([{ "user_id": "unknown" }]));
        let claimed = &body["key_packages"][0];
        assert_eq!(claimed["user_id"], "ubob");
        assert_eq!(claimed["device_id"], "db1");
        last_resort.push(claimed["last_resort"].as_bool().unwrap());
    }
    // One-time packages first; the last-resort package is reused.
    assert_eq!(last_resort, [false, false, true]);

    let (status, body) = send(&hub, Method::GET, "/v2/keypackages/count", &bob.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "available": 0, "has_last_resort": true }));

    // Below the default threshold (10) every one-time claim emits keypackages.low.
    let low = bob.events_of(&hub, "keypackages.low").await;
    assert_eq!(low, [json!({ "available": 1 }), json!({ "available": 0 })]);
}

#[tokio::test]
async fn claim_skips_inactive_devices() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let bob = Client::new(&hub, "ubob", "db1").await;
    bob.upload_key_packages(&hub, 1).await;
    hub.set_device_active("ubob", "db1", false).await;
    let (status, body) = send(
        &hub,
        Method::POST,
        "/v2/keypackages/claim",
        &alice.token,
        Some(json!({ "targets": [{ "user_id": "ubob", "device_id": "db1" }] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key_packages"], json!([]));
    assert_eq!(
        body["missing"],
        json!([{ "user_id": "ubob", "device_id": "db1" }])
    );
}

#[tokio::test]
async fn invalid_uploads_are_rejected() {
    let hub = TestHub::new();
    let bob = Client::new(&hub, "ubob", "db1").await;
    let two = [b64(&bob.key_package()), b64(&bob.key_package())];
    for body in [
        json!({ "key_packages": two, "last_resort": true }),
        json!({ "key_packages": [] }),
        json!({ "key_packages": [b64(b"not a key package")] }),
        json!({ "key_packages": ["%%%"] }),
        json!({ "nope": 1 }),
    ] {
        let (status, response) = send(
            &hub,
            Method::POST,
            "/v2/keypackages",
            &bob.token,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(code(&response), "validation_failed");
    }
}
