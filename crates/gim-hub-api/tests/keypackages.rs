//! KeyPackage upload, count and claim.

mod mls_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use openmls::prelude::{BasicCredential, CredentialWithKey};
use serde_json::{json, Value};

use mls_support::{
    b64, code, device_list, gim_credential, put_device_list, send, signer, user_id, Client,
};

/// Uploads `packages` as `client`; returns the status and response.
async fn upload(hub: &TestHub, client: &Client, packages: &[Vec<u8>]) -> (StatusCode, Value) {
    let packages: Vec<String> = packages.iter().map(|kp| b64(kp)).collect();
    send(
        hub,
        Method::POST,
        "/v2/keypackages",
        &client.token,
        Some(json!({ "key_packages": packages })),
    )
    .await
}

/// Asserts a 400 `validation_failed` naming the credential code `expected`.
fn assert_rejected((status, body): (StatusCode, Value), expected: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code(&body), "validation_failed");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains(expected), "{message}");
}

#[tokio::test]
async fn upload_count_and_claim_with_last_resort() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;

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

    let claim = json!({ "targets": [{ "user_id": bob.user_id }, { "user_id": "unknown" }] });
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
        assert_eq!(claimed["user_id"], bob.user_id.as_str());
        assert_eq!(claimed["device_id"], bob.device_id.as_str());
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
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    bob.upload_key_packages(&hub, 1).await;
    hub.set_device_active(&bob.user_id, &bob.device_id, false)
        .await;
    let (status, body) = send(
        &hub,
        Method::POST,
        "/v2/keypackages/claim",
        &alice.token,
        Some(json!({ "targets": [{ "user_id": bob.user_id, "device_id": bob.device_id }] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key_packages"], json!([]));
    assert_eq!(
        body["missing"],
        json!([{ "user_id": bob.user_id, "device_id": bob.device_id }])
    );
}

#[tokio::test]
async fn invalid_uploads_are_rejected() {
    let hub = TestHub::new();
    let bob = Client::new(&hub, 2, 21).await;
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

#[tokio::test]
async fn upload_requires_the_callers_gim_credential() {
    let hub = TestHub::new();
    // Bob's DeviceList certifies devices 21 and 22.
    let (status, body) =
        put_device_list(&hub, &user_id(2), &device_list(2, 1, &[21, 22], &[])).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let bob = Client::signed_in(&hub, 2, 21).await;
    let bob2 = Client::signed_in(&hub, 2, 22).await;

    let basic = CredentialWithKey {
        credential: BasicCredential::new(bob.user_id.clone().into_bytes()).into(),
        signature_key: bob.signer.public().into(),
    };
    let basic = bob.key_package_with(basic, &bob.signer);
    assert_rejected(upload(&hub, &bob, &[basic]).await, "wrong_credential_type");

    // Another device's valid KeyPackage, uploaded by Bob's device 21.
    assert_rejected(
        upload(&hub, &bob, &[bob2.key_package()]).await,
        "identity_mismatch",
    );

    // Bob's credential on a leaf signed with another key.
    let other = signer(23);
    let mismatched = CredentialWithKey {
        credential: gim_credential(2, 21),
        signature_key: other.public().into(),
    };
    let mismatched = bob.key_package_with(mismatched, &other);
    assert_rejected(upload(&hub, &bob, &[mismatched]).await, "leaf_key_mismatch");

    // One bad package rejects the whole upload.
    let (status, _) = upload(&hub, &bob, &[bob.key_package(), bob2.key_package()]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = upload(&hub, &bob, &[bob.key_package()]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["available"], 1);

    // Device 22 is revoked (which ends its sessions); a new session reaches
    // the credential check.
    let (status, body) =
        put_device_list(&hub, &bob.user_id, &device_list(2, 2, &[21], &[22])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bob2 = Client::signed_in(&hub, 2, 22).await;
    assert_rejected(
        upload(&hub, &bob2, &[bob2.key_package()]).await,
        "revoked_device",
    );

    // Device 23 is neither certified nor revoked.
    let stranger = Client::signed_in(&hub, 2, 23).await;
    assert_rejected(
        upload(&hub, &stranger, &[stranger.key_package()]).await,
        "unknown_device",
    );

    // No DeviceList stored: fail closed.
    let nolist = Client::signed_in(&hub, 6, 61).await;
    assert_rejected(
        upload(&hub, &nolist, &[nolist.key_package()]).await,
        "no_device_list",
    );
    assert_eq!(
        send(&hub, Method::GET, "/v2/keypackages/count", &bob.token, None)
            .await
            .1["available"],
        1
    );
}
