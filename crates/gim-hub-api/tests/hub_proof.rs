//! GET /v2/hub: `public_url` and the proof of possession for `?nonce=`.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use gim_hub_api::testing::TestHub;
use gim_hub_identity::HubId;
use serde_json::{json, Value};
use tower::ServiceExt;

const PUBLIC_URL: &str = "https://hub.example.eu";

fn with_public_url(mut hub: TestHub, public_url: &str) -> TestHub {
    let mut config = (*hub.state.config).clone();
    config.public_url = Some(public_url.to_owned());
    hub.state.config = Arc::new(config);
    hub
}

async fn get(hub: &TestHub, uri: &str) -> (StatusCode, Value) {
    let request = Request::get(uri).body(Body::empty()).unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn nonce_query(nonce: &[u8]) -> String {
    format!("/v2/hub?nonce={}", URL_SAFE_NO_PAD.encode(nonce))
}

/// The proof message recomputed from the spec.
fn proof_message(nonce: &[u8; 32], hub_id: &str, public_url: &str) -> Vec<u8> {
    [
        b"gim-hub-proof-v1".as_slice(),
        &[0],
        nonce,
        &(hub_id.len() as u16).to_be_bytes(),
        hub_id.as_bytes(),
        &(public_url.len() as u16).to_be_bytes(),
        public_url.as_bytes(),
    ]
    .concat()
}

/// Client-side check of a GET /v2/hub?nonce= body.
fn verify(body: &Value, nonce: &[u8; 32], public_url: &str) -> Result<(), String> {
    let key: [u8; 32] = STANDARD
        .decode(body["hub_root_pubkey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = VerifyingKey::from_bytes(&key).unwrap();
    let hub_id = body["hub_id"].as_str().unwrap();
    assert_eq!(HubId::from_root_pubkey(&key).as_str(), hub_id);
    let proof: [u8; 64] = URL_SAFE_NO_PAD
        .decode(body["proof"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    key.verify(
        &proof_message(nonce, hub_id, public_url),
        &Signature::from_bytes(&proof),
    )
    .map_err(|err| err.to_string())
}

#[tokio::test]
async fn without_nonce_no_proof() {
    let hub = with_public_url(TestHub::new(), PUBLIC_URL);
    let (status, body) = get(&hub, "/v2/hub").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "hub_id": hub.state.hub.hub_id().as_str(),
            "hub_root_pubkey":
                STANDARD.encode(hub.state.hub.signing_key().verifying_key().as_bytes()),
            "version": env!("CARGO_PKG_VERSION"),
            "public_url": PUBLIC_URL,
        })
    );

    // No public URL configured: unchanged response, no `public_url`.
    let (status, body) = get(&TestHub::new(), "/v2/hub").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("public_url").is_none() && body.get("proof").is_none());
}

#[tokio::test]
async fn proof_verifies_over_the_exact_message() {
    let hub = with_public_url(TestHub::new(), PUBLIC_URL);
    let nonce = [0x42; 32];
    let (status, body) = get(&hub, &nonce_query(&nonce)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["public_url"], PUBLIC_URL);
    assert_eq!(body["hub_id"], hub.state.hub.hub_id().as_str());
    assert_eq!(verify(&body, &nonce, PUBLIC_URL), Ok(()));
    assert!(verify(&body, &[0x43; 32], PUBLIC_URL).is_err());
    assert!(verify(&body, &nonce, "https://other.example.eu").is_err());

    let (_, other) = get(&hub, &nonce_query(&[0x43; 32])).await;
    assert_ne!(other["proof"], body["proof"]);
    assert_eq!(verify(&other, &[0x43; 32], PUBLIC_URL), Ok(()));
}

#[tokio::test]
async fn proof_matches_the_vectors() {
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../testdata/identity/hub-proof.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    for v in file["cases"].as_array().unwrap() {
        let seed: [u8; 32] = hex::decode(v["root_seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let url = v["public_url"].as_str().unwrap();
        let hub = with_public_url(TestHub::with_hub_seed(seed), url);
        let (status, body) = get(
            &hub,
            &format!("/v2/hub?nonce={}", v["nonce_base64url"].as_str().unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["hub_id"], v["hub_id"]);
        assert_eq!(body["hub_root_pubkey"], v["hub_root_pubkey_base64"]);
        assert_eq!(body["public_url"], url);
        assert_eq!(body["proof"], v["proof_base64url"]);
    }
}

#[tokio::test]
async fn malformed_nonce_is_rejected() {
    let hub = with_public_url(TestHub::new(), PUBLIC_URL);
    let padded = format!("/v2/hub?nonce={}", URL_SAFE.encode([1u8; 32]));
    let standard = format!(
        "/v2/hub?nonce={}",
        STANDARD.encode([0xfb; 32]).trim_end_matches('=')
    );
    for uri in [
        nonce_query(&[1; 31]),
        nonce_query(&[1; 33]),
        nonce_query(&[]),
        padded,
        standard,
        "/v2/hub?nonce=not*base64".to_owned(),
    ] {
        let (status, body) = get(&hub, &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["error"]["code"], "validation_failed", "{uri}");
    }
}

#[tokio::test]
async fn nonce_without_public_url_is_rejected() {
    let (status, body) = get(&TestHub::new(), &nonce_query(&[1; 32])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "validation_failed");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("proof unavailable"));
}
