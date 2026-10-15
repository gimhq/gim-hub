//! Device sign-in: POST /v2/auth/challenge and POST /v2/auth/session, with
//! the vendored gim-core vectors (`testdata/identity/auth.json`,
//! `identity.json`) and freshly signed AuthResponses.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use gim_hub_api::{
    handlers::CHALLENGE_TTL_MS,
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::{
    auth::{self, Challenge},
    users::{self, Device, StoredDeviceList},
};
use gim_hub_identity::{AuthChallenge, DeviceList, UserId, AUTH_RESPONSE_CONTEXT};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// `device_id` of `devices[1]` in identity.json: active in the auth.json
/// list (seq 1), revoked by the identity.json list (seq 2).
const SECOND_DEVICE_INDEX: usize = 1;

fn vectors(name: &str) -> Value {
    let path = format!(
        "{}/../../testdata/identity/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn seed(value: &Value) -> [u8; 32] {
    hex_bytes(value).try_into().unwrap()
}

fn text(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

/// The user's devices from identity.json: `(device_id, signing key)`.
fn devices() -> Vec<(String, SigningKey)> {
    vectors("identity")["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                text(&d["device_id"]),
                SigningKey::from_bytes(&seed(&d["seed"])),
            )
        })
        .collect()
}

/// Stores a SignedDeviceList and the device rows derived from it, as the
/// DeviceList upload does.
async fn store_device_list(hub: &TestHub, signed: Vec<u8>) {
    let user_id = text(&vectors("auth")["user_id"]);
    let list = DeviceList::verify(&signed, &UserId::parse(&user_id).unwrap()).unwrap();
    let now = hub.state.clock.now_ms();
    hub.state
        .db
        .write(move |tx| {
            users::put_device_list(
                tx,
                &StoredDeviceList {
                    user_id: user_id.clone(),
                    root_pubkey: list.root_pubkey().as_bytes().to_vec(),
                    device_list: signed,
                    seq: i64::try_from(list.seq()).unwrap(),
                    updated_at: now,
                },
            )?;
            let certified = list.certs().iter().map(|cert| {
                (
                    cert.device_id().to_string(),
                    cert.device_sig_pubkey().as_bytes().to_vec(),
                    true,
                )
            });
            let revoked = list
                .revoked()
                .iter()
                .map(|id| (id.to_string(), vec![0; 32], false));
            for (device_id, sig_pubkey, active) in certified.chain(revoked) {
                users::put_device(
                    tx,
                    &Device {
                        user_id: user_id.clone(),
                        device_id,
                        sig_pubkey,
                        active,
                    },
                    now,
                )?;
            }
            Ok::<_, gim_hub_db::DbError>(())
        })
        .await
        .unwrap();
}

/// A hub storing the auth.json DeviceList (both devices active).
async fn hub_with_user(hub: TestHub) -> TestHub {
    store_device_list(&hub, hex_bytes(&vectors("auth")["device_list"])).await;
    hub
}

/// Stores the auth.json challenge as issued, with the clock at its
/// `issued_at`.
async fn issue_vector_challenge(hub: &TestHub) {
    let v = vectors("auth");
    let challenge = &v["challenge"];
    let issued_at = challenge["issued_at"].as_i64().unwrap();
    hub.state.clock.advance(issued_at - TEST_NOW);
    let row = Challenge {
        challenge_id: hex::encode(Sha256::digest(hex_bytes(&challenge["nonce"]))),
        user_id: text(&v["user_id"]),
        device_id: text(&v["device_id"]),
        challenge: hex_bytes(&challenge["bytes"]),
        expires_at: challenge["expires_at"].as_i64().unwrap(),
    };
    hub.state
        .db
        .write(move |tx| auth::insert_challenge(tx, &row, issued_at))
        .await
        .unwrap();
}

/// CBOR head of major type `major` with argument `len`.
fn head(major: u8, len: usize) -> Vec<u8> {
    let major = major << 5;
    match u8::try_from(len) {
        Ok(len) if len < 24 => vec![major | len],
        Ok(len) => vec![major | 24, len],
        Err(_) => [
            &[major | 25][..],
            &u16::try_from(len).unwrap().to_be_bytes(),
        ]
        .concat(),
    }
}

fn bstr(bytes: &[u8]) -> Vec<u8> {
    [head(2, bytes.len()), bytes.to_vec()].concat()
}

fn tstr(text: &str) -> Vec<u8> {
    [head(3, text.len()), text.as_bytes().to_vec()].concat()
}

/// Device-side AuthResponse over `challenge`.
fn sign_response(challenge: &[u8], user_id: &str, device_id: &str, key: &SigningKey) -> Vec<u8> {
    let fields = [bstr(challenge), tstr(user_id), tstr(device_id)].concat();
    let tbs = [head(4, 3), fields.clone()].concat();
    let sig = key.sign(&[AUTH_RESPONSE_CONTEXT, &[0], &tbs].concat());
    [head(4, 5), vec![0x01], fields, bstr(&sig.to_bytes())].concat()
}

async fn post(hub: &TestHub, path: &str, body: &Value) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn request_challenge(hub: &TestHub, device_id: &str) -> (StatusCode, Value) {
    let user_id = text(&vectors("auth")["user_id"]);
    post(
        hub,
        "/v2/auth/challenge",
        &json!({ "user_id": user_id, "device_id": device_id }),
    )
    .await
}

/// Requests a challenge for `device_id` and returns its bytes.
async fn challenge_bytes(hub: &TestHub, device_id: &str) -> Vec<u8> {
    let (status, body) = request_challenge(hub, device_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    STANDARD.decode(text(&body["challenge"])).unwrap()
}

async fn create_session(hub: &TestHub, response: &[u8]) -> (StatusCode, Value) {
    post(
        hub,
        "/v2/auth/session",
        &json!({ "response": STANDARD.encode(response) }),
    )
    .await
}

fn error(code: &str) -> Value {
    Value::from(code)
}

/// GET /v2/me with a bearer token: `(user_id, device_id)` of the caller.
async fn get_me(hub: &TestHub, token: &str) -> (String, String) {
    let request = Request::get("/v2/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let me: Value = serde_json::from_slice(&body).unwrap();
    (text(&me["user_id"]), text(&me["device_id"]))
}

#[test]
fn response_encoding_matches_vector() {
    let v = vectors("auth");
    let response = sign_response(
        &hex_bytes(&v["challenge"]["bytes"]),
        v["user_id"].as_str().unwrap(),
        v["device_id"].as_str().unwrap(),
        &SigningKey::from_bytes(&seed(&v["device_seed"])),
    );
    assert_eq!(response, hex_bytes(&v["response"]));
}

#[tokio::test]
async fn vector_response_creates_session_once() {
    let v = vectors("auth");
    let hub = hub_with_user(TestHub::with_hub_seed(seed(&v["hub_root_seed"]))).await;
    assert_eq!(hub.state.hub.hub_id().as_str(), v["audience"]);
    issue_vector_challenge(&hub).await;
    let response = hex_bytes(&v["response"]);

    let (status, body) = create_session(&hub, &response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let now = v["challenge"]["issued_at"].as_i64().unwrap();
    assert_eq!(body["expires_at"], now + 30 * DAY_MS);
    let token = text(&body["token"]);
    assert_eq!(token.len(), 43);
    assert_eq!(
        get_me(&hub, &token).await,
        (text(&v["user_id"]), text(&v["device_id"]))
    );

    let (status, body) = create_session(&hub, &response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("invalid_challenge"));
}

#[tokio::test]
async fn fresh_challenge_and_response_sign_in() {
    let hub = hub_with_user(TestHub::new()).await;
    let user_id = text(&vectors("auth")["user_id"]);
    let (device_id, key) = devices().swap_remove(0);

    let (status, body) = request_challenge(&hub, &device_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["hub_id"], hub.state.hub.hub_id().as_str());
    assert_eq!(body["expires_at"], TEST_NOW + CHALLENGE_TTL_MS);
    let bytes = STANDARD.decode(text(&body["challenge"])).unwrap();
    let challenge = AuthChallenge::decode(&bytes).unwrap();
    assert_eq!(challenge.audience(), hub.state.hub.hub_id().as_str());
    assert_eq!(challenge.issued_at(), TEST_NOW as u64);
    assert_eq!(challenge.expires_at(), (TEST_NOW + CHALLENGE_TTL_MS) as u64);
    assert_eq!(challenge.to_bytes(), bytes);

    let response = sign_response(&bytes, &user_id, &device_id, &key);
    let (status, body) = create_session(&hub, &response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = text(&body["token"]);
    assert_eq!(get_me(&hub, &token).await, (user_id, device_id));

    let (status, body) = create_session(&hub, &response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("invalid_challenge"));
}

#[tokio::test]
async fn expired_challenge_is_rejected() {
    let hub = hub_with_user(TestHub::new()).await;
    let user_id = text(&vectors("auth")["user_id"]);
    let (device_id, key) = devices().swap_remove(0);
    let bytes = challenge_bytes(&hub, &device_id).await;
    hub.state.clock.advance(CHALLENGE_TTL_MS);
    let (status, body) =
        create_session(&hub, &sign_response(&bytes, &user_id, &device_id, &key)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("invalid_challenge"));
}

#[tokio::test]
async fn challenge_for_another_hub_is_rejected() {
    // The vector challenge names the vector hub as audience, not this one.
    let hub = hub_with_user(TestHub::new()).await;
    issue_vector_challenge(&hub).await;
    let (status, body) = create_session(&hub, &hex_bytes(&vectors("auth")["response"])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("invalid_challenge"));
}

#[tokio::test]
async fn revoked_device_is_rejected() {
    let hub = hub_with_user(TestHub::new()).await;
    let user_id = text(&vectors("auth")["user_id"]);
    let (device_id, key) = devices().swap_remove(SECOND_DEVICE_INDEX);
    let bytes = challenge_bytes(&hub, &device_id).await;

    store_device_list(
        &hub,
        hex_bytes(&vectors("identity")["device_list"]["signed"]),
    )
    .await;
    let (status, body) =
        create_session(&hub, &sign_response(&bytes, &user_id, &device_id, &key)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("device_not_active"));

    let (status, body) = request_challenge(&hub, &device_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], error("not_found"));
}

#[tokio::test]
async fn challenge_is_bound_to_its_device() {
    let hub = hub_with_user(TestHub::new()).await;
    let user_id = text(&vectors("auth")["user_id"]);
    let mut devices = devices();
    let (other_id, other_key) = devices.swap_remove(SECOND_DEVICE_INDEX);
    let (device_id, key) = devices.swap_remove(0);
    let bytes = challenge_bytes(&hub, &device_id).await;

    let (status, body) = create_session(
        &hub,
        &sign_response(&bytes, &user_id, &other_id, &other_key),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("invalid_challenge"));

    // The rejected attempt did not consume the challenge.
    let (status, body) =
        create_session(&hub, &sign_response(&bytes, &user_id, &device_id, &key)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn bad_signature_is_rejected() {
    let hub = hub_with_user(TestHub::new()).await;
    let user_id = text(&vectors("auth")["user_id"]);
    let (device_id, key) = devices().swap_remove(0);
    let bytes = challenge_bytes(&hub, &device_id).await;
    let mut response = sign_response(&bytes, &user_id, &device_id, &key);
    let last = response.len() - 1;
    response[last] ^= 1;
    let (status, body) = create_session(&hub, &response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], error("invalid_signature"));
}

#[tokio::test]
async fn challenge_request_errors() {
    let hub = hub_with_user(TestHub::new()).await;
    let user_id = text(&vectors("auth")["user_id"]);
    let device_id = devices().swap_remove(0).0;
    let other_user = text(&vectors("hosting")["hubs"][0]["hub_id"]).replacen('h', "u", 1);

    for (body, status, code) in [
        (
            json!({ "user_id": user_id }),
            StatusCode::BAD_REQUEST,
            "validation_failed",
        ),
        (
            json!({ "user_id": "alice", "device_id": device_id }),
            StatusCode::BAD_REQUEST,
            "validation_failed",
        ),
        (
            json!({ "user_id": user_id, "device_id": "d1" }),
            StatusCode::BAD_REQUEST,
            "validation_failed",
        ),
        (
            json!({ "user_id": other_user, "device_id": device_id }),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            json!({ "user_id": user_id, "device_id": "d54ta5gvdyzz26janc6rgmbeagy" }),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ] {
        let (actual, value) = post(&hub, "/v2/auth/challenge", &body).await;
        assert_eq!(
            (actual, &value["error"]["code"]),
            (status, &error(code)),
            "{body}"
        );
    }
}

#[tokio::test]
async fn malformed_responses_are_rejected() {
    let hub = hub_with_user(TestHub::new()).await;
    for body in [
        json!({}),
        json!({ "response": "not base64!" }),
        json!({ "response": STANDARD.encode([0x85, 0x01]) }),
    ] {
        let (status, value) = post(&hub, "/v2/auth/session", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(value["error"]["code"], error("validation_failed"));
    }
    // A well-formed response for a user without a DeviceList on this hub.
    let other_user = text(&vectors("hosting")["hubs"][0]["hub_id"]).replacen('h', "u", 1);
    let (device_id, key) = devices().swap_remove(0);
    let response = sign_response(&[0x80], &other_user, &device_id, &key);
    let (status, value) = create_session(&hub, &response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value["error"]["code"], error("invalid_challenge"));
}
