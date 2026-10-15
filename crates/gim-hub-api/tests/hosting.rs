//! Hosting records: GET /v2/hub, POST hosting-entry, PUT/GET hosting-record and the
//! `hosting_record.expiring` event, with the `hosting.json` vector and
//! records signed like it.

mod identity_support;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use gim_hub_api::{
    handlers::check_hosting_records,
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::hosting as store;
use gim_hub_identity::{HostingRecord, HubId, UserId};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, GetHostingRecordResponse, S2sRequest,
    S2sResponse,
};
use gim_hub_s2s::{hosting::testing::sign_record, BoxFuture, Federation, SendError};
use serde_json::{json, Value};

use identity_support::{b64, code, key, send};

const HOUR: i64 = 60 * 60 * 1000;

fn vector() -> Value {
    let path = format!(
        "{}/../../testdata/identity/hosting.json",
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

/// The vector's user root key and hub root keys.
fn vector_keys() -> (SigningKey, SigningKey, SigningKey) {
    let v = vector();
    (
        SigningKey::from_bytes(&seed(&v["hosting_record"]["user_root_seed"])),
        SigningKey::from_bytes(&seed(&v["hubs"][0]["root_seed"])),
        SigningKey::from_bytes(&seed(&v["hubs"][1]["root_seed"])),
    )
}

fn vector_user() -> String {
    vector()["hosting_record"]["user_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn vector_expires_at() -> u64 {
    vector()["hosting_record"]["expires_at"].as_u64().unwrap()
}

/// A record of the vector user, signed like the vector.
fn record(seq: u64, expires_at: u64, hub1_priority: u8) -> Vec<u8> {
    let (user, hub0, hub1) = vector_keys();
    sign_record(
        &user,
        seq,
        expires_at,
        &[(&hub0, 0), (&hub1, hub1_priority)],
    )
}

/// A hub that is the vector's hub 0, with the vector user signed in as `d1`.
async fn vector_hub() -> (TestHub, String) {
    let hub = TestHub::with_hub_seed(vector_keys().1.to_bytes());
    let token = hub.create_session(&vector_user(), "d1").await;
    (hub, token)
}

async fn put_record(hub: &TestHub, user_id: &str, record: &[u8]) -> (StatusCode, Value) {
    send(
        hub,
        Method::PUT,
        &format!("/v2/users/{user_id}/hosting-record"),
        None,
        Some(json!({ "hosting_record": b64(record) })),
    )
    .await
}

async fn get_record(hub: &TestHub, user_id: &str) -> (StatusCode, Value) {
    send(
        hub,
        Method::GET,
        &format!("/v2/users/{user_id}/hosting-record"),
        None,
        None,
    )
    .await
}

fn message(body: &Value) -> &str {
    body["error"]["message"].as_str().unwrap_or("")
}

#[test]
fn test_records_are_signed_like_the_vector() {
    let v = vector();
    assert_eq!(
        record(1, vector_expires_at(), 10),
        hex_bytes(&v["hosting_record"]["signed"])
    );
}

#[tokio::test]
async fn hub_identity_needs_no_token() {
    let hub = TestHub::with_hub_seed(vector_keys().1.to_bytes());
    let (status, body) = send(&hub, Method::GET, "/v2/hub", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let v = vector();
    assert_eq!(
        body,
        json!({
            "hub_id": v["hubs"][0]["hub_id"],
            "hub_root_pubkey": b64(&hex_bytes(&v["hubs"][0]["root_pubkey"])),
            "version": env!("CARGO_PKG_VERSION"),
        })
    );
}

#[tokio::test]
async fn hosting_entry_is_signed_for_the_caller() {
    let (hub, token) = vector_hub().await;
    let uri = format!("/v2/users/{}/hosting-entry", vector_user());
    let post = |priority: Value, token: Option<String>, uri: String| {
        let hub = &hub;
        async move {
            send(
                hub,
                Method::POST,
                &uri,
                token.as_deref(),
                Some(json!({ "priority": priority })),
            )
            .await
        }
    };

    let (status, body) = post(json!(0), Some(token.clone()), uri.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let v = vector();
    assert_eq!(body["hub_id"], v["hubs"][0]["hub_id"]);
    assert_eq!(
        body["hub_root_pubkey"],
        b64(&hex_bytes(&v["hubs"][0]["root_pubkey"]))
    );
    assert_eq!(body["priority"], 0);
    // The vector record embeds exactly this entry.
    let entry = STANDARD.decode(body["entry"].as_str().unwrap()).unwrap();
    let signed = hex_bytes(&v["hosting_record"]["signed"]);
    assert!(signed.windows(entry.len()).any(|window| window == entry));
    // Deterministic; the priority is signed.
    let (_, again) = post(json!(0), Some(token.clone()), uri.clone()).await;
    assert_eq!(again, body);
    let (_, other) = post(json!(10), Some(token.clone()), uri.clone()).await;
    assert_ne!(other["entry"], body["entry"]);
    // An empty body means priority 0.
    let (status, default) = send(&hub, Method::POST, &uri, Some(&token), Some(json!({}))).await;
    assert_eq!((status, &default), (StatusCode::OK, &body));

    let (status, body) = post(json!(256), Some(token.clone()), uri.clone()).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, "validation_failed")
    );
    let (status, body) = post(json!(-1), Some(token.clone()), uri.clone()).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, "validation_failed")
    );
    let other_user = format!(
        "/v2/users/{}/hosting-entry",
        UserId::from_root_pubkey(&key(9).verifying_key())
    );
    let (status, body) = post(json!(0), Some(token), other_user).await;
    assert_eq!((status, code(&body)), (StatusCode::FORBIDDEN, "forbidden"));
    let (status, body) = post(json!(0), None, uri).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNAUTHORIZED, "unauthorized")
    );
}

#[tokio::test]
async fn upload_replace_and_fetch() {
    let (hub, _) = vector_hub().await;
    let user = vector_user();
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "not_found"));

    let signed = hex_bytes(&vector()["hosting_record"]["signed"]);
    let (status, body) = put_record(&hub, &user, &signed).await;
    assert_eq!(status, StatusCode::CREATED);
    let expected = json!({
        "user_id": user,
        "hosting_record": b64(&signed),
        "seq": 1,
        "expires_at": vector_expires_at(),
        "hosted": true,
    });
    assert_eq!(body, expected);
    // Idempotent re-upload.
    let (status, body) = put_record(&hub, &user, &signed).await;
    assert_eq!((status, &body), (StatusCode::OK, &expected));
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!((status, &body), (StatusCode::OK, &expected));

    // A higher seq replaces; a lower one, or the same seq with another
    // body, is stale.
    let seq2 = record(2, vector_expires_at() + 1000, 10);
    let (status, body) = put_record(&hub, &user, &seq2).await;
    assert_eq!((status, body["seq"].clone()), (StatusCode::OK, json!(2)));
    let (status, body) = put_record(&hub, &user, &signed).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, "stale_hosting_record")
    );
    let conflicting = record(2, vector_expires_at() + 1000, 20);
    let (status, body) = put_record(&hub, &user, &conflicting).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, "stale_hosting_record")
    );
    let (_, body) = get_record(&hub, &user).await;
    assert_eq!(body["hosting_record"], b64(&seq2));
}

#[tokio::test]
async fn upload_checks_in_order() {
    let (hub, _) = vector_hub().await;
    let user = vector_user();
    let (user_key, hub0, _) = vector_keys();
    let now = TEST_NOW as u64;
    let invalid = |body: &Value, reason: &str| {
        assert_eq!(code(body), "invalid_hosting_record");
        assert!(message(body).contains(reason), "{body}");
    };

    // 1. Verification: another user's record, a tampered one, expired.
    let stranger = UserId::from_root_pubkey(&key(9).verifying_key()).to_string();
    hub.create_session(&stranger, "d9").await;
    let (status, body) = put_record(&hub, &stranger, &record(1, now + 2 * HOUR as u64, 10)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    invalid(&body, "user_id_mismatch");
    let mut tampered = record(1, now + 2 * HOUR as u64, 10);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let (status, body) = put_record(&hub, &user, &tampered).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    invalid(&body, "bad_signature");
    let (status, body) = put_record(&hub, &user, &record(1, now, 10)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    invalid(&body, "expired");
    let (status, body) = send(
        &hub,
        Method::PUT,
        &format!("/v2/users/{user}/hosting-record"),
        None,
        Some(json!({ "hosting_record": "not base64!" })),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_hosting_record")
    );
    let (status, body) = put_record(&hub, &user, &[0; 8193]).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
    );

    // 2. A user of this hub, checked before the lifetime.
    let remote = SigningKey::from_bytes(&[42; 32]);
    let remote_id = UserId::from_root_pubkey(&remote.verifying_key()).to_string();
    let short = sign_record(&remote, 1, now + 1000, &[(&hub0, 0)]);
    let (status, body) = put_record(&hub, &remote_id, &short).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "not_found"));

    // 3. Lifetime 1 hour ..= 30 days.
    for expires_at in [now + HOUR as u64 - 1, now + 30 * 24 * HOUR as u64 + 1] {
        let (status, body) = put_record(&hub, &user, &record(1, expires_at, 10)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        invalid(&body, "lifetime_out_of_range");
    }
    for expires_at in [now + HOUR as u64, now + 30 * 24 * HOUR as u64] {
        let seq = expires_at - now; // increasing
        let (status, _) = put_record(
            &hub,
            &user,
            &sign_record(&user_key, seq, expires_at, &[(&hub0, 0)]),
        )
        .await;
        assert!(status.is_success(), "{status}");
    }
}

#[tokio::test]
async fn record_not_listing_this_hub_is_stored_unhosted() {
    let (hub, _) = vector_hub().await;
    let user = vector_user();
    let (user_key, _, hub1) = vector_keys();
    let moved = sign_record(&user_key, 1, vector_expires_at(), &[(&hub1, 0)]);
    let (status, body) = put_record(&hub, &user, &moved).await;
    assert_eq!(
        (status, body["hosted"].clone()),
        (StatusCode::CREATED, json!(false))
    );
    assert!(matches!(
        hub.state.hosting.require_hosting_record(&user).await,
        Err(gim_hub_s2s::HostingError::Required)
    ));

    let (status, _) = put_record(&hub, &user, &record(2, vector_expires_at(), 10)).await;
    assert_eq!(status, StatusCode::OK);
    let required = hub
        .state
        .hosting
        .require_hosting_record(&user)
        .await
        .unwrap();
    assert_eq!(required.seq(), 2);
    hub.state
        .clock
        .advance(vector_expires_at() as i64 - TEST_NOW);
    assert!(hub
        .state
        .hosting
        .require_hosting_record(&user)
        .await
        .is_err());
    let (status, _) = get_record(&hub, &user).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A peer hub answering `GetHostingRecord` with `record`, or unreachable.
struct FakePeer(Option<Vec<u8>>);

impl Federation for FakePeer {
    fn is_enabled(&self) -> bool {
        true
    }

    fn send(
        &self,
        _: &HubId,
        request: S2sRequest,
    ) -> BoxFuture<'_, Result<S2sResponse, SendError>> {
        let response = match (&self.0, request.op) {
            (Some(record), Some(Op::GetHostingRecord(_))) => Ok(S2sResponse {
                request_id: request.request_id,
                result: Some(OpOutput::GetHostingRecord(GetHostingRecordResponse {
                    hosting_record_cbor: record.clone(),
                })),
                error: None,
            }),
            _ => Err(SendError::Unreachable("down".into())),
        };
        Box::pin(async move { response })
    }
}

/// Caches `record` of a remote user as fetched at `fetched_at`.
async fn cache(hub: &TestHub, user_id: &str, record: &[u8], fetched_at: i64) {
    let record = HostingRecord::verify_claimed(record, 0).unwrap();
    assert_eq!(record.user_id().as_str(), user_id);
    let stored = gim_hub_s2s::hosting::stored_record(&record, false, fetched_at).unwrap();
    hub.state
        .db
        .write(move |tx| store::put(tx, &stored))
        .await
        .unwrap();
}

#[tokio::test]
async fn remote_users_resolve_from_cache_and_peers() {
    // This hub is the vector's hub 1; the vector user is remote.
    let mut hub = TestHub::with_hub_seed(vector_keys().2.to_bytes());
    let user = vector_user();
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "not_found"));

    // A fresh cache row answers, `hosted` false although it lists this hub.
    let seq1 = hex_bytes(&vector()["hosting_record"]["signed"]);
    cache(&hub, &user, &seq1, TEST_NOW).await;
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["seq"].clone(), body["hosted"].clone()),
        (json!(1), json!(false))
    );

    // Stale: the primary hub is asked; its newer record replaces the cache.
    let seq2 = record(2, vector_expires_at(), 10);
    hub.set_federation(Arc::new(FakePeer(Some(seq2.clone()))));
    hub.state.clock.advance(HOUR);
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!((status, body["seq"].clone()), (StatusCode::OK, json!(2)));
    let stored = hub
        .state
        .db
        .read({
            let user = user.clone();
            move |conn| store::get(conn, &user)
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!((stored.seq, stored.fetched_at), (2, TEST_NOW + HOUR));

    // Peers down: a stale but unexpired cache still answers; an expired one
    // with nothing else known is 503 with Retry-After.
    hub.set_federation(Arc::new(FakePeer(None)));
    hub.state.clock.advance(HOUR);
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!((status, body["seq"].clone()), (StatusCode::OK, json!(2)));
    hub.state
        .clock
        .advance(vector_expires_at() as i64 - TEST_NOW - 2 * HOUR);
    let (status, body) = get_record(&hub, &user).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::SERVICE_UNAVAILABLE, "peer_unavailable")
    );
}

#[tokio::test]
async fn expiring_event_is_emitted_once_per_record() {
    let (hub, _) = vector_hub().await;
    let user = vector_user();
    let signed = hex_bytes(&vector()["hosting_record"]["signed"]);
    let (status, _) = put_record(&hub, &user, &signed).await;
    assert_eq!(status, StatusCode::CREATED);
    // Events of device d1, with a fresh session (sessions last 24 hours).
    let events = || {
        let (hub, user) = (&hub, &user);
        async move {
            let token = hub.create_session(user, "d1").await;
            let (status, body) = send(hub, Method::GET, "/v2/events", Some(&token), None).await;
            assert_eq!(status, StatusCode::OK);
            body["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|event| event["type"] == "hosting_record.expiring")
                .cloned()
                .collect::<Vec<_>>()
        }
    };

    // 50 hours left: nothing yet.
    assert_eq!(check_hosting_records(&hub.state).await.unwrap(), (0, 0));
    hub.state.clock.advance(3 * HOUR);
    assert_eq!(check_hosting_records(&hub.state).await.unwrap(), (0, 1));
    let emitted = events().await;
    assert_eq!(emitted.len(), 1);
    assert_eq!(
        emitted[0]["data"],
        json!({ "user_id": user, "expires_at": vector_expires_at(), "seq": 1 })
    );
    assert_eq!(emitted[0]["created_at"], TEST_NOW + 3 * HOUR);

    // Hourly checks do not repeat it for the same seq.
    for _ in 0..30 {
        hub.state.clock.advance(HOUR);
        assert_eq!(check_hosting_records(&hub.state).await.unwrap(), (0, 0));
    }
    assert_eq!(events().await.len(), 1);

    // Expiry: the local row stays (ordering future uploads) but is no
    // longer hosted.
    hub.state.clock.advance(20 * HOUR);
    assert_eq!(check_hosting_records(&hub.state).await.unwrap(), (1, 0));
    let stored = hub
        .state
        .db
        .read({
            let user = user.clone();
            move |conn| store::get(conn, &user)
        })
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.hosted);
    assert_eq!(events().await.len(), 1);
}
