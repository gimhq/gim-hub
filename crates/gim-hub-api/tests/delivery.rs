//! Message delivery: application messages, the event stream (long-poll and
//! WebSocket), pending Welcomes and blobs.
//!
//! Groups and members are seeded directly in the database; MLS messages are
//! real openmls PrivateMessages for a group whose MLS group ID is the gid.

use std::{sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header, HeaderMap, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite;
use tower::ServiceExt;

use gim_hub_api::{
    dto::GID_EXAMPLE,
    testing::{TestHub, TEST_NOW},
    Config,
};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The sender's side of an MLS group with group ID `gid`.
struct MlsSender {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl MlsSender {
    fn new(gid: &str) -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(gid.as_bytes()),
            credential,
        )
        .unwrap();
        Self {
            provider,
            signer,
            group,
        }
    }

    /// An application PrivateMessage for the current epoch (0).
    fn application(&mut self, text: &[u8]) -> Vec<u8> {
        self.group
            .create_message(&self.provider, &self.signer, text)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    /// A Commit (sent as PrivateMessage under the default wire format policy).
    fn commit(&mut self) -> Vec<u8> {
        self.group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .unwrap()
            .commit()
            .to_bytes()
            .unwrap()
    }
}

fn encoded(gid: &str) -> String {
    gid.replace('/', "%2F")
}

/// Stores a group at `epoch` with the given member devices.
async fn seed_group(hub: &TestHub, gid: &str, epoch: i64, members: &[(&str, &str)]) {
    let gid = gid.to_owned();
    let members: Vec<(String, String)> = members
        .iter()
        .map(|(u, d)| ((*u).to_owned(), (*d).to_owned()))
        .collect();
    hub.state
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO groups (gid, kind, epoch, created_by_user_id, created_by_device_id, \
                 created_at) VALUES (?1, 'group', ?2, 'u1', 'd1', 0)",
                (gid.as_str(), epoch),
            )
            .map_err(gim_hub_db::DbError::from)?;
            for (user_id, device_id) in &members {
                tx.execute(
                    "INSERT INTO group_members (gid, user_id, device_id, added_at) \
                     VALUES (?1, ?2, ?3, 0)",
                    [gid.as_str(), user_id, device_id],
                )
                .map_err(gim_hub_db::DbError::from)?;
            }
            Ok::<_, gim_hub_db::DbError>(())
        })
        .await
        .unwrap();
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap().to_owned()
    }
}

async fn call(
    hub: &TestHub,
    method: Method,
    uri: &str,
    token: &str,
    headers: &[(header::HeaderName, &str)],
    body: impl Into<Body>,
) -> Reply {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    let response = hub
        .router()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap();
    Reply {
        status: response.status(),
        headers: response.headers().clone(),
        body: to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    }
}

async fn get(hub: &TestHub, uri: &str, token: &str) -> Reply {
    call(hub, Method::GET, uri, token, &[], Body::empty()).await
}

async fn send(hub: &TestHub, gid: &str, token: &str, client_id: &str, mls: &[u8]) -> Reply {
    let body = json!({ "client_id": client_id, "mls_message": STANDARD.encode(mls) });
    call(
        hub,
        Method::POST,
        &format!("/v2/groups/{}/messages", encoded(gid)),
        token,
        &[(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
    .await
}

async fn events(hub: &TestHub, token: &str, query: &str) -> Reply {
    get(hub, &format!("/v2/events?{query}"), token).await
}

fn with_config(hub: &mut TestHub, edit: impl FnOnce(&mut Config)) {
    let mut config = (*hub.state.config).clone();
    edit(&mut config);
    hub.state.config = Arc::new(config);
}

/// Alice (u1) with devices d1 and d2, Bob (u2) with d1, all in one group.
struct Fixture {
    hub: TestHub,
    alice: String,
    alice2: String,
    bob: String,
    mls: MlsSender,
}

async fn fixture() -> Fixture {
    let hub = TestHub::new();
    let alice = hub.create_session("u1", "d1").await;
    let alice2 = hub.create_session("u1", "d2").await;
    let bob = hub.create_session("u2", "d1").await;
    seed_group(
        &hub,
        GID_EXAMPLE,
        0,
        &[("u1", "d1"), ("u1", "d2"), ("u2", "d1")],
    )
    .await;
    Fixture {
        hub,
        alice,
        alice2,
        bob,
        mls: MlsSender::new(GID_EXAMPLE),
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_stores_fans_out_and_replays() {
    let mut f = fixture().await;
    let mls = f.mls.application(b"hello");
    let reply = send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let message = reply.json();
    let message_id = f
        .hub
        .state
        .db
        .read(|conn| gim_hub_db::push::message_id_at(conn, GID_EXAMPLE, 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        message,
        json!({
            "gid": GID_EXAMPLE,
            "seq": 1,
            "sender_user_id": "u1",
            "sender_device_id": "d1",
            "client_id": "c1",
            "message_id": message_id,
            "kind": "application",
            "epoch": 0,
            "mls_message": STANDARD.encode(&mls),
            "created_at": TEST_NOW,
        })
    );

    // Every member device except the sender gets a message event.
    for token in [&f.bob, &f.alice2] {
        let reply = events(&f.hub, token, "cursor=0").await;
        assert_eq!(reply.status, StatusCode::OK);
        let body = reply.json();
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "message");
        assert_eq!(events[0]["created_at"], TEST_NOW);
        assert_eq!(events[0]["data"], message);
        assert_eq!(body["next_cursor"], events[0]["cursor"]);
    }
    let own = events(&f.hub, &f.alice, "cursor=0").await.json();
    assert_eq!(own, json!({ "events": [], "next_cursor": 0 }));

    // Same client_id again: the stored message, nothing emitted.
    let other = f.mls.application(b"retry");
    let reply = send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &other).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), message);
    let body = events(&f.hub, &f.bob, "cursor=0").await.json();
    assert_eq!(body["events"].as_array().unwrap().len(), 1);

    // The same client_id from another device is a new message.
    let reply = send(&f.hub, GID_EXAMPLE, &f.alice2, "c1", &other).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.json()["seq"], 2);
}

#[tokio::test]
async fn legacy_message_event_gets_message_id() {
    let mut f = fixture().await;
    let mls = f.mls.application(b"hello");
    let message = send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await.json();
    // A message event stored before `message_id` existed, and one for a
    // message no longer stored here.
    let mut legacy = message.clone();
    legacy.as_object_mut().unwrap().remove("message_id");
    let mut gone = legacy.clone();
    gone["seq"] = json!(9);
    let payloads = [legacy.to_string(), gone.to_string()];
    f.hub
        .state
        .db
        .write(move |tx| {
            for payload in &payloads {
                gim_hub_db::events::append(tx, "u2", "d1", "message", payload, TEST_NOW)?;
            }
            Ok::<_, gim_hub_db::DbError>(())
        })
        .await
        .unwrap();

    let body = events(&f.hub, &f.bob, "cursor=0").await.json();
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[1]["data"], message);
    let stand_in = f
        .hub
        .state
        .db
        .read(|conn| gim_hub_push::message_id(conn, GID_EXAMPLE, 9))
        .await
        .unwrap();
    assert_eq!(events[2]["data"]["message_id"], json!(stand_in));
}

#[tokio::test]
async fn list_messages_from_seq() {
    let mut f = fixture().await;
    for i in 1..=3 {
        let mls = f.mls.application(format!("m{i}").as_bytes());
        let reply = send(&f.hub, GID_EXAMPLE, &f.alice, &format!("c{i}"), &mls).await;
        assert_eq!(reply.status, StatusCode::CREATED);
    }
    let uri = |query: &str| format!("/v2/groups/{}/messages?{query}", encoded(GID_EXAMPLE));
    let seqs = |body: &Value| -> Vec<u64> {
        body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["seq"].as_u64().unwrap())
            .collect()
    };

    let body = get(&f.hub, &uri(""), &f.bob).await.json();
    assert_eq!(seqs(&body), [1, 2, 3]);
    assert_eq!(body["has_more"], false);

    let body = get(&f.hub, &uri("from_seq=2"), &f.bob).await.json();
    assert_eq!(seqs(&body), [2, 3]);
    assert_eq!(body["messages"][0]["client_id"], "c2");

    let body = get(&f.hub, &uri("from_seq=1&limit=2"), &f.bob).await.json();
    assert_eq!(seqs(&body), [1, 2]);
    assert_eq!(body["has_more"], true);

    let body = get(&f.hub, &uri("from_seq=4"), &f.bob).await.json();
    assert_eq!(seqs(&body), Vec::<u64>::new());

    for bad in ["from_seq=0", "limit=0", "limit=501", "from_seq=x"] {
        let reply = get(&f.hub, &uri(bad), &f.bob).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(reply.code(), "validation_failed");
    }

    let outsider = f.hub.create_session("u3", "d1").await;
    let reply = get(&f.hub, &uri(""), &outsider).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "not_member");

    let reply = get(&f.hub, "/v2/groups/nope%2Fnope/messages", &f.bob).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stale_epoch_is_rejected() {
    let f = fixture().await;
    let gid = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA/stale";
    seed_group(&f.hub, gid, 5, &[("u1", "d1")]).await;
    let mls = MlsSender::new(gid).application(b"old");
    let reply = send(&f.hub, gid, &f.alice, "c1", &mls).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    let body = reply.json();
    assert_eq!(body["error"]["code"], "stale_epoch");
    assert_eq!(body["current_epoch"], 5);
}

#[tokio::test]
async fn non_member_and_unknown_group_are_rejected() {
    let mut f = fixture().await;
    let outsider = f.hub.create_session("u3", "d1").await;
    let mls = f.mls.application(b"hi");
    let reply = send(&f.hub, GID_EXAMPLE, &outsider, "c1", &mls).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "not_member");

    let gid = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA/missing";
    let mls = MlsSender::new(gid).application(b"hi");
    let reply = send(&f.hub, gid, &f.alice, "c1", &mls).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn too_large_message_is_rejected() {
    let mut f = fixture().await;
    with_config(&mut f.hub, |config| config.max_message_bytes = 64);
    let mls = f.mls.application(&[7u8; 128]);
    assert!(mls.len() > 64);
    let reply = send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.code(), "payload_too_large");

    // A body far beyond the limit is cut off before parsing.
    let huge = vec![b'a'; 64 * 1024];
    let reply = call(
        &f.hub,
        Method::POST,
        &format!("/v2/groups/{}/messages", encoded(GID_EXAMPLE)),
        &f.alice,
        &[],
        huge,
    )
    .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn invalid_messages_are_rejected() {
    let mut f = fixture().await;
    let commit = f.mls.commit();
    let other_group = MlsSender::new("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA/other")
        .application(b"hi");
    for (name, mls) in [
        ("handshake", commit),
        ("other group", other_group),
        ("garbage", b"not mls".to_vec()),
    ] {
        let reply = send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(reply.code(), "validation_failed", "{name}");
    }

    let uri = format!("/v2/groups/{}/messages", encoded(GID_EXAMPLE));
    for body in [
        json!({ "client_id": "", "mls_message": "" }),
        json!({ "client_id": "x".repeat(65), "mls_message": "" }),
        json!({ "client_id": "c1", "mls_message": "%%%" }),
        json!({ "client_id": "c1" }),
    ] {
        let reply = call(&f.hub, Method::POST, &uri, &f.alice, &[], body.to_string()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn long_poll_wakes_on_send() {
    let mut f = fixture().await;
    let hub = Arc::new(f.hub);
    let poll = {
        let (hub, bob) = (hub.clone(), f.bob.clone());
        tokio::spawn(async move { events(&hub, &bob, "cursor=0&wait=20").await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!poll.is_finished());

    let started = std::time::Instant::now();
    let mls = f.mls.application(b"wake");
    assert_eq!(
        send(&hub, GID_EXAMPLE, &f.alice, "c1", &mls).await.status,
        StatusCode::CREATED
    );
    let reply = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .expect("long-poll woke up")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["events"][0]["type"], "message");
    assert_eq!(body["events"][0]["data"]["client_id"], "c1");
}

#[tokio::test]
async fn long_poll_times_out_empty() {
    let mut hub = TestHub::new();
    with_config(&mut hub, |config| config.longpoll_max_wait_seconds = 1);
    let token = hub.create_session("u1", "d1").await;
    let started = std::time::Instant::now();
    let reply = events(&hub, &token, "cursor=7&wait=30").await;
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(reply.json(), json!({ "events": [], "next_cursor": 7 }));

    for bad in ["wait=31", "limit=0", "limit=501", "cursor=-1"] {
        let reply = events(&hub, &token, bad).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(reply.code(), "validation_failed");
    }
}

#[tokio::test]
async fn events_paginate_with_limit() {
    let mut f = fixture().await;
    for i in 1..=3 {
        let mls = f.mls.application(b"m");
        send(&f.hub, GID_EXAMPLE, &f.alice, &format!("c{i}"), &mls).await;
    }
    let first = events(&f.hub, &f.bob, "cursor=0&limit=2").await.json();
    assert_eq!(first["events"].as_array().unwrap().len(), 2);
    let next = first["next_cursor"].as_u64().unwrap();
    assert_eq!(Some(next), first["events"][1]["cursor"].as_u64());
    let rest = events(&f.hub, &f.bob, &format!("cursor={next}"))
        .await
        .json();
    assert_eq!(rest["events"].as_array().unwrap().len(), 1);
    assert_eq!(rest["events"][0]["data"]["seq"], 3);
}

#[tokio::test]
async fn pruned_cursor_is_gone() {
    let mut f = fixture().await;
    let mls = f.mls.application(b"old");
    send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;
    f.hub.state.clock.advance(8 * DAY_MS);
    // Test sessions live one day; sign in again.
    f.alice = f.hub.create_session("u1", "d1").await;
    f.bob = f.hub.create_session("u2", "d1").await;
    let mls = f.mls.application(b"new");
    let reply = send(&f.hub, GID_EXAMPLE, &f.alice, "c2", &mls).await;
    assert_eq!(reply.status, StatusCode::CREATED);

    let cutoff = f.hub.state.clock.now_ms() - 7 * DAY_MS;
    let pruned = f
        .hub
        .state
        .db
        .write(move |tx| gim_hub_db::events::prune_before(tx, cutoff))
        .await
        .unwrap();
    assert_eq!(pruned, 2);

    let reply = events(&f.hub, &f.bob, "cursor=0").await;
    assert_eq!(reply.status, StatusCode::GONE);
    let body = reply.json();
    assert_eq!(body["error"]["code"], "cursor_expired");
    let head = body["cursor"].as_u64().unwrap();
    assert_eq!(head, 4);

    // Bob's cursor after the pruned events still works.
    let reply = events(&f.hub, &f.bob, "cursor=2").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["events"][0]["data"]["client_id"], "c2");
    let reply = events(&f.hub, &f.bob, &format!("cursor={head}")).await;
    assert_eq!(reply.json(), json!({ "events": [], "next_cursor": head }));
}

// ---------------------------------------------------------------------------
// WebSocket stream
// ---------------------------------------------------------------------------

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn serve(hub: &TestHub) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = hub.router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

async fn next_frame(ws: &mut Ws) -> tungstenite::Message {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("frame within 5s")
            .expect("stream open")
            .expect("valid frame");
        if !matches!(
            frame,
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_)
        ) {
            return frame;
        }
    }
}

async fn next_json(ws: &mut Ws) -> Value {
    match next_frame(ws).await {
        tungstenite::Message::Text(text) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

async fn expect_close(ws: &mut Ws, code: u16) {
    match next_frame(ws).await {
        tungstenite::Message::Close(Some(frame)) => assert_eq!(u16::from(frame.code), code),
        other => panic!("expected close {code}, got {other:?}"),
    }
}

#[tokio::test]
async fn stream_replays_then_pushes_live_events() {
    let mut f = fixture().await;
    let addr = serve(&f.hub).await;
    let mls = f.mls.application(b"backlog");
    send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;

    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/v2/stream?cursor=0&token={}", f.bob))
            .await
            .unwrap();
    let frame = next_json(&mut ws).await;
    assert_eq!(frame["type"], "event");
    assert_eq!(frame["event"]["type"], "message");
    assert_eq!(frame["event"]["data"]["client_id"], "c1");
    let first_cursor = frame["event"]["cursor"].as_u64().unwrap();

    let mls = f.mls.application(b"live");
    send(&f.hub, GID_EXAMPLE, &f.alice, "c2", &mls).await;
    let frame = next_json(&mut ws).await;
    assert_eq!(frame["event"]["data"]["client_id"], "c2");
    assert!(frame["event"]["cursor"].as_u64().unwrap() > first_cursor);
}

#[tokio::test]
async fn stream_accepts_bearer_header() {
    let mut f = fixture().await;
    let addr = serve(&f.hub).await;
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(format!(
        "ws://{addr}/v2/stream"
    ))
    .unwrap();
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {}", f.bob).parse().unwrap(),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    // Let the hub subscribe before sending.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mls = f.mls.application(b"live");
    send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;
    let frame = next_json(&mut ws).await;
    assert_eq!(frame["event"]["data"]["client_id"], "c1");
}

#[tokio::test]
async fn stream_rejects_bad_token_and_expired_cursor() {
    let mut f = fixture().await;
    let addr = serve(&f.hub).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v2/stream?token=nope"))
        .await
        .unwrap();
    expect_close(&mut ws, 4401).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v2/stream"))
        .await
        .unwrap();
    expect_close(&mut ws, 4401).await;

    let mls = f.mls.application(b"old");
    send(&f.hub, GID_EXAMPLE, &f.alice, "c1", &mls).await;
    f.hub
        .state
        .db
        .write(|tx| gim_hub_db::events::prune_before(tx, i64::MAX))
        .await
        .unwrap();
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/v2/stream?cursor=0&token={}", f.bob))
            .await
            .unwrap();
    let frame = next_json(&mut ws).await;
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["error"]["code"], "cursor_expired");
    assert_eq!(frame["cursor"], 2);
    expect_close(&mut ws, 4410).await;
}

// ---------------------------------------------------------------------------
// Pending Welcomes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_welcomes_list_and_ack() {
    let hub = TestHub::new();
    let bob = hub.create_session("u2", "d1").await;
    let welcome = |gid: &str, seq: u64| {
        json!({
            "gid": gid,
            "sender_user_id": "u1",
            "sender_device_id": "d1",
            "epoch": 1,
            "seq": seq,
            "welcome": STANDARD.encode(b"welcome"),
        })
    };
    let (w1, w2) = (welcome("g/1", 1), welcome("g/2", 4));
    let payloads = [w1.to_string(), w2.to_string()];
    hub.state
        .db
        .write(move |tx| {
            gim_hub_db::welcomes::insert_pending(tx, "u2", "d1", "g/1", &payloads[0], 10)?;
            gim_hub_db::welcomes::insert_pending(tx, "u2", "d1", "g/2", &payloads[1], 20)?;
            gim_hub_db::welcomes::insert_pending(tx, "u2", "d2", "g/1", &payloads[0], 10)
        })
        .await
        .unwrap();

    let with_created_at = |mut value: Value, at: i64| {
        value["created_at"] = at.into();
        value
    };
    let reply = get(&hub, "/v2/welcomes/pending", &bob).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({ "welcomes": [with_created_at(w1, 10), with_created_at(w2.clone(), 20)] })
    );
    let body = get(&hub, "/v2/welcomes/pending?limit=1", &bob).await.json();
    assert_eq!(body["welcomes"].as_array().unwrap().len(), 1);
    for bad in ["limit=0", "limit=201"] {
        let reply = get(&hub, &format!("/v2/welcomes/pending?{bad}"), &bob).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }

    for _ in 0..2 {
        let reply = call(
            &hub,
            Method::POST,
            "/v2/welcomes/g%2F1/ack",
            &bob,
            &[],
            Body::empty(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        assert!(reply.body.is_empty());
    }
    let reply = call(
        &hub,
        Method::POST,
        "/v2/welcomes/unknown/ack",
        &bob,
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&hub, "/v2/welcomes/pending", &bob).await.json(),
        json!({ "welcomes": [with_created_at(w2, 20)] })
    );
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

async fn upload(hub: &TestHub, token: &str, data: &[u8]) -> Reply {
    call(
        hub,
        Method::POST,
        "/v2/blobs",
        token,
        &[(header::CONTENT_TYPE, "application/octet-stream")],
        data.to_vec(),
    )
    .await
}

#[tokio::test]
async fn blob_roundtrip_with_ranges() {
    let hub = TestHub::new();
    let alice = hub.create_session("u1", "d1").await;
    let bob = hub.create_session("u2", "d1").await;
    let data: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();

    let reply = upload(&hub, &alice, &data).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let body = reply.json();
    assert_eq!(body["size"], data.len());
    let blob_id = body["blob_id"].as_str().unwrap().to_owned();
    let (origin, random) = blob_id.split_once('/').unwrap();
    assert_eq!(origin, hub.state.hub.hub_id().as_str());
    assert!(random.starts_with("b_"));
    assert!(hub
        .state
        .config
        .blobs_dir()
        .join(blob_id.replace('/', "_"))
        .is_file());
    // No temp files are left behind.
    assert_eq!(
        std::fs::read_dir(hub.state.config.blobs_dir())
            .unwrap()
            .count(),
        1
    );

    let uri = format!("/v2/blobs/{}", encoded(&blob_id));
    let reply = get(&hub, &uri, &bob).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, data);
    assert_eq!(reply.headers[header::CONTENT_LENGTH], "200000");
    assert_eq!(reply.headers[header::ACCEPT_RANGES], "bytes");

    let range = |value: &'static str| {
        let (hub, bob, uri) = (&hub, bob.clone(), uri.clone());
        async move {
            call(
                hub,
                Method::GET,
                &uri,
                &bob,
                &[(header::RANGE, value)],
                Body::empty(),
            )
            .await
        }
    };
    let reply = range("bytes=10-19").await;
    assert_eq!(reply.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(reply.body, data[10..20]);
    assert_eq!(reply.headers[header::CONTENT_RANGE], "bytes 10-19/200000");

    let reply = range("bytes=-5").await;
    assert_eq!(reply.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(reply.body, data[199_995..]);

    let reply = range("bytes=150000-").await;
    assert_eq!(reply.body, data[150_000..]);

    let reply = range("bytes=200000-").await;
    assert_eq!(reply.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(reply.code(), "range_not_satisfiable");
    assert_eq!(reply.headers[header::CONTENT_RANGE], "bytes */200000");

    let reply = range("bytes=0-1,5-6").await;
    assert_eq!(reply.status, StatusCode::OK);

    let reply = get(&hub, "/v2/blobs/b_unknown", &bob).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let reply = get(&hub, "/v2/blobs/..%2Fhub_key", &bob).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn blob_size_limit() {
    let mut hub = TestHub::new();
    with_config(&mut hub, |config| config.max_blob_bytes = 16);
    let token = hub.create_session("u1", "d1").await;

    let reply = upload(&hub, &token, &[1u8; 16]).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.json()["size"], 16);

    let reply = upload(&hub, &token, &[1u8; 17]).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.code(), "payload_too_large");

    // Without Content-Length the limit applies while streaming.
    let chunks = futures_util::stream::iter(
        [vec![1u8; 10], vec![2u8; 10]]
            .into_iter()
            .map(Ok::<_, std::io::Error>),
    );
    let reply = call(
        &hub,
        Method::POST,
        "/v2/blobs",
        &token,
        &[],
        Body::from_stream(chunks),
    )
    .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Only the first, accepted blob remains; the partial upload was removed.
    assert_eq!(
        std::fs::read_dir(hub.state.config.blobs_dir())
            .unwrap()
            .count(),
        1
    );
}
