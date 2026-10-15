//! Long-lived event delivery re-checks the session: a WebSocket stream is
//! closed with 4401 and a long-poll answers 401 once the session is deleted,
//! expires or its device is revoked.

mod identity_support;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use futures_util::StreamExt;
use gim_hub_api::testing::{TestHub, TEST_SESSION_TTL_MS};
use gim_hub_db::{events, DbError};
use serde_json::Value;
use tokio_tungstenite::tungstenite;

use identity_support::{code, device_id, device_list, put_device_list, send, user_id};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn serve(hub: &TestHub) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = hub.router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

async fn connect(hub: &TestHub, token: &str) -> Ws {
    let addr = serve(hub).await;
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v2/stream?token={token}"))
        .await
        .unwrap();
    ws
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

async fn next_event_type(ws: &mut Ws) -> String {
    match next_frame(ws).await {
        tungstenite::Message::Text(text) => {
            let frame: Value = serde_json::from_str(text.as_str()).unwrap();
            frame["event"]["type"].as_str().unwrap().to_owned()
        }
        other => panic!("expected a text frame, got {other:?}"),
    }
}

async fn expect_close(ws: &mut Ws, code: u16) {
    match next_frame(ws).await {
        tungstenite::Message::Close(Some(frame)) => assert_eq!(u16::from(frame.code), code),
        other => panic!("expected close {code}, got {other:?}"),
    }
}

/// Appends an event of type `event_type` for the device and wakes it.
async fn push_event(hub: &TestHub, user: &str, device: &str, event_type: &'static str) {
    let now = hub.state.clock.now_ms();
    let (u, d) = (user.to_owned(), device.to_owned());
    hub.state
        .db
        .write(move |tx| events::append(tx, &u, &d, event_type, "{}", now))
        .await
        .unwrap();
    hub.state.notifier.notify(user, device);
}

async fn delete_sessions(hub: &TestHub, user: &str, device: &str) {
    let (u, d) = (user.to_owned(), device.to_owned());
    hub.state
        .db
        .write(move |tx| {
            tx.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND device_id = ?2",
                [&u, &d],
            )?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
}

/// A live stream of u1/d1: one event delivered, then waiting for more.
async fn live_stream(hub: &TestHub) -> Ws {
    let token = hub.create_session("u1", "d1").await;
    let mut ws = connect(hub, &token).await;
    push_event(hub, "u1", "d1", "before").await;
    assert_eq!(next_event_type(&mut ws).await, "before");
    ws
}

#[tokio::test]
async fn stream_closes_when_device_is_revoked() {
    let hub = TestHub::new();
    let user = user_id(1);
    let (d2, d3) = (device_id(2), device_id(3));
    assert_eq!(
        put_device_list(&hub, &user, &device_list(1, 1, &[2, 3], &[]))
            .await
            .0,
        StatusCode::CREATED
    );
    let token = hub.create_session(&user, &d2).await;
    let mut ws = connect(&hub, &token).await;
    push_event(&hub, &user, &d2, "before").await;
    assert_eq!(next_event_type(&mut ws).await, "before");

    let v2 = device_list(1, 2, &[3], &[2]);
    assert_eq!(put_device_list(&hub, &user, &v2).await.0, StatusCode::OK);
    // The upload alone wakes the revoked device's stream.
    expect_close(&mut ws, 4401).await;

    // The remaining device still gets the update.
    let token = hub.create_session(&user, &d3).await;
    let (status, body) = send(&hub, Method::GET, "/v2/events", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["events"][0]["type"], "device_list.updated");
}

#[tokio::test]
async fn stream_closes_when_session_is_deleted() {
    let hub = TestHub::new();
    let mut ws = live_stream(&hub).await;
    delete_sessions(&hub, "u1", "d1").await;
    push_event(&hub, "u1", "d1", "after").await;
    expect_close(&mut ws, 4401).await;
}

#[tokio::test]
async fn stream_closes_when_session_expires() {
    let hub = TestHub::new();
    let mut ws = live_stream(&hub).await;
    hub.state.clock.advance(TEST_SESSION_TTL_MS);
    push_event(&hub, "u1", "d1", "after").await;
    expect_close(&mut ws, 4401).await;
}

#[tokio::test]
async fn long_poll_rejects_session_deleted_during_wait() {
    let hub = Arc::new(TestHub::new());
    let token = hub.create_session("u1", "d1").await;
    let poll = {
        let hub = hub.clone();
        tokio::spawn(async move {
            send(
                &hub,
                Method::GET,
                "/v2/events?cursor=0&wait=20",
                Some(&token),
                None,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!poll.is_finished());

    delete_sessions(&hub, "u1", "d1").await;
    push_event(&hub, "u1", "d1", "after").await;
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .expect("long-poll woke up")
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&body), "unauthorized");
}
