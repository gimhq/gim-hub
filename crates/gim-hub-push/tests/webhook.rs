//! Webhook delivery against an in-process mock push server.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use gim_hub_db::{
    events, push,
    users::{self, Device, StoredDeviceList},
    Db, DbError,
};
use gim_hub_push::{
    http::ReqwestClient, Dispatcher, DispatcherSettings, LogProvider, PushLog, PushProvider,
    Registration, WebhookConfig, WebhookProvider,
};
use ring::hmac;
use serde_json::{json, Value};

const SECRET: &str = "test-secret-test-secret-test-secret";
const HUB_ID: &str = "hubtest";

/// A request the mock push server received.
#[derive(Debug, Clone)]
struct Received {
    at: Instant,
    signature: String,
    delivery: String,
    content_type: String,
    raw: Vec<u8>,
    body: Value,
}

/// Scripted `(status, Retry-After)` responses.
type Script = Arc<Mutex<VecDeque<(u16, Option<&'static str>)>>>;

/// Mock push server: answers with the scripted `(status, Retry-After)`
/// responses, then 204, and records every request.
#[derive(Clone, Default)]
struct Mock {
    script: Script,
    received: Arc<Mutex<Vec<Received>>>,
}

impl Mock {
    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

async fn receive(State(mock): State<Mock>, headers: HeaderMap, raw: Bytes) -> impl IntoResponse {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    mock.received.lock().unwrap().push(Received {
        at: Instant::now(),
        signature: header("x-gim-signature"),
        delivery: header("x-gim-delivery"),
        content_type: header("content-type"),
        raw: raw.to_vec(),
        body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
    });
    let (status, retry_after) = mock
        .script
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or((204, None));
    let mut response = StatusCode::from_u16(status).unwrap().into_response();
    if let Some(retry_after) = retry_after {
        response
            .headers_mut()
            .insert("retry-after", retry_after.parse().unwrap());
    }
    response
}

/// Starts the mock and returns it with its webhook URL.
async fn mock_server(script: Vec<(u16, Option<&'static str>)>) -> (Mock, String) {
    let mock = Mock {
        script: Arc::new(Mutex::new(script.into())),
        ..Mock::default()
    };
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (mock, url)
}

/// Verifies `X-Gim-Signature` with the recipe of `docs/push.md`: split
/// `t=<t>,v1=<hex>`, compute HMAC-SHA256(secret, "<t>." || raw body), compare
/// in constant time, and check that `t` is within 300 s of now.
fn verify_signature(header: &str, raw: &[u8]) -> bool {
    let mut t = None;
    let mut v1 = None;
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", value)) => t = value.parse::<u64>().ok(),
            Some(("v1", value)) => v1 = Some(value.to_owned()),
            _ => {}
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.abs_diff(t) > 300 || v1.len() != 64 {
        return false;
    }
    let Ok(mac) = (0..32)
        .map(|i| u8::from_str_radix(&v1[2 * i..2 * i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
    else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET.as_bytes());
    let mut signed = format!("{t}.").into_bytes();
    signed.extend_from_slice(raw);
    hmac::verify(&key, &signed, &mac).is_ok()
}

fn registration(device_id: &str, provider: &str, token: &str) -> Registration {
    Registration {
        user_id: "u2".into(),
        device_id: device_id.into(),
        provider: provider.into(),
        token: token.into(),
        app_id: None,
        sandbox: None,
        p256dh: None,
        auth: None,
        updated_at: 0,
    }
}

/// A database with active devices of `u2` registered as given.
async fn db_with(registrations: Vec<Registration>) -> Db {
    let db = Db::open_in_memory().unwrap();
    db.write(move |tx| {
        users::put_device_list(
            tx,
            &StoredDeviceList {
                user_id: "u2".into(),
                root_pubkey: vec![0; 32],
                device_list: Vec::new(),
                seq: 0,
                updated_at: 0,
            },
        )?;
        for registration in &registrations {
            users::put_device(
                tx,
                &Device {
                    user_id: "u2".into(),
                    device_id: registration.device_id.clone(),
                    sig_pubkey: vec![0; 32],
                    active: true,
                },
                0,
            )?;
            push::put(tx, registration)?;
        }
        Ok::<_, DbError>(())
    })
    .await
    .unwrap();
    db
}

async fn append(db: &Db, device: &str, event_type: &str, data: Value) {
    let (device, event_type) = (device.to_owned(), event_type.to_owned());
    db.write(move |tx| events::append(tx, "u2", &device, &event_type, &data.to_string(), 0))
        .await
        .unwrap();
}

fn message(seq: u64) -> Value {
    json!({ "gid": "h1/g", "seq": seq, "sender_user_id": "u1", "mls_message": "AAAA" })
}

fn dispatcher(db: &Db, url: &str, log: &PushLog, settings: DispatcherSettings) -> Dispatcher {
    let config = WebhookConfig::new(url, Some(SECRET), Duration::from_secs(5)).unwrap();
    let http = Arc::new(ReqwestClient::new(config.timeout).unwrap());
    let providers: Vec<Arc<dyn PushProvider>> = vec![
        Arc::new(LogProvider::new(log.clone())),
        Arc::new(WebhookProvider::new(&config, HUB_ID, http)),
    ];
    Dispatcher::new(
        db.clone(),
        providers,
        log.clone(),
        DispatcherSettings {
            retry_base: Duration::from_millis(10),
            ..settings
        },
        0,
    )
}

/// Polls and sends until `done` or 10 s pass.
async fn drive(d: &Dispatcher, done: impl Fn() -> bool) {
    d.poll_once().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() && Instant::now() < deadline {
        d.run_pending().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(done(), "timed out: {:?}", d.metrics());
}

async fn stored(db: &Db, device_id: &'static str) -> Option<Registration> {
    db.read(move |conn| push::get_active(conn, "u2", device_id))
        .await
        .unwrap()
}

#[tokio::test]
async fn signed_body_follows_contract_and_500_is_retried_with_same_delivery_id() {
    let (mock, url) = mock_server(vec![(500, None)]).await;
    let mut r = registration("d1", "apns", "tok-1");
    r.app_id = Some("im.g.apps".into());
    r.sandbox = Some(false);
    r.p256dh = Some(vec![4, 4, 4]);
    let db = db_with(vec![r]).await;
    let log = PushLog::default();
    let d = dispatcher(&db, &url, &log, DispatcherSettings::default());
    append(&db, "d1", "message", message(1)).await;
    drive(&d, || d.metrics().sent == 1).await;

    let received = mock.received();
    assert_eq!(received.len(), 2);
    let m = d.metrics();
    assert_eq!((m.retried, m.sent, m.failed), (1, 1, 0));
    for request in &received {
        assert!(verify_signature(&request.signature, &request.raw));
        assert_eq!(request.content_type, "application/json");
        assert_eq!(request.delivery, request.body["delivery_id"]);
    }
    // A tampered body or another secret does not verify.
    let mut tampered = received[0].raw.clone();
    tampered[0] = b' ';
    assert!(!verify_signature(&received[0].signature, &tampered));

    let (first, retry) = (&received[0].body, &received[1].body);
    assert_eq!(first["delivery_id"], retry["delivery_id"]);
    assert_eq!(first["sent_at"], retry["sent_at"]);
    assert!(first["sent_at"].as_i64().unwrap() > 0);
    let collapse_id = first["collapse_id"].clone();
    assert_eq!(
        *first,
        json!({
            "v": 1,
            "hub_id": HUB_ID,
            "delivery_id": first["delivery_id"],
            "sent_at": first["sent_at"],
            "registration": {
                "provider": "apns", "token": "tok-1", "app_id": "im.g.apps",
                "sandbox": false, "p256dh": "BAQE",
            },
            "priority": "high",
            "collapse_id": collapse_id,
            "ttl": 86400,
            "payload": {
                "v": 1, "type": "message", "gid": "h1/g", "seq": 1,
                "message_id": collapse_id, "collapse_id": collapse_id, "mls_message": "AAAA",
            },
        })
    );

    // A new push gets a new delivery id.
    append(&db, "d1", "message", message(2)).await;
    drive(&d, || d.metrics().sent == 2).await;
    assert_ne!(mock.received()[2].body["delivery_id"], first["delivery_id"]);
}

#[tokio::test]
async fn retry_after_of_429_is_honoured() {
    let (mock, url) = mock_server(vec![(429, Some("1"))]).await;
    let db = db_with(vec![registration("d1", "fcm", "tok")]).await;
    let d = dispatcher(
        &db,
        &url,
        &PushLog::default(),
        DispatcherSettings::default(),
    );
    append(&db, "d1", "message", message(1)).await;
    drive(&d, || d.metrics().sent == 1).await;
    let received = mock.received();
    assert_eq!(received.len(), 2);
    assert!(received[1].at - received[0].at >= Duration::from_secs(1));
    assert_eq!(
        received[0].body["delivery_id"],
        received[1].body["delivery_id"]
    );
}

#[tokio::test]
async fn client_errors_are_not_retried_and_keep_the_registration() {
    let (mock, url) = mock_server(vec![(400, None), (302, None)]).await;
    let db = db_with(vec![registration("d1", "fcm", "tok")]).await;
    let d = dispatcher(
        &db,
        &url,
        &PushLog::default(),
        DispatcherSettings::default(),
    );
    append(&db, "d1", "message", message(1)).await;
    drive(&d, || d.metrics().failed == 1).await;
    append(&db, "d1", "message", message(2)).await;
    drive(&d, || d.metrics().failed == 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    d.run_pending().await;
    assert_eq!(mock.received().len(), 2);
    assert_eq!(d.metrics().retried, 0);
    assert!(stored(&db, "d1").await.is_some());
}

#[tokio::test]
async fn gone_registrations_are_deleted_unless_re_registered() {
    let (mock, url) = mock_server(vec![(410, None), (404, None)]).await;
    let db = db_with(vec![
        registration("d1", "fcm", "tok-1"),
        registration("d2", "unifiedpush", "tok-2"),
    ])
    .await;
    let d = dispatcher(
        &db,
        &url,
        &PushLog::default(),
        DispatcherSettings::default(),
    );
    append(&db, "d1", "message", message(1)).await;
    drive(&d, || d.metrics().invalid_token == 1).await;
    assert!(stored(&db, "d1").await.is_none());

    // d2 registers a new token after its push was queued: the 404 for the
    // old token keeps the new registration.
    append(&db, "d2", "message", message(1)).await;
    d.poll_once().await.unwrap();
    db.write(|tx| push::put(tx, &registration("d2", "unifiedpush", "tok-new")))
        .await
        .unwrap();
    drive(&d, || d.metrics().invalid_token == 2).await;
    assert_eq!(mock.received()[1].body["registration"]["token"], "tok-2");
    assert_eq!(stored(&db, "d2").await.unwrap().token, "tok-new");
}

#[tokio::test]
async fn minimal_mode_sends_the_wake_payload() {
    let (mock, url) = mock_server(Vec::new()).await;
    let db = db_with(vec![registration("d1", "fcm", "tok")]).await;
    let settings = DispatcherSettings {
        minimal: true,
        ..DispatcherSettings::default()
    };
    let d = dispatcher(&db, &url, &PushLog::default(), settings);
    append(&db, "d1", "message", message(1)).await;
    drive(&d, || d.metrics().sent == 1).await;
    let body = &mock.received()[0].body;
    assert_eq!(
        body["payload"],
        json!({ "v": 1, "type": "wake", "collapse_id": body["collapse_id"] })
    );
    assert_eq!(body["priority"], "high");
}

#[tokio::test]
async fn priority_by_event_type_proposals_skipped_and_log_stays_local() {
    let (mock, url) = mock_server(Vec::new()).await;
    let db = db_with(vec![
        registration("d1", "fcm", "tok"),
        registration("d2", "log", "log-tok"),
    ])
    .await;
    let log = PushLog::default();
    let settings = DispatcherSettings {
        member_events: true,
        ..DispatcherSettings::default()
    };
    let d = dispatcher(&db, &url, &log, settings);

    let mut proposal = message(1);
    proposal["kind"] = "proposal".into();
    append(&db, "d1", "message", proposal).await;
    assert_eq!(d.poll_once().await.unwrap(), 0);

    let member = json!({
        "gid": "h1/g", "seq": 2, "user_id": "u3", "device_ids": ["d9"],
        "by_user_id": "u1", "by_device_id": "d1", "epoch": 2,
    });
    append(&db, "d1", "group.member_added", member).await;
    drive(&d, || d.metrics().sent == 1).await;
    let welcome = json!({
        "gid": "h1/g", "seq": 2, "sender_user_id": "u1", "sender_device_id": "d1",
        "epoch": 2, "welcome": "V0VMQw==",
    });
    append(&db, "d1", "welcome", welcome).await;
    drive(&d, || d.metrics().sent == 2).await;
    append(&db, "d2", "message", message(3)).await;
    drive(&d, || d.metrics().sent == 3).await;

    let received = mock.received();
    let summary: Vec<_> = received
        .iter()
        .map(|r| {
            (
                r.body["payload"]["type"].clone(),
                r.body["priority"].clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (json!("group.member_added"), json!("normal")),
            (json!("welcome"), json!("high")),
        ]
    );
    for request in &received {
        assert!(request.body.get("user_id").is_none());
        assert!(request.body.get("device_id").is_none());
        assert!(request.body["registration"].get("device_id").is_none());
    }
    let logged = log.recent(None);
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0].device_id, "d2");
}
