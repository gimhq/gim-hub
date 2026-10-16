//! Mock push server: the receiving side of the hub's push webhook
//! (docs/push-mock.md). A test tool, not production software: state is
//! in memory only.

use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;

/// Deliveries kept in memory; the oldest are dropped first.
pub const RING_CAPACITY: usize = 10_000;
/// Longest accepted `wait` of `GET /deliveries`, in seconds.
pub const MAX_WAIT_SECONDS: u64 = 30;
/// Provider whose deliveries carry a `simctl` view.
pub const IOS_SIM_PROVIDER: &str = "mock-ios-sim";

const SIGNATURE_HEADER: &str = "x-gim-signature";
const DELIVERY_HEADER: &str = "x-gim-delivery";

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub secret: Vec<u8>,
    pub max_skew_seconds: u64,
}

impl Config {
    /// Reads `GIM_PUSH_MOCK_LISTEN` (default `0.0.0.0:8090`),
    /// `GIM_PUSH_MOCK_SECRET` (required) and `GIM_PUSH_MOCK_MAX_SKEW_SECONDS`
    /// (default 300).
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let listen = var("GIM_PUSH_MOCK_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:8090".into())
            .parse()
            .map_err(|err| format!("GIM_PUSH_MOCK_LISTEN: {err}"))?;
        let secret = var("GIM_PUSH_MOCK_SECRET")
            .ok_or("GIM_PUSH_MOCK_SECRET is required")?
            .into_bytes();
        let max_skew_seconds = match var("GIM_PUSH_MOCK_MAX_SKEW_SECONDS") {
            Some(v) => v
                .parse()
                .map_err(|err| format!("GIM_PUSH_MOCK_MAX_SKEW_SECONDS: {err}"))?,
            None => 300,
        };
        Ok(Self {
            listen,
            secret,
            max_skew_seconds,
        })
    }
}

/// Why a signature was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    Malformed,
    Skew,
    BadMac,
}

/// `X-Gim-Signature` value for `body` signed at unix second `t`:
/// `t=<t>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`.
pub fn sign(secret: &[u8], t: u64, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, &signed_message(t, body));
    format!("t={t},v1={}", hex::encode(tag.as_ref()))
}

/// Checks an `X-Gim-Signature` header against `body`: the timestamp must be
/// within `max_skew` seconds of `now` and the MAC must match (compared in
/// constant time).
pub fn verify_signature(
    secret: &[u8],
    header: &str,
    body: &[u8],
    now: u64,
    max_skew: u64,
) -> Result<(), SignatureError> {
    let (t, v1) = header
        .split_once(',')
        .and_then(|(t, v1)| Some((t.strip_prefix("t=")?, v1.strip_prefix("v1=")?)))
        .ok_or(SignatureError::Malformed)?;
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SignatureError::Malformed);
    }
    let t: u64 = t.parse().map_err(|_| SignatureError::Malformed)?;
    if v1.len() != 64 || !v1.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(SignatureError::Malformed);
    }
    let mac = hex::decode(v1).map_err(|_| SignatureError::Malformed)?;
    if now.abs_diff(t) > max_skew {
        return Err(SignatureError::Skew);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, &signed_message(t, body), &mac).map_err(|_| SignatureError::BadMac)
}

fn signed_message(t: u64, body: &[u8]) -> Vec<u8> {
    let mut message = format!("{t}.").into_bytes();
    message.extend_from_slice(body);
    message
}

/// A recorded push.
#[derive(Clone, Debug, Serialize)]
pub struct Delivery {
    pub seq: u64,
    /// Unix milliseconds.
    pub received_at: u64,
    pub delivery_id: String,
    pub body: Value,
}

impl Delivery {
    fn provider(&self) -> Option<&str> {
        self.body["registration"]["provider"].as_str()
    }

    fn token(&self) -> Option<&str> {
        self.body["registration"]["token"].as_str()
    }

    /// The delivery as returned by `GET /deliveries`; `mock-ios-sim`
    /// deliveries carry a `simctl` view for `xcrun simctl push`.
    fn view(&self) -> Value {
        let mut value = json!(self);
        if self.provider() == Some(IOS_SIM_PROVIDER) {
            value["simctl"] = json!({
                "bundle_id": self.body["registration"]["app_id"],
                "payload": {
                    "aps": {
                        "alert": { "title": "gim", "body": "New message" },
                        "mutable-content": 1,
                    },
                    "gim": self.body["payload"],
                },
            });
        }
        value
    }
}

/// Outcome counters, reset by `POST /reset`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Counters {
    /// Recorded deliveries.
    pub delivered: u64,
    /// Repeats of a recorded delivery_id.
    pub duplicates: u64,
    /// `gone-` tokens answered with 410.
    pub gone: u64,
    /// `fail-` tokens answered with 500.
    pub failed: u64,
    /// `bad-` tokens answered with 400.
    pub bad: u64,
    /// Requests with a missing or invalid signature (401).
    pub unauthorized: u64,
    /// Signed requests with an invalid body or headers (400).
    pub invalid: u64,
}

#[derive(Default)]
struct Store {
    last_seq: u64,
    deliveries: VecDeque<Delivery>,
    ids: HashSet<String>,
    counters: Counters,
}

struct Inner {
    secret: Vec<u8>,
    max_skew_seconds: u64,
    store: Mutex<Store>,
    /// Bumped on every change, wakes long-polls.
    changed: watch::Sender<u64>,
}

/// Shared state of the mock.
#[derive(Clone)]
pub struct MockState(Arc<Inner>);

impl MockState {
    pub fn new(config: &Config) -> Self {
        Self(Arc::new(Inner {
            secret: config.secret.clone(),
            max_skew_seconds: config.max_skew_seconds,
            store: Mutex::new(Store::default()),
            changed: watch::Sender::new(0),
        }))
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self) {
        self.0.changed.send_modify(|n| *n += 1);
    }

    fn query(&self, filter: &DeliveriesQuery) -> (Vec<Value>, u64) {
        let store = self.store();
        let since = filter.since.unwrap_or(0);
        let wanted = |want: &Option<String>, got: Option<&str>| match want.as_deref() {
            None | Some("") => true,
            Some(want) => got == Some(want),
        };
        let matches = store
            .deliveries
            .iter()
            .filter(|d| d.seq > since)
            .filter(|d| wanted(&filter.token, d.token()) && wanted(&filter.provider, d.provider()))
            .map(Delivery::view)
            .collect();
        (matches, since.max(store.last_seq))
    }
}

pub fn router(state: MockState) -> Router {
    Router::new()
        .route("/push", post(push))
        .route("/deliveries", get(deliveries))
        .route("/stats", get(stats))
        .route("/reset", post(reset))
        .route("/healthz", get(healthz))
        .with_state(state)
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

async fn push(State(state): State<MockState>, headers: HeaderMap, body: Bytes) -> Response {
    let header = |name| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(signature) = header(SIGNATURE_HEADER) else {
        state.store().counters.unauthorized += 1;
        return error(StatusCode::UNAUTHORIZED, "missing X-Gim-Signature");
    };
    if let Err(err) = verify_signature(
        &state.0.secret,
        signature,
        &body,
        now().as_secs(),
        state.0.max_skew_seconds,
    ) {
        state.store().counters.unauthorized += 1;
        tracing::warn!(?err, "rejected push signature");
        return error(StatusCode::UNAUTHORIZED, &format!("signature: {err:?}"));
    }

    let parsed = serde_json::from_slice::<Value>(&body)
        .map_err(|err| err.to_string())
        .and_then(|body| {
            let delivery_id = body["delivery_id"].as_str().unwrap_or_default().to_owned();
            if body["v"] != json!(1) {
                Err("v must be 1".into())
            } else if delivery_id.is_empty() {
                Err("delivery_id missing".into())
            } else if header(DELIVERY_HEADER) != Some(delivery_id.as_str()) {
                Err("X-Gim-Delivery does not match delivery_id".into())
            } else if body["registration"]["provider"].as_str().is_none()
                || body["registration"]["token"].as_str().is_none()
            {
                Err("registration.provider and registration.token required".into())
            } else {
                Ok((delivery_id, body))
            }
        });
    let (delivery_id, body) = match parsed {
        Ok(parsed) => parsed,
        Err(message) => {
            state.store().counters.invalid += 1;
            return error(StatusCode::BAD_REQUEST, &message);
        }
    };

    let mut store = state.store();
    if store.ids.contains(&delivery_id) {
        store.counters.duplicates += 1;
        return Json(json!({ "status": "duplicate" })).into_response();
    }
    let token = body["registration"]["token"].as_str().unwrap_or_default();
    if token.starts_with("gone-") {
        store.counters.gone += 1;
        return error(StatusCode::GONE, "registration gone");
    }
    if token.starts_with("fail-") {
        store.counters.failed += 1;
        return error(StatusCode::INTERNAL_SERVER_ERROR, "simulated failure");
    }
    if token.starts_with("bad-") {
        store.counters.bad += 1;
        return error(StatusCode::BAD_REQUEST, "simulated bad request");
    }

    store.last_seq += 1;
    let seq = store.last_seq;
    if store.deliveries.len() >= RING_CAPACITY {
        if let Some(old) = store.deliveries.pop_front() {
            store.ids.remove(&old.delivery_id);
        }
    }
    store.ids.insert(delivery_id.clone());
    store.deliveries.push_back(Delivery {
        seq,
        received_at: u64::try_from(now().as_millis()).unwrap_or(u64::MAX),
        delivery_id,
        body,
    });
    store.counters.delivered += 1;
    drop(store);
    state.notify();
    Json(json!({ "status": "ok", "seq": seq })).into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct DeliveriesQuery {
    pub token: Option<String>,
    pub provider: Option<String>,
    pub since: Option<u64>,
    pub wait: Option<u64>,
}

async fn deliveries(
    State(state): State<MockState>,
    Query(filter): Query<DeliveriesQuery>,
) -> Json<Value> {
    let wait = Duration::from_secs(filter.wait.unwrap_or(0).min(MAX_WAIT_SECONDS));
    let deadline = tokio::time::Instant::now() + wait;
    let mut changed = state.0.changed.subscribe();
    loop {
        // Mark the current version seen before querying, so a push that
        // lands after the query wakes the wait below.
        changed.borrow_and_update();
        let (matches, next) = state.query(&filter);
        if !matches.is_empty() || wait.is_zero() {
            return Json(json!({ "deliveries": matches, "next": next }));
        }
        match tokio::time::timeout_at(deadline, changed.changed()).await {
            Ok(Ok(())) => {}
            _ => return Json(json!({ "deliveries": [], "next": next })),
        }
    }
}

async fn stats(State(state): State<MockState>) -> Json<Value> {
    let store = state.store();
    Json(json!({
        "deliveries": store.deliveries.len(),
        "last_seq": store.last_seq,
        "counters": store.counters,
    }))
}

async fn reset(State(state): State<MockState>) -> StatusCode {
    {
        let mut store = state.store();
        store.deliveries.clear();
        store.ids.clear();
        store.counters = Counters::default();
    }
    state.notify();
    StatusCode::NO_CONTENT
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}
