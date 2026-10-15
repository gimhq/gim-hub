//! Shared helpers of the identity-area tests: JSON requests and signed
//! DeviceList fixtures (deterministic CBOR built by hand, keys from fixed
//! seeds).

#![allow(dead_code)]

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use gim_hub_api::testing::TestHub;
use gim_hub_identity::{DeviceId, UserId, DEVICE_CERT_CONTEXT, DEVICE_LIST_CONTEXT};
use serde_json::Value;
use tower::ServiceExt;

/// Sends a request with an optional bearer token and JSON body; returns the
/// status and the JSON body (`Null` if empty).
pub async fn send(
    hub: &TestHub,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = hub
        .router()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

/// Error code of an error body.
pub fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or("")
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Ed25519 key from the seed `[seed; 32]`.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn user_id(root_seed: u8) -> String {
    UserId::from_root_pubkey(&key(root_seed).verifying_key()).to_string()
}

pub fn device_id(seed: u8) -> String {
    DeviceId::from_device_pubkey(&key(seed).verifying_key()).to_string()
}

enum Cbor {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 0xff {
        out.extend([major | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(major | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend(n.to_be_bytes());
    }
}

fn encode(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Uint(n) => head(0, *n, out),
        Cbor::Bytes(bytes) => {
            head(2, bytes.len() as u64, out);
            out.extend(bytes);
        }
        Cbor::Text(text) => {
            head(3, text.len() as u64, out);
            out.extend(text.as_bytes());
        }
        Cbor::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                encode(item, out);
            }
        }
    }
}

/// `[tbs, sig]` with `sig` over `context || 0x00 || tbs`.
fn sign(key: &SigningKey, context: &[u8], body: Cbor) -> Vec<u8> {
    let mut tbs = Vec::new();
    encode(&body, &mut tbs);
    let mut input = context.to_vec();
    input.push(0);
    input.extend(&tbs);
    let sig = key.sign(&input).to_bytes().to_vec();
    let mut out = Vec::new();
    encode(
        &Cbor::Array(vec![Cbor::Bytes(tbs), Cbor::Bytes(sig)]),
        &mut out,
    );
    out
}

fn cert(root: &SigningKey, device_seed: u8) -> Vec<u8> {
    let device = key(device_seed).verifying_key();
    let body = Cbor::Array(vec![
        Cbor::Uint(1),
        Cbor::Text(UserId::from_root_pubkey(&root.verifying_key()).to_string()),
        Cbor::Text(device_id(device_seed)),
        Cbor::Bytes(device.as_bytes().to_vec()),
        Cbor::Uint(1_760_000_000_000),
        Cbor::Uint(1),
    ]);
    sign(root, DEVICE_CERT_CONTEXT, body)
}

/// A `SignedDeviceList` of the user with root key `key(root_seed)`,
/// certifying the devices with keys `key(seed)` and revoking the devices of
/// `revoked` seeds.
pub fn device_list(root_seed: u8, seq: u64, devices: &[u8], revoked: &[u8]) -> Vec<u8> {
    let root = key(root_seed);
    let body = Cbor::Array(vec![
        Cbor::Uint(1),
        Cbor::Text(user_id(root_seed)),
        Cbor::Bytes(root.verifying_key().as_bytes().to_vec()),
        Cbor::Uint(seq),
        Cbor::Array(
            devices
                .iter()
                .map(|seed| Cbor::Bytes(cert(&root, *seed)))
                .collect(),
        ),
        Cbor::Array(
            revoked
                .iter()
                .map(|seed| Cbor::Text(device_id(*seed)))
                .collect(),
        ),
    ]);
    sign(&root, DEVICE_LIST_CONTEXT, body)
}

/// PUT /v2/users/{user_id}/device-list.
pub async fn put_device_list(hub: &TestHub, user_id: &str, list: &[u8]) -> (StatusCode, Value) {
    send(
        hub,
        Method::PUT,
        &format!("/v2/users/{user_id}/device-list"),
        None,
        Some(serde_json::json!({ "device_list": b64(list) })),
    )
    .await
}
