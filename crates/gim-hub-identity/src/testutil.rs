//! Test-only builders for signed structures; the hub never signs them.

use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::keys::signing_input;
use crate::{cbor, DeviceId, UserId, DEVICE_CERT_CONTEXT, DEVICE_LIST_CONTEXT};

/// Key from the seed `[seed; 32]`.
pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

/// `[tbs, sig]` with `sig` over `context || 0x00 || tbs`.
pub(crate) fn sign_tbs(key: &SigningKey, context: &[u8], tbs: &[u8]) -> Vec<u8> {
    let sig = key.sign(&signing_input(context, tbs)).to_bytes();
    cbor::encode(&Value::Array(vec![
        Value::Bytes(tbs.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]))
}

pub(crate) fn sign_value(key: &SigningKey, context: &[u8], body: &Value) -> Vec<u8> {
    sign_tbs(key, context, &cbor::encode(body))
}

pub(crate) fn cert_items(
    root: &VerifyingKey,
    device: &VerifyingKey,
    created_at: u64,
    seq: u64,
) -> Vec<Value> {
    vec![
        uint(1),
        Value::Text(UserId::from_root_pubkey(root).to_string()),
        Value::Text(DeviceId::from_device_pubkey(device).to_string()),
        Value::Bytes(device.as_bytes().to_vec()),
        uint(created_at),
        uint(seq),
    ]
}

pub(crate) fn cert_body(
    root: &VerifyingKey,
    device: &VerifyingKey,
    created_at: u64,
    seq: u64,
) -> Value {
    Value::Array(cert_items(root, device, created_at, seq))
}

pub(crate) fn cert(root: &SigningKey, device: &VerifyingKey, created_at: u64, seq: u64) -> Vec<u8> {
    let body = cert_body(&root.verifying_key(), device, created_at, seq);
    sign_value(root, DEVICE_CERT_CONTEXT, &body)
}

pub(crate) fn list_items(
    root: &VerifyingKey,
    seq: u64,
    certs: Vec<Vec<u8>>,
    revoked: Vec<DeviceId>,
) -> Vec<Value> {
    vec![
        uint(1),
        Value::Text(UserId::from_root_pubkey(root).to_string()),
        Value::Bytes(root.as_bytes().to_vec()),
        uint(seq),
        Value::Array(certs.into_iter().map(Value::Bytes).collect()),
        Value::Array(
            revoked
                .into_iter()
                .map(|id| Value::Text(id.to_string()))
                .collect(),
        ),
    ]
}

pub(crate) fn list(
    root: &SigningKey,
    seq: u64,
    certs: Vec<Vec<u8>>,
    revoked: Vec<DeviceId>,
) -> Vec<u8> {
    let body = Value::Array(list_items(&root.verifying_key(), seq, certs, revoked));
    sign_value(root, DEVICE_LIST_CONTEXT, &body)
}
