//! Test helpers (feature `testing`): hosting records signed the way gim-core
//! signs them (docs/identity.md "Hosting record"); the hub never holds a
//! user root key.

use ciborium::Value;
use ed25519_dalek::Signer;
use gim_hub_identity::{
    sort_hosting_entries, HostingEntry, SigningKey, UserId, HOSTING_RECORD_CONTEXT,
};

use super::{encode_cbor, entry_value};

/// A `SignedHostingRecord` of the user with root key `user_root`, listing the
/// hubs `(hub root key, priority)` in canonical order.
pub fn sign_record(
    user_root: &SigningKey,
    seq: u64,
    expires_at: u64,
    hubs: &[(&SigningKey, u8)],
) -> Vec<u8> {
    let root = user_root.verifying_key();
    let user_id = UserId::from_root_pubkey(&root);
    let mut entries: Vec<HostingEntry> = hubs
        .iter()
        .map(|(hub, priority)| HostingEntry::sign(hub, &user_id, *priority))
        .collect();
    sort_hosting_entries(&mut entries);
    let tbs = encode_cbor(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Text(user_id.to_string()),
        Value::Bytes(root.as_bytes().to_vec()),
        Value::Integer(seq.into()),
        Value::Integer(expires_at.into()),
        Value::Array(entries.iter().map(entry_value).collect()),
    ]));
    let sig = user_root.sign(&[HOSTING_RECORD_CONTEXT, &[0], &tbs].concat());
    encode_cbor(&Value::Array(vec![
        Value::Bytes(tbs),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]))
}
