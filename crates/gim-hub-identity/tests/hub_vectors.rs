//! Checks the vendored gim-core hub-side vectors (`testdata/identity/`
//! `hosting.json`, `auth.json`) and the structure of the opaque blobs in
//! `recovery.json` and `link.json`.

use ciborium::Value;
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, SigningKey};
use gim_hub_identity::{
    check_recovery_backup, check_sealed_link_bundle, verify_auth_response, AuthChallenge, DeviceId,
    DeviceList, HostingEntry, HostingRecord, HubId, HubRuntimeCert, IdentityError, UserId,
    AUTH_RESPONSE_CONTEXT, HOSTING_RECORD_CONTEXT,
};
use serde_json::Value as Json;

fn vectors(name: &str) -> Json {
    let path = format!(
        "{}/../../testdata/identity/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(value: &Json) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

fn key(value: &Json) -> SigningKey {
    SigningKey::from_bytes(&hex(value).try_into().unwrap())
}

fn text(value: &Json) -> &str {
    value.as_str().unwrap()
}

fn uint(value: &Json) -> u64 {
    value.as_u64().unwrap()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn sign(key: &SigningKey, context: &[u8], tbs: &[u8]) -> Vec<u8> {
    key.sign(&[context, &[0], tbs].concat()).to_bytes().to_vec()
}

fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    bytes
}

#[test]
fn hub_ids() {
    let v = vectors("hosting");
    for hub in v["hubs"].as_array().unwrap() {
        let root = key(&hub["root_seed"]);
        assert_eq!(
            root.verifying_key().as_bytes().to_vec(),
            hex(&hub["root_pubkey"])
        );
        let hub_id = HubId::from_root_pubkey(&root.verifying_key());
        assert_eq!(hub_id.as_str(), text(&hub["hub_id"]));
        assert_eq!(HubId::parse(text(&hub["hub_id"])), Ok(hub_id));
    }
}

#[test]
fn runtime_cert() {
    let v = vectors("hosting");
    let c = &v["runtime_cert"];
    let hub = key(&v["hubs"][c["hub"].as_u64().unwrap() as usize]["root_seed"]);
    let runtime = key(&c["runtime_seed"]).verifying_key();
    assert_eq!(runtime.as_bytes().to_vec(), hex(&c["runtime_pubkey"]));
    let (not_before, not_after) = (uint(&c["not_before"]), uint(&c["not_after"]));
    let signed = hex(&c["signed"]);

    assert_eq!(
        HubRuntimeCert::issue(&hub, &runtime, not_before, not_after),
        signed
    );
    let cert = HubRuntimeCert::verify(&signed, &hub.verifying_key(), not_before).unwrap();
    assert_eq!(cert.runtime_pubkey(), &runtime);
    assert_eq!(cert.hub_root_pubkey(), &hub.verifying_key());
    assert_eq!(cert.hub_id().as_str(), text(&v["hubs"][0]["hub_id"]));
    assert_eq!(cert.peer_id().to_vec(), hex(&c["peer_id"]));
    assert_eq!(
        (cert.not_before(), cert.not_after()),
        (not_before, not_after)
    );
    assert_eq!(cert.as_bytes(), signed);

    let hub = hub.verifying_key();
    assert_eq!(
        HubRuntimeCert::verify(&signed, &hub, not_before - 1),
        Err(IdentityError::NotYetValid)
    );
    assert_eq!(
        HubRuntimeCert::verify(&signed, &hub, not_after),
        Err(IdentityError::Expired)
    );
    let other = key(&v["hubs"][1]["root_seed"]).verifying_key();
    assert_eq!(
        HubRuntimeCert::verify(&signed, &other, not_before),
        Err(IdentityError::BadSignature)
    );
    assert_eq!(
        HubRuntimeCert::verify(&flip_last(&signed), &hub, not_before),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn hosting_record() {
    let v = vectors("hosting");
    let r = &v["hosting_record"];
    let user = key(&r["user_root_seed"]);
    let user_id = UserId::from_root_pubkey(&user.verifying_key());
    assert_eq!(user_id.as_str(), text(&r["user_id"]));
    let signed = hex(&r["signed"]);
    let expires_at = uint(&r["expires_at"]);

    let record = HostingRecord::verify(&signed, &user_id, expires_at - 1).unwrap();
    assert_eq!(record.user_id(), &user_id);
    assert_eq!(record.user_root_pubkey(), &user.verifying_key());
    assert_eq!(record.seq(), uint(&r["seq"]));
    assert_eq!(record.expires_at(), expires_at);
    assert_eq!(
        record.primary().hub_id().as_str(),
        text(&r["primary_hub_id"])
    );
    assert_eq!(record.as_bytes(), signed);

    // Rebuild every hub entry (hub co-signature) and the record.
    let entries = r["hubs"].as_array().unwrap();
    assert_eq!(record.hubs().len(), entries.len());
    let mut items = Vec::new();
    for (entry, e) in record.hubs().iter().zip(entries) {
        let hub = &v["hubs"][e["hub"].as_u64().unwrap() as usize];
        let priority = u8::try_from(uint(&e["priority"])).unwrap();
        assert_eq!(entry.hub_id().as_str(), text(&hub["hub_id"]));
        assert_eq!(entry.priority(), priority);
        let rebuilt = HostingEntry::sign(&key(&hub["root_seed"]), &user_id, priority);
        assert_eq!(&rebuilt, entry);
        items.push(Value::Array(vec![
            Value::Bytes(hex(&hub["root_pubkey"])),
            Value::Integer(priority.into()),
            Value::Bytes(rebuilt.hub_sig().to_vec()),
        ]));
        assert_eq!(record.entry(entry.hub_id()), Some(entry));
    }
    let tbs = encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Text(user_id.to_string()),
        Value::Bytes(user.verifying_key().as_bytes().to_vec()),
        Value::Integer(record.seq().into()),
        Value::Integer(expires_at.into()),
        Value::Array(items.clone()),
    ]));
    let rebuilt = encode(&Value::Array(vec![
        Value::Bytes(tbs.clone()),
        Value::Bytes(sign(&user, HOSTING_RECORD_CONTEXT, &tbs)),
    ]));
    assert_eq!(rebuilt, signed);

    // Negative: expiry, another user, a bad user signature.
    assert_eq!(
        HostingRecord::verify(&signed, &user_id, expires_at),
        Err(IdentityError::Expired)
    );
    let stranger = UserId::from_root_pubkey(&key(&v["hubs"][0]["root_seed"]).verifying_key());
    assert_eq!(
        HostingRecord::verify(&signed, &stranger, 0),
        Err(IdentityError::UserIdMismatch)
    );
    assert_eq!(
        HostingRecord::verify(&flip_last(&signed), &user_id, 0),
        Err(IdentityError::BadSignature)
    );

    // Negative: a corrupted hub signature, re-signed by the user.
    let mut bad_items = items.clone();
    if let Value::Array(entry) = &mut bad_items[1] {
        let Value::Bytes(sig) = &mut entry[2] else {
            unreachable!()
        };
        sig[0] ^= 1;
    }
    let resign = |seq: u64, hubs: Vec<Value>| {
        let tbs = encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Text(user_id.to_string()),
            Value::Bytes(user.verifying_key().as_bytes().to_vec()),
            Value::Integer(seq.into()),
            Value::Integer(expires_at.into()),
            Value::Array(hubs),
        ]));
        let sig = sign(&user, HOSTING_RECORD_CONTEXT, &tbs);
        encode(&Value::Array(vec![Value::Bytes(tbs), Value::Bytes(sig)]))
    };
    assert_eq!(
        HostingRecord::verify(&resign(record.seq(), bad_items), &user_id, 0),
        Err(IdentityError::BadHubSignature(
            HubId::parse(text(&v["hubs"][1]["hub_id"])).unwrap()
        ))
    );

    // Ordering: a lower seq does not supersede; the highest seq wins.
    let older = resign(record.seq() - 1, items.clone());
    let older = HostingRecord::verify(&older, &user_id, 0).unwrap();
    assert_eq!(
        older.supersedes(&record),
        Err(IdentityError::StaleSeq(record.seq() - 1))
    );
    assert_eq!(record.supersedes(&older), Ok(true));
    assert_eq!(HostingRecord::latest([&record, &older]), Ok(Some(&record)));
    let conflict = resign(record.seq(), items[..1].to_vec());
    let conflict = HostingRecord::verify(&conflict, &user_id, 0).unwrap();
    assert_eq!(
        record.supersedes(&conflict),
        Err(IdentityError::SeqConflict(record.seq()))
    );
}

#[test]
fn auth() {
    let v = vectors("auth");
    let hub = key(&v["hub_root_seed"]);
    let audience = HubId::from_root_pubkey(&hub.verifying_key());
    assert_eq!(audience.as_str(), text(&v["audience"]));
    let user_id = UserId::from_root_pubkey(&key(&v["user_root_seed"]).verifying_key());
    assert_eq!(user_id.as_str(), text(&v["user_id"]));
    let device = key(&v["device_seed"]);
    let device_id = DeviceId::from_device_pubkey(&device.verifying_key());
    assert_eq!(device_id.as_str(), text(&v["device_id"]));

    // The hub builds the challenge byte-for-byte.
    let c = &v["challenge"];
    let nonce: [u8; 32] = hex(&c["nonce"]).try_into().unwrap();
    let (issued_at, expires_at) = (uint(&c["issued_at"]), uint(&c["expires_at"]));
    let challenge = AuthChallenge::new(&audience, nonce, issued_at, expires_at);
    assert_eq!(challenge.to_bytes(), hex(&c["bytes"]));
    assert_eq!(AuthChallenge::decode(&hex(&c["bytes"])), Ok(challenge));

    let list = DeviceList::verify(&hex(&v["device_list"]), &user_id).unwrap();
    let response = hex(&v["response"]);
    let device_ref = verify_auth_response(&response, &audience, None, issued_at, &list).unwrap();
    assert_eq!(device_ref.user_id, user_id);
    assert_eq!(device_ref.device_id, device_id);
    assert_eq!(device_ref.nonce, nonce);

    // Independent re-encoding of the response.
    let tbs = encode(&Value::Array(vec![
        Value::Bytes(hex(&c["bytes"])),
        Value::Text(user_id.to_string()),
        Value::Text(device_id.to_string()),
    ]));
    let rebuilt = encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(hex(&c["bytes"])),
        Value::Text(user_id.to_string()),
        Value::Text(device_id.to_string()),
        Value::Bytes(sign(&device, AUTH_RESPONSE_CONTEXT, &tbs)),
    ]));
    assert_eq!(rebuilt, response);

    // Negative: wrong audience, expired, tampered signature.
    let other = HubId::from_root_pubkey(&key(&v["user_root_seed"]).verifying_key());
    assert_eq!(
        verify_auth_response(&response, &other, None, issued_at, &list),
        Err(IdentityError::AudienceMismatch)
    );
    assert_eq!(
        verify_auth_response(&response, &audience, None, expires_at, &list),
        Err(IdentityError::Expired)
    );
    assert_eq!(
        verify_auth_response(&flip_last(&response), &audience, None, issued_at, &list),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn auth_revoked_device() {
    // identity.json lists revoked devices of the same user; a response
    // naming one of them is rejected before its signature is checked.
    let identity = vectors("identity");
    let v = vectors("auth");
    let user_id = UserId::parse(text(&v["user_id"])).unwrap();
    assert_eq!(text(&identity["user_id"]), user_id.as_str());
    let list = DeviceList::verify(&hex(&identity["device_list"]["signed"]), &user_id).unwrap();
    let revoked = list.revoked().first().expect("vector revokes a device");
    let revoked_seed = identity["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| text(&d["device_id"]) == revoked.as_str())
        .map(|d| key(&d["seed"]))
        .unwrap();

    let challenge = hex(&v["challenge"]["bytes"]);
    let tbs = encode(&Value::Array(vec![
        Value::Bytes(challenge.clone()),
        Value::Text(user_id.to_string()),
        Value::Text(revoked.to_string()),
    ]));
    let response = encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(challenge),
        Value::Text(user_id.to_string()),
        Value::Text(revoked.to_string()),
        Value::Bytes(sign(&revoked_seed, AUTH_RESPONSE_CONTEXT, &tbs)),
    ]));
    let audience = HubId::parse(text(&v["audience"])).unwrap();
    assert_eq!(
        verify_auth_response(
            &response,
            &audience,
            None,
            uint(&v["challenge"]["issued_at"]),
            &list
        ),
        Err(IdentityError::Revoked(revoked.clone()))
    );
}

#[test]
fn recovery_backup_structure() {
    let v = vectors("recovery");
    let user_id = UserId::parse(text(&v["user_id"])).unwrap();
    let blob = hex(&v["blob"]);
    assert_eq!(check_recovery_backup(&blob, &user_id), Ok(()));
    let stranger = UserId::from_root_pubkey(&SigningKey::from_bytes(&[0xee; 32]).verifying_key());
    assert_eq!(
        check_recovery_backup(&blob, &stranger),
        Err(IdentityError::UserIdMismatch)
    );
    let mut trailing = blob;
    trailing.push(0);
    assert_eq!(
        check_recovery_backup(&trailing, &user_id),
        Err(IdentityError::NonCanonical)
    );
}

#[test]
fn sealed_link_bundle_structure() {
    let v = vectors("link");
    let sealed = hex(&v["seal"]["sealed"]);
    assert_eq!(check_sealed_link_bundle(&sealed), Ok(()));
    assert!(check_sealed_link_bundle(&sealed[..sealed.len() - 1]).is_err());
    // A recovery blob is not a sealed bundle.
    assert!(check_sealed_link_bundle(&hex(&vectors("recovery")["blob"])).is_err());
}
