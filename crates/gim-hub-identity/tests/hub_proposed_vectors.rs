//! Checks the hub-proposed vectors of `testdata/identity/auth-v2.json`:
//! AuthChallenge v2 bound to the hub's public URL and the hub proof of
//! possession of `GET /v2/hub?nonce=`.

use ciborium::Value;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use gim_hub_identity::{
    sign_hub_proof, verify_auth_response, verify_hub_proof, AuthChallenge, DeviceId, DeviceList,
    HubId, IdentityError, UserId, AUTH_RESPONSE_CONTEXT,
};
use serde_json::Value as Json;

fn vectors() -> Json {
    let path = format!(
        "{}/../../testdata/identity/auth-v2.json",
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

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

#[test]
fn auth_challenge_v2() {
    let v = vectors();
    let audience = HubId::from_root_pubkey(&key(&v["hub_root_seed"]).verifying_key());
    assert_eq!(audience.as_str(), text(&v["audience"]));
    let url = text(&v["audience_url"]);
    let user_id = UserId::parse(text(&v["user_id"])).unwrap();
    let device = key(&v["device_seed"]);
    let device_id = DeviceId::from_device_pubkey(&device.verifying_key());
    assert_eq!(device_id.as_str(), text(&v["device_id"]));

    // [2, audience, audience_url, nonce, issued_at, expires_at]
    let c = &v["challenge"];
    let nonce: [u8; 32] = hex(&c["nonce"]).try_into().unwrap();
    let (issued_at, expires_at) = (
        c["issued_at"].as_u64().unwrap(),
        c["expires_at"].as_u64().unwrap(),
    );
    let bytes = hex(&c["bytes"]);
    let independent = encode(&Value::Array(vec![
        Value::Integer(2.into()),
        Value::Text(audience.to_string()),
        Value::Text(url.to_owned()),
        Value::Bytes(nonce.to_vec()),
        Value::Integer(issued_at.into()),
        Value::Integer(expires_at.into()),
    ]));
    assert_eq!(independent, bytes);
    let challenge = AuthChallenge::new_v2(&audience, url, nonce, issued_at, expires_at);
    assert_eq!(challenge.to_bytes(), bytes);
    assert_eq!(AuthChallenge::decode(&bytes), Ok(challenge));

    // The AuthResponse framing is unchanged (version 1).
    let tbs = encode(&Value::Array(vec![
        Value::Bytes(bytes.clone()),
        Value::Text(user_id.to_string()),
        Value::Text(device_id.to_string()),
    ]));
    let sig = device.sign(&[AUTH_RESPONSE_CONTEXT, &[0], &tbs].concat());
    let response = encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(bytes),
        Value::Text(user_id.to_string()),
        Value::Text(device_id.to_string()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]));
    assert_eq!(response, hex(&v["response"]));

    let list = DeviceList::verify(&hex(&v["device_list"]), &user_id).unwrap();
    let device_ref =
        verify_auth_response(&response, &audience, Some(url), issued_at, &list).unwrap();
    assert_eq!(device_ref.nonce, nonce);
    for expected_url in [None, Some("https://hub-b.example.eu")] {
        assert_eq!(
            verify_auth_response(&response, &audience, expected_url, issued_at, &list),
            Err(IdentityError::AudienceUrlMismatch)
        );
    }
}

#[test]
fn hub_proof() {
    let v = vectors();
    let root = key(&v["hub_root_seed"]);
    assert_eq!(
        root.verifying_key().as_bytes().to_vec(),
        hex(&v["hub_root_pubkey"])
    );
    let hub_id = HubId::parse(text(&v["audience"])).unwrap();
    let url = text(&v["audience_url"]);
    let p = &v["hub_proof"];
    let nonce: [u8; 32] = hex(&p["nonce"]).try_into().unwrap();
    assert_eq!(BASE64URL_NOPAD.encode(&nonce), text(&p["nonce_base64url"]));

    // "gim-hub-proof-v1" || 0x00 || nonce || hub_id || public_url
    let message = [
        b"gim-hub-proof-v1".as_slice(),
        &[0],
        &nonce,
        hub_id.as_str().as_bytes(),
        url.as_bytes(),
    ]
    .concat();
    assert_eq!(message, hex(&p["message"]));
    let proof = sign_hub_proof(&root, &nonce, url);
    assert_eq!(proof.to_vec(), hex(&p["proof"]));
    assert_eq!(BASE64URL_NOPAD.encode(&proof), text(&p["proof_base64url"]));
    root.verifying_key()
        .verify(&message, &Signature::from_bytes(&proof))
        .unwrap();
    assert_eq!(
        verify_hub_proof(&root.verifying_key(), &hub_id, &nonce, url, &proof),
        Ok(())
    );
}
