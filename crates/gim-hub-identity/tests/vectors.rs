//! Checks the vendored gim-core vectors (`testdata/identity/identity.json`).

use ciborium::Value;
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, SigningKey};
use gim_hub_identity::{
    DeviceCert, DeviceId, DeviceList, IdentityError, UserId, DEVICE_CERT_CONTEXT,
    DEVICE_LIST_CONTEXT,
};
use serde_json::Value as Json;

fn vectors() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/identity/identity.json"
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

/// Independent re-encoding of the signed form, to check the vectors
/// byte-for-byte (Ed25519 signatures are deterministic).
fn sign(key: &SigningKey, context: &[u8], items: Vec<Value>) -> Vec<u8> {
    let tbs = encode(&Value::Array(items));
    let sig = key.sign(&[context, &[0], &tbs].concat()).to_bytes();
    encode(&Value::Array(vec![
        Value::Bytes(tbs),
        Value::Bytes(sig.to_vec()),
    ]))
}

#[test]
fn root_key_and_user_id() {
    let v = vectors();
    let root = key(&v["root_seed"]);
    assert_eq!(
        root.verifying_key().as_bytes().to_vec(),
        hex(&v["root_pubkey"])
    );
    let user_id = UserId::from_root_pubkey(&root.verifying_key());
    assert_eq!(user_id.as_str(), text(&v["user_id"]));
    assert_eq!(UserId::parse(text(&v["user_id"])), Ok(user_id));
}

#[test]
fn device_certs() {
    let v = vectors();
    let root = key(&v["root_seed"]);
    let devices = v["devices"].as_array().unwrap();
    assert!(!devices.is_empty());
    for d in devices {
        let device = key(&d["seed"]);
        assert_eq!(
            device.verifying_key().as_bytes().to_vec(),
            hex(&d["pubkey"])
        );
        let device_id = DeviceId::from_device_pubkey(&device.verifying_key());
        assert_eq!(device_id.as_str(), text(&d["device_id"]));
        assert_eq!(
            DeviceId::parse(text(&d["device_id"])),
            Ok(device_id.clone())
        );

        let signed = hex(&d["signed_cert"]);
        let cert = DeviceCert::verify(&signed, &root.verifying_key()).unwrap();
        assert_eq!(cert.user_id().as_str(), text(&v["user_id"]));
        assert_eq!(cert.device_id(), &device_id);
        assert_eq!(cert.device_sig_pubkey(), &device.verifying_key());
        assert_eq!(cert.created_at(), d["created_at"].as_u64().unwrap());
        assert_eq!(cert.seq(), d["seq"].as_u64().unwrap());
        assert_eq!(cert.as_bytes(), signed);

        let rebuilt = sign(
            &root,
            DEVICE_CERT_CONTEXT,
            vec![
                Value::Integer(1.into()),
                Value::Text(text(&v["user_id"]).into()),
                Value::Text(device_id.to_string()),
                Value::Bytes(device.verifying_key().as_bytes().to_vec()),
                Value::Integer(cert.created_at().into()),
                Value::Integer(cert.seq().into()),
            ],
        );
        assert_eq!(rebuilt, signed);

        // Negative: another root key.
        let other = SigningKey::from_bytes(&[0xee; 32]);
        assert_eq!(
            DeviceCert::verify(&signed, &other.verifying_key()),
            Err(IdentityError::BadSignature)
        );
    }
}

#[test]
fn device_list() {
    let v = vectors();
    let root = key(&v["root_seed"]);
    let user_id = UserId::parse(text(&v["user_id"])).unwrap();
    let l = &v["device_list"];
    let signed = hex(&l["signed"]);
    let list = DeviceList::verify(&signed, &user_id).unwrap();
    assert_eq!(list.user_id(), &user_id);
    assert_eq!(list.root_pubkey(), &root.verifying_key());
    assert_eq!(list.seq(), l["seq"].as_u64().unwrap());
    assert_eq!(list.as_bytes(), signed);

    let ids = |key: &str| -> Vec<String> {
        l[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| text(id).to_owned())
            .collect()
    };
    let certified: Vec<String> = list
        .certs()
        .iter()
        .map(|c| c.device_id().to_string())
        .collect();
    assert_eq!(certified, ids("certs"));
    let revoked: Vec<String> = list.revoked().iter().map(ToString::to_string).collect();
    assert_eq!(revoked, ids("revoked"));

    let devices = v["devices"].as_array().unwrap();
    let mut cert_items = Vec::new();
    for d in devices {
        let id = DeviceId::parse(text(&d["device_id"])).unwrap();
        let revoked = ids("revoked").contains(&id.to_string());
        assert_eq!(list.is_active(&id), !revoked);
        assert_eq!(list.is_revoked(&id), revoked);
        if revoked {
            assert_eq!(list.device_sig_pubkey(&id), None);
        } else {
            assert_eq!(
                list.device_sig_pubkey(&id).unwrap().as_bytes().to_vec(),
                hex(&d["pubkey"])
            );
            assert_eq!(list.cert(&id).unwrap().as_bytes(), hex(&d["signed_cert"]));
            cert_items.push(Value::Bytes(hex(&d["signed_cert"])));
        }
    }

    let rebuilt = sign(
        &root,
        DEVICE_LIST_CONTEXT,
        vec![
            Value::Integer(1.into()),
            Value::Text(user_id.to_string()),
            Value::Bytes(root.verifying_key().as_bytes().to_vec()),
            Value::Integer(list.seq().into()),
            Value::Array(cert_items),
            Value::Array(revoked.into_iter().map(Value::Text).collect()),
        ],
    );
    assert_eq!(rebuilt, signed);
    assert_eq!(list.supersedes(&list.clone()), Ok(false));
}

#[test]
fn device_list_negative() {
    let v = vectors();
    let user_id = UserId::parse(text(&v["user_id"])).unwrap();
    let signed = hex(&v["device_list"]["signed"]);

    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        DeviceList::verify(&tampered, &user_id),
        Err(IdentityError::BadSignature)
    );

    let mut trailing = signed.clone();
    trailing.push(0);
    assert_eq!(
        DeviceList::verify(&trailing, &user_id),
        Err(IdentityError::NonCanonical)
    );

    let stranger = UserId::from_root_pubkey(&SigningKey::from_bytes(&[0xee; 32]).verifying_key());
    assert_eq!(
        DeviceList::verify(&signed, &stranger),
        Err(IdentityError::UserIdMismatch)
    );

    // A signed cert is not a device list, and vice versa.
    let cert = hex(&v["devices"][0]["signed_cert"]);
    assert!(DeviceList::verify(&cert, &user_id).is_err());
    let root = key(&v["root_seed"]);
    assert!(DeviceCert::verify(&signed, &root.verifying_key()).is_err());
}
