//! Checks the vendored gim-core MLS credential vectors
//! (`testdata/identity/credential.json`).

use data_encoding::HEXLOWER;
use gim_hub_identity::{DeviceList, GimCredential, UserId, GIM_CREDENTIAL_TYPE};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/identity/credential.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

/// The verified list a vector names, if any.
fn device_list(value: &Value, user_id: &UserId) -> Option<DeviceList> {
    value
        .as_str()
        .map(|_| DeviceList::verify(&hex(value), user_id).unwrap())
}

#[test]
fn valid_credentials() {
    let file = vectors();
    assert_eq!(file["credential_type"], u64::from(GIM_CREDENTIAL_TYPE));
    let user_id = UserId::parse(file["user_id"].as_str().unwrap()).unwrap();
    let cases = file["valid"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let credential =
            GimCredential::decode_typed(GIM_CREDENTIAL_TYPE, &hex(&case["content_hex"])).unwrap();
        assert_eq!(
            credential.root_pubkey().as_bytes().to_vec(),
            hex(&file["root_pubkey"])
        );
        let list = device_list(&case["device_list"], &user_id);
        let (user, device) = credential
            .verify(list.as_ref(), &hex(&case["leaf_signature_key"]))
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(user.as_str(), case["user_id"], "{name}");
        assert_eq!(device.as_str(), case["device_id"], "{name}");
    }
}

#[test]
fn invalid_credentials() {
    let file = vectors();
    let user_id = UserId::parse(file["user_id"].as_str().unwrap()).unwrap();
    let cases = file["invalid"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let context = &case["context"];
        let credential_type = u16::try_from(context["credential_type"].as_u64().unwrap()).unwrap();
        let list = device_list(&context["device_list"], &user_id);
        let err = GimCredential::decode_typed(credential_type, &hex(&case["input_hex"]))
            .and_then(|credential| {
                credential.verify(list.as_ref(), &hex(&context["leaf_signature_key"]))
            })
            .expect_err(name);
        assert_eq!(err.code(), case["expected_error"], "{name}: {err}");
    }
}
