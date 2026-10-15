//! Runs the vendored gim-core negative vectors
//! (`testdata/identity/negative.json`): every case must fail with exactly
//! its `expected_error` code.

use std::collections::HashSet;

use data_encoding::HEXLOWER;
use gim_hub_identity::{
    auth_response_user_id, parse_public_key, verify_auth_response, DeviceCert, DeviceList,
    HostingRecord, HubId, HubRuntimeCert, IdentityError, UserId,
};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/identity/negative.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    HEXLOWER.decode(value.as_str().unwrap().as_bytes()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// Verifies one case the way the hub would.
fn run(case: &Value) -> Result<(), IdentityError> {
    let input = hex(&case["input_hex"]);
    let context = &case["context"];
    let now = || context["now"].as_u64().unwrap();
    match text(&case["kind"]) {
        "device_cert" => {
            let root = parse_public_key(&hex(&context["root_pubkey"]))?;
            DeviceCert::verify(&input, &root)?;
        }
        "device_list" => {
            let user_id = UserId::parse(text(&context["user_id"]))?;
            let list = DeviceList::verify(&input, &user_id)?;
            if let Some(stored) = context.get("stored") {
                let stored = DeviceList::verify(&hex(stored), &user_id)?;
                list.supersedes(&stored)?;
            }
        }
        "runtime_cert" => {
            let hub = parse_public_key(&hex(&context["hub_root_pubkey"]))?;
            HubRuntimeCert::verify(&input, &hub, now())?;
        }
        "hosting_record" => {
            let record = match context.get("user_id") {
                Some(user_id) => {
                    HostingRecord::verify(&input, &UserId::parse(text(user_id))?, now())?
                }
                None => HostingRecord::verify_claimed(&input, now())?,
            };
            if let Some(stored) = context.get("stored") {
                let stored = HostingRecord::verify(&hex(stored), record.user_id(), now())?;
                record.supersedes(&stored)?;
            }
        }
        "auth_response" => {
            let user_id = auth_response_user_id(&input)?;
            let list = DeviceList::verify(&hex(&context["device_list"]), &user_id)?;
            let audience = HubId::parse(text(&context["audience"]))?;
            verify_auth_response(&input, &audience, now(), &list)?;
        }
        kind => panic!("unknown kind {kind}"),
    }
    Ok(())
}

#[test]
fn every_case_fails_with_its_code() {
    let file = vectors();
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 44);
    let mut names = HashSet::new();
    for case in cases {
        let name = text(&case["name"]);
        assert!(names.insert(name), "duplicate case {name}");
        let err = run(case).expect_err(name);
        assert_eq!(err.code(), text(&case["expected_error"]), "{name}: {err}");
    }
}
