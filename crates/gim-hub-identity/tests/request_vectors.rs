//! Checks `testdata/identity/request.json` (gim-core root-signed request
//! vectors) against `verify_root_request`.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use gim_hub_identity::{
    verify_root_request, IdentityError, RootRequestHeaders, ROOT_REQUEST_MAX_SKEW_MS,
};
use serde_json::Value;

fn vectors() -> Value {
    let path = format!(
        "{}/../../testdata/identity/request.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
fn request_vectors_verify_to_their_user() {
    let file = vectors();
    let cases = file["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let (method, path) = (text(&case["method"]), text(&case["path"]));
        let body = HEXLOWER.decode(text(&case["body"]).as_bytes()).unwrap();
        let now = case["timestamp_ms"].as_u64().unwrap();
        let timestamp = now.to_string();
        let headers = RootRequestHeaders {
            key: text(&case["gim_key"]),
            timestamp: &timestamp,
            signature: text(&case["gim_signature"]),
        };
        let user = verify_root_request(method, path, &body, headers, now).unwrap();
        assert_eq!(user.as_str(), text(&case["user_id"]));

        // Clock skew in both directions.
        let skew = ROOT_REQUEST_MAX_SKEW_MS;
        assert!(verify_root_request(method, path, &body, headers, now + skew).is_ok());
        assert_eq!(
            verify_root_request(method, path, &body, headers, now + skew + 1),
            Err(IdentityError::Expired)
        );
        assert_eq!(
            verify_root_request(method, path, &body, headers, now - skew - 1),
            Err(IdentityError::NotYetValid)
        );
        // Any changed part.
        for (m, p, b) in [
            ("PATCH", path, &body[..]),
            (method, "/other", &body[..]),
            (method, path, b"x"),
        ] {
            assert_eq!(
                verify_root_request(m, p, b, headers, now),
                Err(IdentityError::BadSignature),
                "{m} {p}"
            );
        }
        let padded = format!("0{timestamp}");
        let bad = RootRequestHeaders {
            timestamp: &padded,
            ..headers
        };
        assert!(matches!(
            verify_root_request(method, path, &body, bad, now),
            Err(IdentityError::Malformed(_))
        ));
        let short = BASE64URL_NOPAD.encode(&[1u8; 63]);
        let bad = RootRequestHeaders {
            signature: &short,
            ..headers
        };
        assert!(matches!(
            verify_root_request(method, path, &body, bad, now),
            Err(IdentityError::Malformed(_))
        ));
    }
}
