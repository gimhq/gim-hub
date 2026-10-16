//! Validation of push registrations. Provider, token and keys are opaque to
//! the hub: they are checked for shape only and passed to the push server.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

const MAX_PROVIDER: usize = 64;
const MAX_TOKEN: usize = 4096;
const MAX_KEY: usize = 256;

/// Checks `provider`, `token` and `app_id`. The error is a client-facing
/// reason.
pub fn validate_registration(
    provider: &str,
    token: &str,
    app_id: Option<&str>,
) -> Result<(), String> {
    let valid = !provider.is_empty()
        && provider.len() <= MAX_PROVIDER
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if !valid {
        return Err(format!(
            "provider must be 1-{MAX_PROVIDER} characters of a-z, 0-9, . _ -"
        ));
    }
    if token.is_empty() || token.len() > MAX_TOKEN {
        return Err(format!("token must be 1-{MAX_TOKEN} bytes"));
    }
    if token.chars().any(char::is_control) {
        return Err("token must not contain control characters".into());
    }
    if let Some(app_id) = app_id {
        let valid = !app_id.is_empty()
            && app_id.len() <= 255
            && app_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b));
        if !valid {
            return Err("app_id must be 1-255 characters of A-Z, a-z, 0-9, . - _ :".into());
        }
    }
    Ok(())
}

/// Decodes the optional opaque key `name` (`p256dh` or `auth`): base64url,
/// padding optional, 1-256 characters. The error is a client-facing reason.
pub fn decode_key(name: &str, value: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let invalid = || format!("{name} must be 1-{MAX_KEY} characters of base64url");
    if value.is_empty() || value.len() > MAX_KEY {
        return Err(invalid());
    }
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .ok()
        .filter(|key| !key.is_empty())
        .map(Some)
        .ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_are_opaque_lowercase_names() {
        for ok in [
            "apns",
            "fcm",
            "unifiedpush",
            "log",
            "x.y-z_9",
            &"a".repeat(64),
        ] {
            assert!(validate_registration(ok, "t", None).is_ok(), "{ok}");
        }
        for bad in ["", "APNS", "a b", "a/b", "ü", &"a".repeat(65)] {
            assert!(validate_registration(bad, "t", None).is_err(), "{bad}");
        }
    }

    #[test]
    fn tokens_and_app_ids() {
        assert!(validate_registration("fcm", "anything goes: ü", Some("im.g.apps")).is_ok());
        assert!(validate_registration("fcm", &"x".repeat(4096), None).is_ok());
        assert!(validate_registration("fcm", "bad\ntoken", None).is_err());
        assert!(validate_registration("fcm", "", None).is_err());
        assert!(validate_registration("fcm", &"x".repeat(4097), None).is_err());
        assert!(validate_registration("fcm", "t", Some("bad id")).is_err());
        assert!(validate_registration("fcm", "t", Some("")).is_err());
    }

    #[test]
    fn keys_are_optional_base64url() {
        assert_eq!(decode_key("auth", None), Ok(None));
        assert_eq!(decode_key("auth", Some("BAQE")), Ok(Some(vec![4; 3])));
        assert_eq!(decode_key("auth", Some("BAQ=")), Ok(Some(vec![4, 4])));
        assert_eq!(decode_key("auth", Some("-_8")), Ok(Some(vec![0xfb, 0xff])));
        for bad in ["", "!!", "a+b/", "A", &"A".repeat(257)] {
            assert!(decode_key("auth", Some(bad)).is_err(), "{bad}");
        }
        assert!(decode_key("p256dh", Some(&"A".repeat(256))).is_ok());
    }
}
