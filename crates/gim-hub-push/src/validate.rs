//! Provider-specific validation of push registrations.

use std::net::IpAddr;

use url::{Host, Url};

const MAX_TOKEN: usize = 4096;

/// Checks `token` and `app_id` for `provider` and returns the token in
/// canonical form (APNs tokens lowercased). The error is a client-facing
/// reason.
pub fn validate_registration(
    provider: &str,
    token: &str,
    app_id: Option<&str>,
) -> Result<String, String> {
    if token.is_empty() || token.len() > MAX_TOKEN {
        return Err(format!("token must be 1-{MAX_TOKEN} bytes"));
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
    match provider {
        "apns" => {
            let valid = (64..=200).contains(&token.len())
                && token.len() % 2 == 0
                && token.bytes().all(|b| b.is_ascii_hexdigit());
            if !valid {
                return Err("APNs token must be an even number (64-200) of hex digits".into());
            }
            Ok(token.to_ascii_lowercase())
        }
        "fcm" => {
            let valid = token.len() >= 32
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b));
            if !valid {
                return Err(
                    "FCM token must be at least 32 characters of A-Z, a-z, 0-9, - _ : .".into(),
                );
            }
            Ok(token.to_owned())
        }
        "unifiedpush" => {
            validate_endpoint(token)?;
            Ok(token.to_owned())
        }
        "log" => {
            if token.chars().any(char::is_control) {
                return Err("token must not contain control characters".into());
            }
            Ok(token.to_owned())
        }
        _ => Err(format!("unknown provider {provider:?}")),
    }
}

/// A UnifiedPush endpoint must be a public `https` URL: the hub POSTs to it,
/// so loopback and private addresses are refused.
fn validate_endpoint(token: &str) -> Result<(), String> {
    let url = Url::parse(token).map_err(|err| format!("invalid endpoint URL: {err}"))?;
    if url.scheme() != "https" {
        return Err("endpoint URL must use https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("endpoint URL must not contain credentials".into());
    }
    let public = match url.host() {
        None => false,
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain != "localhost" && !domain.ends_with(".localhost")
        }
        Some(Host::Ipv4(ip)) => is_public(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => is_public(IpAddr::V6(ip)),
    };
    if !public {
        return Err("endpoint URL must name a public host".into());
    }
    Ok(())
}

/// Whether `ip` is a globally routable unicast address. Also enforced on
/// every DNS answer when sending to UnifiedPush endpoints.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                // IPv4-compatible ::/96, NAT64 64:ff9b::/96 and 64:ff9b:1::/48,
                // 6to4 2002::/16.
                || s[..6] == [0; 6]
                || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                || s[..3] == [0x64, 0xff9b, 1]
                || s[0] == 0x2002)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apns_tokens_are_hex_and_lowercased() {
        let token = "AB".repeat(32);
        assert_eq!(
            validate_registration("apns", &token, Some("im.g.apps")).unwrap(),
            "ab".repeat(32)
        );
        assert!(validate_registration("apns", &"ab".repeat(31), None).is_err());
        assert!(validate_registration("apns", &format!("{}a", "ab".repeat(32)), None).is_err());
        assert!(validate_registration("apns", &"zz".repeat(32), None).is_err());
        assert!(validate_registration("apns", &"ab".repeat(32), Some("bad id")).is_err());
    }

    #[test]
    fn fcm_tokens() {
        let token = format!("cXyZ:APA91b{}", "a-_".repeat(20));
        assert!(validate_registration("fcm", &token, None).is_ok());
        assert!(validate_registration("fcm", "short", None).is_err());
        assert!(validate_registration("fcm", &format!("{token} space"), None).is_err());
    }

    #[test]
    fn unifiedpush_endpoints_are_public_https() {
        for ok in [
            "https://push.example.eu/up/abc?x=1",
            "https://203.0.113.9:8443/up",
            "https://[2001:db8::1]/up",
        ] {
            assert!(
                validate_registration("unifiedpush", ok, None).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "http://push.example.eu/up",
            "not a url",
            "https://localhost/up",
            "https://127.0.0.1/up",
            "https://10.1.2.3/up",
            "https://192.168.1.1/up",
            "https://169.254.169.254/latest",
            "https://100.64.0.1/up",
            "https://[::1]/up",
            "https://[fd00::1]/up",
            "https://[::ffff:127.0.0.1]/up",
            "https://[::127.0.0.1]/up",
            "https://[64:ff9b::a00:1]/up",
            "https://[2002:a00:1::1]/up",
            "https://user:pw@push.example.eu/up",
        ] {
            assert!(
                validate_registration("unifiedpush", bad, None).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn log_and_unknown() {
        assert!(validate_registration("log", "anything goes", None).is_ok());
        assert!(validate_registration("log", "bad\ntoken", None).is_err());
        assert!(validate_registration("log", "", None).is_err());
        assert!(validate_registration("log", &"x".repeat(4097), None).is_err());
        assert!(validate_registration("smoke", "t", None).is_err());
    }
}
