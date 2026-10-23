//! Root-signed HTTP requests (gim-core `docs/identity.md`, "Root-signed
//! requests"): a request carries the user's root public key, a timestamp and
//! a root-key signature over the method, path, timestamp and body digest.
//! The hub accepts them for account deletion.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use sha2::{Digest, Sha256};

use crate::keys::{parse_public_key, verify};
use crate::{IdentityError, UserId};

/// Signature context of a root-signed request.
pub const ROOT_REQUEST_CONTEXT: &[u8] = b"gim/root-request/v1";

/// How far a request timestamp may be from the hub's clock, either way.
pub const ROOT_REQUEST_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// The signed part after the context:
/// `method "\n" path "\n" timestamp_ms "\n" hex(SHA-256(body))`.
fn request_tbs(method: &str, path: &str, timestamp_ms: u64, body: &[u8]) -> Vec<u8> {
    format!(
        "{method}\n{path}\n{timestamp_ms}\n{}",
        HEXLOWER.encode(&Sha256::digest(body))
    )
    .into_bytes()
}

/// The `Gim-Key`, `Gim-Timestamp` and `Gim-Signature` headers of a request.
#[derive(Debug, Clone, Copy)]
pub struct RootRequestHeaders<'a> {
    pub key: &'a str,
    pub timestamp: &'a str,
    pub signature: &'a str,
}

/// Verifies a root-signed request received at `now_ms` and returns the user
/// id its key derives. `path` is the request path with its query string as
/// received. Errors: `decode_error` for a header that does not parse
/// (base64url, sizes, canonical decimal timestamp), `invalid_key`,
/// `expired` / `not_yet_valid` beyond [`ROOT_REQUEST_MAX_SKEW_MS`],
/// `bad_signature`.
pub fn verify_root_request(
    method: &str,
    path: &str,
    body: &[u8],
    headers: RootRequestHeaders<'_>,
    now_ms: u64,
) -> Result<UserId, IdentityError> {
    let malformed = |what: &str| IdentityError::Malformed(format!("root request {what}"));
    let key_bytes = BASE64URL_NOPAD
        .decode(headers.key.as_bytes())
        .map_err(|_| malformed("key is not base64url"))?;
    let key = parse_public_key(&key_bytes)?;
    let canonical = headers.timestamp == "0"
        || (!headers.timestamp.starts_with('0')
            && headers.timestamp.bytes().all(|b| b.is_ascii_digit()));
    let timestamp_ms: u64 = headers
        .timestamp
        .parse()
        .ok()
        .filter(|_| canonical)
        .ok_or_else(|| malformed("timestamp is not decimal"))?;
    let signature: [u8; 64] = BASE64URL_NOPAD
        .decode(headers.signature.as_bytes())
        .ok()
        .and_then(|sig| sig.try_into().ok())
        .ok_or_else(|| malformed("signature is not 64 bytes of base64url"))?;
    if timestamp_ms > now_ms.saturating_add(ROOT_REQUEST_MAX_SKEW_MS) {
        return Err(IdentityError::NotYetValid);
    }
    if timestamp_ms.saturating_add(ROOT_REQUEST_MAX_SKEW_MS) < now_ms {
        return Err(IdentityError::Expired);
    }
    verify(
        &key,
        ROOT_REQUEST_CONTEXT,
        &request_tbs(method, path, timestamp_ms, body),
        &signature,
    )?;
    Ok(UserId::from_root_pubkey(&key))
}
