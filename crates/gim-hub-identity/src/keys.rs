use ed25519_dalek::{Signature, VerifyingKey};

use crate::IdentityError;

/// Parses a 32-byte compressed Edwards point; rejects points that do not
/// decompress and small-order points.
pub fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey, IdentityError> {
    let bytes: &[u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidKey)?;
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| IdentityError::InvalidKey)?;
    if key.is_weak() {
        return Err(IdentityError::InvalidKey);
    }
    Ok(key)
}

/// The message every signature covers: `context || 0x00 || tbs`.
pub(crate) fn signing_input(context: &[u8], tbs: &[u8]) -> Vec<u8> {
    [context, &[0], tbs].concat()
}

/// Strict Ed25519 verification of `sig` over `context || 0x00 || tbs`.
pub(crate) fn verify(
    key: &VerifyingKey,
    context: &[u8],
    tbs: &[u8],
    sig: &[u8; 64],
) -> Result<(), IdentityError> {
    key.verify_strict(&signing_input(context, tbs), &Signature::from_bytes(sig))
        .map_err(|_| IdentityError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_keys() {
        // Identity point (small order).
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(parse_public_key(&identity), Err(IdentityError::InvalidKey));
        assert_eq!(parse_public_key(&[0u8; 31]), Err(IdentityError::InvalidKey));
        let valid = crate::testutil::key(1).verifying_key();
        assert_eq!(parse_public_key(valid.as_bytes()), Ok(valid));
    }
}
