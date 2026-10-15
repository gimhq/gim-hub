//! Structural checks of the blobs the hub stores or relays but never opens:
//! `RootKeyBackup` and the sealed `LinkBundle`. Nothing here needs a secret,
//! and passing a check says nothing about whether the blob opens.

use crate::{cbor, IdentityError, UserId};

/// AES-256-GCM tag length; every ciphertext is at least this long.
const TAG_LEN: usize = 16;

fn ciphertext(value: ciborium::Value) -> Result<(), IdentityError> {
    if cbor::byte_string(value)?.len() < TAG_LEN {
        return Err(IdentityError::Malformed(
            "ciphertext is shorter than the AEAD tag".into(),
        ));
    }
    Ok(())
}

/// Checks that `blob` is a structurally valid `RootKeyBackup` of
/// `expected_user_id`: deterministic CBOR, version `1`, six elements, the
/// expected `user_id`, `kdf` of three uints, a 16-byte salt, a 12-byte
/// nonce and a ciphertext with room for the tag. The KDF parameter floor
/// and ceiling are the opener's checks and are not applied here.
pub fn check_recovery_backup(blob: &[u8], expected_user_id: &UserId) -> Result<(), IdentityError> {
    let [_version, user_id, kdf, salt, nonce, sealed] = cbor::decode_body(blob)?;
    if cbor::text(user_id)? != expected_user_id.as_str() {
        return Err(IdentityError::UserIdMismatch);
    }
    let [m_kib, t, p] = cbor::array(kdf)?;
    for param in [m_kib, t, p] {
        cbor::uint(param)?;
    }
    cbor::sized::<16>(salt, "salt")?;
    cbor::sized::<12>(nonce, "nonce")?;
    ciphertext(sealed)
}

/// Checks that `sealed` is a structurally valid sealed `LinkBundle`:
/// deterministic CBOR, version `1`, four elements, a 32-byte
/// `sender_eph_pub`, a 12-byte nonce and a ciphertext with room for the tag.
pub fn check_sealed_link_bundle(bytes: &[u8]) -> Result<(), IdentityError> {
    let [_version, sender_eph_pub, nonce, sealed] = cbor::decode_body(bytes)?;
    cbor::sized::<32>(sender_eph_pub, "sender_eph_pub")?;
    cbor::sized::<12>(nonce, "nonce")?;
    ciphertext(sealed)
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;
    use crate::testutil::key;

    fn uint(value: u64) -> Value {
        Value::Integer(value.into())
    }

    fn backup_items(user_id: &UserId) -> Vec<Value> {
        vec![
            uint(1),
            Value::Text(user_id.to_string()),
            Value::Array(vec![uint(65536), uint(3), uint(1)]),
            Value::Bytes(vec![0; 16]),
            Value::Bytes(vec![0; 12]),
            Value::Bytes(vec![0; 52]),
        ]
    }

    fn bundle_items() -> Vec<Value> {
        vec![
            uint(1),
            Value::Bytes(vec![9; 32]),
            Value::Bytes(vec![0; 12]),
            Value::Bytes(vec![0; 16]),
        ]
    }

    fn encode(items: Vec<Value>) -> Vec<u8> {
        cbor::encode(&Value::Array(items))
    }

    #[test]
    fn recovery_backup_shape() {
        let user = UserId::from_root_pubkey(&key(1).verifying_key());
        let base = backup_items(&user);
        assert_eq!(check_recovery_backup(&encode(base.clone()), &user), Ok(()));
        let other = UserId::from_root_pubkey(&key(2).verifying_key());
        assert_eq!(
            check_recovery_backup(&encode(base.clone()), &other),
            Err(IdentityError::UserIdMismatch)
        );
        let mut v2 = base.clone();
        v2[0] = uint(2);
        assert_eq!(
            check_recovery_backup(&encode(v2), &user),
            Err(IdentityError::UnsupportedVersion(2))
        );
        let mut trailing = encode(base.clone());
        trailing.push(0);
        let mut bad = vec![trailing];
        for (index, value) in [
            (2, Value::Array(vec![uint(1), uint(1)])),
            (3, Value::Bytes(vec![0; 15])),
            (4, Value::Bytes(vec![0; 16])),
            (5, Value::Bytes(vec![0; 15])),
        ] {
            let mut items = base.clone();
            items[index] = value;
            bad.push(encode(items));
        }
        let mut extra = base;
        extra.push(uint(0));
        bad.push(encode(extra));
        for blob in bad {
            assert!(matches!(
                check_recovery_backup(&blob, &user),
                Err(IdentityError::Malformed(_))
            ));
        }
    }

    #[test]
    fn sealed_link_bundle_shape() {
        let base = bundle_items();
        assert_eq!(check_sealed_link_bundle(&encode(base.clone())), Ok(()));
        let mut v2 = base.clone();
        v2[0] = uint(2);
        assert_eq!(
            check_sealed_link_bundle(&encode(v2)),
            Err(IdentityError::UnsupportedVersion(2))
        );
        for (index, value) in [
            (1, Value::Bytes(vec![0; 31])),
            (2, Value::Bytes(vec![0; 13])),
            (3, Value::Bytes(vec![0; 15])),
        ] {
            let mut items = base.clone();
            items[index] = value;
            assert!(matches!(
                check_sealed_link_bundle(&encode(items)),
                Err(IdentityError::Malformed(_))
            ));
        }
    }
}
