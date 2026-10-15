use ed25519_dalek::VerifyingKey;

use crate::keys::verify;
use crate::{cbor, DeviceId, IdentityError, UserId};

/// Signature context of a `SignedDeviceCert`.
pub const DEVICE_CERT_CONTEXT: &[u8] = b"gim/device-cert/v1";

/// A verified `SignedDeviceCert`: the root key binds `device_sig_pubkey`
/// to `user_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    user_id: UserId,
    device_id: DeviceId,
    device_sig_pubkey: VerifyingKey,
    created_at: u64,
    seq: u64,
    signed: Vec<u8>,
}

impl DeviceCert {
    /// Decodes the `SignedDeviceCert` bytes and verifies them against
    /// `root_pubkey` in the spec's verification order: envelope, signature
    /// over `"gim/device-cert/v1" || 0x00 || tbs`, then the body (version,
    /// shape, `user_id` and `device_id` derivations).
    pub fn verify(signed: &[u8], root_pubkey: &VerifyingKey) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(signed)?;
        verify(root_pubkey, DEVICE_CERT_CONTEXT, &tbs, &sig)?;
        let [_version, user_id, device_id, pubkey, created_at, seq] = cbor::decode_body(&tbs)?;
        let user_id = cbor::text(user_id)?;
        let device_id = cbor::text(device_id)?;
        let device_sig_pubkey = cbor::public_key(pubkey)?;
        let created_at = cbor::uint(created_at)?;
        let seq = cbor::uint(seq)?;
        let expected_user_id = UserId::from_root_pubkey(root_pubkey);
        if user_id != expected_user_id.as_str() {
            return Err(IdentityError::UserIdMismatch);
        }
        let expected_device_id = DeviceId::from_device_pubkey(&device_sig_pubkey);
        if device_id != expected_device_id.as_str() {
            return Err(IdentityError::DeviceIdMismatch);
        }
        Ok(Self {
            user_id: expected_user_id,
            device_id: expected_device_id,
            device_sig_pubkey,
            created_at,
            seq,
            signed: signed.to_vec(),
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn device_sig_pubkey(&self) -> &VerifyingKey {
        &self.device_sig_pubkey
    }

    /// Unix time in milliseconds.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The `SignedDeviceCert` bytes this cert was verified from.
    pub fn as_bytes(&self) -> &[u8] {
        &self.signed
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;
    use crate::testutil::*;

    #[test]
    fn verifies_well_formed_cert() {
        let root = key(1);
        let device = key(2).verifying_key();
        let bytes = cert(&root, &device, 1000, 7);
        let cert = DeviceCert::verify(&bytes, &root.verifying_key()).unwrap();
        assert_eq!(
            cert.user_id(),
            &UserId::from_root_pubkey(&root.verifying_key())
        );
        assert_eq!(cert.device_id(), &DeviceId::from_device_pubkey(&device));
        assert_eq!(cert.device_sig_pubkey(), &device);
        assert_eq!((cert.created_at(), cert.seq()), (1000, 7));
        assert_eq!(cert.as_bytes(), bytes);
    }

    #[test]
    fn rejects_tampered_signature() {
        let root = key(1);
        let mut bytes = cert(&root, &key(2).verifying_key(), 1000, 1);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            DeviceCert::verify(&bytes, &root.verifying_key()),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_root_and_context() {
        let root = key(1);
        let device = key(2).verifying_key();
        let bytes = cert(&root, &device, 1000, 1);
        assert_eq!(
            DeviceCert::verify(&bytes, &key(3).verifying_key()),
            Err(IdentityError::BadSignature)
        );
        let body = cert_body(&root.verifying_key(), &device, 1000, 1);
        let wrong_context = sign_value(&root, b"gim/device-list/v1", &body);
        assert_eq!(
            DeviceCert::verify(&wrong_context, &root.verifying_key()),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let root = key(1);
        let mut bytes = cert(&root, &key(2).verifying_key(), 1000, 1);
        bytes.push(0);
        assert_eq!(
            DeviceCert::verify(&bytes, &root.verifying_key()),
            Err(IdentityError::NonCanonical)
        );
        // Trailing bytes inside the signed tbs.
        let mut tbs = cbor::encode(&cert_body(
            &root.verifying_key(),
            &key(2).verifying_key(),
            1,
            1,
        ));
        tbs.push(0);
        let bytes = sign_tbs(&root, DEVICE_CERT_CONTEXT, &tbs);
        assert_eq!(
            DeviceCert::verify(&bytes, &root.verifying_key()),
            Err(IdentityError::NonCanonical)
        );
    }

    #[test]
    fn rejects_id_mismatches() {
        let root = key(1);
        let device = key(2).verifying_key();
        let mut body = cert_items(&root.verifying_key(), &device, 1000, 1);
        body[1] = Value::Text(UserId::from_root_pubkey(&key(9).verifying_key()).to_string());
        let bytes = sign_value(&root, DEVICE_CERT_CONTEXT, &Value::Array(body));
        assert_eq!(
            DeviceCert::verify(&bytes, &root.verifying_key()),
            Err(IdentityError::UserIdMismatch)
        );
        let mut body = cert_items(&root.verifying_key(), &device, 1000, 1);
        body[2] = Value::Text(DeviceId::from_device_pubkey(&key(9).verifying_key()).to_string());
        let bytes = sign_value(&root, DEVICE_CERT_CONTEXT, &Value::Array(body));
        assert_eq!(
            DeviceCert::verify(&bytes, &root.verifying_key()),
            Err(IdentityError::DeviceIdMismatch)
        );
    }

    #[test]
    fn rejects_wrong_shapes() {
        let root = key(1);
        let device = key(2).verifying_key();
        let resign =
            |items: Vec<Value>| sign_value(&root, DEVICE_CERT_CONTEXT, &Value::Array(items));
        let base = cert_items(&root.verifying_key(), &device, 1000, 1);

        let mut v2 = base.clone();
        v2[0] = Value::Integer(2.into());
        assert_eq!(
            DeviceCert::verify(&resign(v2), &root.verifying_key()),
            Err(IdentityError::UnsupportedVersion(2))
        );
        let mut extra = base.clone();
        extra.push(Value::Integer(0.into()));
        let mut short = base.clone();
        short.pop();
        let mut negative_seq = base.clone();
        negative_seq[5] = Value::Integer((-1).into());
        let mut short_key = base.clone();
        short_key[3] = Value::Bytes(vec![0; 31]);
        let mut weak_key = base.clone();
        let mut identity = vec![0u8; 32];
        identity[0] = 1;
        weak_key[3] = Value::Bytes(identity);
        for items in [extra, short, negative_seq, short_key] {
            assert!(matches!(
                DeviceCert::verify(&resign(items), &root.verifying_key()),
                Err(IdentityError::Malformed(_))
            ));
        }
        assert_eq!(
            DeviceCert::verify(&resign(weak_key), &root.verifying_key()),
            Err(IdentityError::InvalidKey)
        );
    }
}
