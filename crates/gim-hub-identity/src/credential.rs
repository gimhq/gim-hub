//! The self-certifying MLS credential of a device (spec section "MLS
//! credential"), at the byte level: the `serialized_content` of an MLS
//! `Credential` with credential type [`GIM_CREDENTIAL_TYPE`].

use ciborium::Value;
use ed25519_dalek::VerifyingKey;

use crate::{cbor, parse_public_key, DeviceCert, DeviceId, DeviceList, IdentityError, UserId};

/// MLS credential type of a gim credential (private-use range).
pub const GIM_CREDENTIAL_TYPE: u16 = 0xF001;

/// The only credential content version.
const CREDENTIAL_VERSION: u64 = 1;

/// Why a credential failed validation. [`CredentialError::code`] gives the
/// stable names of the spec and `credential.json`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("credential type {0:#06x} is not a gim credential")]
    WrongCredentialType(u16),
    #[error("credential content is not deterministic CBOR")]
    NonCanonicalCbor,
    #[error("malformed credential content: {0}")]
    MalformedContent(String),
    #[error("unsupported credential version")]
    UnsupportedVersion,
    #[error("device certificate: {0}")]
    Cert(IdentityError),
    #[error("leaf signature key does not match the certified device key")]
    LeafKeyMismatch,
    #[error("no device list of {user} is known")]
    DeviceListUnknown { user: UserId },
    #[error("device {device} of {user} is revoked")]
    RevokedDevice { user: UserId, device: DeviceId },
    #[error("device {device} of {user} is not certified with the leaf key in the latest list")]
    DeviceNotInList { user: UserId, device: DeviceId },
    /// The device list given to [`GimCredential::verify`] is not the
    /// certified user's.
    #[error("device list of {list_user} given for a credential of {user}")]
    DeviceListUserMismatch { user: UserId, list_user: UserId },
}

impl CredentialError {
    /// Stable snake_case name of the failure. `device_list_user_mismatch`
    /// is a caller error, not part of the spec's table.
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongCredentialType(_) => "wrong_credential_type",
            Self::NonCanonicalCbor => "non_canonical_cbor",
            Self::MalformedContent(_) => "malformed_content",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Cert(IdentityError::BadSignature) => "bad_cert_signature",
            Self::Cert(IdentityError::UserIdMismatch) => "user_id_mismatch",
            Self::Cert(IdentityError::DeviceIdMismatch) => "device_id_mismatch",
            Self::Cert(_) => "invalid_cert",
            Self::LeafKeyMismatch => "leaf_key_mismatch",
            Self::DeviceListUnknown { .. } => "device_list_unknown",
            Self::RevokedDevice { .. } => "revoked_device",
            Self::DeviceNotInList { .. } => "device_not_in_list",
            Self::DeviceListUserMismatch { .. } => "device_list_user_mismatch",
        }
    }
}

/// Decoded credential content
/// `[1, root_pubkey: bstr .size 32, signed_device_cert: bstr]`; not yet
/// verified (see [`GimCredential::verify`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GimCredential {
    root_pubkey: VerifyingKey,
    signed_device_cert: Vec<u8>,
}

impl GimCredential {
    /// [`GimCredential::decode`] after checking that `credential_type` is
    /// [`GIM_CREDENTIAL_TYPE`] (validation step 1).
    pub fn decode_typed(credential_type: u16, content: &[u8]) -> Result<Self, CredentialError> {
        if credential_type != GIM_CREDENTIAL_TYPE {
            return Err(CredentialError::WrongCredentialType(credential_type));
        }
        Self::decode(content)
    }

    /// Decodes the credential content (validation step 2), in this order:
    /// CBOR, deterministic encoding, an array whose first item is an
    /// integer, version `1`, then three items with byte strings, a valid
    /// root key and a well-formed `SignedDeviceCert` envelope.
    pub fn decode(content: &[u8]) -> Result<Self, CredentialError> {
        let malformed = |reason: &str| CredentialError::MalformedContent(reason.into());
        let value = cbor::decode(content).map_err(|err| match err {
            IdentityError::NonCanonical => CredentialError::NonCanonicalCbor,
            other => CredentialError::MalformedContent(other.to_string()),
        })?;
        let Value::Array(items) = value else {
            return Err(malformed("content is not an array"));
        };
        let Some(Value::Integer(version)) = items.first() else {
            return Err(malformed("version is not an integer"));
        };
        if u64::try_from(*version).ok() != Some(CREDENTIAL_VERSION) {
            return Err(CredentialError::UnsupportedVersion);
        }
        let [_, root, cert]: [Value; 3] = items
            .try_into()
            .map_err(|_| malformed("content is not an array of 3 items"))?;
        let (Value::Bytes(root), Value::Bytes(signed_device_cert)) = (root, cert) else {
            return Err(malformed("expected byte strings"));
        };
        if root.len() != 32 {
            return Err(malformed("root public key is not 32 bytes"));
        }
        let root_pubkey = parse_public_key(&root).map_err(|err| malformed(&err.to_string()))?;
        cbor::decode_signed(&signed_device_cert).map_err(CredentialError::Cert)?;
        Ok(Self {
            root_pubkey,
            signed_device_cert,
        })
    }

    pub fn root_pubkey(&self) -> &VerifyingKey {
        &self.root_pubkey
    }

    /// The embedded `SignedDeviceCert` bytes.
    pub fn signed_device_cert(&self) -> &[u8] {
        &self.signed_device_cert
    }

    /// Validates the credential of a leaf whose MLS signature key is
    /// `leaf_sig_pubkey` (validation steps 3-5): the cert verifies under the
    /// root key, its device key equals `leaf_sig_pubkey`, and in
    /// `device_list`, the latest verified list known for the user, the
    /// device is not revoked and is certified with the leaf's key. Fails
    /// closed: `None` (no known list) is `device_list_unknown`. Returns the
    /// leaf's device.
    pub fn verify(
        &self,
        device_list: Option<&DeviceList>,
        leaf_sig_pubkey: &[u8],
    ) -> Result<(UserId, DeviceId), CredentialError> {
        let cert = DeviceCert::verify(&self.signed_device_cert, &self.root_pubkey)
            .map_err(CredentialError::Cert)?;
        if cert.device_sig_pubkey().as_bytes().as_slice() != leaf_sig_pubkey {
            return Err(CredentialError::LeafKeyMismatch);
        }
        let user = cert.user_id().clone();
        let device = cert.device_id().clone();
        let Some(list) = device_list else {
            return Err(CredentialError::DeviceListUnknown { user });
        };
        if list.user_id() != &user {
            return Err(CredentialError::DeviceListUserMismatch {
                user,
                list_user: list.user_id().clone(),
            });
        }
        if list.is_revoked(&device) {
            return Err(CredentialError::RevokedDevice { user, device });
        }
        if list.device_sig_pubkey(&device) != Some(cert.device_sig_pubkey()) {
            return Err(CredentialError::DeviceNotInList { user, device });
        }
        Ok((user, device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn content(version: Value, root: Value, cert: Value) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![version, root, cert]))
    }

    fn sample() -> Vec<u8> {
        let root = key(1);
        content(
            Value::Integer(1.into()),
            Value::Bytes(root.verifying_key().as_bytes().to_vec()),
            Value::Bytes(cert(&root, &key(2).verifying_key(), 1000, 1)),
        )
    }

    fn user_of(seed: u8) -> UserId {
        UserId::from_root_pubkey(&key(seed).verifying_key())
    }

    fn device_of(seed: u8) -> DeviceId {
        DeviceId::from_device_pubkey(&key(seed).verifying_key())
    }

    fn code(result: Result<impl std::fmt::Debug, CredentialError>) -> &'static str {
        result.unwrap_err().code()
    }

    fn active_list() -> DeviceList {
        let root = key(1);
        let bytes = list(
            &root,
            1,
            vec![cert(&root, &key(2).verifying_key(), 1000, 1)],
            vec![],
        );
        DeviceList::verify(&bytes, &user_of(1)).unwrap()
    }

    #[test]
    fn decodes_and_verifies() {
        let credential = GimCredential::decode_typed(GIM_CREDENTIAL_TYPE, &sample()).unwrap();
        assert_eq!(credential.root_pubkey(), &key(1).verifying_key());
        let leaf = key(2).verifying_key();
        let active = active_list();
        assert_eq!(
            credential.verify(Some(&active), leaf.as_bytes()),
            Ok((user_of(1), device_of(2)))
        );
        assert_eq!(
            code(credential.verify(Some(&active), key(3).verifying_key().as_bytes())),
            "leaf_key_mismatch"
        );
        assert_eq!(
            code(credential.verify(Some(&active), &[])),
            "leaf_key_mismatch"
        );
    }

    #[test]
    fn decode_is_strict() {
        let bytes = sample();
        assert_eq!(
            code(GimCredential::decode_typed(1, &bytes)),
            "wrong_credential_type"
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(code(GimCredential::decode(&trailing)), "non_canonical_cbor");
        let mut indefinite = vec![0x9f];
        indefinite.extend_from_slice(&bytes[1..]);
        indefinite.push(0xff);
        assert_eq!(
            code(GimCredential::decode(&indefinite)),
            "non_canonical_cbor"
        );
        for cut in 0..bytes.len() {
            assert_eq!(
                code(GimCredential::decode(&bytes[..cut])),
                "malformed_content"
            );
        }

        let root = Value::Bytes(key(1).verifying_key().as_bytes().to_vec());
        let cert = Value::Bytes(cert(&key(1), &key(2).verifying_key(), 1000, 1));
        let one = || Value::Integer(1.into());
        let decode = |bytes: Vec<u8>| GimCredential::decode(&bytes).map(|_| ());
        assert_eq!(
            code(decode(content(
                Value::Integer(2.into()),
                root.clone(),
                cert.clone()
            ))),
            "unsupported_version"
        );
        assert_eq!(
            code(decode(content(
                Value::Text("1".into()),
                root.clone(),
                cert.clone()
            ))),
            "malformed_content"
        );
        assert_eq!(
            code(decode(content(
                one(),
                Value::Bytes(vec![1; 31]),
                cert.clone()
            ))),
            "malformed_content"
        );
        let mut identity = vec![0u8; 32];
        identity[0] = 1;
        assert_eq!(
            code(decode(content(one(), Value::Bytes(identity), cert.clone()))),
            "malformed_content"
        );
        assert_eq!(
            code(decode(content(
                one(),
                root.clone(),
                Value::Text("x".into())
            ))),
            "malformed_content"
        );
        assert_eq!(
            code(decode(cbor::encode(&Value::Array(vec![
                one(),
                root.clone()
            ])))),
            "malformed_content"
        );
        assert_eq!(
            code(decode(content(one(), root, Value::Bytes(vec![0x01])))),
            "invalid_cert"
        );
        // The version is checked before the shape of the rest.
        assert_eq!(
            code(decode(cbor::encode(&Value::Array(vec![Value::Integer(
                2.into()
            )])))),
            "unsupported_version"
        );
        assert_eq!(
            code(decode(cbor::encode(&Value::Array(vec![])))),
            "malformed_content"
        );
    }

    #[test]
    fn verify_maps_cert_failures() {
        let root = key(1);
        let leaf = key(2).verifying_key();
        let with_cert = |cert: Vec<u8>| {
            let bytes = content(
                Value::Integer(1.into()),
                Value::Bytes(root.verifying_key().as_bytes().to_vec()),
                Value::Bytes(cert),
            );
            GimCredential::decode(&bytes)
                .unwrap()
                .verify(None, leaf.as_bytes())
        };
        assert_eq!(
            code(with_cert(cert(&key(9), &leaf, 1000, 1))),
            "bad_cert_signature"
        );
        let mut items = cert_items(&root.verifying_key(), &leaf, 1000, 1);
        items[1] = Value::Text(user_of(9).to_string());
        assert_eq!(
            code(with_cert(sign_value(
                &root,
                crate::DEVICE_CERT_CONTEXT,
                &Value::Array(items)
            ))),
            "user_id_mismatch"
        );
        let mut items = cert_items(&root.verifying_key(), &leaf, 1000, 1);
        items[2] = Value::Text(device_of(9).to_string());
        assert_eq!(
            code(with_cert(sign_value(
                &root,
                crate::DEVICE_CERT_CONTEXT,
                &Value::Array(items)
            ))),
            "device_id_mismatch"
        );
        let mut items = cert_items(&root.verifying_key(), &leaf, 1000, 1);
        items[0] = Value::Integer(2.into());
        assert_eq!(
            code(with_cert(sign_value(
                &root,
                crate::DEVICE_CERT_CONTEXT,
                &Value::Array(items)
            ))),
            "invalid_cert"
        );
    }

    #[test]
    fn verify_checks_device_list() {
        let root = key(1);
        let credential = GimCredential::decode(&sample()).unwrap();
        let leaf = key(2).verifying_key();
        assert!(credential
            .verify(Some(&active_list()), leaf.as_bytes())
            .is_ok());
        assert_eq!(
            credential.verify(None, leaf.as_bytes()),
            Err(CredentialError::DeviceListUnknown { user: user_of(1) })
        );
        let empty = DeviceList::verify(&list(&root, 1, vec![], vec![]), &user_of(1)).unwrap();
        assert_eq!(
            credential.verify(Some(&empty), leaf.as_bytes()),
            Err(CredentialError::DeviceNotInList {
                user: user_of(1),
                device: device_of(2),
            })
        );
        let revoked = list(&root, 2, vec![], vec![device_of(2)]);
        let revoked = DeviceList::verify(&revoked, &user_of(1)).unwrap();
        assert_eq!(
            credential.verify(Some(&revoked), leaf.as_bytes()),
            Err(CredentialError::RevokedDevice {
                user: user_of(1),
                device: device_of(2),
            })
        );
        let stranger = DeviceList::verify(&list(&key(9), 1, vec![], vec![]), &user_of(9)).unwrap();
        assert_eq!(
            code(credential.verify(Some(&stranger), leaf.as_bytes())),
            "device_list_user_mismatch"
        );
    }
}
