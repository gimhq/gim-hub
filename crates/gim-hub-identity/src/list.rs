use std::cmp::Ordering;
use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;

use crate::keys::{parse_public_key, verify};
use crate::{cbor, DeviceCert, DeviceId, IdentityError, UserId};

/// Signature context of a `SignedDeviceList`.
pub const DEVICE_LIST_CONTEXT: &[u8] = b"gim/device-list/v1";

/// A verified `SignedDeviceList`: signed by the root key of `user_id`, every
/// cert verifies under that key, and no device id is listed twice or is
/// both certified and revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    user_id: UserId,
    root_pubkey: VerifyingKey,
    seq: u64,
    certs: Vec<DeviceCert>,
    revoked: Vec<DeviceId>,
    tbs: Vec<u8>,
    signed: Vec<u8>,
}

impl DeviceList {
    /// Decodes the `SignedDeviceList` bytes and verifies them for
    /// `expected_user_id`, following the spec's verification steps in order.
    pub fn verify(signed: &[u8], expected_user_id: &UserId) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(signed)?;
        let [_version, user_id, root_pubkey, seq, certs, revoked] = cbor::decode_body(&tbs)?;
        let user_id = cbor::text(user_id)?;
        let root_pubkey = parse_public_key(&cbor::byte_string(root_pubkey)?)?;
        let seq = cbor::uint(seq)?;
        let certs = cbor::list(certs)?;
        let revoked = cbor::list(revoked)?;

        let derived = UserId::from_root_pubkey(&root_pubkey);
        if &derived != expected_user_id || user_id != derived.as_str() {
            return Err(IdentityError::UserIdMismatch);
        }
        verify(&root_pubkey, DEVICE_LIST_CONTEXT, &tbs, &sig)?;

        let certs = certs
            .into_iter()
            .map(|cert| DeviceCert::verify(&cbor::byte_string(cert)?, &root_pubkey))
            .collect::<Result<Vec<_>, _>>()?;
        let revoked = revoked
            .into_iter()
            .map(|id| DeviceId::parse(&cbor::text(id)?))
            .collect::<Result<Vec<_>, _>>()?;

        let mut certified = HashSet::new();
        for cert in &certs {
            if !certified.insert(cert.device_id()) {
                return Err(IdentityError::DuplicateDevice(cert.device_id().clone()));
            }
        }
        let mut seen = HashSet::new();
        for id in &revoked {
            if !seen.insert(id) {
                return Err(IdentityError::DuplicateDevice(id.clone()));
            }
            if certified.contains(id) {
                return Err(IdentityError::Revoked(id.clone()));
            }
        }

        Ok(Self {
            user_id: derived,
            root_pubkey,
            seq,
            certs,
            revoked,
            tbs,
            signed: signed.to_vec(),
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn root_pubkey(&self) -> &VerifyingKey {
        &self.root_pubkey
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Certified devices, in list order.
    pub fn certs(&self) -> &[DeviceCert] {
        &self.certs
    }

    /// Revoked device ids, in list order.
    pub fn revoked(&self) -> &[DeviceId] {
        &self.revoked
    }

    /// The cert of a certified device.
    pub fn cert(&self, device_id: &DeviceId) -> Option<&DeviceCert> {
        self.certs.iter().find(|cert| cert.device_id() == device_id)
    }

    /// Whether `device_id` is certified. A verified list never certifies a
    /// revoked device, so certified devices are the active ones.
    pub fn is_active(&self, device_id: &DeviceId) -> bool {
        self.cert(device_id).is_some()
    }

    pub fn is_revoked(&self, device_id: &DeviceId) -> bool {
        self.revoked.contains(device_id)
    }

    /// Signing key of an active device.
    pub fn device_sig_pubkey(&self, device_id: &DeviceId) -> Option<&VerifyingKey> {
        self.cert(device_id).map(DeviceCert::device_sig_pubkey)
    }

    /// Whether `self` replaces `other`, per the spec's "Ordering and
    /// updates": true iff `self.seq > other.seq`. Equal seq with identical
    /// body bytes is not an update (`Ok(false)`); equal seq with different
    /// body bytes is [`IdentityError::SeqConflict`]. Lists of different
    /// users are [`IdentityError::UserIdMismatch`].
    pub fn supersedes(&self, other: &DeviceList) -> Result<bool, IdentityError> {
        if self.user_id != other.user_id {
            return Err(IdentityError::UserIdMismatch);
        }
        match self.seq.cmp(&other.seq) {
            Ordering::Greater => Ok(true),
            Ordering::Less => Ok(false),
            Ordering::Equal if self.tbs == other.tbs => Ok(false),
            Ordering::Equal => Err(IdentityError::SeqConflict(self.seq)),
        }
    }

    /// The `SignedDeviceList` bytes this list was verified from.
    pub fn as_bytes(&self) -> &[u8] {
        &self.signed
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;
    use crate::testutil::*;

    fn user_of(seed: u8) -> UserId {
        UserId::from_root_pubkey(&key(seed).verifying_key())
    }

    fn device_of(seed: u8) -> DeviceId {
        DeviceId::from_device_pubkey(&key(seed).verifying_key())
    }

    fn two_device_list(seq: u64) -> Vec<u8> {
        let root = key(1);
        let certs = vec![
            cert(&root, &key(2).verifying_key(), 1000, 1),
            cert(&root, &key(3).verifying_key(), 2000, 2),
        ];
        list(&root, seq, certs, vec![device_of(4)])
    }

    #[test]
    fn verifies_and_exposes_devices() {
        let bytes = two_device_list(3);
        let list = DeviceList::verify(&bytes, &user_of(1)).unwrap();
        assert_eq!(list.user_id(), &user_of(1));
        assert_eq!(list.root_pubkey(), &key(1).verifying_key());
        assert_eq!(list.seq(), 3);
        assert_eq!(list.certs().len(), 2);
        assert_eq!(list.revoked(), [device_of(4)]);
        assert!(list.is_active(&device_of(2)));
        assert!(!list.is_active(&device_of(4)));
        assert!(list.is_revoked(&device_of(4)));
        assert!(!list.is_active(&device_of(5)));
        assert_eq!(
            list.device_sig_pubkey(&device_of(3)),
            Some(&key(3).verifying_key())
        );
        assert_eq!(list.device_sig_pubkey(&device_of(4)), None);
        assert_eq!(list.cert(&device_of(2)).unwrap().created_at(), 1000);
        assert_eq!(list.as_bytes(), bytes);
    }

    #[test]
    fn rejects_wrong_expected_user() {
        assert_eq!(
            DeviceList::verify(&two_device_list(1), &user_of(9)),
            Err(IdentityError::UserIdMismatch)
        );
    }

    #[test]
    fn rejects_body_user_id_mismatch() {
        let root = key(1);
        let mut items = list_items(&root.verifying_key(), 1, vec![], vec![]);
        items[1] = Value::Text(user_of(9).to_string());
        let bytes = sign_value(&root, DEVICE_LIST_CONTEXT, &Value::Array(items));
        assert_eq!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::UserIdMismatch)
        );
    }

    #[test]
    fn rejects_tampered_signature_and_wrong_context() {
        let mut bytes = two_device_list(1);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        assert_eq!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::BadSignature)
        );
        let root = key(1);
        let body = Value::Array(list_items(&root.verifying_key(), 1, vec![], vec![]));
        let bytes = sign_value(&root, b"gim/device-cert/v1", &body);
        assert_eq!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = two_device_list(1);
        bytes.extend_from_slice(&[0x80]);
        assert!(matches!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_cert_of_other_root() {
        let root = key(1);
        let foreign = cert(&key(9), &key(2).verifying_key(), 1000, 1);
        let bytes = list(&root, 1, vec![foreign], vec![]);
        assert_eq!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rejects_duplicates_and_revoked_certs() {
        let root = key(1);
        let cert2 = || cert(&root, &key(2).verifying_key(), 1000, 1);
        let dup_cert = list(&root, 1, vec![cert2(), cert2()], vec![]);
        assert_eq!(
            DeviceList::verify(&dup_cert, &user_of(1)),
            Err(IdentityError::DuplicateDevice(device_of(2)))
        );
        let dup_revoked = list(&root, 1, vec![], vec![device_of(3), device_of(3)]);
        assert_eq!(
            DeviceList::verify(&dup_revoked, &user_of(1)),
            Err(IdentityError::DuplicateDevice(device_of(3)))
        );
        let both = list(&root, 1, vec![cert2()], vec![device_of(2)]);
        assert_eq!(
            DeviceList::verify(&both, &user_of(1)),
            Err(IdentityError::Revoked(device_of(2)))
        );
    }

    #[test]
    fn rejects_malformed_revoked_and_certs() {
        let root = key(1);
        let mut items = list_items(&root.verifying_key(), 1, vec![], vec![]);
        items[5] = Value::Array(vec![Value::Text("dnope".into())]);
        let bytes = sign_value(&root, DEVICE_LIST_CONTEXT, &Value::Array(items));
        assert!(matches!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::InvalidDeviceId(_))
        ));
        let mut items = list_items(&root.verifying_key(), 1, vec![], vec![]);
        items[4] = Value::Array(vec![Value::Text("not bytes".into())]);
        let bytes = sign_value(&root, DEVICE_LIST_CONTEXT, &Value::Array(items));
        assert!(matches!(
            DeviceList::verify(&bytes, &user_of(1)),
            Err(IdentityError::Malformed(_))
        ));
    }

    #[test]
    fn ordering_and_updates() {
        let v1 = DeviceList::verify(&two_device_list(1), &user_of(1)).unwrap();
        let v2 = DeviceList::verify(&two_device_list(2), &user_of(1)).unwrap();
        assert_eq!(v2.supersedes(&v1), Ok(true));
        assert_eq!(v1.supersedes(&v2), Ok(false));
        // Idempotent re-upload of the same list.
        assert_eq!(v2.supersedes(&v2.clone()), Ok(false));

        let root = key(1);
        let other = list(&root, 2, vec![], vec![]);
        let other = DeviceList::verify(&other, &user_of(1)).unwrap();
        assert_eq!(v2.supersedes(&other), Err(IdentityError::SeqConflict(2)));

        let stranger = list(&key(9), 5, vec![], vec![]);
        let stranger = DeviceList::verify(&stranger, &user_of(9)).unwrap();
        assert_eq!(v2.supersedes(&stranger), Err(IdentityError::UserIdMismatch));
    }
}
