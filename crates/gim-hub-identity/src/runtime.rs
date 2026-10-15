use ciborium::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::keys::{sign, verify};
use crate::{cbor, HubId, IdentityError, FORMAT_VERSION};

/// Signature context of a `SignedHubRuntimeCert`.
pub const HUB_RUNTIME_CERT_CONTEXT: &[u8] = b"gim/hub-runtime-cert/v1";

/// Identity multihash header (`0x00`, length 36) followed by the protobuf
/// libp2p `PublicKey { Type = Ed25519, Data = <32 bytes> }` header.
const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// Length of the libp2p PeerId bytes of an Ed25519 key.
pub const PEER_ID_LEN: usize = 38;

/// The libp2p PeerId bytes of an Ed25519 runtime key:
/// `0x00 0x24 0x08 0x01 0x12 0x20 || runtime_pubkey`.
pub fn libp2p_peer_id(runtime_pubkey: &VerifyingKey) -> [u8; PEER_ID_LEN] {
    let mut peer_id = [0u8; PEER_ID_LEN];
    peer_id[..PEER_ID_PREFIX.len()].copy_from_slice(&PEER_ID_PREFIX);
    peer_id[PEER_ID_PREFIX.len()..].copy_from_slice(runtime_pubkey.as_bytes());
    peer_id
}

/// A verified `SignedHubRuntimeCert`: the hub root key certifies the
/// short-lived runtime (libp2p host) key for `[not_before, not_after)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubRuntimeCert {
    hub_root_pubkey: VerifyingKey,
    runtime_pubkey: VerifyingKey,
    not_before: u64,
    not_after: u64,
    signed: Vec<u8>,
}

impl HubRuntimeCert {
    /// Issues the `SignedHubRuntimeCert` bytes for `runtime_pubkey`, signed
    /// by the hub's own root key. Times are Unix milliseconds; `not_after`
    /// is exclusive.
    pub fn issue(
        hub_root: &SigningKey,
        runtime_pubkey: &VerifyingKey,
        not_before: u64,
        not_after: u64,
    ) -> Vec<u8> {
        let tbs = cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Bytes(hub_root.verifying_key().as_bytes().to_vec()),
            Value::Bytes(runtime_pubkey.as_bytes().to_vec()),
            Value::Integer(not_before.into()),
            Value::Integer(not_after.into()),
        ]));
        let sig = sign(hub_root, HUB_RUNTIME_CERT_CONTEXT, &tbs);
        cbor::encode_signed(&tbs, &sig)
    }

    /// Decodes the `SignedHubRuntimeCert` bytes and verifies them against
    /// `expected_hub_root` at `now` (Unix milliseconds) in the spec's
    /// verification order: envelope, signature by `expected_hub_root`, then
    /// the body (version, `hub_root_pubkey` equals it, `runtime_pubkey`,
    /// times).
    pub fn verify(
        signed: &[u8],
        expected_hub_root: &VerifyingKey,
        now: u64,
    ) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(signed)?;
        verify(expected_hub_root, HUB_RUNTIME_CERT_CONTEXT, &tbs, &sig)?;
        let [_version, hub_root, runtime, not_before, not_after] = cbor::decode_body(&tbs)?;
        if cbor::sized::<32>(hub_root, "hub root key")? != *expected_hub_root.as_bytes() {
            return Err(IdentityError::HubKeyMismatch);
        }
        let runtime_pubkey = cbor::public_key(runtime)?;
        let not_before = cbor::uint(not_before)?;
        let not_after = cbor::uint(not_after)?;
        if now < not_before {
            return Err(IdentityError::NotYetValid);
        }
        if now >= not_after {
            return Err(IdentityError::Expired);
        }
        Ok(Self {
            hub_root_pubkey: *expected_hub_root,
            runtime_pubkey,
            not_before,
            not_after,
            signed: signed.to_vec(),
        })
    }

    pub fn hub_root_pubkey(&self) -> &VerifyingKey {
        &self.hub_root_pubkey
    }

    pub fn hub_id(&self) -> HubId {
        HubId::from_root_pubkey(&self.hub_root_pubkey)
    }

    pub fn runtime_pubkey(&self) -> &VerifyingKey {
        &self.runtime_pubkey
    }

    /// The libp2p PeerId bytes of the certified runtime key. A connection
    /// authenticated with this cert must have exactly this PeerId.
    pub fn peer_id(&self) -> [u8; PEER_ID_LEN] {
        libp2p_peer_id(&self.runtime_pubkey)
    }

    /// Unix time in milliseconds.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// Unix time in milliseconds, exclusive.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The `SignedHubRuntimeCert` bytes this cert was verified from.
    pub fn as_bytes(&self) -> &[u8] {
        &self.signed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn items(hub: &VerifyingKey, runtime: &VerifyingKey) -> Vec<Value> {
        vec![
            Value::Integer(1.into()),
            Value::Bytes(hub.as_bytes().to_vec()),
            Value::Bytes(runtime.as_bytes().to_vec()),
            Value::Integer(100.into()),
            Value::Integer(200.into()),
        ]
    }

    #[test]
    fn issues_and_verifies_within_window() {
        let hub = key(1);
        let runtime = key(2).verifying_key();
        let bytes = HubRuntimeCert::issue(&hub, &runtime, 100, 200);
        let cert = HubRuntimeCert::verify(&bytes, &hub.verifying_key(), 100).unwrap();
        assert_eq!(cert.runtime_pubkey(), &runtime);
        assert_eq!(cert.hub_id(), HubId::from_root_pubkey(&hub.verifying_key()));
        assert_eq!((cert.not_before(), cert.not_after()), (100, 200));
        assert_eq!(cert.peer_id()[6..], runtime.as_bytes()[..]);
        assert_eq!(cert.as_bytes(), bytes);
        assert!(HubRuntimeCert::verify(&bytes, &hub.verifying_key(), 199).is_ok());
        assert_eq!(
            HubRuntimeCert::verify(&bytes, &hub.verifying_key(), 99),
            Err(IdentityError::NotYetValid)
        );
        assert_eq!(
            HubRuntimeCert::verify(&bytes, &hub.verifying_key(), 200),
            Err(IdentityError::Expired)
        );
    }

    #[test]
    fn rejects_other_hub_and_bad_signature() {
        let hub = key(1);
        let bytes = HubRuntimeCert::issue(&hub, &key(2).verifying_key(), 100, 200);
        // Verified with another hub's key: the signature fails first.
        assert_eq!(
            HubRuntimeCert::verify(&bytes, &key(3).verifying_key(), 150),
            Err(IdentityError::BadSignature)
        );
        // Signed by the expected hub, naming another hub in the body.
        let other_body = sign_value(
            &hub,
            HUB_RUNTIME_CERT_CONTEXT,
            &Value::Array(items(&key(3).verifying_key(), &key(2).verifying_key())),
        );
        assert_eq!(
            HubRuntimeCert::verify(&other_body, &hub.verifying_key(), 150),
            Err(IdentityError::HubKeyMismatch)
        );
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            HubRuntimeCert::verify(&tampered, &hub.verifying_key(), 150),
            Err(IdentityError::BadSignature)
        );
        // Body naming the expected hub but signed by another key.
        let forged = sign_value(
            &key(3),
            HUB_RUNTIME_CERT_CONTEXT,
            &Value::Array(items(&hub.verifying_key(), &key(2).verifying_key())),
        );
        assert_eq!(
            HubRuntimeCert::verify(&forged, &hub.verifying_key(), 150),
            Err(IdentityError::BadSignature)
        );
        let wrong_context = sign_value(
            &hub,
            b"gim/hosting-entry/v1",
            &Value::Array(items(&hub.verifying_key(), &key(2).verifying_key())),
        );
        assert_eq!(
            HubRuntimeCert::verify(&wrong_context, &hub.verifying_key(), 150),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_shapes() {
        let hub = key(1);
        let resign =
            |items: Vec<Value>| sign_value(&hub, HUB_RUNTIME_CERT_CONTEXT, &Value::Array(items));
        let base = items(&hub.verifying_key(), &key(2).verifying_key());
        let mut extra = base.clone();
        extra.push(Value::Integer(0.into()));
        let mut short_key = base.clone();
        short_key[2] = Value::Bytes(vec![0; 31]);
        for bad in [extra, short_key] {
            assert!(matches!(
                HubRuntimeCert::verify(&resign(bad), &hub.verifying_key(), 150),
                Err(IdentityError::Malformed(_))
            ));
        }
        let mut weak = base.clone();
        let mut identity = vec![0u8; 32];
        identity[0] = 1;
        weak[2] = Value::Bytes(identity);
        assert_eq!(
            HubRuntimeCert::verify(&resign(weak), &hub.verifying_key(), 150),
            Err(IdentityError::InvalidKey)
        );
        let mut v2 = base;
        v2[0] = Value::Integer(2.into());
        assert_eq!(
            HubRuntimeCert::verify(&resign(v2), &hub.verifying_key(), 150),
            Err(IdentityError::UnsupportedVersion(2))
        );
    }
}
