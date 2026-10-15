use ciborium::Value;

use crate::keys::verify;
use crate::{cbor, DeviceId, DeviceList, HubId, IdentityError, UserId, FORMAT_VERSION};

/// Signature context of `AuthResponse.sig` (device signing key).
pub const AUTH_RESPONSE_CONTEXT: &[u8] = b"gim/auth-response/v1";

/// Longest accepted challenge lifetime, `expires_at - issued_at`, in
/// milliseconds.
pub const MAX_CHALLENGE_LIFETIME_MS: u64 = 300_000;

/// An unsigned `AuthChallenge`. The hub that issues it must remember it and
/// accept its nonce at most once; that store is not part of this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    audience: String,
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

impl AuthChallenge {
    /// A challenge issued by the hub `audience`. `nonce` must come from a
    /// CSPRNG; times are Unix milliseconds, `expires_at` exclusive.
    pub fn new(audience: &HubId, nonce: [u8; 32], issued_at: u64, expires_at: u64) -> Self {
        Self {
            audience: audience.to_string(),
            nonce,
            issued_at,
            expires_at,
        }
    }

    /// Decodes `AuthChallenge` bytes (shape only; nothing is verified).
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let [_version, audience, nonce, issued_at, expires_at] = cbor::decode_body(bytes)?;
        Ok(Self {
            audience: cbor::text(audience)?,
            nonce: cbor::sized(nonce, "nonce")?,
            issued_at: cbor::uint(issued_at)?,
            expires_at: cbor::uint(expires_at)?,
        })
    }

    /// The deterministic CBOR encoding sent to the device.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Text(self.audience.clone()),
            Value::Bytes(self.nonce.to_vec()),
            Value::Integer(self.issued_at.into()),
            Value::Integer(self.expires_at.into()),
        ]))
    }

    /// The issuing hub's id as carried in the challenge (not validated).
    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Unix time in milliseconds.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Unix time in milliseconds, exclusive.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Checks the challenge for the hub `expected_audience` at `now` (Unix
    /// milliseconds): the audience, then `issued_at < expires_at` with a
    /// lifetime of at most [`MAX_CHALLENGE_LIFETIME_MS`], then
    /// `issued_at <= now < expires_at`.
    pub fn check(&self, expected_audience: &HubId, now: u64) -> Result<(), IdentityError> {
        if self.audience != expected_audience.as_str() {
            return Err(IdentityError::AudienceMismatch);
        }
        if self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > MAX_CHALLENGE_LIFETIME_MS
        {
            return Err(IdentityError::InvalidChallengeLifetime);
        }
        if now >= self.expires_at {
            return Err(IdentityError::Expired);
        }
        if now < self.issued_at {
            return Err(IdentityError::NotYetValid);
        }
        Ok(())
    }
}

/// A device authenticated by [`verify_auth_response`]. The caller must still
/// check that it issued a challenge with `nonce` and consume the nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDevice {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub nonce: [u8; 32],
}

/// The `user_id` claimed by `AuthResponse` bytes (step 1 shape checks only),
/// so the hub can load that user's DeviceList for [`verify_auth_response`].
pub fn auth_response_user_id(response: &[u8]) -> Result<UserId, IdentityError> {
    let [_version, _challenge, user_id, _device_id, _sig] = cbor::decode_body(response)?;
    UserId::parse(&cbor::text(user_id)?)
}

/// Verifies `AuthResponse` bytes for the hub `expected_audience` at `now`
/// (Unix milliseconds), against the user's verified `device_list`, in the
/// spec's verification order: the response decodes; the device list is the
/// response user's, the device is not revoked and is certified in it; the
/// signature under the certified device key; then the challenge decodes and
/// passes [`AuthChallenge::check`].
pub fn verify_auth_response(
    response: &[u8],
    expected_audience: &HubId,
    now: u64,
    device_list: &DeviceList,
) -> Result<AuthenticatedDevice, IdentityError> {
    let [_version, challenge, user_id, device_id, sig] = cbor::decode_body(response)?;
    let challenge = cbor::byte_string(challenge)?;
    let user_id = UserId::parse(&cbor::text(user_id)?)?;
    let device_id = DeviceId::parse(&cbor::text(device_id)?)?;
    let sig: [u8; 64] = cbor::sized(sig, "signature")?;

    // `device_list` is verified; it must be this user's.
    if device_list.user_id() != &user_id {
        return Err(IdentityError::UserIdMismatch);
    }
    if device_list.is_revoked(&device_id) {
        return Err(IdentityError::Revoked(device_id));
    }
    let device_key = device_list
        .device_sig_pubkey(&device_id)
        .ok_or_else(|| IdentityError::UnknownDevice(device_id.clone()))?;

    let tbs = cbor::encode(&Value::Array(vec![
        Value::Bytes(challenge.clone()),
        Value::Text(user_id.to_string()),
        Value::Text(device_id.to_string()),
    ]));
    verify(device_key, AUTH_RESPONSE_CONTEXT, &tbs, &sig)?;

    // The issued-challenge and nonce checks are the caller's.
    let decoded = AuthChallenge::decode(&challenge)?;
    decoded.check(expected_audience, now)?;

    Ok(AuthenticatedDevice {
        user_id,
        device_id,
        nonce: decoded.nonce,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::keys::sign;
    use crate::testutil::*;

    const NONCE: [u8; 32] = [7; 32];

    fn hub_id(seed: u8) -> HubId {
        HubId::from_root_pubkey(&key(seed).verifying_key())
    }

    fn challenge(audience: &HubId) -> Vec<u8> {
        AuthChallenge::new(audience, NONCE, 100, 200).to_bytes()
    }

    /// Device-side signing, for tests only.
    fn respond(challenge: &[u8], user_id: &UserId, device: &SigningKey) -> Vec<u8> {
        let device_id = DeviceId::from_device_pubkey(&device.verifying_key());
        let tbs = cbor::encode(&Value::Array(vec![
            Value::Bytes(challenge.to_vec()),
            Value::Text(user_id.to_string()),
            Value::Text(device_id.to_string()),
        ]));
        let sig = sign(device, AUTH_RESPONSE_CONTEXT, &tbs);
        cbor::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(challenge.to_vec()),
            Value::Text(user_id.to_string()),
            Value::Text(device_id.to_string()),
            Value::Bytes(sig.to_vec()),
        ]))
    }

    /// User 1 with active device 2 and revoked device 3.
    fn device_list() -> DeviceList {
        let root = key(1);
        let certs = vec![cert(&root, &key(2).verifying_key(), 1, 1)];
        let revoked = vec![DeviceId::from_device_pubkey(&key(3).verifying_key())];
        let bytes = list(&root, 1, certs, revoked);
        DeviceList::verify(&bytes, &UserId::from_root_pubkey(&root.verifying_key())).unwrap()
    }

    #[test]
    fn challenge_round_trip() {
        let bytes = challenge(&hub_id(9));
        let decoded = AuthChallenge::decode(&bytes).unwrap();
        assert_eq!(decoded, AuthChallenge::new(&hub_id(9), NONCE, 100, 200));
        assert_eq!(decoded.audience(), hub_id(9).as_str());
        assert_eq!(decoded.nonce(), &NONCE);
        assert_eq!((decoded.issued_at(), decoded.expires_at()), (100, 200));
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn authenticates_active_device() {
        let list = device_list();
        let response = respond(&challenge(&hub_id(9)), list.user_id(), &key(2));
        let device = verify_auth_response(&response, &hub_id(9), 199, &list).unwrap();
        assert_eq!(device.user_id, *list.user_id());
        assert_eq!(
            device.device_id,
            DeviceId::from_device_pubkey(&key(2).verifying_key())
        );
        assert_eq!(device.nonce, NONCE);
        assert_eq!(auth_response_user_id(&response).unwrap(), *list.user_id());
        assert_eq!(
            auth_response_user_id(&response[1..]),
            Err(IdentityError::NonCanonical)
        );
        assert!(matches!(
            auth_response_user_id(&response[..response.len() - 1]),
            Err(IdentityError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_wrong_audience_and_expired() {
        let list = device_list();
        let response = respond(&challenge(&hub_id(9)), list.user_id(), &key(2));
        assert_eq!(
            verify_auth_response(&response, &hub_id(8), 150, &list),
            Err(IdentityError::AudienceMismatch)
        );
        assert_eq!(
            verify_auth_response(&response, &hub_id(9), 200, &list),
            Err(IdentityError::Expired)
        );
    }

    #[test]
    fn challenge_times_and_lifetime() {
        let check = |issued_at, expires_at, now| {
            AuthChallenge::new(&hub_id(9), NONCE, issued_at, expires_at).check(&hub_id(9), now)
        };
        let max = MAX_CHALLENGE_LIFETIME_MS;
        assert_eq!(check(1000, 1000 + max, 1000), Ok(()));
        assert_eq!(check(1000, 1000 + max, 999 + max), Ok(()));
        assert_eq!(
            check(1000, 1001 + max, 1000),
            Err(IdentityError::InvalidChallengeLifetime)
        );
        assert_eq!(
            check(1000, 1000, 1000),
            Err(IdentityError::InvalidChallengeLifetime)
        );
        assert_eq!(
            check(1000, 999, 999),
            Err(IdentityError::InvalidChallengeLifetime)
        );
        assert_eq!(check(1000, 2000, 2000), Err(IdentityError::Expired));
        assert_eq!(check(1000, 2000, 999), Err(IdentityError::NotYetValid));
        assert_eq!(
            AuthChallenge::new(&hub_id(9), NONCE, 1000, 2000).check(&hub_id(8), 1500),
            Err(IdentityError::AudienceMismatch)
        );

        // verify_auth_response applies the same checks.
        let list = device_list();
        let long = AuthChallenge::new(&hub_id(9), NONCE, 100, 101 + max).to_bytes();
        assert_eq!(
            verify_auth_response(
                &respond(&long, list.user_id(), &key(2)),
                &hub_id(9),
                150,
                &list
            ),
            Err(IdentityError::InvalidChallengeLifetime)
        );
        let response = respond(&challenge(&hub_id(9)), list.user_id(), &key(2));
        assert_eq!(
            verify_auth_response(&response, &hub_id(9), 99, &list),
            Err(IdentityError::NotYetValid)
        );
    }

    #[test]
    fn rejects_revoked_unknown_and_foreign_devices() {
        let list = device_list();
        let c = challenge(&hub_id(9));
        let revoked = respond(&c, list.user_id(), &key(3));
        assert_eq!(
            verify_auth_response(&revoked, &hub_id(9), 150, &list),
            Err(IdentityError::Revoked(DeviceId::from_device_pubkey(
                &key(3).verifying_key()
            )))
        );
        let unknown = respond(&c, list.user_id(), &key(4));
        assert_eq!(
            verify_auth_response(&unknown, &hub_id(9), 150, &list),
            Err(IdentityError::UnknownDevice(DeviceId::from_device_pubkey(
                &key(4).verifying_key()
            )))
        );
        let other_user = UserId::from_root_pubkey(&key(5).verifying_key());
        let foreign = respond(&c, &other_user, &key(2));
        assert_eq!(
            verify_auth_response(&foreign, &hub_id(9), 150, &list),
            Err(IdentityError::UserIdMismatch)
        );
    }

    #[test]
    fn rejects_bad_signature_and_shapes() {
        let list = device_list();
        let mut response = respond(&challenge(&hub_id(9)), list.user_id(), &key(2));
        let last = response.len() - 1;
        response[last] ^= 1;
        assert_eq!(
            verify_auth_response(&response, &hub_id(9), 150, &list),
            Err(IdentityError::BadSignature)
        );

        // A re-encoded challenge is not the one that was signed.
        let mut c = challenge(&hub_id(9));
        let signed = respond(&c, list.user_id(), &key(2));
        c.push(0);
        assert_eq!(
            verify_auth_response(
                &respond(&c, list.user_id(), &key(2)),
                &hub_id(9),
                150,
                &list
            ),
            Err(IdentityError::NonCanonical)
        );
        let mut trailing = signed;
        trailing.push(0);
        assert_eq!(
            verify_auth_response(&trailing, &hub_id(9), 150, &list),
            Err(IdentityError::NonCanonical)
        );

        let short_nonce = cbor::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Text(hub_id(9).to_string()),
            Value::Bytes(vec![0; 31]),
            Value::Integer(100.into()),
            Value::Integer(200.into()),
        ]));
        assert!(matches!(
            verify_auth_response(
                &respond(&short_nonce, list.user_id(), &key(2)),
                &hub_id(9),
                150,
                &list
            ),
            Err(IdentityError::Malformed(_))
        ));
    }
}
