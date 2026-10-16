use ciborium::Value;

use crate::keys::verify;
use crate::{cbor, DeviceId, DeviceList, HubId, IdentityError, UserId, FORMAT_VERSION};

/// Signature context of `AuthResponse.sig` (device signing key).
pub const AUTH_RESPONSE_CONTEXT: &[u8] = b"gim/auth-response/v1";

/// Version of an `AuthChallenge` that carries the hub's public URL.
pub const AUTH_CHALLENGE_V2: u64 = 2;

/// Longest accepted challenge lifetime, `expires_at - issued_at`, in
/// milliseconds.
pub const AUTH_CHALLENGE_MAX_LIFETIME_MS: u64 = 300_000;

/// An unsigned `AuthChallenge`. The hub that issues it must remember it and
/// accept its nonce at most once; that store is not part of this crate.
///
/// Version 1 is `[1, audience, nonce, issued_at, expires_at]`. Version 2
/// (hub-proposed, `testdata/identity/auth-v2.json`) also binds the hub's
/// public URL: `[2, audience, audience_url, nonce, issued_at, expires_at]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    audience: String,
    audience_url: Option<String>,
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

impl AuthChallenge {
    /// A version 1 challenge issued by the hub `audience`. `nonce` must come
    /// from a CSPRNG; times are Unix milliseconds, `expires_at` exclusive.
    pub fn new(audience: &HubId, nonce: [u8; 32], issued_at: u64, expires_at: u64) -> Self {
        Self {
            audience: audience.to_string(),
            audience_url: None,
            nonce,
            issued_at,
            expires_at,
        }
    }

    /// A version 2 challenge issued by the hub `audience` serving the client
    /// API at `audience_url` (its normalized public URL).
    pub fn new_v2(
        audience: &HubId,
        audience_url: &str,
        nonce: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            audience_url: Some(audience_url.to_owned()),
            ..Self::new(audience, nonce, issued_at, expires_at)
        }
    }

    /// Decodes `AuthChallenge` bytes of version 1 or 2 (shape only; nothing
    /// is verified).
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let value = cbor::decode(bytes)?;
        match cbor::uint(cbor::item(&value, 0)?)? {
            FORMAT_VERSION => {
                let [_version, audience, nonce, issued_at, expires_at] = cbor::array(value)?;
                Ok(Self {
                    audience: cbor::text(audience)?,
                    audience_url: None,
                    nonce: cbor::sized(nonce, "nonce")?,
                    issued_at: cbor::uint(issued_at)?,
                    expires_at: cbor::uint(expires_at)?,
                })
            }
            AUTH_CHALLENGE_V2 => {
                let [_version, audience, audience_url, nonce, issued_at, expires_at] =
                    cbor::array(value)?;
                Ok(Self {
                    audience: cbor::text(audience)?,
                    audience_url: Some(cbor::text(audience_url)?),
                    nonce: cbor::sized(nonce, "nonce")?,
                    issued_at: cbor::uint(issued_at)?,
                    expires_at: cbor::uint(expires_at)?,
                })
            }
            other => Err(IdentityError::UnsupportedVersion(other)),
        }
    }

    /// The deterministic CBOR encoding sent to the device.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut items = vec![
            Value::Integer(self.version().into()),
            Value::Text(self.audience.clone()),
        ];
        if let Some(url) = &self.audience_url {
            items.push(Value::Text(url.clone()));
        }
        items.extend([
            Value::Bytes(self.nonce.to_vec()),
            Value::Integer(self.issued_at.into()),
            Value::Integer(self.expires_at.into()),
        ]);
        cbor::encode(&Value::Array(items))
    }

    /// 1, or 2 when the challenge carries an `audience_url`.
    pub fn version(&self) -> u64 {
        if self.audience_url.is_some() {
            AUTH_CHALLENGE_V2
        } else {
            FORMAT_VERSION
        }
    }

    /// The issuing hub's id as carried in the challenge (not validated).
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The issuing hub's public URL (version 2 only; not validated).
    pub fn audience_url(&self) -> Option<&str> {
        self.audience_url.as_deref()
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

    /// Checks the challenge for the hub `expected_audience` with public URL
    /// `expected_url` at `now` (Unix milliseconds): the audience, then the
    /// URL (a hub with a public URL accepts only version 2 carrying exactly
    /// that URL, a hub without one only version 1), then
    /// `issued_at < expires_at` with a lifetime of at most
    /// [`AUTH_CHALLENGE_MAX_LIFETIME_MS`], then `issued_at <= now < expires_at`.
    pub fn check(
        &self,
        expected_audience: &HubId,
        expected_url: Option<&str>,
        now: u64,
    ) -> Result<(), IdentityError> {
        if self.audience != expected_audience.as_str() {
            return Err(IdentityError::AudienceMismatch);
        }
        if self.audience_url.as_deref() != expected_url {
            return Err(IdentityError::AudienceUrlMismatch);
        }
        if self.issued_at >= self.expires_at {
            return Err(IdentityError::InvalidValidityWindow);
        }
        if self.expires_at - self.issued_at > AUTH_CHALLENGE_MAX_LIFETIME_MS {
            return Err(IdentityError::LifetimeTooLong);
        }
        if now < self.issued_at {
            return Err(IdentityError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(IdentityError::Expired);
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

/// Verifies `AuthResponse` bytes for the hub `expected_audience` with public
/// URL `expected_url` (see [`AuthChallenge::check`]) at `now` (Unix
/// milliseconds), against the user's verified `device_list`, in the
/// spec's verification order: the response decodes; the device list is the
/// response user's, the device is not revoked and is certified in it; the
/// signature under the certified device key; then the challenge decodes and
/// passes [`AuthChallenge::check`].
pub fn verify_auth_response(
    response: &[u8],
    expected_audience: &HubId,
    expected_url: Option<&str>,
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
    decoded.check(expected_audience, expected_url, now)?;

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
        let device = verify_auth_response(&response, &hub_id(9), None, 199, &list).unwrap();
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
            verify_auth_response(&response, &hub_id(8), None, 150, &list),
            Err(IdentityError::AudienceMismatch)
        );
        assert_eq!(
            verify_auth_response(&response, &hub_id(9), None, 200, &list),
            Err(IdentityError::Expired)
        );
    }

    #[test]
    fn challenge_times_and_lifetime() {
        let check = |issued_at, expires_at, now| {
            AuthChallenge::new(&hub_id(9), NONCE, issued_at, expires_at).check(
                &hub_id(9),
                None,
                now,
            )
        };
        let max = AUTH_CHALLENGE_MAX_LIFETIME_MS;
        assert_eq!(check(1000, 1000 + max, 1000), Ok(()));
        assert_eq!(check(1000, 1000 + max, 999 + max), Ok(()));
        assert_eq!(
            check(1000, 1001 + max, 1000),
            Err(IdentityError::LifetimeTooLong)
        );
        assert_eq!(
            check(1000, 1000, 1000),
            Err(IdentityError::InvalidValidityWindow)
        );
        // The window is checked before the times.
        assert_eq!(
            check(1000, 999, 5000),
            Err(IdentityError::InvalidValidityWindow)
        );
        assert_eq!(
            check(1000, 1001 + max, 5 * max),
            Err(IdentityError::LifetimeTooLong)
        );
        assert_eq!(check(1000, 2000, 2000), Err(IdentityError::Expired));
        assert_eq!(check(1000, 2000, 999), Err(IdentityError::NotYetValid));
        assert_eq!(
            AuthChallenge::new(&hub_id(9), NONCE, 1000, 2000).check(&hub_id(8), None, 1500),
            Err(IdentityError::AudienceMismatch)
        );

        // verify_auth_response applies the same checks.
        let list = device_list();
        let long = AuthChallenge::new(&hub_id(9), NONCE, 100, 101 + max).to_bytes();
        assert_eq!(
            verify_auth_response(
                &respond(&long, list.user_id(), &key(2)),
                &hub_id(9),
                None,
                150,
                &list
            ),
            Err(IdentityError::LifetimeTooLong)
        );
        let response = respond(&challenge(&hub_id(9)), list.user_id(), &key(2));
        assert_eq!(
            verify_auth_response(&response, &hub_id(9), None, 99, &list),
            Err(IdentityError::NotYetValid)
        );
    }

    #[test]
    fn rejects_revoked_unknown_and_foreign_devices() {
        let list = device_list();
        let c = challenge(&hub_id(9));
        let revoked = respond(&c, list.user_id(), &key(3));
        assert_eq!(
            verify_auth_response(&revoked, &hub_id(9), None, 150, &list),
            Err(IdentityError::Revoked(DeviceId::from_device_pubkey(
                &key(3).verifying_key()
            )))
        );
        let unknown = respond(&c, list.user_id(), &key(4));
        assert_eq!(
            verify_auth_response(&unknown, &hub_id(9), None, 150, &list),
            Err(IdentityError::UnknownDevice(DeviceId::from_device_pubkey(
                &key(4).verifying_key()
            )))
        );
        let other_user = UserId::from_root_pubkey(&key(5).verifying_key());
        let foreign = respond(&c, &other_user, &key(2));
        assert_eq!(
            verify_auth_response(&foreign, &hub_id(9), None, 150, &list),
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
            verify_auth_response(&response, &hub_id(9), None, 150, &list),
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
                None,
                150,
                &list
            ),
            Err(IdentityError::NonCanonical)
        );
        let mut trailing = signed;
        trailing.push(0);
        assert_eq!(
            verify_auth_response(&trailing, &hub_id(9), None, 150, &list),
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
                None,
                150,
                &list
            ),
            Err(IdentityError::Malformed(_))
        ));
    }

    const URL: &str = "https://hub.example.eu";

    #[test]
    fn challenge_v2_round_trip() {
        let c = AuthChallenge::new_v2(&hub_id(9), URL, NONCE, 100, 200);
        assert_eq!(c.version(), AUTH_CHALLENGE_V2);
        assert_eq!(c.audience_url(), Some(URL));
        let bytes = c.to_bytes();
        // [2, audience, audience_url, nonce, issued_at, expires_at]
        assert_eq!(&bytes[..2], &[0x86, 0x02]);
        let decoded = AuthChallenge::decode(&bytes).unwrap();
        assert_eq!(decoded, c);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(AuthChallenge::new(&hub_id(9), NONCE, 1, 2).version(), 1);
        assert_eq!(
            AuthChallenge::new(&hub_id(9), NONCE, 1, 2).audience_url(),
            None
        );
    }

    #[test]
    fn challenge_versions_and_shapes() {
        let encode = |items: Vec<Value>| cbor::encode(&Value::Array(items));
        let nonce = Value::Bytes(NONCE.to_vec());
        let audience = Value::Text(hub_id(9).to_string());
        // v1 shape with version 2, v2 shape with version 1, version 3.
        let v2_short = encode(vec![
            Value::Integer(2.into()),
            audience.clone(),
            nonce.clone(),
            Value::Integer(100.into()),
            Value::Integer(200.into()),
        ]);
        assert!(matches!(
            AuthChallenge::decode(&v2_short),
            Err(IdentityError::Malformed(_))
        ));
        let v1_long = encode(vec![
            Value::Integer(1.into()),
            audience.clone(),
            Value::Text(URL.into()),
            nonce.clone(),
            Value::Integer(100.into()),
            Value::Integer(200.into()),
        ]);
        assert!(matches!(
            AuthChallenge::decode(&v1_long),
            Err(IdentityError::Malformed(_))
        ));
        let v3 = encode(vec![
            Value::Integer(3.into()),
            audience,
            Value::Text(URL.into()),
            nonce,
            Value::Integer(100.into()),
            Value::Integer(200.into()),
        ]);
        assert_eq!(
            AuthChallenge::decode(&v3),
            Err(IdentityError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn checks_audience_url() {
        let v1 = AuthChallenge::new(&hub_id(9), NONCE, 100, 200);
        let v2 = AuthChallenge::new_v2(&hub_id(9), URL, NONCE, 100, 200);
        assert_eq!(v2.check(&hub_id(9), Some(URL), 150), Ok(()));
        assert_eq!(v1.check(&hub_id(9), None, 150), Ok(()));
        // A hub with a public URL accepts only v2 for that URL, one without
        // only v1.
        assert_eq!(
            v2.check(&hub_id(9), Some("https://other.example.eu"), 150),
            Err(IdentityError::AudienceUrlMismatch)
        );
        assert_eq!(
            v1.check(&hub_id(9), Some(URL), 150),
            Err(IdentityError::AudienceUrlMismatch)
        );
        assert_eq!(
            v2.check(&hub_id(9), None, 150),
            Err(IdentityError::AudienceUrlMismatch)
        );
        // The audience is checked first, the times after the URL.
        assert_eq!(
            v2.check(&hub_id(8), Some("https://other.example.eu"), 150),
            Err(IdentityError::AudienceMismatch)
        );
        assert_eq!(
            v1.check(&hub_id(9), Some(URL), 500),
            Err(IdentityError::AudienceUrlMismatch)
        );

        let list = device_list();
        let response = respond(&v2.to_bytes(), list.user_id(), &key(2));
        let device = verify_auth_response(&response, &hub_id(9), Some(URL), 150, &list).unwrap();
        assert_eq!(device.nonce, NONCE);
        assert_eq!(
            verify_auth_response(
                &response,
                &hub_id(9),
                Some("http://hub.example.eu"),
                150,
                &list
            ),
            Err(IdentityError::AudienceUrlMismatch)
        );
        let response = respond(&v1.to_bytes(), list.user_id(), &key(2));
        assert_eq!(
            verify_auth_response(&response, &hub_id(9), Some(URL), 150, &list),
            Err(IdentityError::AudienceUrlMismatch)
        );
    }
}
