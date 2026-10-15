use std::fmt;
use std::str::FromStr;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::IdentityError;

/// Multihash header of a SHA-256 digest: code `0x12`, length `0x20`.
const SHA256_MULTIHASH: [u8; 2] = [0x12, 0x20];
const DEVICE_HASH_LEN: usize = 16;

/// RFC 4648 base32, lowercase, unpadded.
fn base32(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
}

/// Strict inverse of [`base32`]: only `a-z2-7`, and the round trip must be
/// exact (rejects non-zero trailing bits and impossible lengths).
fn unbase32(text: &str) -> Option<Vec<u8>> {
    if !text
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    let bytes = BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .ok()?;
    (base32(&bytes) == text).then_some(bytes)
}

/// `prefix || base32(0x12 0x20 || SHA-256(pubkey))`.
fn multihash_id(prefix: char, pubkey: &VerifyingKey) -> String {
    let mut multihash = SHA256_MULTIHASH.to_vec();
    multihash.extend_from_slice(&Sha256::digest(pubkey.as_bytes()));
    format!("{prefix}{}", base32(&multihash))
}

/// Validates prefix, alphabet, canonical encoding and the SHA-256 multihash
/// header and length of a [`multihash_id`].
fn check_multihash_id(prefix: char, text: &str) -> Result<(), String> {
    let body = text
        .strip_prefix(prefix)
        .ok_or_else(|| format!("missing '{prefix}' prefix"))?;
    let bytes = unbase32(body).ok_or("not canonical lowercase base32")?;
    if bytes.len() != SHA256_MULTIHASH.len() + 32 || bytes[..2] != SHA256_MULTIHASH {
        return Err("not a sha2-256 multihash".to_owned());
    }
    Ok(())
}

/// `"u" || base32(0x12 0x20 || SHA-256(root_pubkey))`, 56 characters.
///
/// A parsed id is only syntactically valid; bind it to a key with
/// [`UserId::from_root_pubkey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(String);

impl UserId {
    /// Derives the user id of a root public key.
    pub fn from_root_pubkey(root_pubkey: &VerifyingKey) -> Self {
        Self(multihash_id('u', root_pubkey))
    }

    /// Validates prefix, alphabet, canonical encoding and the SHA-256
    /// multihash header and length.
    pub fn parse(text: &str) -> Result<Self, IdentityError> {
        check_multihash_id('u', text).map_err(IdentityError::InvalidUserId)?;
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `"h" || base32(0x12 0x20 || SHA-256(hub_root_pubkey))`, 56 characters.
///
/// A parsed id is only syntactically valid; bind it to a key with
/// [`HubId::from_root_pubkey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HubId(String);

impl HubId {
    /// Derives the hub id of a hub root public key.
    pub fn from_root_pubkey(hub_root_pubkey: &VerifyingKey) -> Self {
        Self(multihash_id('h', hub_root_pubkey))
    }

    /// Validates prefix, alphabet, canonical encoding and the SHA-256
    /// multihash header and length.
    pub fn parse(text: &str) -> Result<Self, IdentityError> {
        check_multihash_id('h', text).map_err(IdentityError::InvalidHubId)?;
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `"d" || base32(SHA-256(device_sig_pubkey)[0..16])`, 27 characters.
///
/// A parsed id is only syntactically valid; bind it to a key with
/// [`DeviceId::from_device_pubkey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(String);

impl DeviceId {
    /// Derives the device id of a device signing public key.
    pub fn from_device_pubkey(device_sig_pubkey: &VerifyingKey) -> Self {
        let digest = Sha256::digest(device_sig_pubkey.as_bytes());
        Self(format!("d{}", base32(&digest[..DEVICE_HASH_LEN])))
    }

    /// Validates prefix, alphabet, canonical encoding and length.
    pub fn parse(text: &str) -> Result<Self, IdentityError> {
        let invalid = |reason: &str| IdentityError::InvalidDeviceId(reason.to_owned());
        let body = text
            .strip_prefix('d')
            .ok_or_else(|| invalid("missing 'd' prefix"))?;
        let bytes = unbase32(body).ok_or_else(|| invalid("not canonical lowercase base32"))?;
        if bytes.len() != DEVICE_HASH_LEN {
            return Err(invalid("not 16 bytes"));
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! string_id {
    ($ty:ident) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $ty {
            type Err = IdentityError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(UserId);
string_id!(DeviceId);
string_id!(HubId);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::key;

    #[test]
    fn derived_ids_round_trip() {
        let user = UserId::from_root_pubkey(&key(1).verifying_key());
        assert_eq!(user.as_str().len(), 56);
        assert_eq!(user.as_str().parse::<UserId>().unwrap(), user);
        let device = DeviceId::from_device_pubkey(&key(2).verifying_key());
        assert_eq!(device.as_str().len(), 27);
        assert_eq!(DeviceId::parse(device.as_str()).unwrap(), device);
        assert_eq!(device.to_string(), device.as_str());
        let hub = HubId::from_root_pubkey(&key(1).verifying_key());
        assert_eq!(hub.as_str().len(), 56);
        assert_eq!(hub.as_str()[1..], user.as_str()[1..]);
        assert_eq!(HubId::parse(hub.as_str()).unwrap(), hub);
    }

    #[test]
    fn rejects_malformed_hub_ids() {
        let hub = HubId::from_root_pubkey(&key(1).verifying_key()).to_string();
        let user = UserId::from_root_pubkey(&key(1).verifying_key()).to_string();
        let head = &hub[..hub.len() - 1];
        for bad in [
            String::new(),
            "h".to_owned(),
            hub[1..].to_owned(),
            hub.to_ascii_uppercase(),
            format!("{hub}a"),
            format!("{head}7"),
            format!("h{}", base32(&[0u8; 34])),
            user,
        ] {
            assert!(
                matches!(HubId::parse(&bad), Err(IdentityError::InvalidHubId(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_malformed_user_ids() {
        let user = UserId::from_root_pubkey(&key(1).verifying_key()).to_string();
        let device = DeviceId::from_device_pubkey(&key(2).verifying_key()).to_string();
        let head = &user[..user.len() - 1];
        for bad in [
            String::new(),
            "u".to_owned(),
            user[1..].to_owned(),
            format!("d{}", &user[1..]),
            user.to_ascii_uppercase(),
            format!("{user}a"),
            head.to_owned(),
            format!("{head}1"),
            format!("{head}="),
            // Last character carries non-zero trailing bits.
            format!("{head}7"),
            // 34 bytes without the multihash header.
            format!("u{}", base32(&[0u8; 34])),
            device,
        ] {
            assert!(
                matches!(UserId::parse(&bad), Err(IdentityError::InvalidUserId(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_malformed_device_ids() {
        let user = UserId::from_root_pubkey(&key(1).verifying_key()).to_string();
        let device = DeviceId::from_device_pubkey(&key(2).verifying_key()).to_string();
        let head = &device[..device.len() - 1];
        for bad in [
            String::new(),
            "d".to_owned(),
            device[1..].to_owned(),
            device.to_ascii_uppercase(),
            format!("{device}a"),
            format!("{head}7"),
            format!("d{}", base32(&[0u8; 17])),
            user,
        ] {
            assert!(
                matches!(
                    DeviceId::parse(&bad),
                    Err(IdentityError::InvalidDeviceId(_))
                ),
                "{bad}"
            );
        }
    }
}
