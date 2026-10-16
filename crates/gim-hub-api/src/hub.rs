//! The hub's own Ed25519 identity.
//!
//! The persisted key is the hub ROOT key: it determines `hub_id` (gim-core
//! identity spec). Short-lived runtime keys certified by the root key are not
//! implemented yet.

use std::{
    io::{self, Write},
    path::Path,
    sync::Arc,
};

use ed25519_dalek::SigningKey;
use gim_hub_identity::{sign_hub_proof, HubId};

/// The hub's root signing key and the ids derived from it.
#[derive(Clone)]
pub struct HubIdentity {
    key: Arc<SigningKey>,
    hub_id: HubId,
}

impl std::fmt::Debug for HubIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubIdentity")
            .field("hub_id", &self.hub_id)
            .finish_non_exhaustive()
    }
}

impl HubIdentity {
    /// Loads the 32-byte key seed at `path`, creating it (mode 0600) with a
    /// fresh random seed if the file does not exist.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        let seed = match std::fs::read(path) {
            Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} must hold exactly 32 bytes", path.display()),
                )
            })?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => create_seed(path)?,
            Err(err) => return Err(err),
        };
        Ok(Self::from_seed(&seed))
    }

    /// Identity for a given 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let hub_id = HubId::from_root_pubkey(&key.verifying_key());
        Self {
            key: Arc::new(key),
            hub_id,
        }
    }

    /// The hub's root signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The hub's id: the audience of sign-in challenges.
    pub fn hub_id(&self) -> &HubId {
        &self.hub_id
    }

    /// The proof of possession of GET /v2/hub: the root key's signature
    /// over the fixed, domain-separated proof message for `nonce`, this
    /// hub's id and `public_url` (never over caller-chosen bytes alone).
    pub fn sign_proof(&self, nonce: &[u8; 32], public_url: &str) -> [u8; 64] {
        sign_hub_proof(&self.key, nonce, public_url)
    }
}

fn create_seed(path: &Path) -> io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(io::Error::other)?;
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(&seed)?;
    file.sync_all()?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/hub_key");
        let first = HubIdentity::load_or_create(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let second = HubIdentity::load_or_create(&path).unwrap();
        assert_eq!(first.hub_id(), second.hub_id());
        assert_eq!(
            first.signing_key().to_bytes(),
            second.signing_key().to_bytes()
        );
    }

    #[test]
    fn malformed_key_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub_key");
        std::fs::write(&path, [0u8; 31]).unwrap();
        let err = HubIdentity::load_or_create(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn hub_id_matches_vector() {
        // testdata/identity/auth.json: hub_root_seed and audience.
        let seed: [u8; 32] = std::array::from_fn(|i| 0x60 + i as u8);
        let hub = HubIdentity::from_seed(&seed);
        assert_eq!(
            hub.hub_id().as_str(),
            "hciqgrcknldyy6lbu2splf5frcdqeftipgfikjxbzeq6x6y55lggapay"
        );
    }
}
