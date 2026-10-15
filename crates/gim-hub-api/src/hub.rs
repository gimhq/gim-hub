//! The hub's own Ed25519 identity.

use std::{
    io::{self, Write},
    path::Path,
    sync::Arc,
};

use ed25519_dalek::{SigningKey, VerifyingKey};

/// The hub's signing key and the PeerId derived from it.
#[derive(Clone)]
pub struct HubIdentity {
    key: Arc<SigningKey>,
    peer_id: Arc<str>,
}

impl std::fmt::Debug for HubIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubIdentity")
            .field("peer_id", &self.peer_id)
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
        let peer_id = peer_id(&key.verifying_key()).into();
        Self {
            key: Arc::new(key),
            peer_id,
        }
    }

    /// The hub's signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The hub's PeerId: used as `hub_peer_id` and as the owner prefix of
    /// group IDs.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

/// libp2p-style PeerId of an Ed25519 public key: base58btc of the identity
/// multihash of the protobuf-encoded `PublicKey { Type = Ed25519, Data }`.
///
/// The formal hub ID format will come from gim-core identity part 2; this
/// is the only place that derives it.
pub fn peer_id(key: &VerifyingKey) -> String {
    // PublicKey protobuf: field 1 (KeyType) = 1 (Ed25519), field 2 (bytes) = key.
    const PROTOBUF_PREFIX: [u8; 4] = [0x08, 0x01, 0x12, 0x20];
    // Multihash: code 0x00 (identity), length 36.
    const MULTIHASH_PREFIX: [u8; 2] = [0x00, 0x24];
    let mut bytes = Vec::with_capacity(38);
    bytes.extend_from_slice(&MULTIHASH_PREFIX);
    bytes.extend_from_slice(&PROTOBUF_PREFIX);
    bytes.extend_from_slice(key.as_bytes());
    bs58::encode(bytes).into_string()
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
        assert_eq!(first.peer_id(), second.peer_id());
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
    fn peer_id_has_libp2p_ed25519_shape() {
        let hub = HubIdentity::from_seed(&[0u8; 32]);
        assert!(hub.peer_id().starts_with("12D3KooW"), "{}", hub.peer_id());
        assert_eq!(hub.peer_id().len(), 52);
        let decoded = bs58::decode(hub.peer_id()).into_vec().unwrap();
        assert_eq!(&decoded[..6], &[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        assert_eq!(&decoded[6..], hub.signing_key().verifying_key().as_bytes());
    }
}
