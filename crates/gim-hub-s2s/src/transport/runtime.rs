//! The hub's runtime key (libp2p host key) and its `SignedHubRuntimeCert`
//! issued by the hub ROOT key (docs/federation.md §3.1).

use std::{
    io::{self, Write},
    path::Path,
};

use gim_hub_identity::{HubRuntimeCert, SigningKey, VerifyingKey};
use libp2p::identity::Keypair;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A new certificate's `not_before` lies this far in the past, so that peers
/// with a slightly slow clock accept it right away.
pub const CERT_BACKDATE_MS: u64 = 5 * 60 * 1000;

/// The runtime key and its current certificate.
#[derive(Clone)]
pub struct RuntimeIdentity {
    key: SigningKey,
    cert: Vec<u8>,
    not_after: u64,
}

impl std::fmt::Debug for RuntimeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeIdentity")
            .field("runtime_pubkey", &self.key.verifying_key())
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl RuntimeIdentity {
    /// Loads `key_path` (32-byte seed, created with mode 0600 if missing) and
    /// `cert_path`. The certificate is (re)issued when it is missing, does
    /// not verify for this hub and key at `now_ms`, or needs renewal.
    pub fn load_or_create(
        key_path: &Path,
        cert_path: &Path,
        hub_root: &SigningKey,
        lifetime_days: u32,
        now_ms: u64,
    ) -> io::Result<Self> {
        let seed = match std::fs::read(key_path) {
            Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} must hold exactly 32 bytes", key_path.display()),
                )
            })?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => create_seed(key_path)?,
            Err(err) => return Err(err),
        };
        let key = SigningKey::from_bytes(&seed);
        let stored = match std::fs::read(cert_path) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        let current = stored.and_then(|bytes| {
            let cert = HubRuntimeCert::verify(&bytes, &hub_root.verifying_key(), now_ms).ok()?;
            (cert.runtime_pubkey() == &key.verifying_key()).then_some(cert)
        });
        let mut identity = match current {
            Some(cert) => Self {
                key,
                cert: cert.as_bytes().to_vec(),
                not_after: cert.not_after(),
            },
            None => Self::issue(key, hub_root, lifetime_days, now_ms),
        };
        if identity.cert != std::fs::read(cert_path).unwrap_or_default() {
            write_atomic(cert_path, &identity.cert)?;
        }
        identity.renew_if_needed(cert_path, hub_root, lifetime_days, now_ms)?;
        Ok(identity)
    }

    /// A fresh certificate for `key`, not persisted.
    pub fn issue(key: SigningKey, hub_root: &SigningKey, lifetime_days: u32, now_ms: u64) -> Self {
        let not_before = now_ms.saturating_sub(CERT_BACKDATE_MS);
        let not_after = now_ms + u64::from(lifetime_days) * DAY_MS;
        let cert = HubRuntimeCert::issue(hub_root, &key.verifying_key(), not_before, not_after);
        Self {
            key,
            cert,
            not_after,
        }
    }

    /// Issues a new certificate for the same key (PeerId unchanged) when less
    /// than a third of the lifetime remains, and writes it atomically.
    /// Returns whether it renewed.
    pub fn renew_if_needed(
        &mut self,
        cert_path: &Path,
        hub_root: &SigningKey,
        lifetime_days: u32,
        now_ms: u64,
    ) -> io::Result<bool> {
        if !needs_renewal(self.not_after, lifetime_days, now_ms) {
            return Ok(false);
        }
        let renewed = Self::issue(self.key.clone(), hub_root, lifetime_days, now_ms);
        write_atomic(cert_path, &renewed.cert)?;
        *self = renewed;
        Ok(true)
    }

    /// The `SignedHubRuntimeCert` bytes.
    pub fn cert(&self) -> &[u8] {
        &self.cert
    }

    /// Unix milliseconds, exclusive.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    pub fn runtime_pubkey(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Replaces the certificate without checks (tests of the refusal path).
    #[cfg(test)]
    pub(crate) fn with_cert(mut self, cert: Vec<u8>) -> Self {
        self.cert = cert;
        self
    }

    pub(crate) fn keypair(&self) -> Keypair {
        Keypair::ed25519_from_bytes(self.key.to_bytes()).expect("32-byte ed25519 seed")
    }
}

/// Less than one third of the lifetime remains at `now_ms`.
pub fn needs_renewal(not_after: u64, lifetime_days: u32, now_ms: u64) -> bool {
    let lifetime = u64::from(lifetime_days) * DAY_MS;
    not_after.saturating_sub(now_ms) < lifetime / 3
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

/// Writes `bytes` to a temp file next to `path`, then renames it over `path`.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_792_000_000_000;

    #[test]
    fn creates_reuses_and_renews() {
        let dir = tempfile::tempdir().unwrap();
        let (key_path, cert_path) = (
            dir.path().join("runtime_key"),
            dir.path().join("runtime_cert"),
        );
        let root = SigningKey::from_bytes(&[7; 32]);

        let first = RuntimeIdentity::load_or_create(&key_path, &cert_path, &root, 30, NOW).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(&cert_path).unwrap(), first.cert());
        let cert = HubRuntimeCert::verify(first.cert(), &root.verifying_key(), NOW).unwrap();
        assert_eq!(cert.runtime_pubkey(), &first.runtime_pubkey());
        assert_eq!(cert.not_before(), NOW - CERT_BACKDATE_MS);
        assert_eq!(cert.not_after(), NOW + 30 * DAY_MS);

        // Ten days later: reused unchanged.
        let later = NOW + 10 * DAY_MS;
        let second =
            RuntimeIdentity::load_or_create(&key_path, &cert_path, &root, 30, later).unwrap();
        assert_eq!(second.cert(), first.cert());

        // 21 days later less than a third remains: renewed, same key.
        let renewal = NOW + 21 * DAY_MS;
        let third =
            RuntimeIdentity::load_or_create(&key_path, &cert_path, &root, 30, renewal).unwrap();
        assert_ne!(third.cert(), first.cert());
        assert_eq!(third.runtime_pubkey(), first.runtime_pubkey());
        assert_eq!(third.not_after(), renewal + 30 * DAY_MS);
        assert_eq!(std::fs::read(&cert_path).unwrap(), third.cert());

        // A certificate from another hub root is replaced.
        let other_root = SigningKey::from_bytes(&[8; 32]);
        let fourth =
            RuntimeIdentity::load_or_create(&key_path, &cert_path, &other_root, 30, renewal)
                .unwrap();
        assert!(
            HubRuntimeCert::verify(fourth.cert(), &other_root.verifying_key(), renewal).is_ok()
        );
        assert_eq!(fourth.runtime_pubkey(), first.runtime_pubkey());
    }

    #[test]
    fn renew_if_needed_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("runtime_cert");
        let root = SigningKey::from_bytes(&[7; 32]);
        let mut identity = RuntimeIdentity::issue(SigningKey::from_bytes(&[9; 32]), &root, 3, NOW);
        assert!(!identity
            .renew_if_needed(&cert_path, &root, 3, NOW + 2 * DAY_MS - 1)
            .unwrap());
        assert!(!cert_path.exists());
        assert!(identity
            .renew_if_needed(&cert_path, &root, 3, NOW + 2 * DAY_MS + 1)
            .unwrap());
        assert_eq!(std::fs::read(&cert_path).unwrap(), identity.cert());
    }

    #[test]
    fn rejects_malformed_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("runtime_key");
        std::fs::write(&key_path, [0u8; 31]).unwrap();
        let err = RuntimeIdentity::load_or_create(
            &key_path,
            &dir.path().join("runtime_cert"),
            &SigningKey::from_bytes(&[7; 32]),
            30,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn libp2p_peer_id_matches_identity_spec_bytes() {
        let identity = RuntimeIdentity::issue(
            SigningKey::from_bytes(&[9; 32]),
            &SigningKey::from_bytes(&[7; 32]),
            30,
            NOW,
        );
        let peer_id = identity.keypair().public().to_peer_id();
        assert_eq!(
            peer_id.to_bytes(),
            gim_hub_identity::libp2p_peer_id(&identity.runtime_pubkey())
        );
    }
}
