use crate::{DeviceId, HubId};

/// Every way decoding or verifying an identity structure can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// Input is not the deterministic CBOR encoding of the expected shape.
    #[error("malformed encoding: {0}")]
    Malformed(String),
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u64),
    /// Not a valid Ed25519 public key (does not decompress or small order).
    #[error("invalid Ed25519 public key")]
    InvalidKey,
    #[error("invalid user id: {0}")]
    InvalidUserId(String),
    #[error("invalid device id: {0}")]
    InvalidDeviceId(String),
    #[error("invalid hub id: {0}")]
    InvalidHubId(String),
    /// Strict Ed25519 verification failed, including a wrong context.
    #[error("signature verification failed")]
    BadSignature,
    /// A user id does not match the root public key or the expected user,
    /// or two lists or records of different users were compared.
    #[error("user id mismatch")]
    UserIdMismatch,
    #[error("device id does not match the device public key")]
    DeviceIdMismatch,
    #[error("device {0} is listed more than once")]
    DuplicateDevice(DeviceId),
    /// The device is revoked (or both certified and revoked in a list).
    #[error("device {0} is revoked")]
    Revoked(DeviceId),
    #[error("device {0} is not certified in the device list")]
    UnknownDevice(DeviceId),
    /// Two different device lists or hosting records of the same user share
    /// a seq.
    #[error("different records with the same seq {0}")]
    SeqConflict(u64),
    /// `now >= not_after` / `now >= expires_at`.
    #[error("expired")]
    Expired,
    /// `now < not_before`.
    #[error("not yet valid")]
    NotYetValid,
    #[error("challenge audience does not match this hub")]
    AudienceMismatch,
    #[error("hub root key does not match the expected hub")]
    HubKeyMismatch,
    #[error("invalid hub signature on the hosting entry of {0}")]
    BadHubSignature(HubId),
    #[error("hub {0} appears more than once")]
    DuplicateHub(HubId),
    #[error("hosting record has {0} hubs, expected 1..=16")]
    HubCount(usize),
}
