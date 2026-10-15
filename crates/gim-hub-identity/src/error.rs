use crate::DeviceId;

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
    /// Strict Ed25519 verification failed, including a wrong context.
    #[error("signature verification failed")]
    BadSignature,
    /// A user id does not match the root public key, or two lists of
    /// different users were compared.
    #[error("user id mismatch")]
    UserIdMismatch,
    #[error("device id does not match the device public key")]
    DeviceIdMismatch,
    #[error("device {0} is listed more than once")]
    DuplicateDevice(DeviceId),
    #[error("device {0} is both certified and revoked")]
    Revoked(DeviceId),
    /// Two different device lists of the same user share a seq.
    #[error("different device lists with the same seq {0}")]
    SeqConflict(u64),
}
