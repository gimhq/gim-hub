use crate::{DeviceId, HubId};

/// Every way decoding or verifying an identity structure can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// Malformed input: not CBOR, wrong type, wrong element count or size.
    #[error("malformed encoding: {0}")]
    Malformed(String),
    /// Valid CBOR that is not the deterministic encoding (non-shortest head,
    /// indefinite length, trailing bytes).
    #[error("not deterministic CBOR")]
    NonCanonical,
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
    /// Strict Ed25519 verification failed: wrong key, wrong context or
    /// tampered bytes.
    #[error("signature verification failed")]
    BadSignature,
    /// A user id does not match the root public key, the expected user or
    /// the stored item.
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
    /// A received device list or hosting record has a lower seq than the
    /// stored one.
    #[error("seq {0} is lower than the stored seq")]
    StaleSeq(u64),
    /// `now >= not_after` / `now >= expires_at`.
    #[error("expired")]
    Expired,
    /// `now < not_before`.
    #[error("not yet valid")]
    NotYetValid,
    #[error("challenge audience does not match this hub")]
    AudienceMismatch,
    /// A runtime cert body names another hub root key than its signer.
    #[error("hub root key does not match the expected hub")]
    HubKeyMismatch,
    #[error("invalid hub signature on the hosting entry of {0}")]
    BadHubSignature(HubId),
    #[error("hub {0} appears more than once")]
    DuplicateHub(HubId),
    #[error("hosting record has {0} hubs, expected 1..=16")]
    HubCount(usize),
    /// Hosting record hubs are not sorted by `(priority, hub_root_pubkey)`.
    #[error("hosting record hubs are not in canonical order")]
    UnsortedHubs,
    /// The user root key of a hosting record is also one of its hub keys.
    #[error("user root key is also a hub root key")]
    UserKeyIsHubKey,
    /// Challenge `issued_at >= expires_at`.
    #[error("challenge validity window is empty")]
    InvalidValidityWindow,
    /// Challenge `expires_at - issued_at` above
    /// [`crate::AUTH_CHALLENGE_MAX_LIFETIME_MS`].
    #[error("challenge lifetime is too long")]
    LifetimeTooLong,
}

impl IdentityError {
    /// Stable snake_case name of the error kind, independent of the message
    /// and payload: the `expected_error` codes of `negative.json` (spec
    /// section "Negative vectors"). `invalid_hub_id` is not part of that table.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "decode_error",
            Self::NonCanonical => "non_canonical_cbor",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::InvalidKey => "invalid_key",
            Self::InvalidUserId(_) => "invalid_user_id",
            Self::InvalidDeviceId(_) => "invalid_device_id",
            Self::InvalidHubId(_) => "invalid_hub_id",
            Self::BadSignature => "bad_signature",
            Self::UserIdMismatch => "user_id_mismatch",
            Self::DeviceIdMismatch => "device_id_mismatch",
            Self::DuplicateDevice(_) => "duplicate_device",
            Self::Revoked(_) => "device_revoked",
            Self::UnknownDevice(_) => "unknown_device",
            Self::SeqConflict(_) => "seq_conflict",
            Self::StaleSeq(_) => "stale_seq",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::AudienceMismatch => "audience_mismatch",
            Self::HubKeyMismatch => "hub_key_mismatch",
            Self::BadHubSignature(_) => "bad_hub_signature",
            Self::DuplicateHub(_) => "duplicate_hub",
            Self::HubCount(_) => "hub_count",
            Self::UnsortedHubs => "unsorted_hubs",
            Self::UserKeyIsHubKey => "user_key_is_hub_key",
            Self::InvalidValidityWindow => "invalid_validity_window",
            Self::LifetimeTooLong => "lifetime_too_long",
        }
    }
}
