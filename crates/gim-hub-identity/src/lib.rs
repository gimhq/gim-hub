//! Hub-side verification of the gim identity formats.
//!
//! gim-core owns the wire formats. The normative spec and test vectors are
//! vendored in `testdata/identity/` (see `testdata/identity/SOURCE` for the
//! upstream revision). This crate implements that spec from the hub's side:
//!
//! - `user_id`, `device_id`, `hub_id`; `SignedDeviceCert` and
//!   `SignedDeviceList` (verify only).
//! - `SignedHubRuntimeCert`: verify, libp2p PeerId bytes, and issue with the
//!   hub's own root key.
//! - `SignedHostingRecord`: verify, primary hub, ordering; the hub co-signs
//!   its own `HostingEntry`.
//! - `AuthChallenge` (built and encoded by the hub) and `AuthResponse`
//!   verification. The issued-challenge / single-use nonce store is the
//!   caller's.
//! - `RootKeyBackup` and sealed `LinkBundle`: structural checks only; the hub
//!   relays them and never opens them.
//!
//! The 0xF001 credential payload is pending gim-core S4 and not implemented
//! here.
//!
//! This crate must stay free of hub-only dependencies so that it can later
//! be shared with gim-core.

mod auth;
mod cbor;
mod cert;
mod error;
mod hosting;
mod ids;
mod keys;
mod list;
mod relay;
mod runtime;

pub use auth::{verify_auth_response, AuthChallenge, AuthenticatedDevice, AUTH_RESPONSE_CONTEXT};
pub use cert::{DeviceCert, DEVICE_CERT_CONTEXT};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::IdentityError;
pub use hosting::{
    HostingEntry, HostingRecord, HOSTING_ENTRY_CONTEXT, HOSTING_RECORD_CONTEXT, MAX_HUBS,
};
pub use ids::{DeviceId, HubId, UserId};
pub use keys::parse_public_key;
pub use list::{DeviceList, DEVICE_LIST_CONTEXT};
pub use relay::{check_recovery_backup, check_sealed_link_bundle};
pub use runtime::{libp2p_peer_id, HubRuntimeCert, HUB_RUNTIME_CERT_CONTEXT, PEER_ID_LEN};

/// The only body format version defined by the spec.
pub const FORMAT_VERSION: u64 = 1;

#[cfg(test)]
pub(crate) mod testutil;
