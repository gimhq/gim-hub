//! Hub-side verification of the gim identity formats.
//!
//! gim-core owns the wire formats. The normative spec and test vectors are
//! vendored in `testdata/identity/` (see `testdata/identity/SOURCE` for the
//! upstream revision). This crate implements part 1 of that spec from the
//! verifier's side: `user_id` / `device_id`, `SignedDeviceCert` and
//! `SignedDeviceList`.
//!
//! Part 2 (`UserHostingRecord`, `HubRuntimeCert`, `AuthChallenge` /
//! `AuthResponse`, `hub_id`) is pending gim-core S8 and not implemented here.
//!
//! This crate must stay free of hub-only dependencies so that it can later
//! be shared with gim-core.

mod cbor;
mod cert;
mod error;
mod ids;
mod keys;
mod list;

pub use cert::{DeviceCert, DEVICE_CERT_CONTEXT};
pub use ed25519_dalek::VerifyingKey;
pub use error::IdentityError;
pub use ids::{DeviceId, UserId};
pub use keys::parse_public_key;
pub use list::{DeviceList, DEVICE_LIST_CONTEXT};

/// The only body format version defined by the spec.
pub const FORMAT_VERSION: u64 = 1;

#[cfg(test)]
pub(crate) mod testutil;
