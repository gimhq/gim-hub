//! Hub-side verification of the gim identity formats.
//!
//! gim-core owns the wire formats. The normative spec and test vectors are
//! vendored in `testdata/identity/` (see `testdata/identity/SOURCE` for the
//! upstream revision). This crate implements that spec from the hub's side:
//!
//! - `user_id`, `device_id`, `hub_id`; `SignedDeviceCert` and
//!   `SignedDeviceList` (verify only, and the "Update and seq rules" via
//!   `DeviceList::supersedes`).
//! - `SignedHubRuntimeCert`: verify, libp2p PeerId bytes, and issue with the
//!   hub's own root key. A PeerId is only its 38 bytes; there is no
//!   string form.
//! - `SignedHostingRecord`: verify, primary hub, update rules; the hub
//!   co-signs its own `HostingEntry` and `sort_hosting_entries` puts entries
//!   in the canonical record order.
//! - `AuthChallenge` v1 and the hub-proposed v2 bound to the hub's public
//!   URL (built, encoded and checked by the hub) and `AuthResponse`
//!   verification. The issued-challenge / single-use nonce store is the
//!   caller's.
//! - The hub-proposed hub proof of possession (`GET /v2/hub?nonce=`).
//! - Root-signed requests (account deletion): verify only.
//! - The MLS credential `0xF001` (`GimCredential`), at the byte level of
//!   its content.
//! - `RootKeyBackup` and sealed `LinkBundle`: structural checks only; the hub
//!   relays them and never opens them.
//!
//! Every signed form is verified in the spec's "Verification order", so the
//! first failing check yields the same stable code
//! ([`IdentityError::code`], [`CredentialError::code`]) as gim-core; the
//! shared `negative.json` and `credential.json` vectors assert this.
//!
//! This crate must stay free of hub-only dependencies so that it can later
//! be shared with gim-core.

mod auth;
mod cbor;
mod cert;
mod credential;
mod error;
mod hosting;
mod ids;
mod keys;
mod list;
mod proof;
mod relay;
mod request;
mod runtime;

pub use auth::{
    auth_response_user_id, verify_auth_response, AuthChallenge, AuthenticatedDevice,
    AUTH_CHALLENGE_MAX_LIFETIME_MS, AUTH_CHALLENGE_V2, AUTH_RESPONSE_CONTEXT,
};
pub use cert::{DeviceCert, DEVICE_CERT_CONTEXT};
pub use credential::{CredentialError, GimCredential, GIM_CREDENTIAL_TYPE};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::IdentityError;
pub use hosting::{
    sort_hosting_entries, HostingEntry, HostingRecord, HOSTING_ENTRY_CONTEXT,
    HOSTING_RECORD_CONTEXT, MAX_HUBS,
};
pub use ids::{DeviceId, HubId, UserId};
pub use keys::parse_public_key;
pub use list::{DeviceList, DEVICE_LIST_CONTEXT};
pub use proof::{sign_hub_proof, verify_hub_proof, HUB_PROOF_CONTEXT, HUB_PROOF_MAX_URL_LEN};
pub use relay::{check_recovery_backup, check_sealed_link_bundle};
pub use request::{
    verify_root_request, RootRequestHeaders, ROOT_REQUEST_CONTEXT, ROOT_REQUEST_MAX_SKEW_MS,
};
pub use runtime::{libp2p_peer_id, HubRuntimeCert, HUB_RUNTIME_CERT_CONTEXT, PEER_ID_LEN};

/// The body format version of every form except `AuthChallenge` v2.
pub const FORMAT_VERSION: u64 = 1;

#[cfg(test)]
pub(crate) mod testutil;
