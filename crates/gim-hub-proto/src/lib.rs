//! Protobuf types generated from `proto/*.proto` for the gim hub.

/// libp2p request-response protocol carrying [`s2s::S2sRequest`] /
/// [`s2s::S2sResponse`].
pub const S2S_PROTOCOL: &str = "/gim/s2s/1.0.0";

/// Private Kademlia DHT protocol id shared by gim hubs.
pub const KAD_PROTOCOL: &str = "/gim/kad/1.0.0";

/// Prefix of the DHT key holding a user's hosting record:
/// `/gim/user/<user_id>`.
pub const USER_RECORD_KEY_PREFIX: &str = "/gim/user/";

/// Prefix of the DHT key holding a hub's locator ([`s2s::HubLocator`]):
/// `/gim/hub/<hub_id>`.
pub const HUB_RECORD_KEY_PREFIX: &str = "/gim/hub/";

/// Server-to-server messages, package `gim.s2s.v1`.
pub mod s2s {
    include!(concat!(env!("OUT_DIR"), "/gim.s2s.v1.rs"));
}
