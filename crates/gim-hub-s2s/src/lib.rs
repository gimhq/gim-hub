//! Hub-to-hub federation for the gim hub (docs/federation.md).
//!
//! - [`config`]: `GIM_HUB_FEDERATION*` / `GIM_HUB_P2P_*` settings (§10).
//! - [`policy`]: [`FederationPolicy`] and the closed-federation
//!   [`AllowlistPolicy`] (§3.3, §3.6).
//! - [`transport`]: the libp2p host, `Hello` binding, DHT and locator
//!   records (§3); the only module that imports libp2p.
//! - [`federation`]: the [`Federation`] trait used by the client API, its
//!   [`Disabled`] implementation, and [`FederationService`] with op
//!   dispatch (§3.7).
//! - [`outbox`]: the durable outbound queue and its per-peer worker (§7).

pub mod config;
pub mod federation;
pub mod outbox;
pub mod policy;
pub mod transport;

pub use config::{ConfigError, FederationConfig};
pub use federation::{
    error, BoxFuture, Disabled, Federation, FederationService, OpHandler, OpResult, StartError,
};
pub use outbox::{Outbox, OutboxConfig, OutboxSender, OutboxSource};
pub use policy::{AllowlistPolicy, Decision, FederationPolicy, OpKind, PolicyError};
pub use transport::{
    InboundRequest, Multiaddr, PeerEvent, RecordDecision, RecordValidator, Responder, SendError,
    Transport,
};
