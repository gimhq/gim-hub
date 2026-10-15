//! The libp2p host (docs/federation.md §2, §3). This is the only module
//! that imports libp2p; callers address peers by `hub_id` and never see a
//! PeerId.
//!
//! - Noise over TCP (yamux) and QUIC; TCP only behind pnet when a PSK is set.
//! - Request-response `/gim/s2s/1.0.0` ([`codec`]), private Kademlia
//!   `/gim/kad/1.0.0` with per-prefix record validators ([`RecordValidator`]).
//! - `Hello` binds a connection's PeerId to a `hub_id` (§3.2); every other
//!   inbound op from an unbound PeerId gets `HELLO_REQUIRED`.
//! - Outbound requests resolve `hub_id` → address (§3.5), dial, `Hello`, and
//!   retry once on `HELLO_REQUIRED`.
//! - libp2p ping on every connection; pings and S2S exchanges with bound
//!   hubs feed [`Liveness`] (docs/multihoming.md §8).

mod binding;
mod codec;
pub mod liveness;
mod records;
mod runtime;
mod swarm;

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use gim_hub_identity::HubId;
use gim_hub_proto::{
    s2s::{ErrorCode, S2sRequest, S2sResponse},
    HUB_RECORD_KEY_PREFIX,
};
use libp2p::{
    kad::{Record, RecordKey},
    multiaddr::Protocol,
    request_response::InboundRequestId,
    PeerId,
};
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};

pub use codec::MAX_FRAME_BYTES;
pub use libp2p::Multiaddr;
pub use liveness::Liveness;
pub use records::{RecordDecision, RecordValidator};
pub use runtime::{needs_renewal, RuntimeIdentity, CERT_BACKDATE_MS};

use crate::{config::Psk, policy::FederationPolicy};
use binding::State;
use records::Validators;
use swarm::{Command, Driver};

/// How often bootstrap addresses are redialed while no peer is bound.
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(300);
/// How often the hub republishes its locator.
const LOCATOR_REPUBLISH_INTERVAL: Duration = Duration::from_secs(3600);
/// Valid DHT records collected by a locator lookup.
const LOCATOR_LOOKUP_RECORDS: usize = 3;
/// Bound on queued inbound requests waiting for a handler.
const INBOUND_QUEUE: usize = 1024;

/// Failure of an outbound S2S operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("federation is disabled")]
    Disabled,
    /// Local policy forbids the peer, or the peer refused this hub.
    #[error("peer refused: {0}")]
    PeerRefused(String),
    /// No address worked: unknown, dial failed, or answered for another hub.
    #[error("peer unreachable: {0}")]
    Unreachable(String),
    #[error("request timed out")]
    Timeout,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("transport stopped")]
    Stopped,
}

/// Peer hub reachability, keyed by `hub_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    /// A hub was bound (or re-bound under a new PeerId).
    Up(HubId),
    /// The last connection to a bound hub closed, or the policy dropped it.
    Down(HubId),
}

/// An inbound request from a bound hub, after `Hello`. Policy admission and
/// dispatch are the caller's.
#[derive(Debug)]
pub struct InboundRequest {
    pub caller: HubId,
    pub request: S2sRequest,
    pub responder: Responder,
}

/// Sends the response of one [`InboundRequest`].
#[derive(Debug)]
pub struct Responder {
    commands: mpsc::UnboundedSender<Command>,
    id: InboundRequestId,
    request_id: String,
}

impl Responder {
    /// Sends `response`, echoing the request's `request_id`.
    pub fn respond(self, mut response: S2sResponse) {
        response.request_id = self.request_id;
        let _ = self.commands.send(Command::Respond {
            id: self.id,
            response,
        });
    }
}

/// Transport settings, from [`crate::FederationConfig`].
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub listen: Vec<Multiaddr>,
    /// Advertised addresses; empty means the actual listen addresses that
    /// are not unspecified.
    pub external_addrs: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub timeout: Duration,
    pub psk: Option<Psk>,
    /// A bound hub without a successful ping or exchange for this long is
    /// down in [`Transport::liveness`]; also shortens the ping interval
    /// ([`liveness::ping_interval`]).
    pub failover: Duration,
}

impl std::fmt::Debug for swarm::Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Command")
    }
}

pub(crate) struct Shared {
    hub_id: HubId,
    policy: Arc<dyn FederationPolicy>,
    validators: Validators,
    state: Mutex<State>,
    peer_events: broadcast::Sender<PeerEvent>,
    liveness: Arc<Liveness>,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("transport state lock")
    }

    /// Records a successful exchange with `peer` if it is bound.
    fn alive(&self, peer: &PeerId) {
        let hub = self.state().bound_hub(peer, now_ms(), self.policy.as_ref());
        if let Some(hub) = hub {
            self.liveness.alive(&hub);
        }
    }
}

/// Handle to the libp2p host. Cheap to clone.
#[derive(Clone)]
pub struct Transport {
    inner: Arc<Inner>,
}

struct Inner {
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
    config: TransportConfig,
    flights: Mutex<HashMap<HubId, Arc<tokio::sync::Mutex<()>>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        for task in self.tasks.get_mut().expect("tasks lock").drain(..) {
            task.abort();
        }
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("hub_id", &self.inner.shared.hub_id)
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Starts the host for `hub_id` with `runtime` as its libp2p identity:
    /// listens (waiting until every listener has an address), then
    /// bootstraps and publishes the locator in the background. Inbound
    /// requests from bound hubs arrive on the returned receiver.
    pub async fn start(
        config: TransportConfig,
        hub_id: HubId,
        runtime: &RuntimeIdentity,
        policy: Arc<dyn FederationPolicy>,
    ) -> Result<(Self, mpsc::Receiver<InboundRequest>), SendError> {
        if config.psk.is_some() != policy.psk().is_some() {
            return Err(SendError::Transport(
                "transport and policy disagree on the PSK".into(),
            ));
        }
        let swarm = swarm::build_swarm(
            runtime.keypair(),
            config.psk,
            config.timeout,
            liveness::ping_interval(config.failover),
        )
        .map_err(|err| SendError::Transport(err.to_string()))?;
        let (peer_events, _) = broadcast::channel(256);
        let shared = Arc::new(Shared {
            hub_id,
            policy,
            validators: Validators::new(),
            state: Mutex::new(State {
                runtime_cert: runtime.cert().to_vec(),
                runtime_not_after: runtime.not_after(),
                ..State::default()
            }),
            peer_events,
            liveness: Arc::new(Liveness::new(config.failover, liveness::monotonic())),
        });
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let mut driver = Driver::new(
            swarm,
            shared.clone(),
            commands.clone(),
            inbound_tx,
            config.external_addrs.clone(),
        );
        driver
            .listen(&config.listen)
            .await
            .map_err(SendError::Transport)?;
        let transport = Self {
            inner: Arc::new(Inner {
                shared,
                commands,
                config,
                flights: Mutex::default(),
                tasks: Mutex::default(),
            }),
        };
        let driver = tokio::spawn(driver.run(command_rx));
        let weak = Arc::downgrade(&transport.inner);
        let maintenance = tokio::spawn(async move {
            let mut bootstrap = tokio::time::interval(BOOTSTRAP_INTERVAL);
            let mut republish = tokio::time::interval(LOCATOR_REPUBLISH_INTERVAL);
            let mut events = match weak.upgrade() {
                Some(inner) => inner.shared.peer_events.subscribe(),
                None => return,
            };
            let mut published = false;
            loop {
                // Bootstrap while no peer is bound; publish the locator
                // hourly and as soon as a peer is bound after a failed put.
                let (do_bootstrap, do_publish) = tokio::select! {
                    _ = bootstrap.tick() => (true, false),
                    _ = republish.tick() => (false, true),
                    event = events.recv() => (false, !published && matches!(event, Ok(PeerEvent::Up(_)))),
                };
                let Some(inner) = weak.upgrade() else { return };
                let transport = Transport { inner };
                if do_bootstrap && transport.bound_hubs().is_empty() {
                    transport.bootstrap().await;
                }
                if do_publish {
                    match transport.publish_locator().await {
                        Ok(()) => published = true,
                        Err(err) => {
                            published = false;
                            tracing::debug!(%err, "locator not published");
                        }
                    }
                }
            }
        });
        transport
            .inner
            .tasks
            .lock()
            .expect("tasks lock")
            .extend([driver, maintenance]);
        Ok((transport, inbound_rx))
    }

    /// This hub's id.
    pub fn hub_id(&self) -> &HubId {
        &self.inner.shared.hub_id
    }

    /// Addresses advertised in `Hello` and the locator.
    pub fn advertised_addrs(&self) -> Vec<Multiaddr> {
        self.shared().state().advertised.clone()
    }

    /// Hubs currently bound (unexpired and admitted by the policy).
    pub fn bound_hubs(&self) -> Vec<HubId> {
        let now = now_ms();
        let state = self.shared().state();
        let mut hubs: Vec<_> = state
            .bindings
            .keys()
            .filter_map(|peer| state.bound_hub(peer, now, self.shared().policy.as_ref()))
            .collect();
        hubs.sort();
        hubs.dedup();
        hubs
    }

    /// Notifications when peer hubs come up or go down.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.shared().peer_events.subscribe()
    }

    /// Reachability of peer hubs for the push rule (docs/multihoming.md §8).
    pub fn liveness(&self) -> Arc<Liveness> {
        self.shared().liveness.clone()
    }

    /// Makes sure a bound connection to `hub_id` is open, resolving and
    /// dialing it if needed (§3.5); pings then run on it.
    pub async fn keep_connected(&self, hub_id: &HubId) -> Result<(), SendError> {
        if hub_id == self.hub_id() {
            return Err(SendError::PeerRefused("cannot connect to this hub".into()));
        }
        if !self.shared().policy.may_contact(hub_id) {
            return Err(SendError::PeerRefused("hub not allowlisted".into()));
        }
        self.ensure_bound(hub_id).await.map(|_| ())
    }

    /// Registers the DHT validator for keys starting with `prefix`.
    pub fn register_record_validator(&self, prefix: &str, validator: Arc<dyn RecordValidator>) {
        self.shared().validators.register(prefix, validator);
    }

    /// Sends `request` to `hub_id` and waits for its response: resolves and
    /// binds the hub if needed (§3.5), and on `HELLO_REQUIRED` sends `Hello`
    /// and retries once. Error responses are returned as responses.
    pub async fn request(
        &self,
        hub_id: &HubId,
        request: S2sRequest,
    ) -> Result<S2sResponse, SendError> {
        if hub_id == self.hub_id() {
            return Err(SendError::PeerRefused("cannot send to this hub".into()));
        }
        if !self.shared().policy.may_contact(hub_id) {
            return Err(SendError::PeerRefused("hub not allowlisted".into()));
        }
        let peer = self.ensure_bound(hub_id).await?;
        let response = self.raw_request(peer, request.clone()).await?;
        if response.error.as_ref().map(|e| e.code()) == Some(ErrorCode::HelloRequired) {
            self.hello(peer, Some(hub_id.clone())).await?;
            return self.raw_request(peer, request).await;
        }
        Ok(response)
    }

    /// Stores `value` under `key` locally and on the closest bound peers
    /// (quorum one). `expires_at_ms` sets the record expiry.
    pub async fn dht_put(
        &self,
        key: &str,
        value: Vec<u8>,
        expires_at_ms: Option<u64>,
    ) -> Result<(), SendError> {
        let mut record = Record::new(RecordKey::new(&key), value);
        record.expires = expires_at_ms
            .map(|at| Instant::now() + Duration::from_millis(at.saturating_sub(now_ms())));
        self.call(|reply| Command::DhtPut { record, reply }).await?
    }

    /// Looks `key` up locally and in the DHT; returns up to `max` distinct
    /// values that pass the key's validator.
    pub async fn dht_get(&self, key: &str, max: usize) -> Result<Vec<Vec<u8>>, SendError> {
        let key = RecordKey::new(&key);
        self.call(|reply| Command::DhtGet {
            key,
            max: max.max(1),
            reply,
        })
        .await
    }

    /// Publishes this hub's locator at `/gim/hub/<hub_id>` (§3.5).
    pub async fn publish_locator(&self) -> Result<(), SendError> {
        let (value, not_after) = {
            let state = self.shared().state();
            (
                records::encode_locator(&state.runtime_cert, &state.advertised),
                state.runtime_not_after,
            )
        };
        let key = format!("{HUB_RECORD_KEY_PREFIX}{}", self.hub_id());
        self.dht_put(&key, value, Some(not_after)).await
    }

    /// Installs a renewed runtime certificate (same key): sends a fresh
    /// `Hello` on every open connection to a bound hub and republishes the
    /// locator (§3.1).
    pub async fn set_runtime_cert(&self, runtime: &RuntimeIdentity) {
        let peers: Vec<(PeerId, HubId)> = {
            let mut state = self.shared().state();
            state.runtime_cert = runtime.cert().to_vec();
            state.runtime_not_after = runtime.not_after();
            state
                .bindings
                .iter()
                .filter(|(peer, _)| state.connections.contains_key(peer))
                .map(|(peer, binding)| (*peer, binding.hub_id.clone()))
                .collect()
        };
        for (peer, hub_id) in peers {
            if let Err(err) = self.hello(peer, Some(hub_id.clone())).await {
                tracing::warn!(%hub_id, %err, "re-Hello after certificate renewal failed");
            }
        }
        if let Err(err) = self.publish_locator().await {
            tracing::warn!(%err, "locator not republished after certificate renewal");
        }
    }

    /// Re-applies the policy to existing bindings: hubs it no longer allows
    /// are unbound and disconnected (§3.3, reload).
    pub fn policy_changed(&self) {
        let _ = self.inner.commands.send(Command::Revalidate);
    }

    /// Dials the bootstrap addresses and the policy's static addresses.
    pub async fn bootstrap(&self) {
        for addr in &self.inner.config.bootstrap {
            let (peer, addr) = swarm::split_peer_id(addr);
            let result = match self.dial(peer, addr.clone()).await {
                Ok(peer) => self.hello(peer, None).await.map(|_| ()),
                Err(err) => Err(err),
            };
            if let Err(err) = result {
                tracing::info!(%addr, %err, "bootstrap address failed");
            }
        }
        let policy = self.shared().policy.clone();
        for hub_id in policy.known_hubs() {
            if policy.static_addrs(&hub_id).is_empty() {
                continue;
            }
            if let Err(err) = self.ensure_bound(&hub_id).await {
                tracing::info!(%hub_id, %err, "static peer unreachable");
            }
        }
    }

    /// Stops the host and closes every connection.
    pub fn shutdown(&self) {
        let _ = self.inner.commands.send(Command::Shutdown);
        for task in self.inner.tasks.lock().expect("tasks lock").drain(..) {
            task.abort();
        }
    }

    fn shared(&self) -> &Shared {
        &self.inner.shared
    }

    async fn call<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, SendError> {
        let (reply, rx) = oneshot::channel();
        self.inner
            .commands
            .send(command(reply))
            .map_err(|_| SendError::Stopped)?;
        rx.await.map_err(|_| SendError::Stopped)
    }

    async fn with_timeout<T>(
        &self,
        future: impl std::future::Future<Output = Result<Result<T, SendError>, SendError>>,
    ) -> Result<T, SendError> {
        match tokio::time::timeout(self.inner.config.timeout, future).await {
            Ok(result) => result?,
            Err(_) => Err(SendError::Timeout),
        }
    }

    pub(crate) async fn dial(
        &self,
        peer: Option<PeerId>,
        addr: Multiaddr,
    ) -> Result<PeerId, SendError> {
        self.with_timeout(self.call(|reply| Command::Dial { peer, addr, reply }))
            .await
    }

    pub(crate) async fn hello(
        &self,
        peer: PeerId,
        expect: Option<HubId>,
    ) -> Result<HubId, SendError> {
        self.with_timeout(self.call(|reply| Command::Hello {
            peer,
            expect,
            reply,
        }))
        .await
    }

    pub(crate) async fn raw_request(
        &self,
        peer: PeerId,
        request: S2sRequest,
    ) -> Result<S2sResponse, SendError> {
        self.with_timeout(self.call(|reply| Command::Request {
            peer,
            request,
            reply,
        }))
        .await
    }

    /// A connected, bound PeerId for `hub_id`, resolving and binding it if
    /// needed (§3.5): open binding, last known peer and addresses, static
    /// addresses, DHT locator. Concurrent calls for one hub are coalesced.
    async fn ensure_bound(&self, hub_id: &HubId) -> Result<PeerId, SendError> {
        let flight = self
            .inner
            .flights
            .lock()
            .expect("flights lock")
            .entry(hub_id.clone())
            .or_default()
            .clone();
        let _guard = flight.lock().await;

        let policy = self.shared().policy.clone();
        let (bound, known) = {
            let state = self.shared().state();
            let bound = state.bound_connected_peer(hub_id, now_ms(), policy.as_ref());
            let known = state.known.get(hub_id).map(|known| {
                (
                    known.peer,
                    state.connections.contains_key(&known.peer),
                    known.addrs.clone(),
                )
            });
            (bound, known)
        };
        if let Some(peer) = bound {
            return Ok(peer);
        }
        let mut last_error = None;
        if let Some((peer, connected, addrs)) = known {
            if connected {
                match self.hello(peer, Some(hub_id.clone())).await {
                    Ok(_) => return Ok(peer),
                    Err(err @ SendError::PeerRefused(_)) => return Err(err),
                    Err(err) => last_error = Some(err),
                }
            }
            for addr in addrs {
                match self.connect(hub_id, Some(peer), addr).await {
                    Ok(peer) => return Ok(peer),
                    Err(err @ SendError::PeerRefused(_)) => return Err(err),
                    Err(err) => last_error = Some(err),
                }
            }
        }
        for addr in policy.static_addrs(hub_id) {
            match self.connect(hub_id, None, addr).await {
                Ok(peer) => return Ok(peer),
                Err(err @ SendError::PeerRefused(_)) => return Err(err),
                Err(err) => last_error = Some(err),
            }
        }
        if let Some(locator) = self.lookup_locator(hub_id).await {
            let peer = PeerId::from_bytes(&locator.cert.peer_id()).ok();
            for addr in locator.addrs {
                match self.connect(hub_id, peer, addr).await {
                    Ok(peer) => return Ok(peer),
                    Err(err @ SendError::PeerRefused(_)) => return Err(err),
                    Err(err) => last_error = Some(err),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| SendError::Unreachable("no address known".into())))
    }

    /// Dials `addr` and binds the connection to `hub_id` with `Hello`.
    async fn connect(
        &self,
        hub_id: &HubId,
        peer: Option<PeerId>,
        addr: Multiaddr,
    ) -> Result<PeerId, SendError> {
        if self.shared().state().is_bad(&addr, Instant::now()) {
            return Err(SendError::Unreachable(format!(
                "{addr} answered for another hub"
            )));
        }
        let peer = self.dial(peer, addr).await?;
        let bound = self
            .shared()
            .state()
            .bound_hub(&peer, now_ms(), self.shared().policy.as_ref());
        if bound.as_ref() != Some(hub_id) {
            self.hello(peer, Some(hub_id.clone())).await?;
        }
        Ok(peer)
    }

    /// The newest valid locator of `hub_id` in the DHT.
    async fn lookup_locator(&self, hub_id: &HubId) -> Option<records::Locator> {
        let key = format!("{HUB_RECORD_KEY_PREFIX}{hub_id}");
        let values = match self.dht_get(&key, LOCATOR_LOOKUP_RECORDS).await {
            Ok(values) => values,
            Err(err) => {
                tracing::debug!(%hub_id, %err, "locator lookup failed");
                return None;
            }
        };
        let now = now_ms();
        values
            .iter()
            .filter_map(|value| records::decode_locator(&key, value, now).ok())
            .max_by_key(|locator| locator.cert.not_before())
    }
}

/// Unix time in milliseconds.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Whether `addr` uses QUIC.
pub fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, Protocol::Quic | Protocol::QuicV1))
}

/// Whether `addr` carries a `/p2p/<PeerId>` component.
pub fn has_peer_id(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2p(_)))
}

/// Whether `addr` names an unspecified IP (`0.0.0.0` / `::`).
pub(crate) fn is_unspecified(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}
