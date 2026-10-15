//! The libp2p swarm and its event loop. Only this task touches the swarm;
//! the [`super::Transport`] handle talks to it with [`Command`]s.

use std::{
    collections::HashMap,
    error::Error,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use gim_hub_identity::{HubId, HubRuntimeCert};
use gim_hub_proto::{
    s2s::{
        s2s_request::Op, s2s_response::Result as Res, Error as S2sError, ErrorCode, HelloRequest,
        HelloResponse, S2sRequest, S2sResponse,
    },
    KAD_PROTOCOL, S2S_PROTOCOL,
};
use libp2p::{
    allow_block_list::{self, BlockedPeers},
    core::{transport::Transport as _, upgrade},
    identity::Keypair,
    kad::{
        self, store::MemoryStore, store::MemoryStoreConfig, store::RecordStore, BucketInserts,
        Caching, GetRecordOk, InboundRequest as KadInbound, Mode, QueryId, QueryResult, Quorum,
        Record, RecordKey, StoreInserts,
    },
    multiaddr::Protocol,
    noise, pnet,
    request_response::{
        self, InboundRequestId, OutboundFailure, OutboundRequestId, ProtocolSupport,
        ResponseChannel,
    },
    swarm::{
        dial_opts::{DialOpts, PeerCondition},
        ConnectionId, NetworkBehaviour, SwarmEvent,
    },
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use tokio::sync::{mpsc, oneshot};

use super::{
    binding::{verify_peer_cert, Binding, Connection, Known, Refusal},
    codec::S2sCodec,
    now_ms, InboundRequest, PeerEvent, Responder, SendError, Shared,
};
use crate::config::Psk;

/// Connections without streams stay open this long.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
/// An inbound connection must complete `Hello` within this time (§3.2).
const HELLO_DEADLINE: Duration = Duration::from_secs(5);
/// Refused hubs' PeerIds and bad addresses are shunned this long (§3.4).
pub(crate) const DENY_DURATION: Duration = Duration::from_secs(600);
/// A refused peer's connection is closed this long after the refusal is
/// sent, so the response reaches it (§3.4: at most 1 s). The peer normally
/// closes first.
const REFUSAL_CLOSE_DELAY: Duration = Duration::from_secs(1);
/// DHT record store limits (§4.4).
const MAX_RECORDS: usize = 65_536;
const MAX_RECORD_BYTES: usize = 8192;

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    block: allow_block_list::Behaviour<BlockedPeers>,
    rr: request_response::Behaviour<S2sCodec>,
    kad: kad::Behaviour<MemoryStore>,
}

impl Behaviour {
    fn new(local: PeerId, timeout: Duration) -> Self {
        let rr = request_response::Behaviour::new(
            [(StreamProtocol::new(S2S_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default().with_request_timeout(timeout),
        );
        let mut config = kad::Config::new(StreamProtocol::new(KAD_PROTOCOL));
        config
            .set_query_timeout(timeout)
            .set_record_filtering(StoreInserts::FilterBoth)
            .set_kbucket_inserts(BucketInserts::Manual)
            .set_caching(Caching::Disabled)
            // Publishers republish their own records; nothing is replicated.
            .set_replication_interval(None)
            .set_publication_interval(None)
            .set_periodic_bootstrap_interval(None);
        let store = MemoryStore::with_config(
            local,
            MemoryStoreConfig {
                max_records: MAX_RECORDS,
                max_value_bytes: MAX_RECORD_BYTES,
                ..MemoryStoreConfig::default()
            },
        );
        let mut kad = kad::Behaviour::with_config(local, store, config);
        kad.set_mode(Some(Mode::Server));
        Self {
            block: allow_block_list::Behaviour::default(),
            rr,
            kad,
        }
    }
}

/// Builds the swarm: Noise and yamux over TCP plus QUIC, or TCP only behind
/// pnet when a PSK is set (§3.3).
pub(crate) fn build_swarm(
    keypair: Keypair,
    psk: Option<Psk>,
    timeout: Duration,
) -> Result<Swarm<Behaviour>, Box<dyn Error + Send + Sync>> {
    let behaviour = move |key: &Keypair| Behaviour::new(key.public().to_peer_id(), timeout);
    let swarm_config = |config: libp2p::swarm::Config| {
        config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
    };
    let swarm = match psk {
        None => SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(behaviour)?
            .with_swarm_config(swarm_config)
            .build(),
        Some(psk) => SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|key| -> Result<_, Box<dyn Error + Send + Sync>> {
                let noise = noise::Config::new(key)?;
                Ok(
                    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
                        .and_then(move |socket, _| {
                            pnet::PnetConfig::new(pnet::PreSharedKey::new(psk)).handshake(socket)
                        })
                        .upgrade(upgrade::Version::V1Lazy)
                        .authenticate(noise)
                        .multiplex(yamux::Config::default())
                        .timeout(Duration::from_secs(20)),
                )
            })?
            .with_behaviour(behaviour)?
            .with_swarm_config(swarm_config)
            .build(),
    };
    Ok(swarm)
}

pub(crate) enum Command {
    /// Sends `request` on an existing connection to `peer`.
    Request {
        peer: PeerId,
        request: S2sRequest,
        reply: oneshot::Sender<Result<S2sResponse, SendError>>,
    },
    /// Sends `Hello` to `peer` and binds it from the response.
    Hello {
        peer: PeerId,
        expect: Option<HubId>,
        reply: oneshot::Sender<Result<HubId, SendError>>,
    },
    /// Opens a connection; replies with the remote PeerId once established.
    Dial {
        peer: Option<PeerId>,
        addr: Multiaddr,
        reply: oneshot::Sender<Result<PeerId, SendError>>,
    },
    Respond {
        id: InboundRequestId,
        response: S2sResponse,
    },
    DhtPut {
        record: Record,
        reply: oneshot::Sender<Result<(), SendError>>,
    },
    DhtGet {
        key: RecordKey,
        max: usize,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
    HelloDeadline {
        peer: PeerId,
    },
    Unblock {
        peer: PeerId,
    },
    /// Closes a refused peer's connections; `block` also denies it.
    CloseRefused {
        peer: PeerId,
        block: bool,
    },
    /// The policy changed: drop bindings it no longer admits.
    Revalidate,
    Shutdown,
}

enum Pending {
    Request(oneshot::Sender<Result<S2sResponse, SendError>>),
    Hello {
        expect: Option<HubId>,
        reply: oneshot::Sender<Result<HubId, SendError>>,
    },
}

/// What to do once a refusal response is flushed (§3.4).
enum Close {
    Disconnect,
    Block,
}

struct Get {
    key: RecordKey,
    max: usize,
    values: Vec<Vec<u8>>,
    reply: oneshot::Sender<Vec<Vec<u8>>>,
}

pub(crate) struct Driver {
    pub swarm: Swarm<Behaviour>,
    pub shared: Arc<Shared>,
    pub commands: mpsc::UnboundedSender<Command>,
    pub inbound: mpsc::Sender<InboundRequest>,
    pub external_addrs: Vec<Multiaddr>,
    pub listen_addrs: Vec<Multiaddr>,
    pending: HashMap<OutboundRequestId, Pending>,
    channels: HashMap<InboundRequestId, (PeerId, ResponseChannel<S2sResponse>)>,
    close_after: HashMap<InboundRequestId, (PeerId, Close)>,
    dials: HashMap<ConnectionId, oneshot::Sender<Result<PeerId, SendError>>>,
    puts: HashMap<QueryId, oneshot::Sender<Result<(), SendError>>>,
    gets: HashMap<QueryId, Get>,
}

impl Driver {
    pub fn new(
        swarm: Swarm<Behaviour>,
        shared: Arc<Shared>,
        commands: mpsc::UnboundedSender<Command>,
        inbound: mpsc::Sender<InboundRequest>,
        external_addrs: Vec<Multiaddr>,
    ) -> Self {
        Self {
            swarm,
            shared,
            commands,
            inbound,
            external_addrs,
            listen_addrs: Vec::new(),
            pending: HashMap::new(),
            channels: HashMap::new(),
            close_after: HashMap::new(),
            dials: HashMap::new(),
            puts: HashMap::new(),
            gets: HashMap::new(),
        }
    }

    /// Starts listening on `addrs` and waits until each listener reports an
    /// address.
    pub async fn listen(&mut self, addrs: &[Multiaddr]) -> Result<(), String> {
        let mut waiting = Vec::new();
        for addr in addrs {
            let id = self
                .swarm
                .listen_on(addr.clone())
                .map_err(|err| format!("listen on {addr}: {err}"))?;
            waiting.push(id);
        }
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        while !waiting.is_empty() {
            let event = tokio::select! {
                event = self.swarm.select_next_some() => event,
                () = &mut deadline => return Err("listeners did not start".into()),
            };
            match event {
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } => {
                    waiting.retain(|id| *id != listener_id);
                    self.listen_addrs.push(address);
                }
                SwarmEvent::ListenerClosed {
                    reason: Err(err), ..
                }
                | SwarmEvent::ListenerError { error: err, .. } => {
                    return Err(format!("listener failed: {err}"))
                }
                _ => {}
            }
        }
        self.update_advertised();
        Ok(())
    }

    pub async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    None | Some(Command::Shutdown) => break,
                    Some(command) => self.on_command(command),
                },
                event = self.swarm.select_next_some() => self.on_swarm_event(event),
            }
        }
    }

    fn update_advertised(&self) {
        let advertised = if self.external_addrs.is_empty() {
            self.listen_addrs
                .iter()
                .filter(|addr| !super::is_unspecified(addr))
                .cloned()
                .collect()
        } else {
            self.external_addrs.clone()
        };
        self.shared.state().advertised = advertised;
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Request {
                peer,
                request,
                reply,
            } => {
                let id = self.swarm.behaviour_mut().rr.send_request(&peer, request);
                self.pending.insert(id, Pending::Request(reply));
            }
            Command::Hello {
                peer,
                expect,
                reply,
            } => {
                let request = {
                    let state = self.shared.state();
                    S2sRequest {
                        request_id: "hello".into(),
                        op: Some(Op::Hello(HelloRequest {
                            runtime_cert: state.runtime_cert.clone(),
                            listen_addrs: state.advertised.iter().map(|a| a.to_vec()).collect(),
                        })),
                    }
                };
                let id = self.swarm.behaviour_mut().rr.send_request(&peer, request);
                self.pending.insert(id, Pending::Hello { expect, reply });
            }
            Command::Dial { peer, addr, reply } => {
                let opts = match peer {
                    Some(peer) => DialOpts::peer_id(peer)
                        .addresses(vec![addr])
                        .condition(PeerCondition::Always)
                        .build(),
                    None => DialOpts::unknown_peer_id().address(addr).build(),
                };
                let id = opts.connection_id();
                match self.swarm.dial(opts) {
                    Ok(()) => {
                        self.dials.insert(id, reply);
                    }
                    Err(err) => {
                        let _ = reply.send(Err(SendError::Unreachable(err.to_string())));
                    }
                }
            }
            Command::Respond { id, response } => self.respond(id, response),
            Command::DhtPut { record, reply } => {
                match self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, Quorum::One)
                {
                    Ok(query) => {
                        self.puts.insert(query, reply);
                    }
                    Err(err) => {
                        let _ = reply.send(Err(SendError::Transport(err.to_string())));
                    }
                }
            }
            Command::DhtGet { key, max, reply } => {
                let query = self.swarm.behaviour_mut().kad.get_record(key.clone());
                self.gets.insert(
                    query,
                    Get {
                        key,
                        max,
                        values: Vec::new(),
                        reply,
                    },
                );
            }
            Command::HelloDeadline { peer } => {
                let bound = self
                    .shared
                    .state()
                    .bound_hub(&peer, now_ms(), self.shared.policy.as_ref())
                    .is_some();
                if !bound && self.swarm.is_connected(&peer) {
                    tracing::debug!(%peer, "no Hello within the deadline; closing");
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
            }
            Command::Unblock { peer } => {
                self.swarm.behaviour_mut().block.unblock_peer(peer);
            }
            Command::CloseRefused { peer, block } => {
                if block {
                    // Closes the connections and refuses new ones.
                    self.swarm.behaviour_mut().block.block_peer(peer);
                    let commands = self.commands.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(DENY_DURATION).await;
                        let _ = commands.send(Command::Unblock { peer });
                    });
                } else {
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
            }
            Command::Revalidate => self.revalidate(),
            Command::Shutdown => {}
        }
    }

    fn on_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Rr(event)) => self.on_rr_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Kad(event)) => self.on_kad_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Block(never)) => match never {},
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let dialer = endpoint.is_dialer();
                let connection = Connection {
                    id: connection_id,
                    remote: endpoint.get_remote_address().clone(),
                    dialer,
                };
                self.shared
                    .state()
                    .connections
                    .entry(peer_id)
                    .or_default()
                    .push(connection);
                if let Some(reply) = self.dials.remove(&connection_id) {
                    let _ = reply.send(Ok(peer_id));
                }
                if !dialer {
                    let commands = self.commands.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(HELLO_DEADLINE).await;
                        let _ = commands.send(Command::HelloDeadline { peer: peer_id });
                    });
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                let mut state = self.shared.state();
                if let Some(connections) = state.connections.get_mut(&peer_id) {
                    connections.retain(|c| c.id != connection_id);
                }
                if num_established == 0 {
                    state.connections.remove(&peer_id);
                    if let Some(binding) = state.bindings.get(&peer_id) {
                        if state.hubs.get(&binding.hub_id) == Some(&peer_id) {
                            let _ = self
                                .shared
                                .peer_events
                                .send(PeerEvent::Down(binding.hub_id.clone()));
                        }
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } => {
                if let Some(reply) = self.dials.remove(&connection_id) {
                    let _ = reply.send(Err(SendError::Unreachable(error.to_string())));
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                self.listen_addrs.push(address);
                self.update_advertised();
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                self.listen_addrs.retain(|addr| *addr != address);
                self.update_advertised();
            }
            _ => {}
        }
    }

    fn on_rr_event(&mut self, event: request_response::Event<S2sRequest, S2sResponse>) {
        use request_response::{Event, Message};
        match event {
            Event::Message {
                peer,
                message:
                    Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                self.channels.insert(request_id, (peer, channel));
                self.on_inbound(peer, request_id, request);
            }
            Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => match self.pending.remove(&request_id) {
                Some(Pending::Request(reply)) => {
                    let _ = reply.send(Ok(response));
                }
                Some(Pending::Hello { expect, reply }) => {
                    let _ = reply.send(self.on_hello_response(peer, expect, response));
                }
                None => {}
            },
            Event::OutboundFailure {
                request_id, error, ..
            } => {
                let error = match error {
                    OutboundFailure::Timeout => SendError::Timeout,
                    OutboundFailure::DialFailure => SendError::Unreachable(error.to_string()),
                    other => SendError::Transport(other.to_string()),
                };
                match self.pending.remove(&request_id) {
                    Some(Pending::Request(reply)) => {
                        let _ = reply.send(Err(error));
                    }
                    Some(Pending::Hello { reply, .. }) => {
                        let _ = reply.send(Err(error));
                    }
                    None => {}
                }
            }
            Event::InboundFailure { request_id, .. } | Event::ResponseSent { request_id, .. } => {
                self.channels.remove(&request_id);
                self.after_response(request_id);
            }
        }
    }

    /// An inbound S2S request: `Hello` binds; anything else needs a binding.
    fn on_inbound(&mut self, peer: PeerId, id: InboundRequestId, request: S2sRequest) {
        let request_id = request.request_id.clone();
        let reply = |result| S2sResponse {
            request_id: request_id.clone(),
            result: Some(result),
            error: None,
        };
        let error = |code: ErrorCode, message: &str| S2sResponse {
            request_id: request_id.clone(),
            result: None,
            error: Some(S2sError {
                code: code as i32,
                message: message.to_owned(),
                ..Default::default()
            }),
        };
        let now = now_ms();
        if let Some(Op::Hello(hello)) = &request.op {
            match verify_peer_cert(&hello.runtime_cert, &peer, now, self.shared.policy.as_ref()) {
                Ok(cert) => {
                    self.bind(peer, &cert, parse_addrs(&hello.listen_addrs));
                    let state = self.shared.state();
                    let response = reply(Res::Hello(HelloResponse {
                        runtime_cert: state.runtime_cert.clone(),
                        listen_addrs: state.advertised.iter().map(|a| a.to_vec()).collect(),
                    }));
                    drop(state);
                    self.respond(id, response);
                }
                Err(Refusal::InvalidCert(reason)) => {
                    tracing::info!(%peer, %reason, "Hello refused: invalid runtime certificate");
                    self.close_after.insert(id, (peer, Close::Disconnect));
                    self.respond(id, error(ErrorCode::Unauthorized, &reason));
                }
                Err(Refusal::NotAllowed(hub_id, reason)) => {
                    tracing::warn!(%peer, %hub_id, reason, "Hello refused");
                    self.close_after.insert(id, (peer, Close::Block));
                    self.respond(id, error(ErrorCode::Unauthorized, reason));
                }
            }
            return;
        }
        let caller = self
            .shared
            .state()
            .bound_hub(&peer, now, self.shared.policy.as_ref());
        let Some(caller) = caller else {
            self.respond(
                id,
                error(
                    ErrorCode::HelloRequired,
                    "send Hello before other operations",
                ),
            );
            return;
        };
        let inbound = InboundRequest {
            caller,
            request,
            responder: Responder {
                commands: self.commands.clone(),
                id,
                request_id: request_id.clone(),
            },
        };
        if self.inbound.try_send(inbound).is_err() {
            self.respond(id, error(ErrorCode::Internal, "hub busy"));
        }
    }

    /// Checks the responder's certificate of an outbound `Hello` (§3.2,
    /// including step 5 when dialing a specific hub) and binds it.
    fn on_hello_response(
        &mut self,
        peer: PeerId,
        expect: Option<HubId>,
        response: S2sResponse,
    ) -> Result<HubId, SendError> {
        if let Some(err) = response.error {
            if err.code() == ErrorCode::Unauthorized {
                // Refused: the responder closes too, after at most 1 s.
                let _ = self.swarm.disconnect_peer_id(peer);
                return Err(SendError::PeerRefused(err.message));
            }
            return Err(SendError::Transport(format!(
                "Hello failed: {}",
                err.message
            )));
        }
        let Some(Res::Hello(hello)) = response.result else {
            let _ = self.swarm.disconnect_peer_id(peer);
            return Err(SendError::Transport("unexpected Hello response".into()));
        };
        let cert = match verify_peer_cert(
            &hello.runtime_cert,
            &peer,
            now_ms(),
            self.shared.policy.as_ref(),
        ) {
            Ok(cert) => cert,
            Err(Refusal::InvalidCert(reason)) => {
                let _ = self.swarm.disconnect_peer_id(peer);
                return Err(SendError::PeerRefused(reason));
            }
            Err(Refusal::NotAllowed(hub_id, reason)) => {
                let _ = self.swarm.disconnect_peer_id(peer);
                return Err(SendError::PeerRefused(format!("{hub_id}: {reason}")));
            }
        };
        let hub_id = cert.hub_id();
        if let Some(expect) = expect.filter(|expect| *expect != hub_id) {
            // Step 5: the address answered for another hub.
            let until = Instant::now() + DENY_DURATION;
            let mut state = self.shared.state();
            let remotes: Vec<_> = state
                .connections
                .get(&peer)
                .into_iter()
                .flatten()
                .filter(|c| c.dialer)
                .map(|c| c.remote.clone())
                .collect();
            for addr in remotes {
                state.bad_addrs.insert(addr, until);
            }
            drop(state);
            let _ = self.swarm.disconnect_peer_id(peer);
            return Err(SendError::Unreachable(format!(
                "address answered for hub {hub_id}, expected {expect}"
            )));
        }
        let mut addrs = parse_addrs(&hello.listen_addrs);
        let dialed: Vec<_> = self
            .shared
            .state()
            .connections
            .get(&peer)
            .into_iter()
            .flatten()
            .filter(|c| c.dialer)
            .map(|c| c.remote.clone())
            .collect();
        for addr in dialed {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
        self.bind(peer, &cert, addrs);
        Ok(hub_id)
    }

    fn bind(&mut self, peer: PeerId, cert: &HubRuntimeCert, addrs: Vec<Multiaddr>) {
        let hub_id = cert.hub_id();
        let mut state = self.shared.state();
        state.bindings.insert(
            peer,
            Binding {
                hub_id: hub_id.clone(),
                not_after: cert.not_after(),
            },
        );
        let previous = state.hubs.insert(hub_id.clone(), peer);
        state.known.insert(
            hub_id.clone(),
            Known {
                peer,
                addrs: addrs.clone(),
            },
        );
        if let Some(old) = previous.filter(|old| *old != peer) {
            // The hub rotated its runtime key.
            state.bindings.remove(&old);
            self.swarm.behaviour_mut().kad.remove_peer(&old);
        }
        drop(state);
        for addr in addrs {
            self.swarm.behaviour_mut().kad.add_address(&peer, addr);
        }
        if previous != Some(peer) {
            tracing::info!(%hub_id, %peer, "peer hub bound");
            let _ = self.shared.peer_events.send(PeerEvent::Up(hub_id));
        }
    }

    fn revalidate(&mut self) {
        let policy = self.shared.policy.clone();
        let mut state = self.shared.state();
        let dropped: Vec<(PeerId, HubId)> = state
            .bindings
            .iter()
            .filter(|(_, b)| policy.allow_hub(&b.hub_id) != crate::policy::Decision::Allow)
            .map(|(peer, b)| (*peer, b.hub_id.clone()))
            .collect();
        for (peer, hub_id) in &dropped {
            state.bindings.remove(peer);
            if state.hubs.get(hub_id) == Some(peer) {
                state.hubs.remove(hub_id);
            }
        }
        drop(state);
        for (peer, hub_id) in dropped {
            tracing::info!(%hub_id, %peer, "hub no longer allowed; dropping binding");
            self.swarm.behaviour_mut().kad.remove_peer(&peer);
            let _ = self.swarm.disconnect_peer_id(peer);
            let _ = self.shared.peer_events.send(PeerEvent::Down(hub_id));
        }
    }

    fn respond(&mut self, id: InboundRequestId, response: S2sResponse) {
        let Some((_, channel)) = self.channels.remove(&id) else {
            return;
        };
        if self
            .swarm
            .behaviour_mut()
            .rr
            .send_response(channel, response)
            .is_err()
        {
            self.after_response(id);
        }
    }

    /// Schedules a pending refusal's close once its response is flushed (or
    /// failed).
    fn after_response(&mut self, id: InboundRequestId) {
        let Some((peer, close)) = self.close_after.remove(&id) else {
            return;
        };
        let block = matches!(close, Close::Block);
        let commands = self.commands.clone();
        tokio::spawn(async move {
            tokio::time::sleep(REFUSAL_CLOSE_DELAY).await;
            let _ = commands.send(Command::CloseRefused { peer, block });
        });
    }

    fn on_kad_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::InboundRequest {
                request:
                    KadInbound::PutRecord {
                        source,
                        record: Some(record),
                        ..
                    },
            } => self.on_inbound_put(source, record),
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => match result {
                QueryResult::PutRecord(result) => {
                    if let Some(reply) = self.puts.remove(&id) {
                        let _ = reply.send(
                            result
                                .map(|_| ())
                                .map_err(|err| SendError::Unreachable(err.to_string())),
                        );
                    }
                }
                QueryResult::GetRecord(result) => {
                    let Some(get) = self.gets.get_mut(&id) else {
                        return;
                    };
                    if let Ok(GetRecordOk::FoundRecord(found)) = result {
                        let value = found.record.value;
                        let valid = !matches!(
                            self.shared.validators.validate(
                                get.key.as_ref(),
                                &value,
                                None,
                                now_ms()
                            ),
                            super::RecordDecision::Reject(_)
                        );
                        if valid && !get.values.contains(&value) {
                            get.values.push(value);
                        }
                    }
                    if step.last || get.values.len() >= get.max {
                        if let Some(get) = self.gets.remove(&id) {
                            let _ = get.reply.send(get.values);
                        }
                        if let Some(mut query) = self.swarm.behaviour_mut().kad.query_mut(&id) {
                            query.finish();
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Inbound `PUT_VALUE`: only from bound peers, only valid records (§3.4,
    /// §4.4).
    fn on_inbound_put(&mut self, source: PeerId, record: Record) {
        let now = now_ms();
        let bound = self
            .shared
            .state()
            .bound_hub(&source, now, self.shared.policy.as_ref())
            .is_some();
        if !bound {
            tracing::debug!(%source, "DHT put from an unbound peer ignored");
            return;
        }
        let store = self.swarm.behaviour_mut().kad.store_mut();
        let existing = store.get(&record.key).map(|r| r.value.clone());
        match self.shared.validators.validate(
            record.key.as_ref(),
            &record.value,
            existing.as_deref(),
            now,
        ) {
            super::RecordDecision::Store => {
                if let Err(err) = store.put(record) {
                    tracing::warn!(%err, "DHT record not stored");
                }
            }
            super::RecordDecision::Keep => {}
            super::RecordDecision::Reject(reason) => {
                tracing::debug!(%source, %reason, "DHT record rejected");
            }
        }
    }
}

fn parse_addrs(bytes: &[Vec<u8>]) -> Vec<Multiaddr> {
    bytes
        .iter()
        .filter_map(|addr| Multiaddr::try_from(addr.clone()).ok())
        .filter(|addr| !super::is_unspecified(addr))
        .collect()
}

/// Splits a trailing `/p2p/<PeerId>` off `addr`.
pub(crate) fn split_peer_id(addr: &Multiaddr) -> (Option<PeerId>, Multiaddr) {
    let mut addr = addr.clone();
    match addr.pop() {
        Some(Protocol::P2p(peer)) => (Some(peer), addr),
        Some(other) => {
            addr.push(other);
            (None, addr)
        }
        None => (None, addr),
    }
}
