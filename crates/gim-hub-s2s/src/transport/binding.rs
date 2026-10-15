//! Runtime certificate checks of the `Hello` binding (docs/federation.md
//! §3.2) and the in-memory PeerId → hub_id bindings.

use std::collections::HashMap;

use ciborium::Value;
use gim_hub_identity::{parse_public_key, HubId, HubRuntimeCert, VerifyingKey};
use libp2p::{swarm::ConnectionId, Multiaddr, PeerId};

use crate::policy::{Decision, FederationPolicy};

/// Why a received runtime certificate does not bind its sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Steps 1-3: the certificate is invalid or not for this PeerId.
    InvalidCert(String),
    /// Step 4: valid certificate of a hub the policy does not admit.
    NotAllowed(HubId, &'static str),
}

/// Steps 1-2: reads `hub_root_pubkey` from the body without trusting the
/// other fields, then verifies the certificate for that key at `now_ms`.
pub(crate) fn verify_cert(cert: &[u8], now_ms: u64) -> Result<HubRuntimeCert, String> {
    let hub_root = claimed_hub_root(cert).map_err(|err| format!("step 1: {err}"))?;
    HubRuntimeCert::verify(cert, &hub_root, now_ms).map_err(|err| format!("step 2: {err}"))
}

/// Steps 1-4 for a certificate received from `peer`.
pub(crate) fn verify_peer_cert(
    cert: &[u8],
    peer: &PeerId,
    now_ms: u64,
    policy: &dyn FederationPolicy,
) -> Result<HubRuntimeCert, Refusal> {
    let cert = verify_cert(cert, now_ms).map_err(Refusal::InvalidCert)?;
    if cert.peer_id()[..] != peer.to_bytes()[..] {
        return Err(Refusal::InvalidCert(
            "step 3: runtime certificate is for another PeerId".into(),
        ));
    }
    match policy.allow_hub(&cert.hub_id()) {
        Decision::Allow => Ok(cert),
        Decision::Deny(reason) => Err(Refusal::NotAllowed(cert.hub_id(), reason)),
        Decision::RateLimited { .. } => Err(Refusal::NotAllowed(cert.hub_id(), "rate limited")),
    }
}

/// Element 1 of the certificate body, `[version, hub_root_pubkey, ...]`.
fn claimed_hub_root(cert: &[u8]) -> Result<VerifyingKey, String> {
    let bytes = |value: Value| match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err("expected a byte string".to_owned()),
    };
    let array = |value: Value| match value {
        Value::Array(items) => Ok(items),
        _ => Err("expected an array".to_owned()),
    };
    let decode = |input: &[u8]| {
        ciborium::from_reader::<Value, _>(input).map_err(|err| format!("malformed CBOR: {err}"))
    };
    let mut signed = array(decode(cert)?)?;
    if signed.len() != 2 {
        return Err("expected [tbs, sig]".into());
    }
    let tbs = bytes(signed.swap_remove(0))?;
    let mut body = array(decode(&tbs)?)?;
    if body.len() < 2 {
        return Err("certificate body too short".into());
    }
    let hub_root = bytes(body.swap_remove(1))?;
    parse_public_key(&hub_root).map_err(|err| err.to_string())
}

/// A PeerId bound to a hub_id by a valid `Hello`.
#[derive(Debug, Clone)]
pub(crate) struct Binding {
    pub hub_id: HubId,
    /// The certificate's `not_after`, Unix milliseconds.
    pub not_after: u64,
}

/// Last PeerId and addresses seen for a hub (resolution step 2, §3.5).
#[derive(Debug, Clone)]
pub(crate) struct Known {
    pub peer: PeerId,
    pub addrs: Vec<Multiaddr>,
}

/// One established connection.
#[derive(Debug, Clone)]
pub(crate) struct Connection {
    pub id: ConnectionId,
    pub remote: Multiaddr,
    /// This hub dialed it, so `remote` is a reachable address of the peer.
    pub dialer: bool,
}

/// Transport state shared by the swarm driver and the [`super::Transport`]
/// handle.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub runtime_cert: Vec<u8>,
    pub runtime_not_after: u64,
    /// Addresses advertised in `Hello` and the locator.
    pub advertised: Vec<Multiaddr>,
    pub bindings: HashMap<PeerId, Binding>,
    pub hubs: HashMap<HubId, PeerId>,
    pub known: HashMap<HubId, Known>,
    pub connections: HashMap<PeerId, Vec<Connection>>,
    /// Addresses that answered for another hub, with the time they become
    /// usable again.
    pub bad_addrs: HashMap<Multiaddr, std::time::Instant>,
}

impl State {
    /// The hub `peer` is bound to, if the binding is unexpired and the
    /// policy still admits the hub.
    pub fn bound_hub(
        &self,
        peer: &PeerId,
        now_ms: u64,
        policy: &dyn FederationPolicy,
    ) -> Option<HubId> {
        let binding = self.bindings.get(peer)?;
        (binding.not_after > now_ms && policy.allow_hub(&binding.hub_id) == Decision::Allow)
            .then(|| binding.hub_id.clone())
    }

    /// The PeerId bound to `hub_id`, if it is connected and still bound.
    pub fn bound_connected_peer(
        &self,
        hub_id: &HubId,
        now_ms: u64,
        policy: &dyn FederationPolicy,
    ) -> Option<PeerId> {
        let peer = self.hubs.get(hub_id)?;
        (self.connections.contains_key(peer)
            && self.bound_hub(peer, now_ms, policy).as_ref() == Some(hub_id))
        .then_some(*peer)
    }

    pub fn is_bad(&self, addr: &Multiaddr, now: std::time::Instant) -> bool {
        self.bad_addrs.get(addr).is_some_and(|until| *until > now)
    }
}

#[cfg(test)]
mod tests {
    use gim_hub_identity::SigningKey;

    use super::*;

    const NOW: u64 = 1_792_000_000_000;

    struct AllowAll;

    impl FederationPolicy for AllowAll {
        fn psk(&self) -> Option<crate::config::Psk> {
            None
        }
        fn allow_hub(&self, _: &HubId) -> Decision {
            Decision::Allow
        }
        fn admit(&self, _: &HubId, _: crate::policy::OpKind) -> Decision {
            Decision::Allow
        }
        fn may_contact(&self, _: &HubId) -> bool {
            true
        }
        fn static_addrs(&self, _: &HubId) -> Vec<Multiaddr> {
            Vec::new()
        }
    }

    fn peer_of(runtime: &SigningKey) -> PeerId {
        PeerId::from_bytes(&gim_hub_identity::libp2p_peer_id(&runtime.verifying_key())).unwrap()
    }

    #[test]
    fn verifies_each_step_in_order() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let runtime = SigningKey::from_bytes(&[2; 32]);
        let cert = HubRuntimeCert::issue(&root, &runtime.verifying_key(), NOW - 10, NOW + 10);
        let peer = peer_of(&runtime);

        let ok = verify_peer_cert(&cert, &peer, NOW, &AllowAll).unwrap();
        assert_eq!(ok.hub_id(), HubId::from_root_pubkey(&root.verifying_key()));

        let step = |result: Result<HubRuntimeCert, Refusal>| match result {
            Err(Refusal::InvalidCert(msg)) => msg[..6].to_owned(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            step(verify_peer_cert(b"junk", &peer, NOW, &AllowAll)),
            "step 1"
        );
        assert_eq!(
            step(verify_peer_cert(&cert, &peer, NOW + 10, &AllowAll)),
            "step 2"
        );
        let mut tampered = cert.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            step(verify_peer_cert(&tampered, &peer, NOW, &AllowAll)),
            "step 2"
        );
        let other_peer = peer_of(&SigningKey::from_bytes(&[3; 32]));
        assert_eq!(
            step(verify_peer_cert(&cert, &other_peer, NOW, &AllowAll)),
            "step 3"
        );
    }

    #[test]
    fn refuses_hubs_the_policy_denies() {
        struct DenyAll;
        impl FederationPolicy for DenyAll {
            fn psk(&self) -> Option<crate::config::Psk> {
                None
            }
            fn allow_hub(&self, _: &HubId) -> Decision {
                Decision::Deny("hub not allowlisted")
            }
            fn admit(&self, _: &HubId, _: crate::policy::OpKind) -> Decision {
                Decision::Allow
            }
            fn may_contact(&self, _: &HubId) -> bool {
                false
            }
            fn static_addrs(&self, _: &HubId) -> Vec<Multiaddr> {
                Vec::new()
            }
        }
        let root = SigningKey::from_bytes(&[1; 32]);
        let runtime = SigningKey::from_bytes(&[2; 32]);
        let cert = HubRuntimeCert::issue(&root, &runtime.verifying_key(), NOW - 10, NOW + 10);
        assert_eq!(
            verify_peer_cert(&cert, &peer_of(&runtime), NOW, &DenyAll).unwrap_err(),
            Refusal::NotAllowed(
                HubId::from_root_pubkey(&root.verifying_key()),
                "hub not allowlisted"
            )
        );
    }
}
