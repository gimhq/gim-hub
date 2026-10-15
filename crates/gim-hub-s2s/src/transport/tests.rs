//! In-process federation tests: hubs on 127.0.0.1 with ephemeral ports.

use std::{sync::Arc, time::Duration};

use gim_hub_identity::{HubId, HubRuntimeCert, SigningKey};
use gim_hub_proto::{
    s2s::{
        s2s_request::Op, s2s_response::Result as OpOutput, ErrorCode, GetDeviceListRequest,
        GetDeviceListResponse, S2sRequest, S2sResponse, SubmitCommitRequest,
    },
    HUB_RECORD_KEY_PREFIX,
};
use tempfile::TempDir;

use super::*;
use crate::{
    config::{FederationConfig, Psk},
    federation::{BoxFuture, Federation, FederationService, OpResult},
    policy::{AllowlistPolicy, OpKind},
};

const TCP: &str = "/ip4/127.0.0.1/tcp/0";
const QUIC: &str = "/ip4/127.0.0.1/udp/0/quic-v1";

fn root(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hub_id(seed: u8) -> HubId {
    HubId::from_root_pubkey(&root(seed).verifying_key())
}

struct Hub {
    seed: u8,
    dir: TempDir,
    policy: Arc<AllowlistPolicy>,
    service: FederationService,
}

/// Starts hub `seed` listening on `listen`, allowing `allowed` (no
/// addresses yet; see [`Hub::allow`]).
async fn start_hub(seed: u8, allowed: &[u8], listen: &str, psk: Option<Psk>) -> Hub {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowlist");
    let text: String = allowed
        .iter()
        .map(|s| format!("{}\n", hub_id(*s)))
        .collect();
    std::fs::write(&path, text).unwrap();
    let policy = Arc::new(AllowlistPolicy::load(&path, &hub_id(seed), psk).unwrap());
    let config = FederationConfig {
        enabled: true,
        listen: vec![listen.parse().unwrap()],
        s2s_timeout: Duration::from_secs(3),
        psk,
        ..FederationConfig::disabled(dir.path())
    };
    let service = FederationService::start(&config, &root(seed), policy.clone())
        .await
        .unwrap();
    Hub {
        seed,
        dir,
        policy,
        service,
    }
}

impl Hub {
    fn id(&self) -> HubId {
        hub_id(self.seed)
    }

    fn transport(&self) -> &Transport {
        self.service.transport()
    }

    /// Rewrites the allowlist: `(hub, with its static addresses)` pairs,
    /// plus `extra` hub seeds without addresses; reloads it.
    fn allow(&self, hubs: &[(&Hub, bool)], extra: &[u8]) {
        let mut text = String::new();
        for (hub, with_addrs) in hubs {
            text.push_str(hub.id().as_str());
            if *with_addrs {
                for addr in hub.transport().advertised_addrs() {
                    text.push(' ');
                    text.push_str(&addr.to_string());
                }
            }
            text.push('\n');
        }
        for seed in extra {
            text.push_str(&format!("{}\n", hub_id(*seed)));
        }
        std::fs::write(self.dir.path().join("allowlist"), text).unwrap();
        self.policy.reload().unwrap();
        self.transport().policy_changed();
    }

    fn connection_count(&self) -> usize {
        self.transport().shared().state().connections.len()
    }

    /// Answers `GetDeviceList` with `"<caller>:<user_id>"`.
    fn serve_device_lists(&self) {
        self.service.register(
            OpKind::GetDeviceList,
            Arc::new(|caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                Box::pin(async move {
                    let Op::GetDeviceList(req) = op else {
                        unreachable!()
                    };
                    Ok(OpOutput::GetDeviceList(GetDeviceListResponse {
                        device_list_cbor: format!("{caller}:{}", req.user_id).into_bytes(),
                    }))
                })
            }),
        );
    }
}

fn get_device_list(user_id: &str) -> S2sRequest {
    S2sRequest {
        request_id: format!("req-{user_id}"),
        op: Some(Op::GetDeviceList(GetDeviceListRequest {
            user_id: user_id.into(),
        })),
    }
}

fn submit_commit() -> S2sRequest {
    S2sRequest {
        request_id: "commit".into(),
        op: Some(Op::SubmitCommit(SubmitCommitRequest::default())),
    }
}

fn error_code(response: &S2sResponse) -> Option<ErrorCode> {
    response.error.as_ref().map(|e| e.code())
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..150 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlisted_hubs_bind_and_round_trip_over_quic() {
    let a = start_hub(1, &[2], QUIC, None).await;
    let b = start_hub(2, &[1], QUIC, None).await;
    a.allow(&[(&b, true)], &[]);
    b.serve_device_lists();
    let mut b_events = b.transport().subscribe();

    let response = a
        .service
        .send(&b.id(), get_device_list("u1"))
        .await
        .unwrap();
    assert_eq!(response.request_id, "req-u1");
    assert_eq!(
        response.result,
        Some(OpOutput::GetDeviceList(GetDeviceListResponse {
            device_list_cbor: format!("{}:u1", a.id()).into_bytes(),
        }))
    );
    // Ops without a handler are not implemented yet.
    let response = a.service.send(&b.id(), submit_commit()).await.unwrap();
    assert_eq!(error_code(&response), Some(ErrorCode::Internal));
    assert_eq!(response.error.unwrap().message, "not implemented");

    // One Hello bound both directions.
    assert_eq!(a.transport().bound_hubs(), vec![b.id()]);
    assert_eq!(b.transport().bound_hubs(), vec![a.id()]);
    assert_eq!(b_events.recv().await.unwrap(), PeerEvent::Up(a.id()));
    // B reaches A over the existing connection, with no static address.
    let response = b.service.send(&a.id(), submit_commit()).await.unwrap();
    assert_eq!(error_code(&response), Some(ErrorCode::Internal));

    // Policy reload: B no longer allows A, drops the binding and closes.
    b.allow(&[], &[9]);
    eventually("B to unbind A", || b.transport().bound_hubs().is_empty()).await;
    eventually("connections to close", || a.connection_count() == 0).await;
    let err = a
        .service
        .send(&b.id(), get_device_list("u2"))
        .await
        .unwrap_err();
    assert!(matches!(err, SendError::PeerRefused(_)), "{err:?}");
    assert_eq!(
        b.service.send(&a.id(), get_device_list("u3")).await,
        Err(SendError::PeerRefused("hub not allowlisted".into()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_not_on_the_allowlist_is_refused_and_disconnected() {
    let a = start_hub(1, &[2], TCP, None).await;
    let x = start_hub(3, &[1], TCP, None).await;
    x.allow(&[(&a, true)], &[]);

    let err = x
        .service
        .send(&a.id(), get_device_list("u1"))
        .await
        .unwrap_err();
    assert_eq!(err, SendError::PeerRefused("hub not allowlisted".into()));
    eventually("A to close the connection", || {
        a.connection_count() == 0 && x.connection_count() == 0
    })
    .await;
    assert!(a.transport().bound_hubs().is_empty());
    // A denies X's PeerId at connection establishment for a while.
    assert!(x
        .service
        .send(&a.id(), get_device_list("u2"))
        .await
        .is_err());
    assert!(a.transport().bound_hubs().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ops_before_hello_get_hello_required() {
    let a = start_hub(1, &[2], TCP, None).await;
    let b = start_hub(2, &[1], TCP, None).await;
    a.serve_device_lists();
    let addr = a.transport().advertised_addrs()[0].clone();

    let peer = b.transport().dial(None, addr).await.unwrap();
    let response = b
        .transport()
        .raw_request(peer, get_device_list("u1"))
        .await
        .unwrap();
    assert_eq!(error_code(&response), Some(ErrorCode::HelloRequired));
    assert_eq!(response.request_id, "req-u1");
    assert!(a.transport().bound_hubs().is_empty());

    assert_eq!(
        b.transport().hello(peer, Some(a.id())).await.unwrap(),
        a.id()
    );
    let response = b
        .transport()
        .raw_request(peer, get_device_list("u1"))
        .await
        .unwrap();
    assert!(response.result.is_some(), "{response:?}");
}

/// `addr` with its IPv4 host replaced by `/dns4/localhost`, plus
/// `/p2p/<peer>`.
fn dns4_localhost(addr: &Multiaddr, peer: PeerId) -> Multiaddr {
    addr.iter()
        .map(|p| match p {
            libp2p::multiaddr::Protocol::Ip4(_) => {
                libp2p::multiaddr::Protocol::Dns4("localhost".into())
            }
            other => other,
        })
        .chain([libp2p::multiaddr::Protocol::P2p(peer)])
        .collect()
}

fn local_peer_id(hub: &Hub) -> PeerId {
    let cert = hub.transport().shared().state().runtime_cert.clone();
    let cert = HubRuntimeCert::verify(&cert, &root(hub.seed).verifying_key(), now_ms()).unwrap();
    PeerId::from_bytes(&cert.peer_id()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns4_address_is_dialed_and_bound() {
    for psk in [None, Some([7; 32])] {
        let a = start_hub(1, &[2], TCP, psk).await;
        let b = start_hub(2, &[1], TCP, psk).await;
        a.serve_device_lists();
        let addr = dns4_localhost(&a.transport().advertised_addrs()[0], local_peer_id(&a));

        let peer = b
            .transport()
            .dial(Some(local_peer_id(&a)), addr)
            .await
            .unwrap();
        assert_eq!(peer, local_peer_id(&a));
        assert_eq!(
            b.transport().hello(peer, Some(a.id())).await.unwrap(),
            a.id()
        );
        let response = b
            .transport()
            .raw_request(peer, get_device_list("u1"))
            .await
            .unwrap();
        assert!(response.result.is_some(), "{response:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_cert_for_another_peer_id_is_refused() {
    let a = start_hub(1, &[3], TCP, None).await;

    // Hub 3 presents a valid certificate of its root for a different key.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("allowlist"),
        format!("{} {}\n", a.id(), a.transport().advertised_addrs()[0]),
    )
    .unwrap();
    let policy =
        Arc::new(AllowlistPolicy::load(&dir.path().join("allowlist"), &hub_id(3), None).unwrap());
    let other_key = SigningKey::from_bytes(&[42; 32]).verifying_key();
    let now = now_ms();
    let foreign = HubRuntimeCert::issue(&root(3), &other_key, now - 1000, now + 60_000);
    let runtime = RuntimeIdentity::issue(SigningKey::from_bytes(&[41; 32]), &root(3), 30, now)
        .with_cert(foreign);
    let config = TransportConfig {
        listen: vec![TCP.parse().unwrap()],
        external_addrs: Vec::new(),
        bootstrap: Vec::new(),
        timeout: Duration::from_secs(3),
        psk: None,
    };
    let (x, _inbound) = Transport::start(config, hub_id(3), &runtime, policy)
        .await
        .unwrap();

    let err = x.request(&a.id(), get_device_list("u1")).await.unwrap_err();
    match err {
        SendError::PeerRefused(reason) => assert!(reason.starts_with("step 3"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert!(a.transport().bound_hubs().is_empty());
    eventually("A to close the connection", || a.connection_count() == 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn psk_mismatch_prevents_any_connection() {
    let psk: Psk = [7; 32];
    let a = start_hub(1, &[2, 3], TCP, Some(psk)).await;
    let b = start_hub(2, &[1], TCP, Some([8; 32])).await;
    let c = start_hub(3, &[1], TCP, Some(psk)).await;
    a.allow(&[(&b, true), (&c, true)], &[]);

    // Same PSK: TCP behind pnet works.
    let response = a.service.send(&c.id(), submit_commit()).await.unwrap();
    assert_eq!(error_code(&response), Some(ErrorCode::Internal));

    // Different PSK: the pnet handshake fails, nothing reaches B.
    let err = a.service.send(&b.id(), submit_commit()).await.unwrap_err();
    assert!(
        matches!(err, SendError::Unreachable(_) | SendError::Timeout),
        "{err:?}"
    );
    assert!(b.transport().bound_hubs().is_empty());
    assert_eq!(b.connection_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_listen_with_psk_fails_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    std::fs::write(
        &key,
        format!("/key/swarm/psk/1.0.0/\n/base16/\n{}\n", "ab".repeat(32)),
    )
    .unwrap();
    let err = FederationConfig::from_vars(
        [
            ("GIM_HUB_FEDERATION".to_owned(), "true".to_owned()),
            ("GIM_HUB_P2P_LISTEN".to_owned(), QUIC.to_owned()),
            ("GIM_HUB_P2P_PSK_FILE".to_owned(), key.display().to_string()),
        ],
        dir.path(),
    )
    .unwrap_err();
    assert_eq!(err.name, "GIM_HUB_P2P_LISTEN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_locator_publish_and_lookup_between_three_hubs() {
    let a = start_hub(1, &[2, 3], TCP, None).await;
    let b = start_hub(2, &[1, 3], TCP, None).await;
    let c = start_hub(3, &[1, 2], TCP, None).await;
    // Only B's address is configured anywhere; A is found via the DHT.
    a.allow(&[(&b, true)], &[3]);
    c.allow(&[(&b, true)], &[1]);

    a.transport().bootstrap().await;
    assert_eq!(a.transport().bound_hubs(), vec![b.id()]);
    a.transport().publish_locator().await.unwrap();
    c.transport().bootstrap().await;
    assert_eq!(c.transport().bound_hubs(), vec![b.id()]);

    let key = format!("{HUB_RECORD_KEY_PREFIX}{}", a.id());
    let values = c.transport().dht_get(&key, 3).await.unwrap();
    assert_eq!(values.len(), 1);
    let locator = records::decode_locator(&key, &values[0], now_ms()).unwrap();
    assert_eq!(locator.cert.hub_id(), a.id());
    assert_eq!(locator.addrs, a.transport().advertised_addrs());

    // C resolves A through its locator, dials, binds and round-trips.
    let response = c.service.send(&a.id(), submit_commit()).await.unwrap();
    assert_eq!(error_code(&response), Some(ErrorCode::Internal));
    assert!(c.transport().bound_hubs().contains(&a.id()));
    assert!(a.transport().bound_hubs().contains(&c.id()));

    // An unknown key prefix is never stored.
    let _ = a
        .transport()
        .dht_put("/other/key", b"v".to_vec(), None)
        .await;
    assert!(b
        .transport()
        .dht_get("/other/key", 1)
        .await
        .unwrap()
        .is_empty());
}
