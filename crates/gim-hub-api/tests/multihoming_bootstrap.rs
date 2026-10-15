//! Bootstrap of a hub newly listed for a user across in-process hubs on
//! 127.0.0.1 (real libp2p transport, ephemeral ports): `SeedReplica` from
//! the owners, `CopyPendingWelcomes` from co-hosts, and `DeliverWelcome` /
//! `Deliver` to every listed hub of a member (docs/multihoming.md §2.2,
//! §4.3, §4.4).

mod mls_support;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use gim_hub_api::{
    handlers::{
        register_claim_op, register_device_list_ops, register_group_ops, register_hosting_record_op,
    },
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::{groups, hosting as store, DbError};
use gim_hub_identity::{HostingRecord, HubId};
use gim_hub_proto::s2s::{
    s2s_request::Op, CopyPendingWelcomesRequest, ErrorCode, GroupSnapshot, Member, PendingWelcome,
    S2sRequest, S2sResponse, SeedReplicaRequest,
};
use gim_hub_s2s::{
    hosting::testing::sign_record, ops::hosting_record::HostingRecordService, AllowlistPolicy,
    ClaimService, Federation, FederationConfig, FederationService, GroupService, GroupSource,
    Multiaddr, Outbox, OutboxConfig, OutboxSource,
};
use openmls::prelude::{
    tls_codec::Deserialize, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, ProcessedMessageContent, StagedWelcome, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use mls_support::{
    b64, device_list, encode, group_path, key, put_device_list, send, unb64, user_id, Client,
};

const DAY: i64 = 24 * 60 * 60 * 1000;

type Ops = (
    Arc<ClaimService>,
    Arc<GroupService>,
    Arc<HostingRecordService>,
);

/// A hub with a running federation service, outbox and op handlers.
struct Node {
    seed: u8,
    hub: TestHub,
    service: FederationService,
    policy: Arc<AllowlistPolicy>,
    dir: TempDir,
    outbox: Outbox,
    _ops: Ops,
}

impl Node {
    /// Hub with root key seed `[seed; 32]`, allowing no peer yet.
    async fn start(seed: u8) -> Self {
        let mut hub = TestHub::with_hub_seed([seed; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist");
        // An allowlist must not be empty: start with an unrelated hub.
        let placeholder = HubId::from_root_pubkey(&key(200).verifying_key());
        std::fs::write(&path, format!("{placeholder}\n")).unwrap();
        let policy = Arc::new(AllowlistPolicy::load(&path, hub.state.hub.hub_id(), None).unwrap());
        let config = FederationConfig {
            enabled: true,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap()],
            s2s_timeout: Duration::from_secs(3),
            ..FederationConfig::disabled(dir.path())
        };
        let service =
            FederationService::start(&config, hub.state.hub.signing_key(), policy.clone())
                .await
                .unwrap();
        let (outbox, ops) = wire(&mut hub, &service);
        Self {
            seed,
            hub,
            service,
            policy,
            dir,
            outbox,
            _ops: ops,
        }
    }

    fn id(&self) -> HubId {
        self.hub.state.hub.hub_id().clone()
    }

    /// Allows `peers` with their addresses.
    fn allow(&self, peers: &[&Node]) {
        let mut text = String::new();
        for peer in peers {
            text.push_str(peer.id().as_str());
            for addr in peer.service.transport().advertised_addrs() {
                text.push(' ');
                text.push_str(&addr.to_string());
            }
            text.push('\n');
        }
        std::fs::write(self.dir.path().join("allowlist"), text).unwrap();
        self.policy.reload().unwrap();
        self.service.transport().policy_changed();
    }

    /// Sends `op` from this hub to `to`.
    async fn send_op(&self, to: &Node, op: Op) -> S2sResponse {
        let request = S2sRequest {
            request_id: "r".into(),
            op: Some(op),
        };
        self.service.send(&to.id(), request).await.unwrap()
    }

    /// `(last_seq, replica_from_seq)` of the replica of `gid`.
    async fn replica(&self, gid: &str) -> Option<(u64, u64)> {
        let gid = gid.to_owned();
        self.hub
            .state
            .db
            .read(move |conn| {
                let group = groups::get(conn, &gid)?;
                let replica = groups::replica(conn, &gid)?;
                Ok::<_, DbError>(group.zip(replica).map(|(g, r)| (g.last_seq, r.from_seq)))
            })
            .await
            .unwrap()
    }

    /// Stored `seq` of the record of `user_id`.
    async fn record_seq(&self, user_id: &str) -> Option<i64> {
        let user_id = user_id.to_owned();
        self.hub
            .state
            .db
            .read(move |conn| store::get(conn, &user_id))
            .await
            .unwrap()
            .map(|row| row.seq)
    }

    /// Pending Welcome rows of `user_id` (all devices, acknowledged or not).
    async fn welcome_rows(&self, user_id: &str) -> i64 {
        let user_id = user_id.to_owned();
        self.hub
            .state
            .db
            .read(move |conn| {
                Ok::<_, DbError>(conn.query_row(
                    "SELECT COUNT(*) FROM pending_welcomes WHERE user_id = ?1",
                    [&user_id],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap()
    }
}

/// Wires `service` into the hub as `main.rs` does.
fn wire(hub: &mut TestHub, service: &FederationService) -> (Outbox, Ops) {
    hub.set_federation(Arc::new(service.clone()));
    hub.state.hosting.register(service);
    let config = OutboxConfig {
        ttl: Duration::from_secs(3600),
        max_entries_per_peer: 1000,
        max_bytes_per_peer: 1 << 24,
        backoff_max: Duration::from_millis(500),
        sweep_interval: Duration::from_secs(60),
    };
    let outbox = Outbox::new(
        hub.state.db.clone(),
        Arc::new(service.clone()),
        Arc::new(GroupSource::new(hub.state.hub.hub_id().clone())),
        config,
    );
    outbox.start(Some(service.transport().subscribe()));
    hub.state.outbox = Arc::new(outbox.clone());
    register_device_list_ops(&hub.state, service);
    let ops = (
        register_claim_op(&hub.state, service),
        register_group_ops(&hub.state, service),
        register_hosting_record_op(&hub.state, service),
    );
    (outbox, ops)
}

impl Drop for Node {
    fn drop(&mut self) {
        self.outbox.shutdown();
        self.service.shutdown();
    }
}

/// Hubs with root seeds `seeds`, all allowing each other.
async fn cluster(seeds: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    for seed in seeds {
        nodes.push(Node::start(*seed).await);
    }
    for node in &nodes {
        let peers: Vec<&Node> = nodes.iter().filter(|n| n.seed != node.seed).collect();
        node.allow(&peers);
    }
    nodes
}

/// A record (20 days) of the user with root seed `root_seed` listing the
/// hubs `(hub seed, priority)`.
fn record(root_seed: u8, seq: u64, hubs: &[(u8, u8)]) -> Vec<u8> {
    let keys: Vec<_> = hubs.iter().map(|(seed, _)| key(*seed)).collect();
    let entries: Vec<_> = keys
        .iter()
        .zip(hubs)
        .map(|(key, (_, priority))| (key, *priority))
        .collect();
    let expires_at = u64::try_from(TEST_NOW + 20 * DAY).unwrap();
    sign_record(&key(root_seed), seq, expires_at, &entries)
}

/// Client `PUT .../hosting-record` of `record` on `node`.
async fn put_record(node: &Node, root_seed: u8, record: &[u8]) {
    let (status, body) = send(
        &node.hub,
        Method::PUT,
        &format!("/v2/users/{}/hosting-record", user_id(root_seed)),
        "",
        Some(json!({ "hosting_record": b64(record) })),
    )
    .await;
    assert!(status.is_success(), "{body}");
}

/// Uploads `record` on `home` and caches it on every other node.
async fn host(nodes: &[Node], root_seed: u8, record: &[u8], home: &Node) {
    put_record(home, root_seed, record).await;
    let verified = HostingRecord::verify_claimed(record, 0).unwrap();
    for node in nodes.iter().filter(|node| node.seed != home.seed) {
        let stored =
            gim_hub_s2s::hosting::stored_record(&verified, false, node.hub.state.clock.now_ms())
                .unwrap();
        node.hub
            .state
            .db
            .write(move |tx| store::put(tx, &stored))
            .await
            .unwrap();
    }
}

/// Polls `check` every 25 ms for up to 15 s.
async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..600 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Waits until `client`'s device has at least `count` events of
/// `event_type` on `hub` and returns them.
async fn wait_events(client: &Client, hub: &TestHub, event_type: &str, count: usize) -> Vec<Value> {
    eventually(&format!("{count} {event_type} event(s)"), || async {
        client.events_of(hub, event_type).await.len() >= count
    })
    .await;
    client.events_of(hub, event_type).await
}

/// Waits for the `message` event with `seq` of `client`'s device on `hub`.
async fn wait_message(client: &Client, hub: &TestHub, seq: u64) -> Value {
    eventually(&format!("message seq {seq}"), || async {
        client
            .events_of(hub, "message")
            .await
            .iter()
            .any(|event| event["seq"] == seq)
    })
    .await;
    client
        .events_of(hub, "message")
        .await
        .into_iter()
        .find(|event| event["seq"] == seq)
        .unwrap()
}

/// Joins the MLS group from a `welcome` event.
fn join(client: &Client, welcome: &Value) -> MlsGroup {
    let message = MlsMessageIn::tls_deserialize_exact(unb64(&welcome["welcome"])).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    StagedWelcome::new_from_welcome(&client.provider, &config, welcome, None)
        .unwrap()
        .into_group(&client.provider)
        .unwrap()
}

/// The plaintext of an application `message` event.
fn decrypt(client: &Client, group: &mut MlsGroup, event: &Value) -> Vec<u8> {
    let message = MlsMessageIn::tls_deserialize_exact(unb64(&event["mls_message"])).unwrap();
    let processed = group
        .process_message(
            &client.provider,
            message.try_into_protocol_message().unwrap(),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        _ => panic!("not an application message"),
    }
}

/// Submits a Commit adding `recipients` with their Welcome.
async fn commit_add(
    owner: &Node,
    sender: &Client,
    gid: &str,
    client_id: &str,
    (commit, welcome): (&MlsMessageOut, &MlsMessageOut),
    recipients: &[&Client],
) -> Value {
    let body = json!({
        "client_id": client_id,
        "mls_message": encode(commit),
        "welcome": encode(welcome),
        "welcome_recipients": recipients
            .iter()
            .map(|c| json!({ "user_id": c.user_id, "device_id": c.device_id }))
            .collect::<Vec<_>>(),
    });
    let (status, result) = sender.submit_commit(&owner.hub, gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    result
}

/// Sends an application message; returns its seq.
async fn post_message(
    owner: &Node,
    sender: &Client,
    group: &mut MlsGroup,
    gid: &str,
    text: &str,
) -> u64 {
    let mls = group
        .create_message(&sender.provider, &sender.signer, text.as_bytes())
        .unwrap()
        .to_bytes()
        .unwrap();
    let (status, message) = send(
        &owner.hub,
        Method::POST,
        &format!("{}/messages", group_path(gid)),
        &sender.token,
        Some(json!({ "client_id": text, "mls_message": b64(&mls) })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{message}");
    message["seq"].as_u64().unwrap()
}

/// `GET /v2/welcomes/pending` of the device behind `token`.
async fn pending(node: &Node, token: &str) -> Vec<Value> {
    let (status, body) = send(&node.hub, Method::GET, "/v2/welcomes/pending", token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["welcomes"].as_array().unwrap().clone()
}

fn error_code(response: &S2sResponse) -> Option<ErrorCode> {
    response.error.as_ref().map(|error| error.code())
}

/// alice on A is in G (owned by C, with an unacknowledged Welcome) and in H
/// (owned by A) and adds hub B: both owners seed B's replicas at their
/// current seq, A copies the pending Welcome, later messages and Welcomes
/// reach A and B with no gap.
#[tokio::test]
async fn added_hub_is_seeded_and_receives_welcomes_and_messages() {
    let nodes = cluster(&[101, 102, 103]).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let alice = Client::new(&a.hub, 1, 11).await;
    alice.upload_key_packages(&a.hub, 1).await;
    let bob = Client::new(&c.hub, 2, 21).await;
    host(&nodes, 1, &record(1, 1, &[(101, 0)]), a).await;
    host(&nodes, 2, &record(2, 1, &[(103, 0)]), c).await;

    // G on C: bob adds alice (seq 1), then sends one message (seq 2).
    let (g, mut bob_g) = bob.create_group(&c.hub).await;
    let kp = bob.claim(&c.hub, &alice).await;
    let (commit, welcome, _) = bob_g
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    commit_add(c, &bob, &g, "c1", (&commit, &welcome), &[&alice]).await;
    bob_g.merge_pending_commit(&bob.provider).unwrap();
    let mut alice_g = join(&alice, &wait_events(&alice, &a.hub, "welcome", 1).await[0]);
    assert_eq!(post_message(c, &bob, &mut bob_g, &g, "m2").await, 2);
    wait_message(&alice, &a.hub, 2).await;
    // H on A with alice only.
    let (h, _) = alice.create_group(&a.hub).await;
    assert_eq!(b.replica(&g).await, None);

    // alice adds B (§4.1): DeviceList and session on B, record seq 2 on B,
    // then on A. C learns it through NotifyHostingRecord from A.
    let (status, body) =
        put_device_list(&b.hub, &alice.user_id, &device_list(1, 1, &[11], &[])).await;
    assert!(status.is_success(), "{body}");
    let alice_b = b.hub.create_session(&alice.user_id, &alice.device_id).await;
    let record2 = record(1, 2, &[(101, 0), (102, 1)]);
    put_record(b, 1, &record2).await;
    put_record(a, 1, &record2).await;

    // Seeds from C (remote record) and A (local record), after the
    // current seq; no events on B for them.
    eventually("seeded replicas on B", || async {
        b.replica(&g).await == Some((2, 3)) && b.replica(&h).await == Some((0, 1))
    })
    .await;
    assert_eq!(c.record_seq(&alice.user_id).await, Some(2));
    for event_type in ["message", "group.member_added"] {
        assert!(alice.events_of(&b.hub, event_type).await.is_empty());
    }

    // The pending Welcome is copied to B; acknowledged there independently.
    let copied = wait_events(&alice, &b.hub, "welcome", 1).await;
    assert_eq!(copied[0]["gid"], json!(g));
    assert_eq!(copied[0]["seq"], 1);
    let on_a = pending(a, &alice.token).await;
    let on_b = pending(b, &alice_b).await;
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_b[0]["welcome"], on_a[0]["welcome"]);
    let (status, _) = send(
        &b.hub,
        Method::POST,
        &format!("/v2/welcomes/{}/ack", urlencoding(&g)),
        &alice_b,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(pending(b, &alice_b).await.is_empty());
    assert_eq!(pending(a, &alice.token).await.len(), 1);

    // Later messages reach both of alice's hubs; B's log starts at seq 3.
    assert_eq!(post_message(c, &bob, &mut bob_g, &g, "m3").await, 3);
    let on_b = wait_message(&alice, &b.hub, 3).await;
    let on_a = wait_message(&alice, &a.hub, 3).await;
    assert_eq!(on_a["message_id"], on_b["message_id"]);
    assert_eq!(decrypt(&alice, &mut alice_g, &on_b), b"m3");
    assert_eq!(b.replica(&g).await, Some((3, 3)));
    let (status, log) = send(
        &b.hub,
        Method::GET,
        &format!("{}/messages?from_seq=3&limit=10", group_path(&g)),
        &alice_b,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{log}");
    assert_eq!(log["messages"].as_array().unwrap().len(), 1);

    // A new device of alice (on A and B) is added by bob: the Welcome goes
    // to both listed hubs (§2.2), the Commit to alice's device on both.
    let list2 = device_list(1, 2, &[11, 12], &[]);
    for node in [a, b] {
        let (status, body) = put_device_list(&node.hub, &alice.user_id, &list2).await;
        assert!(status.is_success(), "{body}");
    }
    let alice2 = Client::signed_in(&a.hub, 1, 12).await;
    alice2.upload_key_packages(&a.hub, 1).await;
    let kp = bob.claim(&c.hub, &alice2).await;
    let (commit, welcome, _) = bob_g
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let result = commit_add(c, &bob, &g, "c4", (&commit, &welcome), &[&alice2]).await;
    assert_eq!(result["seq"], 4);
    for node in [a, b] {
        let welcomes = wait_events(&alice2, &node.hub, "welcome", 1).await;
        assert_eq!((welcomes.len(), &welcomes[0]["seq"]), (1, &json!(4)));
        wait_message(&alice, &node.hub, 4).await;
    }
    eventually("seq 4 on B", || async {
        b.replica(&g).await == Some((4, 3))
    })
    .await;

    // Replays are no-ops: a stale seed for a live replica, a second copy.
    let stale = SeedReplicaRequest {
        gid: g.clone(),
        user_id: alice.user_id.clone(),
        group: Some(GroupSnapshot {
            kind: "group".into(),
            epoch: 1,
            seq: 1,
            members: vec![Member {
                user_id: alice.user_id.clone(),
                device_id: alice.device_id.clone(),
            }],
            ..Default::default()
        }),
    };
    let response = c.send_op(b, Op::SeedReplica(stale)).await;
    assert_eq!(error_code(&response), None, "{response:?}");
    assert_eq!(b.replica(&g).await, Some((4, 3)));
    let rows = b.welcome_rows(&alice.user_id).await;
    let (source, user, peer) = (GroupSource::new(a.id()), alice.user_id.clone(), b.id());
    let copy = a
        .hub
        .state
        .db
        .read(move |conn| source.pending_welcomes(conn, &user, &peer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(copy.welcomes.len(), 2);
    let response = a.send_op(b, Op::CopyPendingWelcomes(copy)).await;
    assert_eq!(error_code(&response), None, "{response:?}");
    assert_eq!(b.welcome_rows(&alice.user_id).await, rows);
}

/// `SeedReplica` only from the gid owner, for a hosted user in the roster;
/// `CopyPendingWelcomes` only from a hub listed for the user; both
/// idempotent.
#[tokio::test]
async fn bootstrap_ops_are_authorized_and_idempotent() {
    let nodes = cluster(&[101, 102, 103]).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // alice is hosted on A and B; carol has no user on B.
    let alice = Client::new(&b.hub, 1, 11).await;
    put_record(b, 1, &record(1, 1, &[(101, 0), (102, 1)])).await;
    let gid = format!("{}/seedtest", a.id());
    let seed = |user_id: &str, members: &[&str]| {
        Op::SeedReplica(SeedReplicaRequest {
            gid: gid.clone(),
            user_id: user_id.to_owned(),
            group: Some(GroupSnapshot {
                kind: "group".into(),
                created_by_user_id: alice.user_id.clone(),
                created_by_device_id: alice.device_id.clone(),
                created_at: 1,
                epoch: 3,
                seq: 7,
                members: members
                    .iter()
                    .map(|user_id| Member {
                        user_id: (*user_id).to_owned(),
                        device_id: alice.device_id.clone(),
                    })
                    .collect(),
            }),
        })
    };
    let carol = user_id(3);

    // Not the owner; user not in the roster; user not hosted here.
    let response = c.send_op(b, seed(&alice.user_id, &[&alice.user_id])).await;
    assert_eq!(error_code(&response), Some(ErrorCode::Unauthorized));
    let response = a.send_op(b, seed(&alice.user_id, &[&carol])).await;
    assert_eq!(error_code(&response), Some(ErrorCode::Invalid));
    let response = a.send_op(b, seed(&carol, &[&carol])).await;
    assert_eq!(error_code(&response), Some(ErrorCode::NotFound));
    assert_eq!(b.replica(&gid).await, None);

    // The owner seeds; a replay keeps the replica.
    for _ in 0..2 {
        let response = a.send_op(b, seed(&alice.user_id, &[&alice.user_id])).await;
        assert_eq!(error_code(&response), None, "{response:?}");
        assert_eq!(b.replica(&gid).await, Some((7, 8)));
    }
    let (status, group) = send(&b.hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(
        (group["epoch"].clone(), group["last_seq"].clone()),
        (json!(3), json!(7))
    );
    assert!(alice.events(&b.hub).await.is_empty());

    let payload = json!({ "gid": gid, "seq": 5, "epoch": 2, "welcome": "AA==" }).to_string();
    let copy = |user_id: &str| {
        Op::CopyPendingWelcomes(CopyPendingWelcomesRequest {
            user_id: user_id.to_owned(),
            welcomes: vec![
                PendingWelcome {
                    device_id: alice.device_id.clone(),
                    gid: gid.clone(),
                    message_id: "m1".into(),
                    payload_json: payload.clone(),
                    created_at: 1,
                },
                // Unknown device and a payload that is not an object: skipped.
                PendingWelcome {
                    device_id: "unknown".into(),
                    gid: gid.clone(),
                    message_id: "m1".into(),
                    payload_json: payload.clone(),
                    created_at: 1,
                },
                PendingWelcome {
                    device_id: alice.device_id.clone(),
                    gid: gid.clone(),
                    message_id: "m2".into(),
                    payload_json: "[]".into(),
                    created_at: 1,
                },
            ],
        })
    };
    // C is not listed for alice; carol is not hosted on B.
    let response = c.send_op(b, copy(&alice.user_id)).await;
    assert_eq!(error_code(&response), Some(ErrorCode::Unauthorized));
    let response = a.send_op(b, copy(&carol)).await;
    assert_eq!(error_code(&response), Some(ErrorCode::NotFound));
    for _ in 0..2 {
        let response = a.send_op(b, copy(&alice.user_id)).await;
        assert_eq!(error_code(&response), None, "{response:?}");
        assert_eq!(b.welcome_rows(&alice.user_id).await, 1);
    }
    let listed = pending(b, &alice.token).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["seq"], 5);
    assert_eq!(alice.events_of(&b.hub, "welcome").await.len(), 1);
}

/// `gid` percent-encoded for a path segment.
fn urlencoding(gid: &str) -> String {
    gid.replace('/', "%2F")
}
