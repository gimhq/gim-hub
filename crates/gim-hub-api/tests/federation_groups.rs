//! Group federation across in-process hubs on 127.0.0.1 (real libp2p
//! transport, ephemeral ports): Commits and messages of remote members on
//! the owning hub, forwarding from member hubs, replicas, `Deliver`,
//! `DeliverWelcome`, `FetchLog` gap fill and refusals
//! (docs/federation.md §5.3, §5.4, §6.2-§6.7).

mod mls_support;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use gim_hub_api::{
    handlers::{register_claim_op, register_device_list_ops, register_group_ops},
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::groups;
use gim_hub_identity::{HostingRecord, HubId};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, ErrorCode, MessageKind, S2sRequest,
    SequencedMessage, SubmitMessageRequest, SubmitMessageResponse,
};
use gim_hub_s2s::{
    hosting::testing::sign_record, AllowlistPolicy, BoxFuture, ClaimService, Federation,
    FederationConfig, FederationService, GroupService, GroupSource, Multiaddr, OpKind, OpResult,
    Outbox, OutboxConfig,
};
use openmls::prelude::{
    tls_codec::Deserialize, GroupId, LeafNodeIndex, LeafNodeParameters, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProcessedMessageContent, StagedWelcome, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use mls_support::{
    b64, capabilities, code, encode, group_path, key, send, unb64, Client, CIPHERSUITE,
    GIM_CREDENTIAL,
};

const DAY: i64 = 24 * 60 * 60 * 1000;

/// A hub with a running federation service, outbox and op handlers.
struct Node {
    seed: u8,
    hub: TestHub,
    service: FederationService,
    policy: Arc<AllowlistPolicy>,
    dir: TempDir,
    outbox: Outbox,
    max_entries: u64,
    /// The address the hub listens on.
    addr: Multiaddr,
    _ops: (Arc<ClaimService>, Arc<GroupService>),
}

fn federation_config(dir: &TempDir, listen: Multiaddr) -> FederationConfig {
    FederationConfig {
        enabled: true,
        listen: vec![listen],
        s2s_timeout: Duration::from_secs(3),
        ..FederationConfig::disabled(dir.path())
    }
}

impl Node {
    /// Hub with root key seed `[seed; 32]`, allowing no peer yet; its outbox
    /// keeps at most `max_entries` entries per peer.
    async fn start(seed: u8, max_entries: u64) -> Self {
        let mut hub = TestHub::with_hub_seed([seed; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist");
        // An allowlist must not be empty: start with an unrelated hub.
        let placeholder = HubId::from_root_pubkey(&key(200).verifying_key());
        std::fs::write(&path, format!("{placeholder}\n")).unwrap();
        let policy = Arc::new(AllowlistPolicy::load(&path, hub.state.hub.hub_id(), None).unwrap());
        let config = federation_config(&dir, "/ip4/127.0.0.1/tcp/0".parse().unwrap());
        let service =
            FederationService::start(&config, hub.state.hub.signing_key(), policy.clone())
                .await
                .unwrap();
        let (outbox, ops) = wire(&mut hub, &service, max_entries);
        let addr = service.transport().advertised_addrs()[0].clone();
        Self {
            addr,
            seed,
            hub,
            service,
            policy,
            dir,
            outbox,
            max_entries,
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

    /// Stops the hub's federation (transport, outbox).
    fn stop(&self) {
        self.outbox.shutdown();
        self.service.shutdown();
    }

    /// Starts federation again on the same address with the same runtime
    /// key, as after a restart of the hub process.
    async fn restart(&mut self) {
        let config = federation_config(&self.dir, self.addr.clone());
        let mut attempts = 0;
        let service = loop {
            match FederationService::start(
                &config,
                self.hub.state.hub.signing_key(),
                self.policy.clone(),
            )
            .await
            {
                Ok(service) => break service,
                Err(_) if attempts < 50 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => panic!("restart failed: {err}"),
            }
        };
        let (outbox, ops) = wire(&mut self.hub, &service, self.max_entries);
        self.service = service;
        self.outbox = outbox;
        self._ops = ops;
    }
}

/// Wires `service` into the hub as `main.rs` does: S2S sends, hosting, the
/// outbox with the group source, and the identity and group ops.
fn wire(
    hub: &mut TestHub,
    service: &FederationService,
    max_entries: u64,
) -> (Outbox, (Arc<ClaimService>, Arc<GroupService>)) {
    hub.set_federation(Arc::new(service.clone()));
    hub.state.hosting.register(service);
    let config = OutboxConfig {
        ttl: Duration::from_secs(3600),
        max_entries_per_peer: max_entries,
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
    );
    (outbox, ops)
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Hubs with root seeds `seeds`, all allowing each other.
async fn cluster(seeds: &[u8], max_entries: u64) -> Vec<Node> {
    let mut nodes = Vec::new();
    for seed in seeds {
        nodes.push(Node::start(*seed, max_entries).await);
    }
    for node in &nodes {
        let peers: Vec<&Node> = nodes.iter().filter(|n| n.seed != node.seed).collect();
        node.allow(&peers);
    }
    nodes
}

/// The hosting record (seq 1, 7 days) of the user with root seed
/// `root_seed`, listing the hub with root seed `hub_seed`.
fn hosting_record(root_seed: u8, hub_seed: u8) -> Vec<u8> {
    let expires_at = u64::try_from(TEST_NOW + 7 * DAY).unwrap();
    sign_record(&key(root_seed), 1, expires_at, &[(&key(hub_seed), 0)])
}

/// Publishes the hosting record of the user with root seed `root_seed` on
/// its hub `home` and caches it on every other node (there is no DHT here).
async fn host(nodes: &[&Node], root_seed: u8, home: &Node) {
    let record = hosting_record(root_seed, home.seed);
    let (status, body) = send(
        &home.hub,
        Method::PUT,
        &format!(
            "/v2/users/{}/hosting-record",
            mls_support::user_id(root_seed)
        ),
        "",
        Some(json!({ "hosting_record": b64(&record) })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["hosted"], json!(true));
    for node in nodes.iter().filter(|node| node.seed != home.seed) {
        let verified = HostingRecord::verify_claimed(&record, 0).unwrap();
        let stored =
            gim_hub_s2s::hosting::stored_record(&verified, false, node.hub.state.clock.now_ms())
                .unwrap();
        node.hub
            .state
            .db
            .write(move |tx| gim_hub_db::hosting::put(tx, &stored))
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

/// Waits until `client` has at least `count` events of `event_type` on
/// `hub` and returns them.
async fn wait_events(client: &Client, hub: &TestHub, event_type: &str, count: usize) -> Vec<Value> {
    eventually(&format!("{count} {event_type} event(s)"), || async {
        client.events_of(hub, event_type).await.len() >= count
    })
    .await;
    client.events_of(hub, event_type).await
}

/// Creates a group of `kind` on the client's hub and the matching MLS group.
async fn create_group(client: &Client, hub: &TestHub, kind: &str) -> (String, MlsGroup) {
    let (status, body) = send(
        hub,
        Method::POST,
        "/v2/groups",
        &client.token,
        Some(json!({ "kind": kind })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let gid = body["gid"].as_str().unwrap().to_owned();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .capabilities(capabilities(GIM_CREDENTIAL))
        .use_ratchet_tree_extension(true)
        .build();
    let group = MlsGroup::new_with_group_id(
        &client.provider,
        &client.signer,
        &config,
        GroupId::from_slice(gid.as_bytes()),
        client.credential.clone(),
    )
    .unwrap();
    (gid, group)
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

/// Processes a `message` event: merges a Commit, or returns the plaintext of
/// an application message.
fn process(client: &Client, group: &mut MlsGroup, event: &Value) -> Option<Vec<u8>> {
    let message = MlsMessageIn::tls_deserialize_exact(unb64(&event["mls_message"])).unwrap();
    let processed = group
        .process_message(
            &client.provider,
            message.try_into_protocol_message().unwrap(),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => Some(message.into_bytes()),
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&client.provider, *staged)
                .unwrap();
            None
        }
        _ => panic!("unexpected message"),
    }
}

/// Waits for the `message` event with `seq` and processes it.
async fn receive(
    client: &Client,
    hub: &TestHub,
    group: &mut MlsGroup,
    seq: u64,
) -> Option<Vec<u8>> {
    let events = wait_message(client, hub, seq).await;
    process(client, group, &events)
}

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

fn commit_body(client_id: &str, commit: &MlsMessageOut) -> Value {
    json!({ "client_id": client_id, "mls_message": encode(commit) })
}

fn with_welcome(mut body: Value, welcome: &MlsMessageOut, recipients: &[&Client]) -> Value {
    body["welcome"] = json!(encode(welcome));
    body["welcome_recipients"] = recipients
        .iter()
        .map(|c| json!({ "user_id": c.user_id, "device_id": c.device_id }))
        .collect();
    body
}

async fn post_message(
    client: &Client,
    hub: &TestHub,
    gid: &str,
    client_id: &str,
    mls: &[u8],
) -> (StatusCode, Value) {
    send(
        hub,
        Method::POST,
        &format!("{}/messages", group_path(gid)),
        &client.token,
        Some(json!({ "client_id": client_id, "mls_message": b64(mls) })),
    )
    .await
}

fn application(client: &Client, group: &mut MlsGroup, text: &[u8]) -> Vec<u8> {
    group
        .create_message(&client.provider, &client.signer, text)
        .unwrap()
        .to_bytes()
        .unwrap()
}

/// `(seq, client_id, mls_message)` of the group log as seen by `client`.
async fn log(client: &Client, hub: &TestHub, gid: &str) -> Vec<(u64, String, String)> {
    let (status, body) = send(
        hub,
        Method::GET,
        &format!("{}/messages?from_seq=1&limit=500", group_path(gid)),
        &client.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["seq"].as_u64().unwrap(),
                m["client_id"].as_str().unwrap().to_owned(),
                m["mls_message"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn device_ids(group: &Value) -> Vec<String> {
    let mut ids: Vec<String> = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["device_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

fn sorted(ids: &[&str]) -> Vec<String> {
    let mut ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    ids.sort();
    ids
}

fn leaf_of(group: &MlsGroup, client: &Client) -> LeafNodeIndex {
    group
        .members()
        .find(|m| m.signature_key == client.credential.signature_key.as_slice())
        .unwrap()
        .index
}

#[tokio::test]
async fn cross_hub_direct_message() {
    let nodes = cluster(&[101, 102], 1000).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = Client::new(&a.hub, 1, 11).await;
    alice.upload_key_packages(&a.hub, 1).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    host(&[a, b], 1, a).await;
    host(&[a, b], 2, b).await;

    // bob@B creates a direct group on B and adds alice@A.
    let (gid, mut bob_group) = create_group(&bob, &b.hub, "direct").await;
    let kp = bob.claim(&b.hub, &alice).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[&alice]);
    let (status, result) = bob.submit_commit(&b.hub, &gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 1, "epoch": 1, "duplicate": false }));
    bob_group.merge_pending_commit(&bob.provider).unwrap();

    // The Welcome reaches alice on A, then the Commit builds A's replica.
    let welcomes = wait_events(&alice, &a.hub, "welcome", 1).await;
    assert_eq!(welcomes[0]["gid"], json!(gid));
    assert_eq!(welcomes[0]["seq"], 1);
    assert_eq!(welcomes[0]["epoch"], 1);
    assert_eq!(welcomes[0]["sender_user_id"], json!(bob.user_id));
    assert_eq!(welcomes[0]["sender_device_id"], json!(bob.device_id));
    let mut alice_group = join(&alice, &welcomes[0]);
    let added = wait_events(&alice, &a.hub, "group.member_added", 1).await;
    assert_eq!(added, bob.events_of(&b.hub, "group.member_added").await);
    assert_eq!(added[0]["user_id"], json!(alice.user_id));
    let (_, pending) = send(
        &a.hub,
        Method::GET,
        "/v2/welcomes/pending",
        &alice.token,
        None,
    )
    .await;
    assert_eq!(pending["welcomes"][0]["gid"], json!(gid));
    let (status, group) = send(&a.hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(group["kind"], "direct");
    assert_eq!(
        (group["epoch"].clone(), group["last_seq"].clone()),
        (json!(1), json!(1))
    );
    assert_eq!(
        device_ids(&group),
        sorted(&[&alice.device_id, &bob.device_id])
    );

    // Messages in both directions.
    for i in 0..3 {
        let mls = application(&bob, &mut bob_group, format!("b{i}").as_bytes());
        let (status, message) = post_message(&bob, &b.hub, &gid, &format!("b{i}"), &mls).await;
        assert_eq!(status, StatusCode::CREATED, "{message}");
        assert_eq!(message["seq"], 2 + i);
    }
    for i in 0..3u64 {
        let text = receive(&alice, &a.hub, &mut alice_group, 2 + i).await;
        assert_eq!(text.unwrap(), format!("b{i}").into_bytes());
    }
    let mut sent = Vec::new();
    for i in 0..3u64 {
        let mls = application(&alice, &mut alice_group, format!("a{i}").as_bytes());
        let (status, message) = post_message(&alice, &a.hub, &gid, &format!("a{i}"), &mls).await;
        assert_eq!(status, StatusCode::CREATED, "{message}");
        assert_eq!(message["seq"], 5 + i);
        assert_eq!(message["sender_user_id"], json!(alice.user_id));
        sent.push((mls, message));
    }
    for i in 0..3u64 {
        let text = receive(&bob, &b.hub, &mut bob_group, 5 + i).await;
        assert_eq!(text.unwrap(), format!("a{i}").into_bytes());
    }
    // client_id replay on the member hub: 200 with the stored message.
    let (status, replay) = post_message(&alice, &a.hub, &gid, "a0", &sent[0].0).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, sent[0].1);

    // Same log, same seqs, on both hubs; nothing duplicated.
    let on_a = log(&alice, &a.hub, &gid).await;
    assert_eq!(on_a, log(&bob, &b.hub, &gid).await);
    assert_eq!(
        on_a.iter().map(|(seq, ..)| *seq).collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    assert_eq!(alice.events_of(&a.hub, "message").await.len(), 3);
    assert_eq!(bob.events_of(&b.hub, "message").await.len(), 3);

    // The owner is down: submits fail with 503, the replica still serves reads.
    b.stop();
    let mls = application(&alice, &mut alice_group, b"later");
    let (status, body) = post_message(&alice, &a.hub, &gid, "a9", &mls).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(code(&body), "peer_unavailable");
    assert_eq!(log(&alice, &a.hub, &gid).await, on_a);
}

/// The stored message ID of `(gid, seq)` on `hub`.
async fn message_id(hub: &TestHub, gid: &str, seq: i64) -> String {
    let gid = gid.to_owned();
    hub.state
        .db
        .read(move |conn| gim_hub_db::push::message_id_at(conn, &gid, seq))
        .await
        .unwrap()
        .unwrap()
}

/// Events emitted on a member hub by `DeliverWelcome` and `Deliver` push to
/// its local devices, with the owner's message ID as collapse id.
#[tokio::test]
async fn federated_events_push_to_local_devices() {
    let nodes = cluster(&[101, 102], 1000).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = Client::new(&a.hub, 1, 11).await;
    alice.upload_key_packages(&a.hub, 1).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    host(&[a, b], 1, a).await;
    host(&[a, b], 2, b).await;
    let (status, _) = send(
        &a.hub,
        Method::PUT,
        "/v2/push/registration",
        &alice.token,
        Some(json!({ "provider": "log", "token": "alice-log" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // bob@B creates a direct group on B and adds alice@A.
    let (gid, mut bob_group) = create_group(&bob, &b.hub, "direct").await;
    let kp = bob.claim(&b.hub, &alice).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[&alice]);
    let (status, result) = bob.submit_commit(&b.hub, &gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    wait_events(&alice, &a.hub, "welcome", 1).await;
    wait_events(&alice, &a.hub, "group.member_added", 1).await;
    assert_eq!(a.hub.deliver_pushes().await, 1);
    let pushes = a.hub.state.push.log().recent(Some(&alice.device_id));
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].payload["type"], "welcome");
    assert_eq!(pushes[0].payload["gid"], json!(gid));
    assert_eq!(pushes[0].payload["seq"], 1);
    assert!(pushes[0].payload.get("sender_user_id").is_none());
    assert_eq!(
        pushes[0].payload["message_id"],
        json!(message_id(&b.hub, &gid, 1).await)
    );

    // A message sequenced on B reaches A through Deliver and is pushed there.
    let mls = application(&bob, &mut bob_group, b"hi");
    let (status, message) = post_message(&bob, &b.hub, &gid, "m1", &mls).await;
    assert_eq!(status, StatusCode::CREATED, "{message}");
    let event = wait_message(&alice, &a.hub, 2).await;
    assert_eq!(a.hub.deliver_pushes().await, 1);
    let push = a.hub.state.push.log().recent(None).pop().unwrap();
    let owner_id = message_id(&b.hub, &gid, 2).await;
    assert_eq!(owner_id, message_id(&a.hub, &gid, 2).await);
    // The client Message carries the owner's ID on both hubs.
    assert_eq!(message["message_id"], json!(owner_id));
    assert_eq!(event["message_id"], json!(owner_id));
    for (hub, client) in [(&b.hub, &bob), (&a.hub, &alice)] {
        let (status, body) = send(
            hub,
            Method::GET,
            &format!("{}/messages?from_seq=2", group_path(&gid)),
            &client.token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["messages"][0]["message_id"], json!(owner_id));
    }
    assert_eq!(
        push.payload,
        json!({
            "v": 1,
            "type": "message",
            "gid": gid,
            "seq": 2,
            "message_id": owner_id,
            "collapse_id": owner_id,
            "mls_message": message["mls_message"],
        })
    );
    // Nothing is pushed for the sender's own device or on the owner hub.
    assert_eq!(b.hub.deliver_pushes().await, 0);
}

#[tokio::test]
async fn three_hubs_add_remove_and_concurrent_commits() {
    let nodes = cluster(&[101, 102, 103], 1000).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let all = [a, b, c];
    let alice = Client::new(&a.hub, 1, 11).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    let carol = Client::new(&c.hub, 3, 31).await;
    let dave = Client::new(&c.hub, 4, 41).await;
    for (client, home, root) in [(&bob, b, 2), (&carol, c, 3), (&dave, c, 4)] {
        client.upload_key_packages(&home.hub, 1).await;
        host(&all, root, home).await;
    }
    host(&all, 1, a).await;

    // alice@A creates the group and adds bob@B and carol@C.
    let (gid, mut alice_group) = create_group(&alice, &a.hub, "group").await;
    let kps = vec![
        alice.claim(&a.hub, &bob).await,
        alice.claim(&a.hub, &carol).await,
    ];
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[&bob, &carol]);
    let (status, result) = alice.submit_commit(&a.hub, &gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let mut bob_group = join(&bob, &wait_events(&bob, &b.hub, "welcome", 1).await[0]);
    let mut carol_group = join(&carol, &wait_events(&carol, &c.hub, "welcome", 1).await[0]);
    wait_events(&carol, &c.hub, "group.member_added", 2).await;
    let (_, replica) = send(&c.hub, Method::GET, &group_path(&gid), &carol.token, None).await;
    assert_eq!(
        device_ids(&replica),
        sorted(&[&alice.device_id, &bob.device_id, &carol.device_id])
    );

    // bob@B adds dave@C: B forwards the Commit to A, A learns dave's
    // identity from the KeyPackage credential and fetches his DeviceList.
    let kp = bob.claim(&b.hub, &dave).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c2", &commit), &welcome, &[&dave]);
    let (status, result) = bob.submit_commit(&b.hub, &gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 2, "epoch": 2, "duplicate": false }));
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    receive(&alice, &a.hub, &mut alice_group, 2).await;
    receive(&carol, &c.hub, &mut carol_group, 2).await;
    let mut dave_group = join(&dave, &wait_events(&dave, &c.hub, "welcome", 1).await[0]);
    let dave_added = |events: Vec<Value>| {
        events
            .into_iter()
            .filter(|event| event["user_id"] == json!(dave.user_id))
            .collect::<Vec<_>>()
    };
    let expected = json!({
        "gid": gid, "user_id": dave.user_id, "device_ids": [dave.device_id],
        "by_user_id": bob.user_id, "by_device_id": bob.device_id, "epoch": 2, "seq": 2,
    });
    for (client, node) in [(&alice, a), (&bob, b), (&carol, c), (&dave, c)] {
        eventually("dave's member_added", || async {
            !dave_added(client.events_of(&node.hub, "group.member_added").await).is_empty()
        })
        .await;
        assert_eq!(
            dave_added(client.events_of(&node.hub, "group.member_added").await),
            std::slice::from_ref(&expected)
        );
    }

    // bob@B removes carol@C; C keeps its replica for dave.
    let (commit, _, _) = bob_group
        .remove_members(&bob.provider, &bob.signer, &[leaf_of(&bob_group, &carol)])
        .unwrap();
    let (status, result) = bob
        .submit_commit(&b.hub, &gid, commit_body("c3", &commit))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["seq"], 3);
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    receive(&alice, &a.hub, &mut alice_group, 3).await;
    receive(&dave, &c.hub, &mut dave_group, 3).await;
    // carol receives the removing Commit, then nothing.
    wait_message(&carol, &c.hub, 3).await;
    for (client, node) in [(&alice, a), (&bob, b), (&carol, c), (&dave, c)] {
        let removed = wait_events(client, &node.hub, "group.member_removed", 1).await;
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0]["user_id"], json!(carol.user_id));
        assert_eq!(removed[0]["device_ids"], json!([carol.device_id]));
        assert_eq!(removed[0]["seq"], 3);
    }
    let (_, replica) = send(&c.hub, Method::GET, &group_path(&gid), &dave.token, None).await;
    assert_eq!(
        device_ids(&replica),
        sorted(&[&alice.device_id, &bob.device_id, &dave.device_id])
    );
    let (status, body) = send(&c.hub, Method::GET, &group_path(&gid), &carol.token, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "not_member");

    // Concurrent Commits from B and C for epoch 3: exactly one wins.
    let bob_commit = bob_group
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();
    let dave_commit = dave_group
        .self_update(&dave.provider, &dave.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();
    let (bob_body, dave_body) = (
        commit_body("u1", &bob_commit),
        commit_body("u1", &dave_commit),
    );
    let (bob_result, dave_result) = tokio::join!(
        bob.submit_commit(&b.hub, &gid, bob_body.clone()),
        dave.submit_commit(&c.hub, &gid, dave_body.clone()),
    );
    let mut statuses = [bob_result.0, dave_result.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::CONFLICT],
        "{bob_result:?} {dave_result:?}"
    );
    let (winner, hub, body, (_, won), (_, lost)) = if bob_result.0 == StatusCode::CREATED {
        (&bob, &b.hub, bob_body, bob_result, dave_result)
    } else {
        (&dave, &c.hub, dave_body, dave_result, bob_result)
    };
    assert_eq!(won, json!({ "seq": 4, "epoch": 4, "duplicate": false }));
    assert_eq!(code(&lost), "stale_epoch");
    assert_eq!(lost["current_epoch"], 4);
    // Resubmitting the winner through its member hub is a duplicate.
    let (status, again) = winner.submit_commit(hub, &gid, body).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again, json!({ "seq": 4, "epoch": 4, "duplicate": true }));

    // Every hub holds the same log from its join point.
    let on_a = log(&alice, &a.hub, &gid).await;
    assert_eq!(on_a.len(), 4);
    let db = c.hub.state.db.clone();
    let key = gid.clone();
    eventually("C's replica to reach seq 4", || {
        let (db, key) = (db.clone(), key.clone());
        async move {
            db.read(move |conn| groups::get(conn, &key))
                .await
                .unwrap()
                .is_some_and(|group| group.last_seq == 4)
        }
    })
    .await;
    assert_eq!(log(&bob, &b.hub, &gid).await, on_a);
    assert_eq!(log(&dave, &c.hub, &gid).await, on_a);
}

#[tokio::test]
async fn peer_outage_is_filled_from_the_outbox_and_the_log() {
    // A queues at most 5 entries per peer, so most of the backlog for C is
    // evicted and C has to fetch it with FetchLog.
    let mut nodes = cluster(&[101, 103], 5).await;
    let alice = Client::new(&nodes[0].hub, 1, 11).await;
    let carol = Client::new(&nodes[1].hub, 3, 31).await;
    carol.upload_key_packages(&nodes[1].hub, 1).await;
    {
        let all = [&nodes[0], &nodes[1]];
        host(&all, 1, &nodes[0]).await;
        host(&all, 3, &nodes[1]).await;
    }
    let (a, c) = (&nodes[0], &nodes[1]);
    let (gid, mut alice_group) = create_group(&alice, &a.hub, "group").await;
    let kp = alice.claim(&a.hub, &carol).await;
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[&carol]);
    let (status, result) = alice.submit_commit(&a.hub, &gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let mut carol_group = join(&carol, &wait_events(&carol, &c.hub, "welcome", 1).await[0]);
    wait_events(&carol, &c.hub, "group.member_added", 1).await;

    // C goes down while A sequences 20 messages.
    nodes[1].stop();
    let a = &nodes[0];
    for i in 0..20u64 {
        let mls = application(&alice, &mut alice_group, format!("m{i}").as_bytes());
        let (status, message) = post_message(&alice, &a.hub, &gid, &format!("m{i}"), &mls).await;
        assert_eq!(status, StatusCode::CREATED, "{message}");
        assert_eq!(message["seq"], 2 + i);
    }

    // The backlog for C overflowed the cap: the evicted messages can only
    // come from C's FetchLog.
    let c_id = nodes[1].id();
    assert!(
        nodes[0]
            .outbox
            .dropped_total(&c_id, gim_hub_s2s::outbox::DropReason::Evicted)
            > 0
    );

    // C comes back: the outbox, the resync nudge and FetchLog fill the gap.
    nodes[1].restart().await;
    let c = &nodes[1];
    for i in 0..20u64 {
        let text = receive(&carol, &c.hub, &mut carol_group, 2 + i).await;
        assert_eq!(text.unwrap(), format!("m{i}").into_bytes());
    }
    let seqs: Vec<u64> = carol
        .events_of(&c.hub, "message")
        .await
        .iter()
        .map(|event| event["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (2..=21).collect::<Vec<_>>());
    assert_eq!(
        log(&carol, &c.hub, &gid).await,
        log(&alice, &nodes[0].hub, &gid).await
    );
    // A's queue for C drains completely.
    let db = nodes[0].hub.state.db.clone();
    let peer = c.id().to_string();
    eventually("A's outbox for C to drain", || {
        let (db, peer) = (db.clone(), peer.clone());
        async move {
            db.read(move |conn| gim_hub_db::outbox::backlog(conn, &peer))
                .await
                .unwrap()
                .entries
                == 0
        }
    })
    .await;
    assert_eq!(carol.events_of(&c.hub, "message").await.len(), 20);
}

#[tokio::test]
async fn submits_from_unlisted_or_unknown_hubs_are_refused() {
    // A and B allow each other; X (104) allows A but A does not allow X.
    let nodes = cluster(&[101, 102], 1000).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let x = Node::start(104, 1000).await;
    x.allow(&[a]);
    let alice = Client::new(&a.hub, 1, 11).await;
    host(&[a, b, &x], 1, a).await;
    let (gid, mut alice_group) = create_group(&alice, &a.hub, "group").await;
    let mls = application(&alice, &mut alice_group, b"hi");

    // B is allowlisted but not listed for alice.
    let request = S2sRequest {
        request_id: "r".into(),
        op: Some(Op::SubmitMessage(SubmitMessageRequest {
            gid: gid.clone(),
            sender_user_id: alice.user_id.clone(),
            sender_device_id: alice.device_id.clone(),
            client_id: "c1".into(),
            mls_message: mls.clone(),
        })),
    };
    let response = b.service.send(&a.id(), request.clone()).await.unwrap();
    assert_eq!(response.error.unwrap().code(), ErrorCode::Unauthorized);
    // X is not allowlisted: A refuses the Hello.
    assert!(matches!(
        x.service.send(&a.id(), request).await,
        Err(gim_hub_s2s::SendError::PeerRefused(_))
    ));

    // eve@X is a member of X's replica of the group: her submit is refused.
    let eve = Client::new(&x.hub, 5, 51).await;
    host(&[&x], 5, &x).await;
    let (key, members) = (
        gid.clone(),
        vec![
            (alice.user_id.clone(), alice.device_id.clone()),
            (eve.user_id.clone(), eve.device_id.clone()),
        ],
    );
    let creator = (alice.user_id.clone(), alice.device_id.clone());
    x.hub
        .state
        .db
        .write(move |tx| {
            groups::create_replica(
                tx,
                &groups::Group {
                    gid: key,
                    kind: "group".into(),
                    epoch: 0,
                    last_seq: 0,
                    created_by_user_id: creator.0,
                    created_by_device_id: creator.1,
                    created_at: TEST_NOW,
                },
                &members,
                TEST_NOW,
            )
        })
        .await
        .unwrap();
    let (status, body) = post_message(&eve, &x.hub, &gid, "e1", &mls).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(code(&body), "peer_refused");
    // Nothing was stored on A.
    let (_, messages) = send(
        &a.hub,
        Method::GET,
        &format!("{}/messages", group_path(&gid)),
        &alice.token,
        None,
    )
    .await;
    assert_eq!(messages["messages"], json!([]));
}

#[tokio::test]
async fn forwarded_submit_answered_with_a_non_application_message_is_refused() {
    let nodes = cluster(&[101, 102], 1000).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = Client::new(&a.hub, 1, 11).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    host(&[a, b], 1, a).await;
    host(&[a, b], 2, b).await;
    let (gid, mut alice_group) = create_group(&alice, &a.hub, "group").await;
    let mls = application(&alice, &mut alice_group, b"hi");

    // B holds a replica listing bob; A answers every submit with a Commit.
    let (key, members) = (
        gid.clone(),
        vec![
            (alice.user_id.clone(), alice.device_id.clone()),
            (bob.user_id.clone(), bob.device_id.clone()),
        ],
    );
    let creator = (alice.user_id.clone(), alice.device_id.clone());
    b.hub
        .state
        .db
        .write(move |tx| {
            groups::create_replica(
                tx,
                &groups::Group {
                    gid: key,
                    kind: "group".into(),
                    epoch: 0,
                    last_seq: 0,
                    created_by_user_id: creator.0,
                    created_by_device_id: creator.1,
                    created_at: TEST_NOW,
                },
                &members,
                TEST_NOW,
            )
        })
        .await
        .unwrap();
    a.service.register(
        OpKind::SubmitMessage,
        Arc::new(|_: HubId, op: Op| -> BoxFuture<'static, OpResult> {
            Box::pin(async move {
                let Op::SubmitMessage(req) = op else {
                    unreachable!()
                };
                Ok(OpOutput::SubmitMessage(SubmitMessageResponse {
                    seq: 1,
                    epoch: 1,
                    duplicate: false,
                    message: Some(SequencedMessage {
                        gid: req.gid,
                        seq: 1,
                        epoch: 1,
                        kind: MessageKind::Commit.into(),
                        sender_user_id: req.sender_user_id,
                        sender_device_id: req.sender_device_id,
                        client_id: req.client_id,
                        payload: req.mls_message,
                        ..Default::default()
                    }),
                }))
            })
        }),
    );

    let (status, body) = post_message(&bob, &b.hub, &gid, "b1", &mls).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(code(&body), "peer_refused");
    assert_eq!(
        body["error"]["message"],
        "owning hub answered with a non-application message"
    );
    assert_eq!(log(&bob, &b.hub, &gid).await, Vec::new());
}
