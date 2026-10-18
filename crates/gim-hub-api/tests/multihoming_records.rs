//! Multi-homing hosting records across in-process hubs on 127.0.0.1 (real
//! libp2p transport, ephemeral ports): `NotifyHostingRecord` propagation to
//! co-hosts and owners, `hosting_record.updated`, DeviceLists to co-hosts,
//! the removed state with its write gate and purge, and re-adding a hub
//! (docs/multihoming.md §3.2, §4.2, §4.5, §7.3).

mod mls_support;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::http::{Method, StatusCode};
use gim_hub_api::{
    handlers::{
        purge_removed_users, register_claim_op, register_device_list_ops, register_group_ops,
        register_hosting_record_op,
    },
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::{groups, hosting as store, users, DbError, Transaction};
use gim_hub_identity::{HostingRecord, HubId};
use gim_hub_proto::s2s::{
    s2s_request::Op, ErrorCode, NotifyHostingRecordRequest, S2sRequest, S2sResponse,
};
use gim_hub_s2s::{
    hosting::{testing::sign_record, HubSetChange, HubSetHook},
    ops::hosting_record::HostingRecordService,
    AllowlistPolicy, ClaimService, Federation, FederationConfig, FederationService, GroupService,
    GroupSource, Multiaddr, Outbox, OutboxConfig,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use mls_support::{
    b64, code, device_list, group_path, key, put_device_list, send, user_id, Client,
};

const HOUR: i64 = 60 * 60 * 1000;
const DAY: i64 = 24 * HOUR;
const UPDATED: &str = "hosting_record.updated";

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
    addr: Multiaddr,
    _ops: Ops,
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
    /// Hub with root key seed `[seed; 32]`, allowing no peer yet.
    async fn start(seed: u8) -> Self {
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
        let (outbox, ops) = wire(&mut hub, &service);
        let addr = service.transport().advertised_addrs()[0].clone();
        Self {
            seed,
            hub,
            service,
            policy,
            dir,
            outbox,
            addr,
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

    /// Starts federation again on the same address, as after a restart.
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
        let (outbox, ops) = wire(&mut self.hub, &service);
        self.service = service;
        self.outbox = outbox;
        self._ops = ops;
    }

    /// Sends `NotifyHostingRecord` for `record` of the user with root seed
    /// `root_seed` from this hub to `to`.
    async fn notify(&self, to: &Node, root_seed: u8, record: &[u8]) -> S2sResponse {
        let request = S2sRequest {
            request_id: "r".into(),
            op: Some(Op::NotifyHostingRecord(NotifyHostingRecordRequest {
                user_id: user_id(root_seed),
                hosting_record_cbor: record.to_vec(),
            })),
        };
        self.service.send(&to.id(), request).await.unwrap()
    }

    /// The stored record of `user_id`: `(seq, hosted, removed_at)`.
    async fn stored(&self, user_id: &str) -> Option<(i64, bool, Option<i64>)> {
        let user_id = user_id.to_owned();
        self.hub
            .state
            .db
            .read(move |conn| {
                let removed_at = store::removed_at(conn, &user_id)?;
                Ok::<_, DbError>(
                    store::get(conn, &user_id)?.map(|row| (row.seq, row.hosted, removed_at)),
                )
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
        self.stop();
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
async fn put_record(node: &Node, root_seed: u8, record: &[u8]) -> (StatusCode, Value) {
    send(
        &node.hub,
        Method::PUT,
        &format!("/v2/users/{}/hosting-record", user_id(root_seed)),
        "",
        Some(json!({ "hosting_record": b64(record) })),
    )
    .await
}

/// Stores `record` as a cached remote record on `node`.
async fn cache_record(node: &Node, record: &[u8]) {
    let record = HostingRecord::verify_claimed(record, 0).unwrap();
    let stored =
        gim_hub_s2s::hosting::stored_record(&record, false, node.hub.state.clock.now_ms()).unwrap();
    node.hub
        .state
        .db
        .write(move |tx| store::put(tx, &stored))
        .await
        .unwrap();
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

/// Waits until `node` stores the record `seq` of `user_id`.
async fn wait_seq(node: &Node, user_id: &str, seq: i64) {
    eventually(
        &format!("record seq {seq} on hub {}", node.seed),
        || async {
            node.stored(user_id)
                .await
                .is_some_and(|(stored, ..)| stored == seq)
        },
    )
    .await;
}

/// Hub-set changes seen by a [`HubSetHook`]: `(user_id, added, removed,
/// local, hosted)`.
#[derive(Default)]
struct Recorder(Mutex<Vec<Change>>);

type Change = (String, Vec<String>, Vec<String>, bool, bool);

impl HubSetHook for Recorder {
    fn hub_set_changed(
        &self,
        _: &Transaction<'_>,
        change: &HubSetChange<'_>,
    ) -> Result<(), DbError> {
        let ids = |hubs: &[HubId]| hubs.iter().map(ToString::to_string).collect();
        self.0.lock().unwrap().push((
            change.user_id.to_owned(),
            ids(change.added),
            ids(change.removed),
            change.local,
            change.hosted,
        ));
        Ok(())
    }
}

/// Stores the group `gid` with `members` (user, device) in its roster on
/// `node` (the owner, or a hub holding a replica).
async fn store_group(node: &Node, gid: &str, members: &[&Client]) {
    let members: Vec<(String, String)> = members
        .iter()
        .map(|c| (c.user_id.clone(), c.device_id.clone()))
        .collect();
    let id = gid.to_owned();
    node.hub
        .state
        .db
        .write(move |tx| {
            groups::create(
                tx,
                &groups::Group {
                    gid: id.clone(),
                    kind: "group".into(),
                    epoch: 1,
                    last_seq: 1,
                    created_by_user_id: members[0].0.clone(),
                    created_by_device_id: members[0].1.clone(),
                    created_at: TEST_NOW,
                },
            )?;
            // The creator is the first member.
            for (leaf, (user, device)) in (1..).zip(&members[1..]) {
                groups::add_member(tx, &id, user, device, leaf, TEST_NOW)?;
            }
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn records_propagate_to_co_hosts_and_owners() {
    let nodes = cluster(&[101, 102, 103]).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // alice (root 1) has a user on A and B; carol (root 3) is on C, which
    // owns a group with both.
    let alice_a = Client::new(&a.hub, 1, 11).await;
    let alice_b = Client::new(&b.hub, 1, 11).await;
    let carol = Client::new(&c.hub, 3, 31).await;
    let gid = format!("{}/g1", c.id());
    for node in [a, c] {
        store_group(node, &gid, &[&carol, &alice_a]).await;
    }
    let seq1 = record(1, 1, &[(101, 0)]);
    for node in [a, b] {
        let (status, body) = put_record(node, 1, &seq1).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    cache_record(c, &seq1).await;
    let (owner_hook, co_host_hook) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    c.hub.state.hosting.set_hub_set_hook(owner_hook.clone());
    b.hub.state.hosting.set_hub_set_hook(co_host_hook.clone());

    // alice adds B, uploading the record to A only.
    let seq2 = record(1, 2, &[(101, 0), (102, 1)]);
    let (status, body) = put_record(a, 1, &seq2).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    wait_seq(b, &alice_a.user_id, 2).await;
    wait_seq(c, &alice_a.user_id, 2).await;
    assert_eq!(b.stored(&alice_a.user_id).await, Some((2, true, None)));
    // The owner caches it as a remote record.
    assert_eq!(c.stored(&alice_a.user_id).await, Some((2, false, None)));

    // Each hub tells alice's device about the new hub list once.
    let hubs = json!([
        { "hub_id": a.id().to_string(), "priority": 0 },
        { "hub_id": b.id().to_string(), "priority": 1 },
    ]);
    let mut hubs_sorted = hubs.as_array().unwrap().clone();
    hubs_sorted.sort_by_key(|hub| hub["hub_id"].as_str().unwrap().to_owned());
    for (node, client) in [(a, &alice_a), (b, &alice_b)] {
        let events = client.events_of(&node.hub, UPDATED).await;
        assert_eq!(events.len(), 1, "{events:?}");
        let mut listed = events[0]["hubs"].as_array().unwrap().clone();
        listed.sort_by_key(|hub| hub["hub_id"].as_str().unwrap().to_owned());
        assert_eq!(listed, hubs_sorted);
        assert_eq!(events[0]["seq"], json!(2));
        assert_eq!(events[0]["hosted"], json!(true));
        assert_eq!(events[0]["user_id"], json!(alice_a.user_id));
    }
    // The hub-set hook ran on the owner (remote user) and the co-host.
    let added = vec![b.id().to_string()];
    assert_eq!(
        *owner_hook.0.lock().unwrap(),
        [(alice_a.user_id.clone(), added.clone(), vec![], false, false)]
    );
    assert_eq!(
        *co_host_hook.0.lock().unwrap(),
        [(alice_a.user_id.clone(), added, vec![], true, true)]
    );

    // Resends and stale records are no-ops answered {}.
    for (from, to, record) in [(a, c, &seq2), (b, a, &seq2), (a, b, &seq1)] {
        let response = from.notify(to, 1, record).await;
        assert!(response.error.is_none(), "{:?}", response.error);
    }
    // A record from a hub listed in neither the record nor the stored one
    // is refused; garbage is invalid.
    let seq3 = record(1, 3, &[(101, 0)]);
    let response = c.notify(b, 1, &seq3).await;
    assert_eq!(response.error.unwrap().code(), ErrorCode::Unauthorized);
    let response = a.notify(b, 1, b"garbage").await;
    assert_eq!(response.error.unwrap().code(), ErrorCode::Invalid);
    // A renewal with the same entries is stored but neither propagated nor
    // announced.
    let renewal = record(1, 3, &[(101, 0), (102, 1)]);
    let (status, _) = put_record(a, 1, &renewal).await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(b.stored(&alice_a.user_id).await.unwrap().0, 2);
    assert_eq!(alice_a.events_of(&a.hub, UPDATED).await.len(), 1);
    assert_eq!(alice_b.events_of(&b.hub, UPDATED).await.len(), 1);
    assert_eq!(owner_hook.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn device_lists_reach_co_hosts() {
    let nodes = cluster(&[101, 102]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    Client::new(&a.hub, 1, 11).await;
    Client::new(&b.hub, 1, 11).await;
    let both = record(1, 1, &[(101, 0), (102, 1)]);
    for node in [a, b] {
        assert_eq!(put_record(node, 1, &both).await.0, StatusCode::CREATED);
    }

    // A device linked on A appears on B and can sign in there.
    let list = device_list(1, 2, &[11, 12], &[]);
    let (status, body) = put_device_list(&a.hub, &user_id(1), &list).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let db = b.hub.state.db.clone();
    eventually("the DeviceList on B to reach seq 2", || {
        let db = db.clone();
        async move {
            db.read(|conn| users::get_device_list(conn, &user_id(1)))
                .await
                .unwrap()
                .is_some_and(|list| list.seq == 2)
        }
    })
    .await;
    let active = b
        .hub
        .state
        .db
        .read(|conn| users::active_device_ids(conn, &user_id(1)))
        .await
        .unwrap();
    assert!(active.contains(&mls_support::device_id(12)), "{active:?}");
}

#[tokio::test]
async fn removed_hub_refuses_writes_then_purges_and_can_be_listed_again() {
    let nodes = cluster(&[101, 102]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice_a = Client::new(&a.hub, 1, 11).await;
    let alice = Client::new(&b.hub, 1, 11).await;
    let both = record(1, 1, &[(101, 0), (102, 1)]);
    for node in [a, b] {
        assert_eq!(put_record(node, 1, &both).await.0, StatusCode::CREATED);
    }
    alice.upload_key_packages(&b.hub, 2).await;
    let send_b = |method: Method, path: String, body: Option<Value>| {
        let token = alice.token.clone();
        let hub = &b.hub;
        async move { send(hub, method, &path, &token, body).await }
    };

    // alice removes B with a PUT to A only: A tells B.
    let only_a = record(1, 2, &[(101, 0)]);
    assert_eq!(put_record(a, 1, &only_a).await.0, StatusCode::OK);
    wait_seq(b, &alice.user_id, 2).await;
    let (_, hosted, removed_at) = b.stored(&alice.user_id).await.unwrap();
    assert!(!hosted);
    assert_eq!(removed_at, Some(TEST_NOW));
    let events = alice.events_of(&b.hub, UPDATED).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["hosted"], json!(false));
    assert_eq!(alice_a.events_of(&a.hub, UPDATED).await.len(), 1);

    // Writes are refused...
    let gid = format!("{}/g1", a.id());
    for (method, path, body) in [
        (
            Method::POST,
            "/v2/keypackages".to_owned(),
            json!({ "key_packages": [b64(&alice.key_package())] }),
        ),
        (
            Method::POST,
            "/v2/groups".to_owned(),
            json!({ "kind": "group" }),
        ),
        (
            Method::POST,
            "/v2/keypackages/claim".to_owned(),
            json!({ "targets": [{ "user_id": alice.user_id }] }),
        ),
    ] {
        let (status, body) = send_b(method, path.clone(), Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert_eq!(code(&body), "hosting_record_required", "{path}");
    }
    // ...reads and acks are served; the unclaimed KeyPackages are gone.
    for path in [
        "/v2/me",
        "/v2/events",
        "/v2/welcomes/pending",
        "/v2/keypackages/count",
    ] {
        let (status, body) = send_b(Method::GET, path.into(), None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    let (_, count) = send_b(Method::GET, "/v2/keypackages/count".into(), None).await;
    assert_eq!(count["available"], json!(0));
    let (status, body) = send_b(Method::POST, format!("{}/ack", group_ack(&gid)), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // DeviceList uploads still land.
    let list = device_list(1, 2, &[11, 12], &[]);
    let (status, body) = put_device_list(&b.hub, &alice.user_id, &list).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Listing B again ends the removal.
    let again = record(1, 3, &[(101, 0), (102, 1)]);
    assert_eq!(put_record(b, 1, &again).await.0, StatusCode::OK);
    assert_eq!(b.stored(&alice.user_id).await, Some((3, true, None)));
    alice.upload_key_packages(&b.hub, 1).await;
    wait_seq(a, &alice.user_id, 3).await;

    // Removed again, the data is purged after the grace period; the
    // record stays as a tombstone.
    let removed = record(1, 4, &[(101, 0)]);
    assert_eq!(put_record(b, 1, &removed).await.0, StatusCode::OK);
    let grace = i64::from(b.hub.state.config.load().unhosted_grace_hours) * HOUR;
    let is_local = || {
        let (db, user) = (b.hub.state.db.clone(), alice.user_id.clone());
        async move {
            db.read(move |conn| store::is_local(conn, &user))
                .await
                .unwrap()
        }
    };
    b.hub.state.clock.advance(grace - 1);
    assert_eq!(purge_removed_users(&b.hub.state).await.unwrap(), 0);
    assert!(is_local().await);
    b.hub.state.clock.advance(1);
    assert_eq!(purge_removed_users(&b.hub.state).await.unwrap(), 1);
    assert!(!is_local().await);
    let (status, _) = send_b(Method::GET, "/v2/me".into(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        b.stored(&alice.user_id).await,
        Some((4, false, Some(TEST_NOW)))
    );
    // A replay of an older record listing B is still ordered by the tombstone.
    let response = a.notify(b, 1, &again).await;
    assert!(response.error.is_none());
    assert_eq!(b.stored(&alice.user_id).await.unwrap().0, 4);
}

/// `/v2/welcomes/{gid}` for `gid`.
fn group_ack(gid: &str) -> String {
    group_path(gid).replacen("/v2/groups/", "/v2/welcomes/", 1)
}

#[tokio::test]
async fn removal_notice_waits_in_the_outbox_while_the_hub_is_down() {
    let mut nodes = cluster(&[101, 102]).await;
    Client::new(&nodes[0].hub, 1, 11).await;
    Client::new(&nodes[1].hub, 1, 11).await;
    let both = record(1, 1, &[(101, 0), (102, 1)]);
    for node in &nodes {
        assert_eq!(put_record(node, 1, &both).await.0, StatusCode::CREATED);
    }

    // B is down while alice removes it with a PUT to A only.
    nodes[1].stop();
    let only_a = record(1, 2, &[(101, 0)]);
    assert_eq!(put_record(&nodes[0], 1, &only_a).await.0, StatusCode::OK);
    let (db, peer) = (nodes[0].hub.state.db.clone(), nodes[1].id().to_string());
    let queued = db
        .read(move |conn| gim_hub_db::outbox::head(conn, &peer, 0, 10))
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].kind, gim_hub_db::outbox::Kind::HostingRecord);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(nodes[1].stored(&user_id(1)).await.unwrap().0, 1);

    // B comes back and enters the removed state.
    nodes[1].restart().await;
    wait_seq(&nodes[1], &user_id(1), 2).await;
    let (_, hosted, removed_at) = nodes[1].stored(&user_id(1)).await.unwrap();
    assert!(!hosted && removed_at.is_some());
    let peer = nodes[1].id().to_string();
    eventually("A's outbox for B to drain", || {
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
}
