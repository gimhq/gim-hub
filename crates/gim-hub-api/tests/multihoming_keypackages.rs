//! Multi-homed KeyPackages across in-process hubs on 127.0.0.1 (real libp2p
//! transport, ephemeral ports): claim routing over the listed hubs with
//! fallback and per-device follow-up, routing of local users not hosted
//! here, `duplicate_key_package`, burns and `kp_not_claimed`
//! (docs/multihoming.md §5.2-§5.4).

mod mls_support;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use gim_hub_api::{
    handlers::{register_claim_op, register_device_list_ops},
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::DbError;
use gim_hub_identity::{HostingRecord, HubId};
use gim_hub_s2s::{
    hosting::testing::sign_record, AllowlistPolicy, ClaimService, FederationConfig,
    FederationService,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use mls_support::{b64, code, device_list, encode, key, put_device_list, send, user_id, Client};

const DAY: i64 = 24 * 60 * 60 * 1000;

/// A hub with a running federation service and the identity ops.
struct Node {
    seed: u8,
    hub: TestHub,
    service: FederationService,
    policy: Arc<AllowlistPolicy>,
    dir: TempDir,
    _claims: Arc<ClaimService>,
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
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            s2s_timeout: Duration::from_secs(3),
            ..FederationConfig::disabled(dir.path())
        };
        let service =
            FederationService::start(&config, hub.state.hub.signing_key(), policy.clone())
                .await
                .unwrap();
        hub.set_federation(Arc::new(service.clone()));
        hub.state.hosting.register(&service);
        register_device_list_ops(&hub.state, &service);
        let claims = register_claim_op(&hub.state, &service);
        Self {
            seed,
            hub,
            service,
            policy,
            dir,
            _claims: claims,
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

    /// Stops the hub's federation: it no longer answers S2S requests.
    fn stop(&self) {
        self.service.shutdown();
    }

    /// Stores `record` as freshly fetched, without the upload path (no DHT
    /// here; for a local user this also bypasses the hosting handler).
    async fn store_record(&self, record: &[u8]) {
        let record = HostingRecord::verify_claimed(record, 0).unwrap();
        let hosted = record.entry(&self.id()).is_some();
        let stored =
            gim_hub_s2s::hosting::stored_record(&record, hosted, self.hub.state.clock.now_ms())
                .unwrap();
        self.hub
            .state
            .db
            .write(move |tx| gim_hub_db::hosting::put(tx, &stored))
            .await
            .unwrap();
    }

    /// Uploads `record` (listing this hub) through the client API.
    async fn put_record(&self, root_seed: u8, record: &[u8]) {
        let (status, body) = send(
            &self.hub,
            Method::PUT,
            &format!("/v2/users/{}/hosting-record", user_id(root_seed)),
            "",
            Some(json!({ "hosting_record": b64(record) })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["hosted"], json!(true));
    }

    /// `(available, has_last_resort)` of a device's stock.
    async fn stock(&self, client: &Client) -> (u64, bool) {
        let (status, body) = send(
            &self.hub,
            Method::GET,
            "/v2/keypackages/count",
            &client.token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["available"].as_u64().unwrap(),
            body["has_last_resort"].as_bool().unwrap(),
        )
    }

    /// `(user_id, device_id, target_hub_id)` of the brokered claims.
    async fn ledger(&self) -> Vec<(String, String, String)> {
        self.hub
            .state
            .db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT user_id, device_id, target_hub_id FROM remote_kp_claims \
                     ORDER BY claimed_at, device_id",
                )?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DbError>(rows)
            })
            .await
            .unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
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

/// The hosting record (seq 1, 7 days) of the user with root seed
/// `root_seed`, listing the hubs `(hub_seed, priority)`.
fn record(root_seed: u8, hubs: &[(u8, u8)]) -> Vec<u8> {
    let expires_at = u64::try_from(TEST_NOW + 7 * DAY).unwrap();
    let keys: Vec<_> = hubs.iter().map(|(seed, _)| key(*seed)).collect();
    let entries: Vec<_> = keys
        .iter()
        .zip(hubs)
        .map(|(key, (_, priority))| (key, *priority))
        .collect();
    sign_record(&key(root_seed), 1, expires_at, &entries)
}

async fn claim(node: &Node, client: &Client, targets: Value) -> (StatusCode, Value) {
    send(
        &node.hub,
        Method::POST,
        "/v2/keypackages/claim",
        &client.token,
        Some(json!({ "targets": targets })),
    )
    .await
}

async fn upload(node: &Node, client: &Client, packages: &[&[u8]]) -> (StatusCode, Value) {
    let packages: Vec<String> = packages.iter().map(|kp| b64(kp)).collect();
    send(
        &node.hub,
        Method::POST,
        "/v2/keypackages",
        &client.token,
        Some(json!({ "key_packages": packages })),
    )
    .await
}

/// `(device_id, last_resort)` of the claimed packages.
fn claimed(body: &Value) -> Vec<(String, bool)> {
    body["key_packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|kp| {
            (
                kp["device_id"].as_str().unwrap().to_owned(),
                kp["last_resort"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn fallback_hub_serves_the_claim_when_the_primary_is_down() {
    let nodes = cluster(&[101, 102, 103]).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // alice (root 1) on A (primary) and B, one disjoint package on each;
    // bob (root 2) on C.
    let alice_record = record(1, &[(101, 0), (102, 1)]);
    let alice_a = Client::new(&a.hub, 1, 11).await;
    let alice_b = Client::new(&b.hub, 1, 11).await;
    alice_a.upload_key_packages(&a.hub, 1).await;
    alice_b.upload_key_packages(&b.hub, 1).await;
    a.put_record(1, &alice_record).await;
    b.put_record(1, &alice_record).await;
    let bob = Client::new(&c.hub, 2, 21).await;
    c.put_record(2, &record(2, &[(103, 0)])).await;
    c.store_record(&alice_record).await;

    // The primary serves the claim.
    let target = json!([{ "user_id": alice_a.user_id }]);
    let (status, body) = claim(c, &bob, target.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(claimed(&body), [(alice_a.device_id.clone(), false)]);
    assert_eq!(a.stock(&alice_a).await, (0, false));
    assert_eq!(b.stock(&alice_b).await, (1, false));

    // Primary down: the fallback serves a package from its own set.
    a.stop();
    let (status, body) = claim(c, &bob, target.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(claimed(&body), [(alice_a.device_id.clone(), false)]);
    assert_eq!(body["unavailable"], json!([]));
    assert_eq!(b.stock(&alice_b).await, (0, false));
    let user = alice_a.user_id.clone();
    let device = alice_a.device_id.clone();
    assert_eq!(
        c.ledger().await,
        [
            (user.clone(), device.clone(), a.id().to_string()),
            (user.clone(), device.clone(), b.id().to_string()),
        ]
    );

    // Primary down, fallback without packages: unavailable (retryable).
    let (status, body) = claim(c, &bob, target.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_packages"], json!([]));
    assert_eq!(body["missing"], json!([]));
    assert_eq!(body["unavailable"], target);

    // Every listed hub down: unavailable.
    b.stop();
    let (status, body) = claim(c, &bob, target.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_packages"], json!([]));
    assert_eq!(body["unavailable"], target);
}

#[tokio::test]
async fn devices_missing_on_the_answering_hub_are_claimed_from_the_next() {
    let nodes = cluster(&[101, 102, 103]).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // alice's devices 11 and 12; device 12 uploaded to B (secondary) only.
    let alice_record = record(1, &[(101, 0), (102, 1)]);
    let list = device_list(1, 1, &[11, 12], &[]);
    for node in [a, b] {
        let (status, body) = put_device_list(&node.hub, &user_id(1), &list).await;
        assert!(status.is_success(), "{body}");
        node.put_record(1, &alice_record).await;
    }
    let d11_a = Client::signed_in(&a.hub, 1, 11).await;
    let d11_b = Client::signed_in(&b.hub, 1, 11).await;
    let d12_b = Client::signed_in(&b.hub, 1, 12).await;
    d11_a.upload_key_packages(&a.hub, 2).await;
    d11_b.upload_key_packages(&b.hub, 2).await;
    d12_b.upload_key_packages(&b.hub, 2).await;
    let bob = Client::new(&c.hub, 2, 21).await;
    c.put_record(2, &record(2, &[(103, 0)])).await;
    c.store_record(&alice_record).await;

    let (status, body) = claim(c, &bob, json!([{ "user_id": d11_a.user_id }])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut devices = claimed(&body);
    devices.sort();
    let mut expected = vec![
        (d11_a.device_id.clone(), false),
        (d12_b.device_id.clone(), false),
    ];
    expected.sort();
    assert_eq!(devices, expected);
    assert_eq!(body["missing"], json!([]));
    // Device 11 came from A only, device 12 from B.
    assert_eq!(a.stock(&d11_a).await, (1, false));
    assert_eq!(b.stock(&d11_b).await, (2, false));
    assert_eq!(b.stock(&d12_b).await, (1, false));
    let mut ledger = c.ledger().await;
    ledger.sort();
    let mut expected = vec![
        (
            d11_a.user_id.clone(),
            d11_a.device_id.clone(),
            a.id().to_string(),
        ),
        (
            d12_b.user_id.clone(),
            d12_b.device_id.clone(),
            b.id().to_string(),
        ),
    ];
    expected.sort();
    assert_eq!(ledger, expected);
}

#[tokio::test]
async fn local_user_not_hosted_here_is_routed_by_record_and_burned() {
    let nodes = cluster(&[101, 102]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    // alice is local on A and B, but her record lists B only; she (wrongly)
    // uploaded the same package to both.
    let alice_record = record(1, &[(102, 0)]);
    let alice_a = Client::new(&a.hub, 1, 11).await;
    let alice_b = Client::new(&b.hub, 1, 11).await;
    let package = alice_a.key_package();
    assert_eq!(
        upload(a, &alice_a, &[package.as_slice()]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        upload(b, &alice_b, &[package.as_slice()]).await.0,
        StatusCode::OK
    );
    b.put_record(1, &alice_record).await;
    a.store_record(&alice_record).await;
    let bob = Client::new(&a.hub, 2, 21).await;
    a.put_record(2, &record(2, &[(101, 0)])).await;

    // bob@A claims alice from B, not from A's local set.
    let (status, body) = claim(a, &bob, json!([{ "user_id": alice_a.user_id }])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(claimed(&body), [(alice_a.device_id.clone(), false)]);
    assert_eq!(b.stock(&alice_b).await, (0, false));
    assert_eq!(
        a.ledger().await,
        [(
            alice_a.user_id.clone(),
            alice_a.device_id.clone(),
            b.id().to_string()
        )]
    );
    // A's copy of the brokered package is burned.
    assert_eq!(a.stock(&alice_a).await, (0, false));

    // Re-uploading the brokered package to A is rejected as a whole.
    let fresh = alice_a.key_package();
    let (status, body) = upload(a, &alice_a, &[fresh.as_slice(), package.as_slice()]).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(code(&body), "duplicate_key_package");
    assert_eq!(a.stock(&alice_a).await, (0, false));
    assert_eq!(
        upload(a, &alice_a, &[fresh.as_slice()]).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn add_with_a_package_claimed_through_another_hub_is_kp_not_claimed() {
    let nodes = cluster(&[101, 102]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    // alice on A, with a copy of her package (wrongly) uploaded to B too.
    let alice = Client::new(&a.hub, 1, 11).await;
    let alice_b = Client::new(&b.hub, 1, 11).await;
    let package = alice.key_package();
    assert_eq!(
        upload(a, &alice, &[package.as_slice()]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        upload(b, &alice_b, &[package.as_slice()]).await.0,
        StatusCode::OK
    );
    a.put_record(1, &record(1, &[(101, 0)])).await;
    b.store_record(&record(1, &[(101, 0)])).await;
    // bob on A and B claims alice through A, then commits through B.
    let bob_record = record(2, &[(101, 0), (102, 1)]);
    let bob_a = Client::new(&a.hub, 2, 21).await;
    let bob_b = Client::new(&b.hub, 2, 21).await;
    a.put_record(2, &bob_record).await;
    b.put_record(2, &bob_record).await;
    let kp = bob_a.claim(&a.hub, &alice).await;

    let (gid, mut group) = bob_b.create_group(&b.hub).await;
    let (commit, welcome, _) = group
        .add_members(&bob_b.provider, &bob_b.signer, &[kp])
        .unwrap();
    let body = json!({
        "client_id": "c1",
        "mls_message": encode(&commit),
        "welcome": encode(&welcome),
        "welcome_recipients": [{ "user_id": alice.user_id, "device_id": alice.device_id }],
    });
    let (status, result) = bob_b.submit_commit(&b.hub, &gid, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    assert_eq!(code(&result), "validation_failed");
    let message = result["error"]["message"].as_str().unwrap();
    assert!(message.contains("kp_not_claimed"), "{message}");
    // B saw its unclaimed copy in the Add and burned it.
    assert_eq!(b.stock(&alice_b).await, (0, false));
}
