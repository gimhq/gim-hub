//! Remote identity across two in-process hubs on 127.0.0.1 (real libp2p
//! transport, ephemeral ports): cross-hub KeyPackage claims and their
//! ledger, remote DeviceList reads, and `NotifyDeviceList` propagation
//! (docs/federation.md §5.1, §5.2, §6.1).

mod mls_support;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use gim_hub_api::{
    handlers::{register_claim_op, register_device_list_ops},
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::{groups, remote_identity, Connection, DbError};
use gim_hub_identity::{HostingRecord, HubId};
use gim_hub_proto::s2s::{
    s2s_request::Op, ClaimKeyPackageRequest, ErrorCode, S2sRequest, SequencedMessage,
};
use gim_hub_s2s::{
    hosting::testing::sign_record, ops::device_list::local_device_list, AllowlistPolicy,
    ClaimService, Federation, FederationConfig, FederationService, Outbox, OutboxConfig,
    OutboxSource,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use mls_support::{b64, code, device_list, key, put_device_list, send, user_id, Client};

const DAY: i64 = 24 * 60 * 60 * 1000;

/// Builds `NotifyDeviceList` entries from the `users` table; nothing else
/// is queued in these tests.
struct IdentitySource;

impl OutboxSource for IdentitySource {
    fn deliver_messages(
        &self,
        _: &Connection,
        keys: &[(String, u64)],
    ) -> Result<Vec<Option<SequencedMessage>>, DbError> {
        Ok(vec![None; keys.len()])
    }

    fn device_list(&self, conn: &Connection, user_id: &str) -> Result<Option<Vec<u8>>, DbError> {
        local_device_list(conn, user_id)
    }

    fn resync_nudge(&self, _: &Connection, _: &HubId) -> Result<Vec<SequencedMessage>, DbError> {
        Ok(Vec::new())
    }
}

/// A hub with a running federation service.
struct Node {
    hub: TestHub,
    service: FederationService,
    policy: Arc<AllowlistPolicy>,
    dir: TempDir,
    outbox: Option<Outbox>,
    _claims: Option<Arc<ClaimService>>,
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
        Self {
            hub,
            service,
            policy,
            dir,
            outbox: None,
            _claims: None,
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

    /// Starts the outbox (with `outbox`) and registers the identity ops on
    /// the final state, as `main.rs` does.
    fn finish(&mut self, outbox: bool) {
        if outbox {
            let config = OutboxConfig {
                ttl: Duration::from_secs(3600),
                max_entries_per_peer: 1000,
                max_bytes_per_peer: 1 << 20,
                backoff_max: Duration::from_secs(1),
                sweep_interval: Duration::from_secs(60),
            };
            let outbox = Outbox::new(
                self.hub.state.db.clone(),
                Arc::new(self.service.clone()),
                Arc::new(IdentitySource),
                config,
            );
            outbox.start(Some(self.service.transport().subscribe()));
            self.hub.state.outbox = Arc::new(outbox.clone());
            self.outbox = Some(outbox);
        }
        register_device_list_ops(&self.hub.state, &self.service);
        self._claims = Some(register_claim_op(&self.hub.state, &self.service));
    }

    /// Stores `record` of a remote user as freshly fetched (no DHT here).
    async fn cache_record(&self, record: &[u8]) {
        let record = HostingRecord::verify_claimed(record, 0).unwrap();
        let stored =
            gim_hub_s2s::hosting::stored_record(&record, false, self.hub.state.clock.now_ms())
                .unwrap();
        self.hub
            .state
            .db
            .write(move |tx| gim_hub_db::hosting::put(tx, &stored))
            .await
            .unwrap();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(outbox) = &self.outbox {
            outbox.shutdown();
        }
        self.service.shutdown();
    }
}

/// Two hubs allowing each other; `a` runs an outbox.
async fn pair() -> (Node, Node) {
    let (mut a, mut b) = (Node::start(101).await, Node::start(102).await);
    a.allow(&[&b]);
    b.allow(&[&a]);
    a.finish(true);
    b.finish(false);
    (a, b)
}

/// The hosting record (seq 1, 7 days) of the user with root seed
/// `root_seed`, listing the hub with root seed `hub_seed`.
fn hosting_record(root_seed: u8, hub_seed: u8) -> Vec<u8> {
    let expires_at = u64::try_from(TEST_NOW + 7 * DAY).unwrap();
    sign_record(&key(root_seed), 1, expires_at, &[(&key(hub_seed), 0)])
}

/// Uploads the user's hosting record listing `hub` to `hub`.
async fn host(node: &Node, root_seed: u8, hub_seed: u8) {
    let (status, body) = send(
        &node.hub,
        Method::PUT,
        &format!("/v2/users/{}/hosting-record", user_id(root_seed)),
        "",
        Some(json!({ "hosting_record": b64(&hosting_record(root_seed, hub_seed)) })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["hosted"], json!(true));
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

/// Polls `check` every 50 ms for up to 10 s.
async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn remote_claim_records_the_ledger_and_maps_unreachable_hubs() {
    let (a, b) = pair().await;
    // alice (root 1) on A, bob (root 2) on B, carol (root 3) on an
    // unreachable hub C (root 103).
    let alice = Client::new(&a.hub, 1, 11).await;
    alice.upload_key_packages(&a.hub, 2).await;
    host(&a, 1, 101).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    b.cache_record(&hosting_record(1, 101)).await;
    b.cache_record(&hosting_record(3, 103)).await;

    // Bob has no hosting record yet: B does not act for him.
    let (status, body) = claim(&b, &bob, json!([{ "user_id": alice.user_id }])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "hosting_record_required");

    host(&b, 2, 102).await;
    let (status, body) = claim(
        &b,
        &bob,
        json!([{ "user_id": alice.user_id }, { "user_id": user_id(3) }]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["missing"], json!([]));
    assert_eq!(body["unavailable"], json!([{ "user_id": user_id(3) }]));
    let claimed = body["key_packages"].as_array().unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0]["user_id"], json!(alice.user_id));
    assert_eq!(claimed[0]["device_id"], json!(alice.device_id));
    assert_eq!(claimed[0]["last_resort"], json!(false));

    // B recorded the brokered claim; A consumed the package.
    let ledger: Vec<(String, String, String, String, String)> = b
        .hub
        .state
        .db
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT user_id, device_id, target_hub_id, claimed_by_user_id, \
                 claimed_by_device_id FROM remote_kp_claims",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, DbError>(rows)
        })
        .await
        .unwrap();
    assert_eq!(
        ledger,
        [(
            alice.user_id.clone(),
            alice.device_id.clone(),
            a.id().to_string(),
            bob.user_id.clone(),
            bob.device_id.clone(),
        )]
    );
    let (_, count) = send(
        &a.hub,
        Method::GET,
        "/v2/keypackages/count",
        &alice.token,
        None,
    )
    .await;
    assert_eq!(count["available"], json!(1));

    // Without KeyPackages left the remote target is missing.
    claim(&b, &bob, json!([{ "user_id": alice.user_id }])).await;
    let (status, body) = claim(&b, &bob, json!([{ "user_id": alice.user_id }])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["missing"], json!([{ "user_id": alice.user_id }]));
    assert_eq!(body["key_packages"], json!([]));
}

#[tokio::test]
async fn claims_from_unlisted_requesters_are_refused_and_rate_limited() {
    let (a, b) = pair().await;
    let alice = Client::new(&a.hub, 1, 11).await;
    alice.upload_key_packages(&a.hub, 1).await;
    host(&a, 1, 101).await;
    Client::new(&b.hub, 2, 21).await;
    host(&b, 2, 102).await;

    let request = |requester: String| S2sRequest {
        request_id: "r".into(),
        op: Some(Op::ClaimKeyPackage(ClaimKeyPackageRequest {
            requester_user_id: requester,
            target_user_id: user_id(1),
            device_id: None,
        })),
    };
    // Carol's hosting record is unknown to A and B: B is not listed for her.
    let response = b.service.send(&a.id(), request(user_id(3))).await.unwrap();
    assert_eq!(response.error.unwrap().code(), ErrorCode::Unauthorized);
    let (_, count) = send(
        &a.hub,
        Method::GET,
        "/v2/keypackages/count",
        &alice.token,
        None,
    )
    .await;
    assert_eq!(count["available"], json!(1));

    // B is listed for bob: 10 claims per minute for (B, bob, alice).
    let mut codes = Vec::new();
    for _ in 0..11 {
        let response = b.service.send(&a.id(), request(user_id(2))).await.unwrap();
        codes.push(response.error.map(|err| err.code()));
    }
    assert_eq!(codes[0], None);
    assert!(codes[1..10].iter().all(|c| *c == Some(ErrorCode::NotFound)));
    assert_eq!(codes[10], Some(ErrorCode::RateLimited));
    a.hub.state.clock.advance(60_000);
    let response = b.service.send(&a.id(), request(user_id(2))).await.unwrap();
    assert_eq!(response.error.unwrap().code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn remote_users_are_read_from_their_hub_and_cached() {
    let (a, b) = pair().await;
    Client::new(&a.hub, 1, 11).await;
    host(&a, 1, 101).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    b.cache_record(&hosting_record(1, 101)).await;
    b.cache_record(&hosting_record(3, 103)).await;

    let alice_list = b64(&device_list(1, 1, &[11], &[]));
    // The read is public, including the fetch from A: the empty (invalid)
    // bearer token is ignored.
    let (status, body) = send(
        &b.hub,
        Method::GET,
        &format!("/v2/users/{}/device-list", user_id(1)),
        "",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({ "user_id": user_id(1), "device_list": alice_list })
    );
    let (status, body) = send(
        &b.hub,
        Method::GET,
        &format!("/v2/users/{}", user_id(1)),
        &bob.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({ "user_id": user_id(1), "device_list": alice_list })
    );
    let cached = b
        .hub
        .state
        .db
        .read(|conn| remote_identity::get_device_list(conn, &user_id(1)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cached.seq, 1);

    // The cached copy answers while A is gone.
    a.service.shutdown();
    let (status, _) = send(
        &b.hub,
        Method::GET,
        &format!("/v2/users/{}/device-list", user_id(1)),
        &bob.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Carol's hub is unreachable and nothing is cached: 503; unknown: 404.
    let (status, body) = send(
        &b.hub,
        Method::GET,
        &format!("/v2/users/{}", user_id(3)),
        &bob.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(code(&body), "peer_unavailable");
    let (status, _) = send(
        &b.hub,
        Method::GET,
        &format!("/v2/users/{}/device-list", user_id(4)),
        &bob.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn device_list_updates_reach_the_peer_hub() {
    let (a, b) = pair().await;
    let alice = Client::new(&a.hub, 1, 11).await;
    host(&a, 1, 101).await;
    let bob = Client::new(&b.hub, 2, 21).await;
    host(&b, 2, 102).await;
    b.cache_record(&hosting_record(1, 101)).await;

    // A group owned by B with alice and bob; A holds its replica.
    let gid = format!("{}/g1", b.id());
    for node in [&a, &b] {
        let (gid, alice, bob) = (gid.clone(), alice.clone_ids(), bob.clone_ids());
        node.hub
            .state
            .db
            .write(move |tx| {
                groups::create(
                    tx,
                    &groups::Group {
                        gid: gid.clone(),
                        kind: "group".into(),
                        epoch: 1,
                        last_seq: 1,
                        created_by_user_id: bob.0,
                        created_by_device_id: bob.1,
                        created_at: TEST_NOW,
                    },
                )?;
                groups::add_member(tx, &gid, &alice.0, &alice.1, 1, TEST_NOW)
            })
            .await
            .unwrap();
    }
    // B caches alice's list (seq 1) on first use.
    let (status, _) = send(
        &b.hub,
        Method::GET,
        &format!("/v2/users/{}/device-list", alice.user_id),
        &bob.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Alice adds a device on A: A pushes the list to B.
    let (status, body) =
        put_device_list(&a.hub, &alice.user_id, &device_list(1, 2, &[11, 12], &[])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let db = b.hub.state.db.clone();
    eventually("the cached list to reach seq 2", || {
        let db = db.clone();
        async move {
            db.read(|conn| remote_identity::get_device_list(conn, &user_id(1)))
                .await
                .unwrap()
                .is_some_and(|list| list.seq == 2)
        }
    })
    .await;
    let updates = bob.events_of(&b.hub, "device_list.updated").await;
    assert_eq!(
        updates,
        [json!({
            "user_id": alice.user_id,
            "device_list": b64(&device_list(1, 2, &[11, 12], &[])),
        })]
    );
}

trait Ids {
    fn clone_ids(&self) -> (String, String);
}

impl Ids for Client {
    fn clone_ids(&self) -> (String, String) {
        (self.user_id.clone(), self.device_id.clone())
    }
}
