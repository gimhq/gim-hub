//! Federated blob reads across in-process hubs on 127.0.0.1 (real libp2p
//! transport, ephemeral ports): `GET /v2/blobs/{blob_id}` of a blob uploaded
//! on another hub fetches it from the origin with `FetchBlob`, caches it and
//! serves it (docs/federation.md §5.6).
//!
//! Groups and hosting records are seeded directly in the database.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header, HeaderMap, Method, Request, StatusCode},
};
use gim_hub_api::{
    handlers::register_blob_op,
    testing::{TestHub, TEST_NOW},
};
use gim_hub_db::{
    groups::{self, Group},
    hosting::{self, StoredHostingRecord},
};
use gim_hub_identity::{HubId, SigningKey};
use gim_hub_proto::s2s::{s2s_request::Op, S2sRequest, S2sResponse};
use gim_hub_s2s::{
    ops::blob::{fetch_chunk, CHUNK_BYTES},
    AllowlistPolicy, BlobService, BoxFuture, Federation, FederationConfig, FederationService,
    FetchBlobError, Multiaddr, SendError,
};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

/// Federation that counts the `FetchBlob` requests it sends.
struct Counting {
    inner: FederationService,
    fetches: AtomicUsize,
}

impl Federation for Counting {
    fn is_enabled(&self) -> bool {
        true
    }

    fn send(
        &self,
        hub_id: &HubId,
        request: S2sRequest,
    ) -> BoxFuture<'_, Result<S2sResponse, SendError>> {
        if matches!(request.op, Some(Op::FetchBlob(_))) {
            self.fetches.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.send(hub_id, request)
    }
}

/// A hub with a running federation service and the `FetchBlob` op.
struct Node {
    seed: u8,
    hub: TestHub,
    service: FederationService,
    federation: Arc<Counting>,
    policy: Arc<AllowlistPolicy>,
    dir: TempDir,
    addr: Multiaddr,
    _blobs: Arc<BlobService>,
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
    async fn start(seed: u8) -> Self {
        let mut hub = TestHub::with_hub_seed([seed; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist");
        // An allowlist must not be empty: start with an unrelated hub.
        let placeholder =
            HubId::from_root_pubkey(&SigningKey::from_bytes(&[200; 32]).verifying_key());
        std::fs::write(&path, format!("{placeholder}\n")).unwrap();
        let policy = Arc::new(AllowlistPolicy::load(&path, hub.state.hub.hub_id(), None).unwrap());
        let config = federation_config(&dir, "/ip4/127.0.0.1/tcp/0".parse().unwrap());
        let service =
            FederationService::start(&config, hub.state.hub.signing_key(), policy.clone())
                .await
                .unwrap();
        let (federation, blobs) = wire(&mut hub, &service);
        let addr = service.transport().advertised_addrs()[0].clone();
        Self {
            seed,
            hub,
            service,
            federation,
            policy,
            dir,
            addr,
            _blobs: blobs,
        }
    }

    fn id(&self) -> HubId {
        self.hub.state.hub.hub_id().clone()
    }

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

    fn fetches(&self) -> usize {
        self.federation.fetches.load(Ordering::SeqCst)
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
        let (federation, blobs) = wire(&mut self.hub, &service);
        self.service = service;
        self.federation = federation;
        self._blobs = blobs;
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.service.shutdown();
    }
}

fn wire(hub: &mut TestHub, service: &FederationService) -> (Arc<Counting>, Arc<BlobService>) {
    let federation = Arc::new(Counting {
        inner: service.clone(),
        fetches: AtomicUsize::new(0),
    });
    hub.set_federation(federation.clone());
    let blobs = register_blob_op(&hub.state, service);
    (federation, blobs)
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

/// Seeds, on `home`, a DM `<home>/dm` of `owner` (hosted on `home`) and
/// `peer`, whose hosting record lists `peer_hub`.
async fn share_group(home: &Node, owner: &str, peer: &str, peer_hub: &Node) {
    let gid = format!("{}/dm", home.id());
    let (owner, peer, peer_hub) = (owner.to_owned(), peer.to_owned(), peer_hub.id());
    home.hub
        .state
        .db
        .write(move |tx| {
            groups::create(
                tx,
                &Group {
                    gid: gid.clone(),
                    kind: "direct".into(),
                    epoch: 1,
                    last_seq: 0,
                    created_by_user_id: owner,
                    created_by_device_id: "d1".into(),
                    created_at: TEST_NOW,
                },
            )?;
            groups::add_member(tx, &gid, &peer, "d1", 1, TEST_NOW)?;
            hosting::put(
                tx,
                &StoredHostingRecord {
                    user_id: peer,
                    record: vec![0],
                    seq: 1,
                    expires_at: TEST_NOW + 86_400_000,
                    hosted: false,
                    hub_ids: vec![peer_hub.as_str().to_owned()],
                    fetched_at: TEST_NOW,
                    published_at: None,
                    updated_at: TEST_NOW,
                },
            )
        })
        .await
        .unwrap();
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn code(&self) -> String {
        let value: Value = serde_json::from_slice(&self.body).unwrap();
        value["error"]["code"].as_str().unwrap().to_owned()
    }
}

async fn call(
    hub: &TestHub,
    method: Method,
    uri: &str,
    token: &str,
    headers: &[(header::HeaderName, &str)],
    body: Vec<u8>,
) -> Reply {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    let response = hub
        .router()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    Reply {
        status: response.status(),
        headers: response.headers().clone(),
        body: to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    }
}

/// Uploads `data` on `hub`; returns the blob id.
async fn upload(hub: &TestHub, token: &str, data: &[u8]) -> String {
    let reply = call(hub, Method::POST, "/v2/blobs", token, &[], data.to_vec()).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let value: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(value["size"], data.len());
    value["blob_id"].as_str().unwrap().to_owned()
}

fn blob_uri(blob_id: &str) -> String {
    format!("/v2/blobs/{}", blob_id.replace('/', "%2F"))
}

async fn download(hub: &TestHub, token: &str, blob_id: &str) -> Reply {
    call(hub, Method::GET, &blob_uri(blob_id), token, &[], Vec::new()).await
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn cross_hub_blob_is_fetched_cached_and_served() {
    let nodes = cluster(&[11, 12]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    share_group(a, "alice", "bob", b).await;
    let alice = a.hub.create_session("alice", "d1").await;
    let bob = b.hub.create_session("bob", "d1").await;

    let bytes = data(300_000);
    let blob_id = upload(&a.hub, &alice, &bytes).await;
    assert!(blob_id.starts_with(&format!("{}/b_", a.id())));

    let reply = download(&b.hub, &bob, &blob_id).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, bytes);
    assert_eq!(reply.headers[header::CONTENT_LENGTH], "300000");
    assert_eq!(b.fetches(), 1);
    // The cached copy: a file under the safe name, no temp file left.
    let names: Vec<String> = std::fs::read_dir(b.hub.state.config.blobs_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, [blob_id.replace('/', "_")]);

    // Cache hits, Range included, send no S2S request.
    let reply = download(&b.hub, &bob, &blob_id).await;
    assert_eq!(reply.body, bytes);
    let reply = call(
        &b.hub,
        Method::GET,
        &blob_uri(&blob_id),
        &bob,
        &[(header::RANGE, "bytes=100-199")],
        Vec::new(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(reply.body, bytes[100..200]);
    assert_eq!(reply.headers[header::CONTENT_RANGE], "bytes 100-199/300000");
    assert_eq!(b.fetches(), 1);

    // Unknown ids of the origin are 404; invalid ids are 404 without S2S.
    let unknown = format!("{}/b_AAAAAAAAAAAAAAAAAAAAAA", a.id());
    assert_eq!(
        download(&b.hub, &bob, &unknown).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(b.fetches(), 2);
    for bad in [
        "b_unknown",
        "..%2Fhub_key",
        "hnothub%2Fb_AAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let reply = call(
            &b.hub,
            Method::GET,
            &format!("/v2/blobs/{bad}"),
            &bob,
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert_eq!(b.fetches(), 2);
}

#[tokio::test]
async fn blobs_larger_than_a_chunk_are_reassembled() {
    let nodes = cluster(&[21, 22]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    share_group(a, "alice", "bob", b).await;
    let alice = a.hub.create_session("alice", "d1").await;
    let bob = b.hub.create_session("bob", "d1").await;

    let chunk = CHUNK_BYTES as usize;
    let bytes = data(2 * chunk + 12_345);
    let blob_id = upload(&a.hub, &alice, &bytes).await;
    let reply = download(&b.hub, &bob, &blob_id).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body.len(), bytes.len());
    assert!(reply.body == bytes);
    assert_eq!(b.fetches(), 3);
}

#[tokio::test]
async fn concurrent_downloads_fetch_once() {
    let nodes = cluster(&[31, 32]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    share_group(a, "alice", "bob", b).await;
    let alice = a.hub.create_session("alice", "d1").await;
    let bob = b.hub.create_session("bob", "d1").await;

    let bytes = data(1_000_000);
    let blob_id = upload(&a.hub, &alice, &bytes).await;
    let replies =
        futures_util::future::join_all((0..8).map(|_| download(&b.hub, &bob, &blob_id))).await;
    for reply in replies {
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body == bytes);
    }
    assert_eq!(b.fetches(), 1);
}

#[tokio::test]
async fn origin_outage_is_503_until_it_is_back() {
    let mut nodes = cluster(&[41, 42]).await;
    share_group(&nodes[0], "alice", "bob", &nodes[1]).await;
    let alice = nodes[0].hub.create_session("alice", "d1").await;
    let bob = nodes[1].hub.create_session("bob", "d1").await;
    let cached = upload(&nodes[0].hub, &alice, b"cached").await;
    let fresh = upload(&nodes[0].hub, &alice, b"not fetched yet").await;
    assert_eq!(
        download(&nodes[1].hub, &bob, &cached).await.status,
        StatusCode::OK
    );

    nodes[0].service.shutdown();
    let reply = download(&nodes[1].hub, &bob, &fresh).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.code(), "peer_unavailable");
    assert!(reply.headers.contains_key(header::RETRY_AFTER));
    // The copy fetched before the outage is still served.
    let reply = download(&nodes[1].hub, &bob, &cached).await;
    assert_eq!(reply.body, &b"cached"[..]);

    nodes[0].restart().await;
    let mut reply = download(&nodes[1].hub, &bob, &fresh).await;
    for _ in 0..50 {
        if reply.status == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        reply = download(&nodes[1].hub, &bob, &fresh).await;
    }
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, &b"not fetched yet"[..]);
}

#[tokio::test]
async fn unrelated_hubs_and_cached_copies_are_refused() {
    let nodes = cluster(&[51, 52, 53]).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    share_group(a, "alice", "bob", b).await;
    let alice = a.hub.create_session("alice", "d1").await;
    let bob = b.hub.create_session("bob", "d1").await;
    let carol = c.hub.create_session("carol", "d1").await;
    let blob_id = upload(&a.hub, &alice, b"secret ciphertext").await;

    // C is allowlisted but hosts no user sharing a group with alice.
    let reply = download(&c.hub, &carol, &blob_id).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(reply.code(), "peer_refused");

    // B caches a copy but never serves it on: no transitive serving.
    assert_eq!(
        download(&b.hub, &bob, &blob_id).await.status,
        StatusCode::OK
    );
    let err = fetch_chunk(&c.service, &b.id(), &blob_id, 0, 0)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, FetchBlobError::Refused(reason) if reason.contains("origin")),
        "{err:?}"
    );
}

#[tokio::test]
async fn legacy_ids_mean_this_hub_and_foreign_ids_need_federation() {
    let nodes = cluster(&[61, 62]).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.hub.create_session("alice", "d1").await;
    let bob = b.hub.create_session("bob", "d1").await;

    // A blob stored before origin-qualified ids.
    let legacy = "b_Hk4dN7sL2pX9cV0mB5qT1g";
    let dir = a.hub.state.config.blobs_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(legacy), b"old blob").unwrap();
    a.hub
        .state
        .db
        .write(|tx| {
            gim_hub_db::blobs::insert(
                tx,
                &gim_hub_db::blobs::Blob {
                    blob_id: legacy.into(),
                    size: 8,
                    uploader_user_id: "alice".into(),
                    uploader_device_id: "d1".into(),
                    created_at: TEST_NOW,
                },
            )
        })
        .await
        .unwrap();
    let reply = download(&a.hub, &alice, legacy).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, &b"old blob"[..]);
    // On another hub the legacy id names that hub: not found, no S2S.
    assert_eq!(
        download(&b.hub, &bob, legacy).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(b.fetches(), 0);

    // Without federation a foreign id is not found.
    let single = TestHub::new();
    let token = single.create_session("dave", "d1").await;
    let blob_id = upload(&a.hub, &alice, b"new blob").await;
    assert_eq!(
        download(&single, &token, &blob_id).await.status,
        StatusCode::NOT_FOUND
    );
}
