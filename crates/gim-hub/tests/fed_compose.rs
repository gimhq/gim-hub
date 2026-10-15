//! Compose acceptance driver for closed federation (docs/federation.md
//! §11.2, §11.3; plan acceptance M2b). It speaks the client API v2 over HTTP
//! to the hubs of `deploy/federation/compose.yaml` with real MLS clients
//! (openmls, 0xF001 credentials, DeviceLists, hosting records) and stops and
//! starts hub containers through the Docker API for the outage cases.
//!
//! Ignored by default: `scripts/fed-test.sh` starts the topology and runs it
//! with `--ignored` in a container attached to the federation network.
//!
//! Environment: `GIM_FED_HUB_{A,B,C,X}` (base URLs), `GIM_FED_HUB_X_ID`
//! (hub-x's hub_id), `GIM_FED_PROJECT` (compose project name, for container
//! names), `GIM_FED_DOCKER_SOCKET` (default `/var/run/docker.sock`).

#[path = "../../gim-hub-api/tests/mls_support/mod.rs"]
mod mls_support;

use std::{
    future::Future,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::Signer;
use gim_hub_identity::{AUTH_RESPONSE_CONTEXT, HOSTING_RECORD_CONTEXT};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, LeafNodeIndex, LeafNodeParameters,
    MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, OpenMlsProvider, ProcessedMessageContent, ProtocolVersion, StagedWelcome,
    MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};

use mls_support::{
    b64, capabilities, code, device_id, device_list, encode, gim_credential, group_path, key,
    signer, unb64, user_id, CIPHERSUITE, GIM_CREDENTIAL,
};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Upper bound of every wait for federation to converge.
const CONVERGE: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// HTTP and Docker
// ---------------------------------------------------------------------------

/// One HTTP/1.1 request; returns the status and the JSON body (`Null` if
/// empty), or a transport error.
async fn http(
    base: &str,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(StatusCode, Value), String> {
    let authority = base.trim_start_matches("http://").trim_end_matches('/');
    let stream = tokio::net::TcpStream::connect(authority)
        .await
        .map_err(|err| format!("connect {authority}: {err}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| err.to_string())?;
    tokio::spawn(conn);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, authority);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Bytes::from(body.to_string())
        }
        None => Bytes::new(),
    };
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        sender.send_request(request.body(Full::new(payload)).unwrap()),
    )
    .await
    .map_err(|_| format!("{base}{path}: timed out"))?
    .map_err(|err| err.to_string())?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|err| err.to_string())?
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|err| format!("{base}{path}: {err}"))?
    };
    Ok((status, value))
}

/// A Docker Engine API call over the unix socket (curl is in the rust image).
fn docker(method: &str, path: &str) -> String {
    let socket =
        std::env::var("GIM_FED_DOCKER_SOCKET").unwrap_or_else(|_| "/var/run/docker.sock".into());
    let output = Command::new("curl")
        .args(["-sS", "--fail-with-body", "--unix-socket", &socket, "-X"])
        .arg(method)
        .arg(format!("http://localhost{path}"))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "docker {method} {path}: {text} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

/// A hub of the compose project.
#[derive(Clone)]
struct Hub {
    service: &'static str,
    base: String,
}

impl Hub {
    fn from_env(service: &'static str, var: &str) -> Self {
        Self {
            service,
            base: std::env::var(var).unwrap_or_else(|_| panic!("{var} is not set")),
        }
    }

    fn container(&self) -> String {
        let project = std::env::var("GIM_FED_PROJECT").unwrap_or_else(|_| "gim-fed".into());
        format!("{project}-{}-1", self.service)
    }

    fn stop(&self) {
        docker(
            "POST",
            &format!("/containers/{}/stop?t=10", self.container()),
        );
    }

    async fn start(&self) {
        docker("POST", &format!("/containers/{}/start", self.container()));
        self.wait_healthy().await;
    }

    fn logs(&self) -> String {
        docker(
            "GET",
            &format!("/containers/{}/logs?stdout=1&stderr=1", self.container()),
        )
    }

    async fn wait_healthy(&self) {
        eventually(&format!("{} /healthz", self.service), || async {
            matches!(
                http(&self.base, Method::GET, "/healthz", None, None).await,
                Ok((StatusCode::OK, _))
            )
        })
        .await;
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        http(&self.base, method.clone(), path, token, body.as_ref())
            .await
            .unwrap_or_else(|err| panic!("{method} {}{path}: {err}", self.service))
    }
}

/// Polls `check` every 200 ms until it holds, for at most [`CONVERGE`].
async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + CONVERGE;
    while Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Device-side CBOR (AuthResponse, SignedHostingRecord)
// ---------------------------------------------------------------------------

fn head(major: u8, n: u64) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | n as u8],
        24..=0xff => vec![major | 24, n as u8],
        0x100..=0xffff => [vec![major | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![major | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![major | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

fn bstr(bytes: &[u8]) -> Vec<u8> {
    [head(2, bytes.len() as u64), bytes.to_vec()].concat()
}

fn tstr(text: &str) -> Vec<u8> {
    [head(3, text.len() as u64), text.as_bytes().to_vec()].concat()
}

/// AuthResponse `[1, challenge, user_id, device_id, sig]`, signed by the
/// device key over `[challenge, user_id, device_id]`.
fn auth_response(challenge: &[u8], user_id: &str, device_id: &str, device_seed: u8) -> Vec<u8> {
    let fields = [bstr(challenge), tstr(user_id), tstr(device_id)].concat();
    let tbs = [head(4, 3), fields.clone()].concat();
    let sig = key(device_seed).sign(&[AUTH_RESPONSE_CONTEXT, &[0], &tbs].concat());
    [head(4, 5), head(0, 1), fields, bstr(&sig.to_bytes())].concat()
}

/// `SignedHostingRecord` of the user with root key `key(root_seed)` listing
/// the hub-signed `entry` (CBOR `HostingEntry`, as returned by the hub).
fn hosting_record(root_seed: u8, seq: u64, expires_at: u64, entry: &[u8]) -> Vec<u8> {
    let root = key(root_seed);
    let tbs = [
        head(4, 6),
        head(0, 1),
        tstr(&user_id(root_seed)),
        bstr(root.verifying_key().as_bytes()),
        head(0, seq),
        head(0, expires_at),
        head(4, 1),
        entry.to_vec(),
    ]
    .concat();
    let sig = root.sign(&[HOSTING_RECORD_CONTEXT, &[0], &tbs].concat());
    [head(4, 2), bstr(&tbs), bstr(&sig.to_bytes())].concat()
}

// ---------------------------------------------------------------------------
// MLS clients over HTTP
// ---------------------------------------------------------------------------

/// One device of a user hosted on `hub`, signed in over the client API.
struct User {
    name: &'static str,
    hub: Hub,
    user_id: String,
    device_id: String,
    token: String,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl User {
    /// Uploads a DeviceList certifying device `key(device_seed)`, signs in
    /// with challenge/response, uploads `key_packages` KeyPackages and
    /// publishes a hosting record listing `hub`.
    async fn sign_up(
        name: &'static str,
        hub: &Hub,
        root_seed: u8,
        device_seed: u8,
        key_packages: usize,
    ) -> Self {
        let (uid, did) = (user_id(root_seed), device_id(device_seed));
        let list = device_list(root_seed, 1, &[device_seed], &[]);
        let (status, body) = hub
            .call(
                Method::PUT,
                &format!("/v2/users/{uid}/device-list"),
                None,
                Some(json!({ "device_list": b64(&list) })),
            )
            .await;
        assert!(status.is_success(), "{name} device list: {body}");

        let (status, body) = hub
            .call(
                Method::POST,
                "/v2/auth/challenge",
                None,
                Some(json!({ "user_id": uid, "device_id": did })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{name} challenge: {body}");
        let response = auth_response(&unb64(&body["challenge"]), &uid, &did, device_seed);
        let (status, body) = hub
            .call(
                Method::POST,
                "/v2/auth/session",
                None,
                Some(json!({ "response": b64(&response) })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{name} session: {body}");

        let provider = OpenMlsRustCrypto::default();
        let signer = signer(device_seed);
        signer.store(provider.storage()).unwrap();
        let user = Self {
            name,
            hub: hub.clone(),
            credential: CredentialWithKey {
                credential: gim_credential(root_seed, device_seed),
                signature_key: signer.public().into(),
            },
            token: body["token"].as_str().unwrap().to_owned(),
            user_id: uid,
            device_id: did,
            provider,
            signer,
        };
        if key_packages > 0 {
            let packages: Vec<String> = (0..key_packages)
                .map(|_| b64(&user.key_package()))
                .collect();
            let (status, body) = user
                .call(
                    Method::POST,
                    "/v2/keypackages",
                    Some(json!({ "key_packages": packages })),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{name} key packages: {body}");
        }
        user.publish_hosting_record(root_seed).await;
        user
    }

    /// POST hosting-entry, sign the record with the user root key, PUT it.
    async fn publish_hosting_record(&self, root_seed: u8) {
        let (status, body) = self
            .call(
                Method::POST,
                &format!("/v2/users/{}/hosting-entry", self.user_id),
                Some(json!({})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{} hosting entry: {body}",
            self.name
        );
        let record = hosting_record(root_seed, 1, now_ms() + 7 * DAY_MS, &unb64(&body["entry"]));
        let (status, body) = self
            .hub
            .call(
                Method::PUT,
                &format!("/v2/users/{}/hosting-record", self.user_id),
                None,
                Some(json!({ "hosting_record": b64(&record) })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{} hosting record: {body}",
            self.name
        );
        assert_eq!(body["hosted"], json!(true));
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.hub.call(method, path, Some(&self.token), body).await
    }

    fn key_package(&self) -> Vec<u8> {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities(GIM_CREDENTIAL))
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap()
    }

    /// Claims a KeyPackage of `target`'s device through this user's hub,
    /// retrying while the target is `unavailable` (peers still binding).
    async fn claim(&self, target: &User) -> KeyPackage {
        let request =
            json!({ "targets": [{ "user_id": target.user_id, "device_id": target.device_id }] });
        let mut last = Value::Null;
        let deadline = Instant::now() + CONVERGE;
        while Instant::now() < deadline {
            let (status, body) = self
                .call(Method::POST, "/v2/keypackages/claim", Some(request.clone()))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            if let Some(package) = body["key_packages"].get(0) {
                return KeyPackageIn::tls_deserialize_exact(unb64(&package["key_package"]))
                    .unwrap()
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .unwrap();
            }
            last = body;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("{} could not claim {}: {last}", self.name, target.name);
    }

    async fn create_group(&self, kind: &str) -> (String, MlsGroup) {
        let (status, body) = self
            .call(Method::POST, "/v2/groups", Some(json!({ "kind": kind })))
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
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(gid.as_bytes()),
            self.credential.clone(),
        )
        .unwrap();
        (gid, group)
    }

    /// Data of this device's events of `event_type`, in cursor order.
    async fn events_of(&self, event_type: &str) -> Vec<Value> {
        let (status, body) = self
            .call(Method::GET, "/v2/events?cursor=0&limit=500", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["type"] == event_type)
            .map(|event| event["data"].clone())
            .collect()
    }

    /// Seqs of this device's `message` events of `gid`, in delivery order.
    async fn message_seqs(&self, gid: &str) -> Vec<u64> {
        self.events_of("message")
            .await
            .iter()
            .filter(|event| event["gid"] == gid)
            .map(|event| event["seq"].as_u64().unwrap())
            .collect()
    }

    async fn wait_message(&self, gid: &str, seq: u64) -> Value {
        let find = |events: Vec<Value>| {
            events
                .into_iter()
                .find(|event| event["gid"] == gid && event["seq"] == seq)
        };
        eventually(&format!("{} to receive seq {seq}", self.name), || async {
            find(self.events_of("message").await).is_some()
        })
        .await;
        find(self.events_of("message").await).unwrap()
    }

    /// Waits for the message `seq` of `gid` and processes it: merges a
    /// Commit, or returns the plaintext of an application message.
    async fn receive(&self, group: &mut MlsGroup, gid: &str, seq: u64) -> Option<Vec<u8>> {
        let event = self.wait_message(gid, seq).await;
        let message = MlsMessageIn::tls_deserialize_exact(unb64(&event["mls_message"])).unwrap();
        let processed = group
            .process_message(&self.provider, message.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Some(message.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group.merge_staged_commit(&self.provider, *staged).unwrap();
                None
            }
            _ => panic!("unexpected message"),
        }
    }

    /// Joins from the first `welcome` event of `gid`.
    async fn join(&self, gid: &str) -> MlsGroup {
        eventually(&format!("{}'s Welcome", self.name), || async {
            self.events_of("welcome")
                .await
                .iter()
                .any(|event| event["gid"] == gid)
        })
        .await;
        let events = self.events_of("welcome").await;
        let event = events.iter().find(|event| event["gid"] == gid).unwrap();
        let message = MlsMessageIn::tls_deserialize_exact(unb64(&event["welcome"])).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            panic!("not a Welcome");
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .unwrap()
            .into_group(&self.provider)
            .unwrap()
    }

    async fn submit_commit(&self, gid: &str, body: Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            &format!("{}/commits", group_path(gid)),
            Some(body),
        )
        .await
    }

    async fn post_message(&self, gid: &str, client_id: &str, mls: &[u8]) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            &format!("{}/messages", group_path(gid)),
            Some(json!({ "client_id": client_id, "mls_message": b64(mls) })),
        )
        .await
    }

    /// Encrypts and sends an application message; asserts it got `seq`.
    async fn send_text(&self, group: &mut MlsGroup, gid: &str, text: &str, seq: u64) {
        let mls = application(self, group, text.as_bytes());
        let (status, body) = self.post_message(gid, text, &mls).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{} sends {text}: {body}",
            self.name
        );
        assert_eq!(body["seq"], seq, "{body}");
    }

    /// `(seq, client_id, mls_message)` of the group log on this user's hub.
    async fn log(&self, gid: &str) -> Vec<(u64, String, String)> {
        let (status, body) = self
            .call(
                Method::GET,
                &format!("{}/messages?from_seq=1&limit=500", group_path(gid)),
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

    async fn roster(&self, gid: &str) -> (StatusCode, Vec<String>) {
        let (status, body) = self.call(Method::GET, &group_path(gid), None).await;
        let mut ids: Vec<String> = body["members"]
            .as_array()
            .map(|members| {
                members
                    .iter()
                    .map(|m| m["device_id"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        (status, ids)
    }
}

fn application(user: &User, group: &mut MlsGroup, text: &[u8]) -> Vec<u8> {
    group
        .create_message(&user.provider, &user.signer, text)
        .unwrap()
        .to_bytes()
        .unwrap()
}

fn commit_body(client_id: &str, commit: &MlsMessageOut) -> Value {
    json!({ "client_id": client_id, "mls_message": encode(commit) })
}

fn with_welcome(mut body: Value, welcome: &MlsMessageOut, recipients: &[&User]) -> Value {
    body["welcome"] = json!(encode(welcome));
    body["welcome_recipients"] = recipients
        .iter()
        .map(|u| json!({ "user_id": u.user_id, "device_id": u.device_id }))
        .collect();
    body
}

fn leaf_of(group: &MlsGroup, user: &User) -> LeafNodeIndex {
    group
        .members()
        .find(|m| m.signature_key == user.credential.signature_key.as_slice())
        .unwrap()
        .index
}

fn sorted(ids: &[&str]) -> Vec<String> {
    let mut ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    ids.sort();
    ids
}

/// Prints a step result with the time since `start`.
fn ok(step: &str, start: Instant) {
    println!("fed: ok   {step} ({:.1}s)", start.elapsed().as_secs_f64());
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs deploy/federation/compose.yaml; run by scripts/fed-test.sh"]
async fn compose_federation() {
    let a = Hub::from_env("hub-a", "GIM_FED_HUB_A");
    let b = Hub::from_env("hub-b", "GIM_FED_HUB_B");
    let c = Hub::from_env("hub-c", "GIM_FED_HUB_C");
    let x = Hub::from_env("hub-x", "GIM_FED_HUB_X");
    let x_id = std::env::var("GIM_FED_HUB_X_ID").expect("GIM_FED_HUB_X_ID is not set");
    for hub in [&a, &b, &c, &x] {
        hub.wait_healthy().await;
    }

    let start = Instant::now();
    let alice = User::sign_up("alice", &a, 1, 11, 2).await;
    let bob = User::sign_up("bob", &b, 2, 21, 2).await;
    let carol = User::sign_up("carol", &c, 3, 31, 2).await;
    let dave = User::sign_up("dave", &c, 4, 41, 2).await;
    let eve = User::sign_up("eve", &x, 5, 51, 2).await;
    // Remote hubs resolve the records (DHT or GetHostingRecord).
    for (hub, user) in [(&b, &alice), (&c, &alice), (&a, &bob), (&a, &carol)] {
        let path = format!("/v2/users/{}/hosting-record", user.user_id);
        eventually(
            &format!("{}'s record on {}", user.name, hub.service),
            || async {
                let (status, body) = hub.call(Method::GET, &path, None, None).await;
                status == StatusCode::OK && body["seq"] == 1
            },
        )
        .await;
    }
    ok("sign-up, hosting records resolved across hubs", start);

    cross_hub_dm(&alice, &bob).await;
    let (gid, mut groups) = three_hub_group(&alice, &bob, &carol, &dave).await;
    concurrent_commits(&gid, &alice, &bob, &dave, &mut groups).await;
    member_hub_outage(&gid, &c, &alice, &bob, &dave, &mut groups).await;
    owner_hub_outage(&gid, &a, &alice, &bob, &dave, &mut groups).await;
    refusal(&a, &x_id, &alice, &eve).await;
    println!("fed: PASS ({:.1}s)", start.elapsed().as_secs_f64());
}

/// T2: bob@B opens a direct group with alice@A; both send three messages.
async fn cross_hub_dm(alice: &User, bob: &User) {
    let start = Instant::now();
    let (gid, mut bob_group) = bob.create_group("direct").await;
    let kp = bob.claim(alice).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[alice]);
    let (status, result) = bob.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 1, "epoch": 1, "duplicate": false }));
    bob_group.merge_pending_commit(&bob.provider).unwrap();

    let mut alice_group = alice.join(&gid).await;
    for i in 0..3u64 {
        bob.send_text(&mut bob_group, &gid, &format!("b{i}"), 2 + i)
            .await;
    }
    for i in 0..3u64 {
        let text = alice.receive(&mut alice_group, &gid, 2 + i).await;
        assert_eq!(text.unwrap(), format!("b{i}").into_bytes());
    }
    let mut first = None;
    for i in 0..3u64 {
        let mls = application(alice, &mut alice_group, format!("a{i}").as_bytes());
        let (status, message) = alice.post_message(&gid, &format!("a{i}"), &mls).await;
        assert_eq!(status, StatusCode::CREATED, "{message}");
        assert_eq!(message["seq"], 5 + i);
        first.get_or_insert((mls, message));
    }
    for i in 0..3u64 {
        let text = bob.receive(&mut bob_group, &gid, 5 + i).await;
        assert_eq!(text.unwrap(), format!("a{i}").into_bytes());
    }
    // client_id replay through the member hub: the stored message.
    let (mls, message) = first.unwrap();
    let (status, replay) = alice.post_message(&gid, "a0", &mls).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, message);

    let on_a = alice.log(&gid).await;
    assert_eq!(on_a, bob.log(&gid).await);
    assert_eq!(
        on_a.iter().map(|(seq, ..)| *seq).collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    assert_eq!(alice.message_seqs(&gid).await, [2, 3, 4]);
    assert_eq!(bob.message_seqs(&gid).await, [5, 6, 7]);
    ok("cross-hub DM (B owns, A member)", start);
}

/// MLS groups of the group scenarios, per member.
struct Groups {
    alice: MlsGroup,
    bob: MlsGroup,
    dave: MlsGroup,
}

/// T3/T4: alice@A creates a group with bob@B and carol@C; everyone sends;
/// bob (non-owning hub) adds dave@C and removes carol.
async fn three_hub_group(alice: &User, bob: &User, carol: &User, dave: &User) -> (String, Groups) {
    let start = Instant::now();
    let (gid, mut alice_group) = alice.create_group("group").await;
    let kps = vec![alice.claim(bob).await, alice.claim(carol).await];
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[bob, carol]);
    let (status, result) = alice.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let mut bob_group = bob.join(&gid).await;
    let mut carol_group = carol.join(&gid).await;
    let three = sorted(&[&alice.device_id, &bob.device_id, &carol.device_id]);
    for user in [bob, carol] {
        eventually(&format!("{}'s replica roster", user.name), || async {
            user.roster(&gid).await == (StatusCode::OK, three.clone())
        })
        .await;
    }

    alice
        .send_text(&mut alice_group, &gid, "hello from A", 2)
        .await;
    bob.send_text(&mut bob_group, &gid, "hello from B", 3).await;
    carol
        .send_text(&mut carol_group, &gid, "hello from C", 4)
        .await;
    for (user, group, seqs) in [
        (alice, &mut alice_group, [3, 4]),
        (bob, &mut bob_group, [2, 4]),
        (carol, &mut carol_group, [2, 3]),
    ] {
        for seq in seqs {
            assert!(user.receive(group, &gid, seq).await.is_some());
        }
        assert_eq!(user.message_seqs(&gid).await, seqs);
    }
    ok("3-hub group: every member gets every message once", start);

    // bob@B adds dave@C: the Commit is forwarded to the owner A.
    let start = Instant::now();
    let kp = bob.claim(dave).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c2", &commit), &welcome, &[dave]);
    let (status, result) = bob.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 5, "epoch": 2, "duplicate": false }));
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    alice.receive(&mut alice_group, &gid, 5).await;
    carol.receive(&mut carol_group, &gid, 5).await;
    let mut dave_group = dave.join(&gid).await;

    // bob removes carol; C keeps its replica for dave.
    let (commit, _, _) = bob_group
        .remove_members(&bob.provider, &bob.signer, &[leaf_of(&bob_group, carol)])
        .unwrap();
    let (status, result) = bob.submit_commit(&gid, commit_body("c3", &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["seq"], 6);
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    alice.receive(&mut alice_group, &gid, 6).await;
    dave.receive(&mut dave_group, &gid, 6).await;
    carol.wait_message(&gid, 6).await;
    for user in [alice, bob, carol, dave] {
        let of_group = |events: Vec<Value>| -> Vec<Value> {
            events.into_iter().filter(|e| e["gid"] == gid).collect()
        };
        eventually(&format!("{}'s membership events", user.name), || async {
            of_group(user.events_of("group.member_added").await)
                .iter()
                .any(|e| e["user_id"] == json!(dave.user_id) && e["seq"] == 5)
                && !of_group(user.events_of("group.member_removed").await).is_empty()
        })
        .await;
        let removed = of_group(user.events_of("group.member_removed").await);
        assert_eq!(removed.len(), 1, "{}: {removed:?}", user.name);
        assert_eq!(removed[0]["user_id"], json!(carol.user_id));
        assert_eq!(removed[0]["seq"], 6);
    }
    let roster = sorted(&[&alice.device_id, &bob.device_id, &dave.device_id]);
    assert_eq!(dave.roster(&gid).await, (StatusCode::OK, roster));
    let (status, body) = carol.call(Method::GET, &group_path(&gid), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "not_member");
    // Nothing reaches carol after the removing Commit.
    alice
        .send_text(&mut alice_group, &gid, "after removal", 7)
        .await;
    for (user, group) in [(bob, &mut bob_group), (dave, &mut dave_group)] {
        assert!(user.receive(group, &gid, 7).await.is_some());
    }
    assert_eq!(carol.message_seqs(&gid).await, [2, 3, 5, 6]);
    ok(
        "add (dave@C) and remove (carol@C) from non-owning hub B",
        start,
    );

    (
        gid,
        Groups {
            alice: alice_group,
            bob: bob_group,
            dave: dave_group,
        },
    )
}

/// T5: bob@B and dave@C commit at the same epoch through their member hubs.
async fn concurrent_commits(gid: &str, alice: &User, bob: &User, dave: &User, groups: &mut Groups) {
    let start = Instant::now();
    let bob_commit = groups
        .bob
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();
    let dave_commit = groups
        .dave
        .self_update(&dave.provider, &dave.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();
    let (bob_body, dave_body) = (
        commit_body("u-bob", &bob_commit),
        commit_body("u-dave", &dave_commit),
    );
    let (bob_result, dave_result) = tokio::join!(
        bob.submit_commit(gid, bob_body.clone()),
        dave.submit_commit(gid, dave_body.clone()),
    );
    let mut statuses = [bob_result.0, dave_result.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::CONFLICT],
        "{bob_result:?} {dave_result:?}"
    );
    let bob_won = bob_result.0 == StatusCode::CREATED;
    let (won, lost) = if bob_won {
        (&bob_result.1, &dave_result.1)
    } else {
        (&dave_result.1, &bob_result.1)
    };
    assert_eq!(won, &json!({ "seq": 8, "epoch": 4, "duplicate": false }));
    assert_eq!(code(lost), "stale_epoch", "{lost}");
    assert_eq!(lost["current_epoch"], 4);

    let (winner, loser, winner_body) = if bob_won {
        (bob, dave, bob_body)
    } else {
        (dave, bob, dave_body)
    };
    // Resubmitting the winner is a duplicate.
    let (status, again) = winner.submit_commit(gid, winner_body).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again, json!({ "seq": 8, "epoch": 4, "duplicate": true }));

    let (winner_group, loser_group) = if bob_won {
        (&mut groups.bob, &mut groups.dave)
    } else {
        (&mut groups.dave, &mut groups.bob)
    };
    winner_group.merge_pending_commit(&winner.provider).unwrap();
    alice.receive(&mut groups.alice, gid, 8).await;
    // The loser catches up and retries successfully.
    loser_group
        .clear_pending_commit(loser.provider.storage())
        .unwrap();
    loser.receive(loser_group, gid, 8).await;
    let retry = loser_group
        .self_update(
            &loser.provider,
            &loser.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    let (status, result) = loser
        .submit_commit(gid, commit_body("u-retry", &retry))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 9, "epoch": 5, "duplicate": false }));
    loser_group.merge_pending_commit(&loser.provider).unwrap();
    alice.receive(&mut groups.alice, gid, 9).await;
    winner.receive(winner_group, gid, 9).await;

    // Same log on every hub.
    let on_a = alice.log(gid).await;
    assert_eq!(on_a.len(), 9);
    eventually("replicas to reach seq 9", || async {
        bob.log(gid).await == on_a && dave.log(gid).await == on_a
    })
    .await;
    ok(
        &format!(
            "concurrent Commit conflict ({} won, {} got 409 stale_epoch, retry ok)",
            winner.name, loser.name
        ),
        start,
    );
}

/// T7: hub-c (dave) is stopped while alice@A and bob@B send 50 messages;
/// after the restart dave receives all of them once, in order.
async fn member_hub_outage(
    gid: &str,
    c: &Hub,
    alice: &User,
    bob: &User,
    dave: &User,
    groups: &mut Groups,
) {
    let start = Instant::now();
    c.stop();
    for i in 0..50u64 {
        let (user, group) = if i % 2 == 0 {
            (alice, &mut groups.alice)
        } else {
            (bob, &mut groups.bob)
        };
        user.send_text(group, gid, &format!("outage-{i}"), 10 + i)
            .await;
    }
    c.start().await;
    for i in 0..50u64 {
        let text = dave.receive(&mut groups.dave, gid, 10 + i).await;
        assert_eq!(text.unwrap(), format!("outage-{i}").into_bytes());
    }
    // Exactly once, in order.
    let seqs = dave.message_seqs(gid).await;
    let tail: Vec<u64> = seqs.iter().copied().filter(|seq| *seq >= 10).collect();
    assert_eq!(tail, (10..60).collect::<Vec<_>>(), "{seqs:?}");
    let mut unique = seqs.clone();
    unique.dedup();
    assert_eq!(unique, seqs, "duplicate deliveries");
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    eventually("C's replica to match A's log", || async {
        dave.log(gid).await == alice.log(gid).await
    })
    .await;
    ok(
        "member hub outage (stop/start hub-c): 50 messages, no loss, no duplicates",
        start,
    );
}

/// T9: the owner hub-a is stopped; bob's send fails with 503 and B's replica
/// still serves reads; after the restart the same send succeeds.
async fn owner_hub_outage(
    gid: &str,
    a: &Hub,
    alice: &User,
    bob: &User,
    dave: &User,
    groups: &mut Groups,
) {
    let start = Instant::now();
    let before = bob.log(gid).await;
    a.stop();
    let mls = application(bob, &mut groups.bob, b"while the owner is down");
    let (status, body) = bob.post_message(gid, "owner-down", &mls).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(code(&body), "peer_unavailable");
    assert_eq!(bob.log(gid).await, before);
    a.start().await;
    // Retry the same message (same client_id) until A is reachable again.
    let deadline = Instant::now() + CONVERGE;
    let (status, body) = loop {
        let result = bob.post_message(gid, "owner-down", &mls).await;
        if result.0 != StatusCode::SERVICE_UNAVAILABLE || Instant::now() > deadline {
            break result;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["seq"], 60, "{body}");
    for (user, group) in [(alice, &mut groups.alice), (dave, &mut groups.dave)] {
        let text = user.receive(group, gid, 60).await;
        assert_eq!(text.unwrap(), b"while the owner is down");
    }
    ok(
        "owner hub outage (stop/start hub-a): 503 peer_unavailable, then delivered",
        start,
    );
}

/// T10: hub-x is on nobody's allowlist: hub-a refuses its Hello and eve@X
/// cannot claim alice@A.
async fn refusal(a: &Hub, x_id: &str, alice: &User, eve: &User) {
    let start = Instant::now();
    let request = json!({ "targets": [{ "user_id": alice.user_id }] });
    let (status, body) = eve
        .call(Method::POST, "/v2/keypackages/claim", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_packages"], json!([]), "{body}");
    let listed = |field: &str| {
        body[field]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["user_id"] == json!(alice.user_id))
    };
    assert!(listed("unavailable") || listed("missing"), "{body}");

    eventually("hub-a to log the refused Hello of hub-x", || async {
        a.logs()
            .lines()
            .any(|line| line.contains("Hello refused") && line.contains(x_id))
    })
    .await;
    // Nothing about eve reached A.
    let (status, body) = alice
        .call(Method::GET, &format!("/v2/users/{}", eve.user_id), None)
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let (status, body) = a
        .call(
            Method::GET,
            &format!("/v2/users/{}/hosting-record", eve.user_id),
            None,
            None,
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    ok(
        "non-allowlisted hub-x refused; eve@X cannot reach alice@A",
        start,
    );
}
