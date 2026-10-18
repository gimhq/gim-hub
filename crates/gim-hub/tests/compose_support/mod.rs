//! Shared driver code of the compose acceptance suites
//! (`fed_compose.rs`, `multihoming_compose.rs`): HTTP and Docker access to
//! the hubs of `deploy/federation/compose.yaml`, device-side CBOR, and MLS
//! clients signed in over the client API v2.

#![allow(dead_code)]

use std::{
    future::Future,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::Signer;
use gim_hub_identity::{
    parse_public_key, verify_hub_proof, AuthChallenge, HubId, AUTH_CHALLENGE_V2,
    AUTH_RESPONSE_CONTEXT, HOSTING_RECORD_CONTEXT,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, LeafNodeIndex, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    OpenMlsProvider, ProcessedMessageContent, ProtocolVersion, StagedWelcome,
    MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};

use super::mls_support::{
    b64, capabilities, device_id, device_list, encode, gim_credential, group_path, key, signer,
    unb64, user_id, CIPHERSUITE, GIM_CREDENTIAL,
};

pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Upper bound of every wait for federation to converge.
pub const CONVERGE: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// HTTP and Docker
// ---------------------------------------------------------------------------

/// One HTTP/1.1 request; returns the status and the JSON body (`Null` if
/// empty), or a transport error.
pub async fn http(
    base: &str,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(StatusCode, Value), String> {
    let mut headers = Vec::new();
    let payload = match body {
        Some(body) => {
            headers.push((header::CONTENT_TYPE, "application/json".to_owned()));
            body.to_string().into_bytes()
        }
        None => Vec::new(),
    };
    let (status, _, bytes) = http_bytes(base, method, path, token, &headers, payload).await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|err| format!("{base}{path}: {err}"))?
    };
    Ok((status, value))
}

/// One HTTP/1.1 request with a raw body and extra `headers`; returns the
/// status, the response headers and the raw body, or a transport error.
pub async fn http_bytes(
    base: &str,
    method: Method,
    path: &str,
    token: Option<&str>,
    headers: &[(header::HeaderName, String)],
    body: Vec<u8>,
) -> Result<(StatusCode, header::HeaderMap, Bytes), String> {
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
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        sender.send_request(request.body(Full::new(Bytes::from(body))).unwrap()),
    )
    .await
    .map_err(|_| format!("{base}{path}: timed out"))?
    .map_err(|err| err.to_string())?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|err| err.to_string())?
        .to_bytes();
    Ok((status, response_headers, bytes))
}

/// A Docker Engine API call over the unix socket (curl is in the rust image).
pub fn docker(method: &str, path: &str) -> String {
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

/// A Docker Engine API call with a JSON body.
fn docker_json(path: &str, body: &Value) -> String {
    let socket =
        std::env::var("GIM_FED_DOCKER_SOCKET").unwrap_or_else(|_| "/var/run/docker.sock".into());
    let output = Command::new("curl")
        .args([
            "-sS",
            "--fail-with-body",
            "--unix-socket",
            &socket,
            "-X",
            "POST",
        ])
        .args(["-H", "Content-Type: application/json", "-d"])
        .arg(body.to_string())
        .arg(format!("http://localhost{path}"))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "docker POST {path}: {text} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

/// A hub of the compose project.
#[derive(Clone)]
pub struct Hub {
    pub service: &'static str,
    pub base: String,
}

impl Hub {
    pub fn from_env(service: &'static str, var: &str) -> Self {
        Self {
            service,
            base: std::env::var(var).unwrap_or_else(|_| panic!("{var} is not set")),
        }
    }

    pub fn container(&self) -> String {
        let project = std::env::var("GIM_FED_PROJECT").unwrap_or_else(|_| "gim-fed".into());
        format!("{project}-{}-1", self.service)
    }

    pub fn stop(&self) {
        docker(
            "POST",
            &format!("/containers/{}/stop?t=10", self.container()),
        );
    }

    pub async fn start(&self) {
        docker("POST", &format!("/containers/{}/start", self.container()));
        self.wait_healthy().await;
    }

    /// Runs `cmd` in the hub's container (`docker exec`); asserts exit 0
    /// and returns the output.
    pub fn exec(&self, cmd: &[&str]) -> String {
        let created = docker_json(
            &format!("/containers/{}/exec", self.container()),
            &json!({ "Cmd": cmd, "AttachStdout": true, "AttachStderr": true }),
        );
        let id = serde_json::from_str::<Value>(&created).unwrap()["Id"]
            .as_str()
            .unwrap()
            .to_owned();
        let output = docker_json(
            &format!("/exec/{id}/start"),
            &json!({ "Detach": false, "Tty": false }),
        );
        let inspect: Value =
            serde_json::from_str(&docker("GET", &format!("/exec/{id}/json"))).unwrap();
        assert_eq!(inspect["ExitCode"], 0, "{} {cmd:?}: {output}", self.service);
        output
    }

    pub fn logs(&self) -> String {
        docker(
            "GET",
            &format!("/containers/{}/logs?stdout=1&stderr=1", self.container()),
        )
    }

    pub async fn wait_healthy(&self) {
        eventually(&format!("{} /healthz", self.service), || async {
            matches!(
                http(&self.base, Method::GET, "/healthz", None, None).await,
                Ok((StatusCode::OK, _))
            )
        })
        .await;
    }

    pub async fn call(
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

    /// The hub's `GIM_HUB_PUBLIC_URL`: the driver's base URL.
    pub fn public_url(&self) -> &str {
        self.base.trim_end_matches('/')
    }

    /// Checks GET /v2/hub?nonce= as a client would: `hub_id` is
    /// `expected_hub_id` and derives from `hub_root_pubkey`, `public_url`
    /// is the URL called, and `proof` verifies under the root key; a second
    /// nonce gives another proof.
    pub async fn check_proof(&self, expected_hub_id: &str) {
        let mut proofs = Vec::new();
        for nonce in [[0x5a; 32], [0xa5; 32]] {
            let path = format!("/v2/hub?nonce={}", URL_SAFE_NO_PAD.encode(nonce));
            let (status, body) = self.call(Method::GET, &path, None, None).await;
            assert_eq!(status, StatusCode::OK, "{} {path}: {body}", self.service);
            assert_eq!(body["hub_id"], expected_hub_id, "{}", self.service);
            assert_eq!(body["public_url"], self.public_url(), "{}", self.service);
            let root = parse_public_key(&unb64(&body["hub_root_pubkey"])).unwrap();
            let proof: [u8; 64] = URL_SAFE_NO_PAD
                .decode(body["proof"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let hub_id = HubId::parse(expected_hub_id).unwrap();
            verify_hub_proof(&root, &hub_id, &nonce, self.public_url(), &proof)
                .unwrap_or_else(|err| panic!("{} proof: {err}", self.service));
            proofs.push(proof);
        }
        assert_ne!(proofs[0], proofs[1]);
    }
}

/// Polls `check` every 200 ms until it holds, for at most [`CONVERGE`].
pub async fn eventually<F, Fut>(what: &str, mut check: F)
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

pub fn now_ms() -> u64 {
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

pub fn head(major: u8, n: u64) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | n as u8],
        24..=0xff => vec![major | 24, n as u8],
        0x100..=0xffff => [vec![major | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![major | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![major | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

pub fn bstr(bytes: &[u8]) -> Vec<u8> {
    [head(2, bytes.len() as u64), bytes.to_vec()].concat()
}

pub fn tstr(text: &str) -> Vec<u8> {
    [head(3, text.len() as u64), text.as_bytes().to_vec()].concat()
}

/// AuthResponse `[1, challenge, user_id, device_id, sig]`, signed by the
/// device key over `[challenge, user_id, device_id]`.
pub fn auth_response(challenge: &[u8], user_id: &str, device_id: &str, device_seed: u8) -> Vec<u8> {
    let fields = [bstr(challenge), tstr(user_id), tstr(device_id)].concat();
    let tbs = [head(4, 3), fields.clone()].concat();
    let sig = key(device_seed).sign(&[AUTH_RESPONSE_CONTEXT, &[0], &tbs].concat());
    [head(4, 5), head(0, 1), fields, bstr(&sig.to_bytes())].concat()
}

/// `SignedHostingRecord` of the user with root key `key(root_seed)` listing
/// the hub-signed `entries` (CBOR `HostingEntry`, as returned by the hub).
pub fn hosting_record(root_seed: u8, seq: u64, expires_at: u64, entries: &[&[u8]]) -> Vec<u8> {
    let root = key(root_seed);
    let tbs = [
        head(4, 6),
        head(0, 1),
        tstr(&user_id(root_seed)),
        bstr(root.verifying_key().as_bytes()),
        head(0, seq),
        head(0, expires_at),
        head(4, entries.len() as u64),
        entries.concat(),
    ]
    .concat();
    let sig = root.sign(&[HOSTING_RECORD_CONTEXT, &[0], &tbs].concat());
    [head(4, 2), bstr(&tbs), bstr(&sig.to_bytes())].concat()
}

// ---------------------------------------------------------------------------
// MLS clients over HTTP
// ---------------------------------------------------------------------------

/// One device of a user hosted on `hub`, signed in over the client API.
pub struct User {
    pub name: &'static str,
    pub hub: Hub,
    pub user_id: String,
    pub device_id: String,
    pub token: String,
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
}

impl User {
    /// Uploads a DeviceList certifying device `key(device_seed)`, signs in
    /// with challenge/response, uploads `key_packages` KeyPackages and
    /// publishes a hosting record listing `hub`.
    pub async fn sign_up(
        name: &'static str,
        hub: &Hub,
        root_seed: u8,
        device_seed: u8,
        key_packages: usize,
    ) -> Self {
        let uid = user_id(root_seed);
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
        let user = Self::sign_in(name, hub, root_seed, device_seed, key_packages).await;
        user.publish_hosting_record(root_seed).await;
        user
    }

    /// Signs in device `key(device_seed)`, which the user's DeviceList
    /// certifies, with challenge/response and uploads `key_packages`
    /// KeyPackages.
    pub async fn sign_in(
        name: &'static str,
        hub: &Hub,
        root_seed: u8,
        device_seed: u8,
        key_packages: usize,
    ) -> Self {
        let (uid, did) = (user_id(root_seed), device_id(device_seed));
        let (status, body) = hub
            .call(
                Method::POST,
                "/v2/auth/challenge",
                None,
                Some(json!({ "user_id": uid, "device_id": did })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{name} challenge: {body}");
        // A federating hub issues v2 challenges bound to its public URL.
        let challenge = unb64(&body["challenge"]);
        let decoded = AuthChallenge::decode(&challenge).unwrap();
        assert_eq!(decoded.version(), AUTH_CHALLENGE_V2, "{name} challenge");
        assert_eq!(decoded.audience(), body["hub_id"], "{name} challenge");
        assert_eq!(
            decoded.audience_url(),
            Some(hub.public_url()),
            "{name} challenge"
        );
        let response = auth_response(&challenge, &uid, &did, device_seed);
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
        user
    }

    /// POST hosting-entry, sign the record with the user root key, PUT it.
    pub async fn publish_hosting_record(&self, root_seed: u8) {
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
        let record = hosting_record(
            root_seed,
            1,
            now_ms() + 7 * DAY_MS,
            &[&unb64(&body["entry"])],
        );
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

    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.hub.call(method, path, Some(&self.token), body).await
    }

    pub fn key_package(&self) -> Vec<u8> {
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
    pub async fn claim(&self, target: &User) -> KeyPackage {
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

    pub async fn create_group(&self, kind: &str) -> (String, MlsGroup) {
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
    pub async fn events_of(&self, event_type: &str) -> Vec<Value> {
        let mut events = Vec::new();
        let mut cursor = 0;
        loop {
            let (status, body) = self
                .call(
                    Method::GET,
                    &format!("/v2/events?cursor={cursor}&limit=500"),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let page = body["events"].as_array().unwrap();
            if page.is_empty() {
                return events;
            }
            events.extend(
                page.iter()
                    .filter(|event| event["type"] == event_type)
                    .map(|event| event["data"].clone()),
            );
            cursor = body["next_cursor"].as_u64().unwrap();
        }
    }

    /// Seqs of this device's `message` events of `gid`, in delivery order.
    pub async fn message_seqs(&self, gid: &str) -> Vec<u64> {
        self.events_of("message")
            .await
            .iter()
            .filter(|event| event["gid"] == gid)
            .map(|event| event["seq"].as_u64().unwrap())
            .collect()
    }

    pub async fn wait_message(&self, gid: &str, seq: u64) -> Value {
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
    pub async fn receive(&self, group: &mut MlsGroup, gid: &str, seq: u64) -> Option<Vec<u8>> {
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
    pub async fn join(&self, gid: &str) -> MlsGroup {
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

    pub async fn submit_commit(&self, gid: &str, body: Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            &format!("{}/commits", group_path(gid)),
            Some(body),
        )
        .await
    }

    pub async fn post_message(
        &self,
        gid: &str,
        client_id: &str,
        mls: &[u8],
    ) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            &format!("{}/messages", group_path(gid)),
            Some(json!({ "client_id": client_id, "mls_message": b64(mls) })),
        )
        .await
    }

    /// Encrypts and sends an application message; asserts it got `seq`.
    pub async fn send_text(&self, group: &mut MlsGroup, gid: &str, text: &str, seq: u64) {
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
    pub async fn log(&self, gid: &str) -> Vec<(u64, String, String)> {
        let mut log = Vec::new();
        let mut from_seq = 1;
        loop {
            let (status, body) = self
                .call(
                    Method::GET,
                    &format!("{}/messages?from_seq={from_seq}&limit=500", group_path(gid)),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            log.extend(body["messages"].as_array().unwrap().iter().map(|m| {
                (
                    m["seq"].as_u64().unwrap(),
                    m["client_id"].as_str().unwrap().to_owned(),
                    m["mls_message"].as_str().unwrap().to_owned(),
                )
            }));
            match log.last() {
                Some((seq, ..)) if body["has_more"] == true => from_seq = seq + 1,
                _ => return log,
            }
        }
    }

    pub async fn roster(&self, gid: &str) -> (StatusCode, Vec<String>) {
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

pub fn application(user: &User, group: &mut MlsGroup, text: &[u8]) -> Vec<u8> {
    group
        .create_message(&user.provider, &user.signer, text)
        .unwrap()
        .to_bytes()
        .unwrap()
}

pub fn commit_body(client_id: &str, commit: &MlsMessageOut) -> Value {
    json!({ "client_id": client_id, "mls_message": encode(commit) })
}

pub fn with_welcome(mut body: Value, welcome: &MlsMessageOut, recipients: &[&User]) -> Value {
    body["welcome"] = json!(encode(welcome));
    body["welcome_recipients"] = recipients
        .iter()
        .map(|u| json!({ "user_id": u.user_id, "device_id": u.device_id }))
        .collect();
    body
}

pub fn leaf_of(group: &MlsGroup, user: &User) -> LeafNodeIndex {
    group
        .members()
        .find(|m| m.signature_key == user.credential.signature_key.as_slice())
        .unwrap()
        .index
}

pub fn sorted(ids: &[&str]) -> Vec<String> {
    let mut ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    ids.sort();
    ids
}
