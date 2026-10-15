//! Shared helpers of the KeyPackage and group tests: JSON requests, real MLS
//! clients (openmls) and direct reads of the event stream.

#![allow(dead_code)]

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_api::testing::TestHub;
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, MlsMessageOut, OpenMlsProvider, ProtocolVersion, WireFormatPolicy,
    MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};
use tower::ServiceExt;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Sends a request with an optional bearer token and JSON body; returns the
/// status and the JSON body (`Null` if empty).
pub async fn send(
    hub: &TestHub,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = hub
        .router()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

pub fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or("")
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(text: &Value) -> Vec<u8> {
    STANDARD.decode(text.as_str().unwrap()).unwrap()
}

pub fn encode(message: &MlsMessageOut) -> String {
    b64(&message.tls_serialize_detached().unwrap())
}

/// Path of a group with the gid percent-encoded.
pub fn group_path(gid: &str) -> String {
    format!("/v2/groups/{}", gid.replace('/', "%2F"))
}

/// An MLS client signed in to the hub as one device.
pub struct Client {
    pub user_id: String,
    pub device_id: String,
    pub token: String,
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
}

impl Client {
    pub async fn new(hub: &TestHub, user_id: &str, device_id: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(format!("{user_id}/{device_id}").into_bytes()).into(),
            signature_key: signer.public().into(),
        };
        Self {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            token: hub.create_session(user_id, device_id).await,
            provider,
            signer,
            credential,
        }
    }

    /// A fresh serialized KeyPackage.
    pub fn key_package(&self) -> Vec<u8> {
        KeyPackage::builder()
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

    /// Uploads `count` one-time KeyPackages.
    pub async fn upload_key_packages(&self, hub: &TestHub, count: usize) -> Value {
        let packages: Vec<String> = (0..count).map(|_| b64(&self.key_package())).collect();
        let (status, body) = send(
            hub,
            Method::POST,
            "/v2/keypackages",
            &self.token,
            Some(json!({ "key_packages": packages })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Creates a hub group and the matching MLS group (MLS group ID = gid
    /// bytes) with the given wire-format policy.
    pub async fn create_group_with(
        &self,
        hub: &TestHub,
        policy: WireFormatPolicy,
    ) -> (String, MlsGroup) {
        let (status, body) = send(
            hub,
            Method::POST,
            "/v2/groups",
            &self.token,
            Some(json!({ "kind": "group" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let gid = body["gid"].as_str().unwrap().to_owned();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(policy)
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

    /// A group whose handshake messages are PublicMessages.
    pub async fn create_group(&self, hub: &TestHub) -> (String, MlsGroup) {
        self.create_group_with(hub, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .await
    }

    /// Claims one KeyPackage of `target`'s device through the hub.
    pub async fn claim(&self, hub: &TestHub, target: &Client) -> KeyPackage {
        let (status, body) = send(
            hub,
            Method::POST,
            "/v2/keypackages/claim",
            &self.token,
            Some(json!({ "targets": [{ "user_id": target.user_id, "device_id": target.device_id }] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let bytes = unb64(&body["key_packages"][0]["key_package"]);
        KeyPackageIn::tls_deserialize_exact(bytes)
            .unwrap()
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .unwrap()
    }

    pub async fn submit_commit(
        &self,
        hub: &TestHub,
        gid: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        send(
            hub,
            Method::POST,
            &format!("{}/commits", group_path(gid)),
            &self.token,
            Some(body),
        )
        .await
    }

    /// Events of this device as `(type, data)`.
    pub async fn events(&self, hub: &TestHub) -> Vec<(String, Value)> {
        let (user_id, device_id) = (self.user_id.clone(), self.device_id.clone());
        hub.state
            .db
            .read(move |conn| gim_hub_db::events::list_after(conn, &user_id, &device_id, 0, 500))
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.event_type, serde_json::from_str(&e.payload).unwrap()))
            .collect()
    }

    /// Data of this device's events of one type.
    pub async fn events_of(&self, hub: &TestHub, event_type: &str) -> Vec<Value> {
        self.events(hub)
            .await
            .into_iter()
            .filter(|(t, _)| t == event_type)
            .map(|(_, data)| data)
            .collect()
    }
}
