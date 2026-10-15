//! Shared helpers of the KeyPackage and group tests: JSON requests, real MLS
//! clients (openmls) with gim credentials (type 0xF001) and direct reads of
//! the event stream.

#![allow(dead_code)]

#[path = "../identity_support/mod.rs"]
mod identity_support;

pub use identity_support::{device_id, device_list, key, put_device_list, user_id};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_api::testing::TestHub;
use gim_hub_identity::{DeviceList, UserId, GIM_CREDENTIAL_TYPE};
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey, GroupId, KeyPackage,
    KeyPackageIn, MlsGroup, MlsGroupCreateConfig, MlsMessageOut, OpenMlsProvider, ProtocolVersion,
    WireFormatPolicy, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
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

/// The gim MLS credential type.
pub const GIM_CREDENTIAL: CredentialType = CredentialType::Other(GIM_CREDENTIAL_TYPE);

/// Leaf capabilities whose only supported credential type is `credential_type`.
pub fn capabilities(credential_type: CredentialType) -> Capabilities {
    Capabilities::new(None, None, None, None, Some(&[credential_type]))
}

/// The gim credential of the device `key(device_seed)` of the user with
/// root key `key(root_seed)`: deterministic CBOR
/// `[1, root_pubkey, signed_device_cert]`.
pub fn gim_credential(root_seed: u8, device_seed: u8) -> Credential {
    let user = UserId::parse(&user_id(root_seed)).unwrap();
    let list = DeviceList::verify(&device_list(root_seed, 1, &[device_seed], &[]), &user).unwrap();
    let cert = list.certs()[0].as_bytes();
    let mut content = vec![0x83, 0x01, 0x58, 0x20];
    content.extend(key(root_seed).verifying_key().as_bytes());
    match u8::try_from(cert.len()) {
        Ok(len) if len >= 24 => content.extend([0x58, len]),
        _ => {
            content.push(0x59);
            content.extend(u16::try_from(cert.len()).unwrap().to_be_bytes());
        }
    }
    content.extend(cert);
    Credential::new(GIM_CREDENTIAL, content)
}

/// The openmls signer of the device key `key(device_seed)`.
pub fn signer(device_seed: u8) -> SignatureKeyPair {
    let device = key(device_seed);
    SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        device.to_bytes().to_vec(),
        device.verifying_key().to_bytes().to_vec(),
    )
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
    /// The device `key(device_seed)` of the user with root key
    /// `key(root_seed)`, after uploading a DeviceList (seq 1) that
    /// certifies just this device.
    pub async fn new(hub: &TestHub, root_seed: u8, device_seed: u8) -> Self {
        let list = device_list(root_seed, 1, &[device_seed], &[]);
        let (status, body) = put_device_list(hub, &user_id(root_seed), &list).await;
        assert!(status.is_success(), "{body}");
        Self::signed_in(hub, root_seed, device_seed).await
    }

    /// Like [`Client::new`], without uploading a DeviceList.
    pub async fn signed_in(hub: &TestHub, root_seed: u8, device_seed: u8) -> Self {
        let (user_id, device_id) = (user_id(root_seed), device_id(device_seed));
        let provider = OpenMlsRustCrypto::default();
        let signer = signer(device_seed);
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: gim_credential(root_seed, device_seed),
            signature_key: signer.public().into(),
        };
        Self {
            token: hub.create_session(&user_id, &device_id).await,
            user_id,
            device_id,
            provider,
            signer,
            credential,
        }
    }

    /// A fresh serialized KeyPackage.
    pub fn key_package(&self) -> Vec<u8> {
        self.key_package_with(self.credential.clone(), &self.signer)
    }

    /// A fresh serialized KeyPackage with any credential and signer.
    pub fn key_package_with(
        &self,
        credential: CredentialWithKey,
        signer: &SignatureKeyPair,
    ) -> Vec<u8> {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities(credential.credential.credential_type()))
            .build(CIPHERSUITE, &self.provider, signer, credential)
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
