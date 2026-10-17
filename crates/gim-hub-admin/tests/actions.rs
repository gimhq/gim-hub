//! Admin reads and mutations: every mutation and its audit entry,
//! suspension against real sign-in, the allowlist, lode and the redacted
//! configuration.

mod support;

use std::sync::Arc;

use axum::http::{header, Method, Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use gim_hub_api::{testing::TestHub, Config, HubIdentity};
use gim_hub_db::{
    groups,
    users::{self, Device, StoredDeviceList},
};
use gim_hub_identity::{DeviceList, UserId, AUTH_RESPONSE_CONTEXT};
use gim_hub_s2s::{Decision, FederationConfig, FederationPolicy, FederationService};
use serde_json::{json, Value};
use support::{Admin, Options};
use tower::ServiceExt;

fn vectors(name: &str) -> Value {
    let path = format!(
        "{}/../../testdata/identity/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn text(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

/// Stores the auth.json DeviceList and its devices, as the upload does.
async fn store_vector_user(hub: &TestHub) {
    let v = vectors("auth");
    let user_id = text(&v["user_id"]);
    let signed = hex_bytes(&v["device_list"]);
    let list = DeviceList::verify(&signed, &UserId::parse(&user_id).unwrap()).unwrap();
    let now = hub.state.clock.now_ms();
    hub.state
        .db
        .write(move |tx| {
            users::put_device_list(
                tx,
                &StoredDeviceList {
                    user_id: user_id.clone(),
                    root_pubkey: list.root_pubkey().as_bytes().to_vec(),
                    device_list: signed,
                    seq: i64::try_from(list.seq()).unwrap(),
                    updated_at: now,
                },
            )?;
            for cert in list.certs() {
                users::put_device(
                    tx,
                    &Device {
                        user_id: user_id.clone(),
                        device_id: cert.device_id().to_string(),
                        sig_pubkey: cert.device_sig_pubkey().as_bytes().to_vec(),
                        active: true,
                    },
                    now,
                )?;
            }
            Ok::<_, gim_hub_db::DbError>(())
        })
        .await
        .unwrap();
}

fn head(major: u8, len: usize) -> Vec<u8> {
    let major = major << 5;
    match u8::try_from(len) {
        Ok(len) if len < 24 => vec![major | len],
        Ok(len) => vec![major | 24, len],
        Err(_) => [
            &[major | 25][..],
            &u16::try_from(len).unwrap().to_be_bytes(),
        ]
        .concat(),
    }
}

fn bstr(bytes: &[u8]) -> Vec<u8> {
    [head(2, bytes.len()), bytes.to_vec()].concat()
}

fn tstr(text: &str) -> Vec<u8> {
    [head(3, text.len()), text.as_bytes().to_vec()].concat()
}

/// Device-side AuthResponse over `challenge`.
fn sign_response(challenge: &[u8], user_id: &str, device_id: &str, key: &SigningKey) -> Vec<u8> {
    let fields = [bstr(challenge), tstr(user_id), tstr(device_id)].concat();
    let tbs = [head(4, 3), fields.clone()].concat();
    let sig = key.sign(&[AUTH_RESPONSE_CONTEXT, &[0], &tbs].concat());
    [head(4, 5), vec![0x01], fields, bstr(&sig.to_bytes())].concat()
}

async fn client_post(hub: &TestHub, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// Signs in the vector device: challenge, then session.
async fn sign_in(hub: &TestHub) -> ((StatusCode, Value), Option<(StatusCode, Value)>) {
    let v = vectors("auth");
    let (user_id, device_id) = (text(&v["user_id"]), text(&v["device_id"]));
    let challenge = client_post(
        hub,
        "/v2/auth/challenge",
        json!({ "user_id": user_id, "device_id": device_id }),
    )
    .await;
    if challenge.0 != StatusCode::OK {
        return (challenge, None);
    }
    let bytes = STANDARD.decode(text(&challenge.1["challenge"])).unwrap();
    let key = SigningKey::from_bytes(&hex_bytes(&v["device_seed"]).try_into().unwrap());
    let response = sign_response(&bytes, &user_id, &device_id, &key);
    let session = client_post(
        hub,
        "/v2/auth/session",
        json!({ "response": STANDARD.encode(response) }),
    )
    .await;
    (challenge, Some(session))
}

async fn me_status(hub: &TestHub, token: &str) -> StatusCode {
    let request = Request::get("/v2/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    hub.router().oneshot(request).await.unwrap().status()
}

/// The audit entry fields checked by the tests.
fn audit_row(entry: &Value) -> Value {
    json!([
        entry["actor"],
        entry["action"],
        entry["target"],
        entry["source_ip"],
        entry["result"]
    ])
}

#[tokio::test]
async fn suspended_user_cannot_sign_in_until_unsuspended() {
    let admin = Admin::new();
    let hub = &admin.hub;
    store_vector_user(hub).await;
    let v = vectors("auth");
    let user_id = text(&v["user_id"]);

    let (challenge, session) = sign_in(hub).await;
    assert_eq!(challenge.0, StatusCode::OK, "{}", challenge.1);
    let (status, body) = session.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = text(&body["token"]);
    assert_eq!(me_status(hub, &token).await, StatusCode::OK);

    // A challenge issued before the suspension cannot be answered after it.
    let pending = client_post(
        hub,
        "/v2/auth/challenge",
        json!({ "user_id": user_id, "device_id": text(&v["device_id"]) }),
    )
    .await;
    assert_eq!(pending.0, StatusCode::OK);

    let login = admin.login().await;
    let suspend = admin
        .call(
            Method::POST,
            &format!("/admin/api/users/{user_id}/suspend"),
            &login,
            Some(&json!({ "reason": "spam" })),
        )
        .await;
    assert_eq!(suspend.status, StatusCode::NO_CONTENT, "{}", suspend.body);
    assert_eq!(me_status(hub, &token).await, StatusCode::UNAUTHORIZED);

    let (challenge, _) = sign_in(hub).await;
    assert_eq!(challenge.0, StatusCode::FORBIDDEN);
    assert_eq!(
        challenge.1,
        json!({ "error": { "code": "user_suspended", "message": "user is suspended" } })
    );
    let bytes = STANDARD.decode(text(&pending.1["challenge"])).unwrap();
    let key = SigningKey::from_bytes(&hex_bytes(&v["device_seed"]).try_into().unwrap());
    let response = sign_response(&bytes, &user_id, &text(&v["device_id"]), &key);
    let (status, body) = client_post(
        hub,
        "/v2/auth/session",
        json!({ "response": STANDARD.encode(response) }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({ "error": { "code": "user_suspended", "message": "user is suspended" } })
    );

    let detail = admin
        .call(
            Method::GET,
            &format!("/admin/api/users/{user_id}"),
            &login,
            None,
        )
        .await;
    assert_eq!(detail.body["suspended"], true);
    assert!(detail.body["suspended_at"].is_i64());
    let again = admin
        .call(
            Method::POST,
            &format!("/admin/api/users/{user_id}/suspend"),
            &login,
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "conflict");

    let unsuspend = admin
        .call(
            Method::POST,
            &format!("/admin/api/users/{user_id}/unsuspend"),
            &login,
            Some(&json!({})),
        )
        .await;
    assert_eq!(unsuspend.status, StatusCode::NO_CONTENT);
    let (challenge, session) = sign_in(hub).await;
    assert_eq!(challenge.0, StatusCode::OK);
    assert_eq!(session.unwrap().0, StatusCode::OK);
    let not_suspended = admin
        .call(
            Method::POST,
            &format!("/admin/api/users/{user_id}/unsuspend"),
            &login,
            None,
        )
        .await;
    assert_eq!(not_suspended.status, StatusCode::CONFLICT);

    let audit = admin.audit(&login).await;
    let rows: Vec<Value> = audit.iter().take(4).map(audit_row).collect();
    assert_eq!(
        rows,
        [
            json!(["token", "user_unsuspend", user_id, "127.0.0.1", "error"]),
            json!(["token", "user_unsuspend", user_id, "127.0.0.1", "ok"]),
            json!(["token", "user_suspend", user_id, "127.0.0.1", "error"]),
            json!(["token", "user_suspend", user_id, "127.0.0.1", "ok"]),
        ]
    );
    assert_eq!(audit[3]["detail"], "spam");
    let unknown = admin
        .call(
            Method::POST,
            "/admin/api/users/nobody/suspend",
            &login,
            None,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn users_devices_sessions_and_handles() {
    let admin = Admin::new();
    let hub = &admin.hub;
    let token = hub.create_session("u-alice", "d1").await;
    hub.create_session("u-alice", "d2").await;
    hub.create_session("u-bob", "d1").await;
    let now = hub.state.clock.now_ms();
    hub.state
        .db
        .write(move |tx| {
            gim_hub_db::handles::claim(tx, "alice", "u-alice", now)?;
            groups::create(
                tx,
                &groups::Group {
                    gid: "hub/g1".into(),
                    kind: "group".into(),
                    epoch: 0,
                    last_seq: 0,
                    created_by_user_id: "u-alice".into(),
                    created_by_device_id: "d1".into(),
                    created_at: now,
                },
            )
        })
        .await
        .unwrap();
    let login = admin.login().await;

    let list = admin
        .call(Method::GET, "/admin/api/users?q=ALI&limit=10", &login, None)
        .await;
    assert_eq!(list.status, StatusCode::OK);
    let now_s = now / 1000;
    assert_eq!(
        list.body,
        json!({
            "items": [{
                "user_id": "u-alice",
                "handle": "alice",
                "suspended": false,
                "created_at": now_s,
                "device_count": 2,
                "last_seen": now_s,
            }],
            "next_cursor": null,
        })
    );
    let page = admin
        .call(Method::GET, "/admin/api/users?limit=1", &login, None)
        .await;
    assert_eq!(page.body["items"][0]["user_id"], "u-alice");
    let cursor = text(&page.body["next_cursor"]);
    let next = admin
        .call(
            Method::GET,
            &format!("/admin/api/users?limit=1&cursor={cursor}"),
            &login,
            None,
        )
        .await;
    assert_eq!(next.body["items"][0]["user_id"], "u-bob");
    assert_eq!(next.body["next_cursor"], Value::Null);
    for bad in ["limit=0", "limit=101", "cursor=%%%", "limit=x"] {
        let response = admin
            .call(
                Method::GET,
                &format!("/admin/api/users?{bad}"),
                &login,
                None,
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad}");
    }

    let detail = admin
        .call(Method::GET, "/admin/api/users/u-alice", &login, None)
        .await;
    assert_eq!(detail.status, StatusCode::OK);
    // A5: metadata only, no group data.
    let keys: Vec<&String> = detail.body.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "created_at",
            "devices",
            "handle",
            "hosting_hubs",
            "suspended",
            "suspended_at",
            "user_id"
        ]
    );
    assert!(!detail.body.to_string().contains("hub/g1"));
    let devices = detail.body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0]["device_id"], "d1");
    assert_eq!(devices[0]["active"], true);
    assert_eq!(devices[0]["last_seen"], now_s);
    let session_ref = text(&devices[0]["sessions"][0]["session_ref"]);
    assert_eq!(session_ref.len(), 16);
    assert!(!detail.body.to_string().contains(&token));
    let unknown = admin
        .call(Method::GET, "/admin/api/users/nobody", &login, None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let revoke = admin
        .call(
            Method::DELETE,
            "/admin/api/users/u-alice/devices/d1/sessions",
            &login,
            None,
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK);
    assert_eq!(revoke.body, json!({ "revoked": 1 }));
    assert_eq!(me_status(hub, &token).await, StatusCode::UNAUTHORIZED);
    let missing = admin
        .call(
            Method::DELETE,
            "/admin/api/users/u-alice/devices/d9/sessions",
            &login,
            None,
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let release = admin
        .call(
            Method::POST,
            "/admin/api/handles/alice/release",
            &login,
            None,
        )
        .await;
    assert_eq!(release.status, StatusCode::NO_CONTENT);
    let again = admin
        .call(
            Method::POST,
            "/admin/api/handles/alice/release",
            &login,
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    let user = admin
        .call(Method::GET, "/admin/api/users/u-alice", &login, None)
        .await;
    assert_eq!(user.body["handle"], Value::Null);

    let overview = admin
        .call(Method::GET, "/admin/api/overview", &login, None)
        .await;
    assert_eq!(overview.status, StatusCode::OK);
    assert_eq!(
        overview.body["counts"],
        json!({ "users": 2, "devices": 3, "groups": 1, "blobs": 0 })
    );
    assert_eq!(overview.body["hub_id"], hub.state.hub.hub_id().as_str());
    assert_eq!(overview.body["event_retention_days"], 7);
    assert_eq!(overview.body["push"]["sent"], 0);
    assert!(overview.body["storage"]["db_bytes"].is_u64());

    let rows: Vec<Value> = admin
        .audit(&login)
        .await
        .iter()
        .take(4)
        .map(audit_row)
        .collect();
    assert_eq!(
        rows,
        [
            json!(["token", "handle_release", "alice", "127.0.0.1", "error"]),
            json!(["token", "handle_release", "alice", "127.0.0.1", "ok"]),
            json!([
                "token",
                "device_sessions_revoke",
                "u-alice/d9",
                "127.0.0.1",
                "error"
            ]),
            json!([
                "token",
                "device_sessions_revoke",
                "u-alice/d1",
                "127.0.0.1",
                "ok"
            ]),
        ]
    );
}

#[tokio::test]
async fn audit_log_pages() {
    let admin = Admin::new();
    let login = admin.login().await;
    for _ in 0..3 {
        admin
            .call(Method::POST, "/admin/api/lode/check", &login, None)
            .await;
    }
    let first = admin
        .call(Method::GET, "/admin/api/audit?limit=2", &login, None)
        .await;
    let items = first.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[0]["id"].as_i64() > items[1]["id"].as_i64());
    let cursor = text(&first.body["next_cursor"]);
    let rest = admin
        .call(
            Method::GET,
            &format!("/admin/api/audit?limit=2&cursor={cursor}"),
            &login,
            None,
        )
        .await;
    let items = rest.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[1]["action"], "login_ok");
    assert_eq!(rest.body["next_cursor"], Value::Null);
    let bad = admin
        .call(Method::GET, "/admin/api/audit?limit=201", &login, None)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

async fn federated_admin() -> (Admin, Arc<std::path::PathBuf>) {
    let hub = TestHub::new();
    let data_dir = hub.state.config.data_dir.clone();
    let allowlist = data_dir.join("allowlist");
    let peer = HubIdentity::from_seed(&[9; 32]);
    std::fs::write(
        &allowlist,
        format!("{} /ip4/127.0.0.1/tcp/4999\n", peer.hub_id()),
    )
    .unwrap();
    let config = FederationConfig::from_vars(
        [
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_LISTEN", "/ip4/127.0.0.1/tcp/0"),
            ("GIM_HUB_FEDERATION_ALLOWLIST", allowlist.to_str().unwrap()),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned())),
        &data_dir,
    )
    .unwrap();
    let service = FederationService::start_with_allowlist(&config, hub.state.hub.signing_key())
        .await
        .unwrap();
    let admin = Admin::with(
        hub,
        Options {
            federation: Some((config, service)),
            ..Options::default()
        },
    );
    (admin, Arc::new(allowlist))
}

#[tokio::test]
async fn allowlist_edit_takes_effect_immediately() {
    let (admin, path) = federated_admin().await;
    let federation = admin.state.federation.clone().unwrap();
    let policy = federation.allowlist().unwrap().clone();
    let old = HubIdentity::from_seed(&[9; 32]).hub_id().clone();
    let new = HubIdentity::from_seed(&[10; 32]).hub_id().clone();
    assert_eq!(policy.allow_hub(&old), Decision::Allow);
    assert!(matches!(policy.allow_hub(&new), Decision::Deny(_)));
    let login = admin.login().await;

    let get = admin
        .call(Method::GET, "/admin/api/federation/allowlist", &login, None)
        .await;
    assert_eq!(get.status, StatusCode::OK);
    assert_eq!(get.body["path"], path.display().to_string());
    assert_eq!(
        get.body["entries"],
        json!([{ "hub_id": old.as_str(), "addrs": ["/ip4/127.0.0.1/tcp/4999"] }])
    );

    let status = admin
        .call(Method::GET, "/admin/api/federation", &login, None)
        .await;
    assert_eq!(status.body["enabled"], true);
    assert_eq!(status.body["peer_id"], federation.peer_id());
    assert!(federation.peer_id().starts_with("12D3KooW"));
    assert_eq!(status.body["peers"][0]["hub_id"], old.as_str());
    assert_eq!(status.body["peers"][0]["connected"], false);

    let text = format!("# edited\n{new}\n");
    let put = admin
        .call(
            Method::PUT,
            "/admin/api/federation/allowlist",
            &login,
            Some(&json!({ "text": text })),
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.body);
    assert_eq!(put.body["text"], text);
    assert_eq!(
        put.body["entries"],
        json!([{ "hub_id": new.as_str(), "addrs": [] }])
    );
    assert_eq!(std::fs::read_to_string(&*path).unwrap(), text);
    assert_eq!(policy.allow_hub(&new), Decision::Allow);
    assert!(matches!(policy.allow_hub(&old), Decision::Deny(_)));

    for invalid in ["not-a-hub-id\n", "# nothing\n", &format!("{new} /p2p/x\n")] {
        let response = admin
            .call(
                Method::PUT,
                "/admin/api/federation/allowlist",
                &login,
                Some(&json!({ "text": invalid })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{invalid}"
        );
        assert_eq!(response.code(), "validation_failed");
        assert_eq!(std::fs::read_to_string(&*path).unwrap(), text);
    }
    assert_eq!(policy.allow_hub(&new), Decision::Allow);
    let first_error = admin
        .call(
            Method::PUT,
            "/admin/api/federation/allowlist",
            &login,
            Some(&json!({ "text": "not-a-hub-id\n" })),
        )
        .await;
    assert!(first_error.body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("allowlist line 1:"));

    let audit = admin.audit(&login).await;
    let ok = audit
        .iter()
        .find(|e| e["action"] == "allowlist_update" && e["result"] == "ok")
        .unwrap();
    assert_eq!(
        audit_row(ok),
        json!([
            "token",
            "allowlist_update",
            path.display().to_string(),
            "127.0.0.1",
            "ok"
        ])
    );
    federation.shutdown();
}

#[tokio::test]
async fn federation_off() {
    let admin = Admin::new();
    let login = admin.login().await;
    let status = admin
        .call(Method::GET, "/admin/api/federation", &login, None)
        .await;
    assert_eq!(
        status.body,
        json!({
            "enabled": false,
            "peer_id": null,
            "listen_addrs": [],
            "external_addrs": [],
            "peers": [],
        })
    );
    let get = admin
        .call(Method::GET, "/admin/api/federation/allowlist", &login, None)
        .await;
    assert_eq!(get.status, StatusCode::NOT_FOUND);
    let put = admin
        .call(
            Method::PUT,
            "/admin/api/federation/allowlist",
            &login,
            Some(&json!({ "text": "x" })),
        )
        .await;
    assert_eq!(put.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lode_requests_keep_lodes_fields() {
    let lode_dir = tempfile::tempdir().unwrap();
    let state_path = lode_dir.path().join("state.json");
    let lode_fields = json!({
        "current": "0.2.0",
        "last_good": "0.1.9",
        "available": "0.2.1",
        "status": "running",
        "pid": 4242,
        "last_check": "2026-10-16T08:00:00Z",
        "config_generation": 3,
        "history": [{ "version": "0.1.9", "at": "2026-10-01T00:00:00Z", "result": "good" }],
        "future_field": { "kept": true },
    });
    std::fs::write(&state_path, lode_fields.to_string()).unwrap();
    let admin = Admin::with(
        TestHub::new(),
        Options {
            lode_dir: Some(lode_dir.path().to_owned()),
            ..Options::default()
        },
    );
    let login = admin.login().await;

    let status = admin
        .call(Method::GET, "/admin/api/lode", &login, None)
        .await;
    assert_eq!(
        status.body,
        json!({
            "supervised": true,
            "status": "running",
            "current": "0.2.0",
            "available": "0.2.1",
            "last_good": "0.1.9",
            "last_check": "2026-10-16T08:00:00Z",
            "last_error": null,
            "history": [{ "version": "0.1.9", "at": "2026-10-01T00:00:00Z", "result": "good" }],
        })
    );

    let post = |uri: &'static str, body: Option<Value>| {
        let (admin, login) = (&admin, &login);
        async move { admin.call(Method::POST, uri, login, body.as_ref()).await }
    };
    assert_eq!(
        post("/admin/api/lode/check", Some(json!({}))).await.status,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post(
            "/admin/api/lode/update",
            Some(json!({ "version": "latest" }))
        )
        .await
        .status,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post("/admin/api/lode/restart", Some(json!({})))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post("/admin/api/lode/update", Some(json!({ "version": " " })))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    let mut written: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(written["check_nonce"], 1);
    assert_eq!(written["target"], "latest");
    assert_eq!(written["restart_nonce"], 1);
    assert!(lode_dir.path().join("state.json.lock").is_file());

    assert_eq!(
        post("/admin/api/lode/rollback", Some(json!({})))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    written = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(written["target"], "0.1.9");
    assert_eq!(
        post(
            "/admin/api/lode/rollback",
            Some(json!({ "version": "0.1.5" }))
        )
        .await
        .status,
        StatusCode::ACCEPTED
    );
    written = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(written["target"], "0.1.5");
    let fields = written.as_object_mut().unwrap();
    for key in ["check_nonce", "target", "restart_nonce"] {
        fields.remove(key);
    }
    assert_eq!(written, lode_fields);

    let rows: Vec<Value> = admin
        .audit(&login)
        .await
        .iter()
        .take(6)
        .map(audit_row)
        .collect();
    assert_eq!(
        rows,
        [
            json!(["token", "lode_rollback", "0.1.5", "127.0.0.1", "ok"]),
            json!(["token", "lode_rollback", "0.1.9", "127.0.0.1", "ok"]),
            json!(["token", "lode_update", null, "127.0.0.1", "error"]),
            json!(["token", "lode_restart", null, "127.0.0.1", "ok"]),
            json!(["token", "lode_update", "latest", "127.0.0.1", "ok"]),
            json!(["token", "lode_check", null, "127.0.0.1", "ok"]),
        ]
    );
}

#[tokio::test]
async fn lode_rollback_without_last_good_conflicts() {
    let lode_dir = tempfile::tempdir().unwrap();
    let admin = Admin::with(
        TestHub::new(),
        Options {
            lode_dir: Some(lode_dir.path().to_owned()),
            ..Options::default()
        },
    );
    let login = admin.login().await;
    let status = admin
        .call(Method::GET, "/admin/api/lode", &login, None)
        .await;
    assert_eq!(status.body["supervised"], true);
    assert_eq!(status.body["current"], Value::Null);
    let rollback = admin
        .call(Method::POST, "/admin/api/lode/rollback", &login, None)
        .await;
    assert_eq!(rollback.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn lode_unsupervised() {
    let admin = Admin::new();
    let login = admin.login().await;
    let status = admin
        .call(Method::GET, "/admin/api/lode", &login, None)
        .await;
    assert_eq!(status.body, json!({ "supervised": false }));
    for (uri, body) in [
        ("/admin/api/lode/check", None),
        (
            "/admin/api/lode/update",
            Some(json!({ "version": "latest" })),
        ),
        ("/admin/api/lode/restart", None),
        ("/admin/api/lode/rollback", None),
    ] {
        let response = admin.call(Method::POST, uri, &login, body.as_ref()).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(response.code(), "unavailable");
    }
}

#[tokio::test]
async fn config_redacts_secrets() {
    let mut hub = TestHub::new();
    let webhook_secret = "w3bhook-secret-".repeat(3);
    let data_dir = hub.state.config.data_dir.display().to_string();
    let config = Config::from_vars(
        [
            ("GIM_HUB_DATA_DIR", data_dir.as_str()),
            ("GIM_HUB_PUSH_WEBHOOK_URL", "https://push.example.eu/hook"),
            ("GIM_HUB_PUSH_WEBHOOK_SECRET", &webhook_secret),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned())),
    )
    .unwrap();
    hub.state.config = Arc::new(config);
    let admin = Admin::with(hub, Options::default());
    let login = admin.login().await;
    let response = admin
        .call(Method::GET, "/admin/api/config", &login, None)
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.body.to_string();
    assert!(!body.contains(&webhook_secret));
    assert!(!body.contains(&admin.token));
    let items = response.body["items"].as_array().unwrap();
    let get = |key: &str| {
        items
            .iter()
            .find(|item| item["key"] == key)
            .unwrap_or_else(|| panic!("{key}"))
            .clone()
    };
    assert_eq!(
        get("GIM_HUB_PUSH_WEBHOOK_SECRET"),
        json!({ "key": "GIM_HUB_PUSH_WEBHOOK_SECRET", "value": null, "redacted": true })
    );
    assert_eq!(
        get("GIM_HUB_PUSH_WEBHOOK_URL")["value"],
        "https://push.example.eu/hook"
    );
    assert_eq!(get("GIM_HUB_LISTEN")["value"], "0.0.0.0:8080");
    assert_eq!(get("GIM_HUB_FEDERATION")["value"], "false");
    let token_file = get("GIM_HUB_ADMIN_TOKEN_FILE");
    assert_eq!(token_file["redacted"], false);
    assert!(token_file["value"]
        .as_str()
        .unwrap()
        .ends_with("admin.token"));
    assert!(items
        .iter()
        .all(|item| item["key"].as_str().unwrap().starts_with("GIM_HUB_")));
}

#[tokio::test]
async fn config_redacts_the_psk() {
    let hub = TestHub::new();
    let mut federation_config = FederationConfig::from_vars(
        [("GIM_HUB_FEDERATION".to_owned(), "true".to_owned())],
        &hub.state.config.data_dir,
    )
    .unwrap();
    federation_config.psk = Some([0x5a; 32]);
    let admin = Admin::with(
        hub,
        Options {
            federation_config: Some(federation_config),
            ..Options::default()
        },
    );
    let login = admin.login().await;
    let response = admin
        .call(Method::GET, "/admin/api/config", &login, None)
        .await;
    let items = response.body["items"].as_array().unwrap();
    let psk = items
        .iter()
        .find(|item| item["key"] == "GIM_HUB_P2P_PSK_FILE")
        .unwrap();
    assert_eq!(psk["redacted"], true);
    assert_eq!(psk["value"], Value::Null);
    assert!(!response.body.to_string().contains(&"5a".repeat(32)));
}
