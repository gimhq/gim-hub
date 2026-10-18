//! Stored settings: GET/PUT/DELETE /admin/api/settings[/{key}] and the
//! file- and table-backed federation allowlist.

mod support;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use gim_hub_api::{
    settings::{self, Vars, SETTINGS},
    testing::TestHub,
    HubIdentity,
};
use gim_hub_s2s::{Decision, FederationConfig, FederationPolicy, FederationService};
use serde_json::{json, Value};
use support::{Admin, Options};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

async fn put(admin: &Admin, login: &support::Login, key: &str, value: Value) -> support::Response {
    admin
        .call(
            Method::PUT,
            &format!("/admin/api/settings/{key}"),
            login,
            Some(&json!({ "value": value })),
        )
        .await
}

fn find<'a>(list: &'a Value, key: &str) -> &'a Value {
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["key"] == key)
        .unwrap()
}

#[tokio::test]
async fn list_shows_every_stored_setting_with_its_source() {
    let admin = Admin::with(
        TestHub::new(),
        Options {
            env: vec![("GIM_HUB_PUSH_MINIMAL", "true".into())],
            ..Options::default()
        },
    );
    let login = admin.login().await;
    let list = admin
        .call(Method::GET, "/admin/api/settings", &login, None)
        .await;
    assert_eq!(list.status, StatusCode::OK);
    let items = list.body["items"].as_array().unwrap();
    assert_eq!(items.len(), SETTINGS.len());
    assert_eq!(list.body["restart_pending"], false);
    for key in settings::BOOTSTRAP {
        assert!(items.iter().all(|item| item["key"] != *key), "{key}");
    }
    assert_eq!(
        find(&list.body, "GIM_HUB_EVENT_RETENTION_DAYS"),
        &json!({
            "key": "GIM_HUB_EVENT_RETENTION_DAYS",
            "group": "storage",
            "type": "integer",
            "enum": null,
            "description": "Events older than this are pruned (days, minimum 1)",
            "default": 7,
            "value": 7,
            "is_set": false,
            "source": "default",
            "read_only": false,
            "apply": "live",
            "restart_pending": false,
            "updated_at": null,
            "updated_by": null,
        })
    );
    let minimal = find(&list.body, "GIM_HUB_PUSH_MINIMAL");
    assert_eq!(
        (&minimal["value"], &minimal["source"], &minimal["read_only"]),
        (&json!(true), &json!("env"), &json!(true))
    );
    let listen = find(&list.body, "GIM_HUB_P2P_LISTEN");
    assert_eq!(listen["type"], "list");
    assert_eq!(
        listen["default"],
        json!(["/ip4/0.0.0.0/udp/4001/quic-v1", "/ip4/0.0.0.0/tcp/4001"])
    );

    for key in ["GIM_HUB_NOPE", "GIM_HUB_LISTEN", "GIM_HUB_ADMIN_TOKEN"] {
        let get = admin
            .call(
                Method::GET,
                &format!("/admin/api/settings/{key}"),
                &login,
                None,
            )
            .await;
        assert_eq!(get.status, StatusCode::NOT_FOUND, "{key}");
        assert_eq!(get.code(), "not_found");
        assert_eq!(
            put(&admin, &login, key, json!(1)).await.status,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn live_settings_take_effect_at_once_and_are_audited() {
    let admin = Admin::new();
    let login = admin.login().await;
    let hub = &admin.hub;

    // Retention (storage).
    let response = put(&admin, &login, "GIM_HUB_EVENT_RETENTION_DAYS", json!(30)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.body["value"], 30);
    assert_eq!(response.body["source"], "stored");
    assert_eq!(response.body["is_set"], true);
    assert_eq!(response.body["updated_by"], "token");
    assert_eq!(
        response.body["updated_at"],
        hub.state.clock.now_ms().div_euclid(1000)
    );
    assert_eq!(hub.state.config.load().event_retention_days, 30);

    // Push options.
    assert!(!hub.state.push.settings().minimal);
    let response = put(&admin, &login, "GIM_HUB_PUSH_MINIMAL", json!(true)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(hub.state.push.settings().minimal);
    assert!(hub.state.config.load().push.minimal);

    // Rate limits: one public read per minute from now on.
    let read = || async {
        hub.router()
            .oneshot(
                Request::get("/v2/users/u-unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    };
    assert_ne!(read().await, StatusCode::TOO_MANY_REQUESTS);
    assert_ne!(read().await, StatusCode::TOO_MANY_REQUESTS);
    let response = put(
        &admin,
        &login,
        "GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN",
        json!("1"),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["value"], 1);
    // The bucket keeps at most the new burst of one.
    read().await;
    assert_eq!(read().await, StatusCode::TOO_MANY_REQUESTS);

    // Back to the default.
    let response = admin
        .call(
            Method::DELETE,
            "/admin/api/settings/GIM_HUB_EVENT_RETENTION_DAYS",
            &login,
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        (&response.body["value"], &response.body["source"]),
        (&json!(7), &json!("default"))
    );
    assert_eq!(response.body["updated_by"], Value::Null);
    assert_eq!(hub.state.config.load().event_retention_days, 7);

    let audit = admin.audit(&login).await;
    let rows: Vec<_> = audit
        .iter()
        .filter(|e| e["action"] == "setting_update" || e["action"] == "setting_unset")
        .map(|e| {
            json!([
                e["actor"],
                e["action"],
                e["target"],
                e["result"],
                e["detail"]
            ])
        })
        .collect();
    assert_eq!(
        rows,
        [
            json!([
                "token",
                "setting_unset",
                "GIM_HUB_EVENT_RETENTION_DAYS",
                "ok",
                "30 -> 7"
            ]),
            json!([
                "token",
                "setting_update",
                "GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN",
                "ok",
                "60 -> 1"
            ]),
            json!([
                "token",
                "setting_update",
                "GIM_HUB_PUSH_MINIMAL",
                "ok",
                "false -> true"
            ]),
            json!([
                "token",
                "setting_update",
                "GIM_HUB_EVENT_RETENTION_DAYS",
                "ok",
                "7 -> 30"
            ]),
        ]
    );
}

#[tokio::test]
async fn invalid_values_and_env_set_keys_are_refused() {
    let admin = Admin::with(
        TestHub::new(),
        Options {
            env: vec![("GIM_HUB_SESSION_TTL_DAYS", "3".into())],
            ..Options::default()
        },
    );
    let login = admin.login().await;
    for (key, value, message) in [
        (
            "GIM_HUB_EVENT_RETENTION_DAYS",
            json!(0),
            "invalid GIM_HUB_EVENT_RETENTION_DAYS=\"0\": must be at least 1",
        ),
        ("GIM_HUB_PUSH_MINIMAL", json!("yes"), "GIM_HUB_PUSH_MINIMAL"),
        (
            "GIM_HUB_PUBLIC_URL",
            json!("ftp://hub"),
            "scheme must be http or https",
        ),
        (
            "GIM_HUB_FEDERATION",
            json!(true),
            "required when GIM_HUB_FEDERATION=true",
        ),
    ] {
        let response = put(&admin, &login, key, value).await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY, "{key}");
        assert_eq!(response.code(), "validation_failed");
        let got = response.body["error"]["message"].as_str().unwrap();
        assert!(got.contains(message), "{key}: {got}");
    }
    let malformed = admin
        .call(
            Method::PUT,
            "/admin/api/settings/GIM_HUB_PUSH_MINIMAL",
            &login,
            Some(&json!({ "nope": 1 })),
        )
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert!(admin
        .hub
        .state
        .db
        .read(gim_hub_db::settings::list)
        .await
        .unwrap()
        .is_empty());

    let response = put(&admin, &login, "GIM_HUB_SESSION_TTL_DAYS", json!(4)).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "conflict");
    assert_eq!(response.body["error"]["message"], "set by environment");
    let response = admin
        .call(
            Method::DELETE,
            "/admin/api/settings/GIM_HUB_SESSION_TTL_DAYS",
            &login,
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    let get = admin
        .call(
            Method::GET,
            "/admin/api/settings/GIM_HUB_SESSION_TTL_DAYS",
            &login,
            None,
        )
        .await;
    assert_eq!(
        (
            &get.body["value"],
            &get.body["source"],
            &get.body["read_only"]
        ),
        (&json!(3), &json!("env"), &json!(true))
    );
    let audit = admin.audit(&login).await;
    let failed = audit
        .iter()
        .find(|e| e["action"] == "setting_update" && e["target"] == "GIM_HUB_SESSION_TTL_DAYS")
        .unwrap();
    assert_eq!(failed["result"], "error");
}

#[tokio::test]
async fn secrets_are_never_returned() {
    let admin = Admin::new();
    let login = admin.login().await;
    let response = put(&admin, &login, "GIM_HUB_PUSH_WEBHOOK_SECRET", json!(SECRET)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.body["value"], Value::Null);
    assert_eq!(response.body["is_set"], true);
    assert_eq!(response.body["default"], Value::Null);
    let response = put(
        &admin,
        &login,
        "GIM_HUB_PUSH_WEBHOOK_URL",
        json!("https://push.example.eu/hook"),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let webhook = admin.hub.state.config.load().push.webhook.clone().unwrap();
    assert_eq!(webhook.secret, SECRET);

    for uri in [
        "/admin/api/settings",
        "/admin/api/settings/GIM_HUB_PUSH_WEBHOOK_SECRET",
        "/admin/api/config",
        "/admin/api/audit",
    ] {
        let body = admin.call(Method::GET, uri, &login, None).await.body;
        assert!(!body.to_string().contains(SECRET), "{uri}");
    }
    let audit = admin.audit(&login).await;
    let secret = audit
        .iter()
        .find(|e| e["target"] == "GIM_HUB_PUSH_WEBHOOK_SECRET")
        .unwrap();
    assert_eq!(secret["detail"], "null -> ***");
}

#[tokio::test]
async fn ui_value_encodings_and_reset_of_a_default() {
    let admin = Admin::new();
    let login = admin.login().await;
    // Raw text the UI could not parse as a number, or a non-integer: 422.
    for (key, value) in [
        ("GIM_HUB_EVENT_RETENTION_DAYS", json!("abc")),
        ("GIM_HUB_EVENT_RETENTION_DAYS", json!("1.5")),
        ("GIM_HUB_EVENT_RETENTION_DAYS", json!(1.5)),
        ("GIM_HUB_EVENT_RETENTION_DAYS", json!(-1)),
        ("GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS", json!("10s")),
        ("GIM_HUB_P2P_BOOTSTRAP", json!([1, 2])),
        ("GIM_HUB_PUSH_MINIMAL", json!(1)),
    ] {
        let response = put(&admin, &login, key, value.clone()).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{key} = {value}: {}",
            response.body
        );
        assert_eq!(response.code(), "validation_failed");
    }

    // Typed values as the UI sends them; the list reflects each write at once.
    for (key, value) in [
        ("GIM_HUB_EVENT_RETENTION_DAYS", json!(9)),
        ("GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS", json!(20)),
        ("GIM_HUB_PUSH_MINIMAL", json!(true)),
        (
            "GIM_HUB_P2P_BOOTSTRAP",
            json!(["/dns4/hub-b.example.eu/tcp/4001"]),
        ),
        ("GIM_HUB_PUBLIC_URL", json!("https://hub.example.eu")),
    ] {
        let response = put(&admin, &login, key, value.clone()).await;
        assert_eq!(response.status, StatusCode::OK, "{key}: {}", response.body);
        assert_eq!(response.body["value"], value);
        let list = admin
            .call(Method::GET, "/admin/api/settings", &login, None)
            .await;
        let item = find(&list.body, key);
        assert_eq!(
            (&item["value"], &item["source"]),
            (&value, &json!("stored"))
        );
        assert_eq!(item["updated_by"], "token");
    }
    let list = admin
        .call(Method::GET, "/admin/api/settings", &login, None)
        .await;
    assert_eq!(list.body["restart_pending"], true);

    // DELETE of a row at its default: 200 with the unchanged item.
    let path = "/admin/api/settings/GIM_HUB_KEYPACKAGE_LOW_THRESHOLD";
    let before = admin.call(Method::GET, path, &login, None).await;
    let response = admin.call(Method::DELETE, path, &login, None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.body, before.body);
    assert_eq!(response.body["source"], "default");

    // Unsetting the restart setting clears the global flag at once.
    let response = admin
        .call(
            Method::DELETE,
            "/admin/api/settings/GIM_HUB_PUBLIC_URL",
            &login,
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let response = admin
        .call(
            Method::DELETE,
            "/admin/api/settings/GIM_HUB_P2P_BOOTSTRAP",
            &login,
            None,
        )
        .await;
    assert_eq!(response.body["source"], "default");
    let list = admin
        .call(Method::GET, "/admin/api/settings", &login, None)
        .await;
    assert_eq!(list.body["restart_pending"], false);
}

#[tokio::test]
async fn restart_settings_are_pending_until_restart() {
    let admin = Admin::new();
    let login = admin.login().await;
    let response = put(
        &admin,
        &login,
        "GIM_HUB_PUBLIC_URL",
        json!("HTTPS://Hub.Example.EU/"),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.body["apply"], "restart");
    assert_eq!(response.body["restart_pending"], true);
    assert_eq!(response.body["value"], "HTTPS://Hub.Example.EU/");
    // Not applied by the running hub.
    assert_eq!(admin.hub.state.config.load().public_url, None);
    let list = admin
        .call(Method::GET, "/admin/api/settings", &login, None)
        .await;
    assert_eq!(list.body["restart_pending"], true);

    // A restart (a new runtime on the same database) applies it.
    let env: Vars = admin.state.settings.env().clone();
    let (restarted, effective) = settings::Runtime::load(admin.hub.state.db.clone(), env)
        .await
        .unwrap();
    assert_eq!(
        effective.config.public_url.as_deref(),
        Some("https://hub.example.eu")
    );
    let sources = restarted.sources().await.unwrap();
    assert!(SETTINGS
        .iter()
        .all(|setting| !restarted.state(&sources, setting).restart_pending));
}

#[tokio::test]
async fn changes_from_another_process_are_picked_up() {
    let admin = Admin::new();
    let watcher = admin
        .state
        .settings
        .spawn_watcher(Duration::from_millis(20));
    // What `gim-hub config set` does, on the same database.
    settings::set(
        &admin.hub.state.db,
        &Vars::new(),
        "GIM_HUB_MAX_MESSAGE_BYTES",
        &json!("64"),
        settings::CLI_ACTOR,
        1,
    )
    .await
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while admin.hub.state.config.load().max_message_bytes != 64 {
        assert!(std::time::Instant::now() < deadline, "not picked up");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    watcher.abort();
    let login = admin.login().await;
    let get = admin
        .call(
            Method::GET,
            "/admin/api/settings/GIM_HUB_MAX_MESSAGE_BYTES",
            &login,
            None,
        )
        .await;
    assert_eq!(get.body["updated_by"], "cli");
}

/// A federated admin; `env` is the hub's environment for the settings.
async fn federated(
    allowlist_text: Option<String>,
    file: Option<&str>,
    env: Vec<(&'static str, String)>,
) -> Admin {
    let hub = TestHub::new();
    let data_dir = hub.state.config.load().data_dir.clone();
    let mut vars = vec![
        ("GIM_HUB_FEDERATION".to_owned(), "true".to_owned()),
        (
            "GIM_HUB_P2P_LISTEN".to_owned(),
            "/ip4/127.0.0.1/tcp/0".to_owned(),
        ),
    ];
    if let Some(file) = file {
        let path = data_dir.join(file);
        std::fs::write(
            &path,
            format!("{}\n", HubIdentity::from_seed(&[9; 32]).hub_id()),
        )
        .unwrap();
        vars.push((
            "GIM_HUB_FEDERATION_ALLOWLIST".to_owned(),
            path.display().to_string(),
        ));
    }
    let mut config = FederationConfig::from_vars(vars, &data_dir).unwrap();
    config.allowlist_text = allowlist_text;
    let service = FederationService::start_with_allowlist(&config, hub.state.hub.signing_key())
        .await
        .unwrap();
    Admin::with(
        hub,
        Options {
            federation: Some((config, service)),
            env,
            ..Options::default()
        },
    )
}

#[tokio::test]
async fn stored_allowlist_is_edited_and_applied() {
    let peer = HubIdentity::from_seed(&[9; 32]).hub_id().clone();
    let other = HubIdentity::from_seed(&[10; 32]).hub_id().clone();
    let admin = federated(Some(format!("{peer}\n")), None, Vec::new()).await;
    let federation = admin.state.federation.clone().unwrap();
    let policy = federation.allowlist().unwrap().clone();
    let login = admin.login().await;
    let get = admin
        .call(Method::GET, "/admin/api/federation/allowlist", &login, None)
        .await;
    // Nothing stored yet and no default file: the (empty) stored allowlist.
    assert_eq!(get.status, StatusCode::OK, "{}", get.body);
    assert_eq!(
        (&get.body["source"], &get.body["read_only"]),
        (&json!("stored"), &json!(false))
    );

    let put = admin
        .call(
            Method::PUT,
            "/admin/api/federation/allowlist",
            &login,
            Some(&json!({ "text": format!("{other} /dns4/hub-c.example.eu/tcp/4001\n") })),
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.body);
    assert_eq!(
        put.body["entries"],
        json!([{ "hub_id": other.as_str(), "addrs": ["/dns4/hub-c.example.eu/tcp/4001"] }])
    );
    assert_eq!(policy.allow_hub(&other), Decision::Allow);
    assert!(matches!(policy.allow_hub(&peer), Decision::Deny(_)));
    federation.shutdown();
}

#[tokio::test]
async fn allowlist_file_is_read_only() {
    let admin = federated(
        None,
        Some("allowlist.conf"),
        vec![("GIM_HUB_FEDERATION_ALLOWLIST", "/set/by/env".into())],
    )
    .await;
    let federation = admin.state.federation.clone().unwrap();
    let login = admin.login().await;
    let get = admin
        .call(Method::GET, "/admin/api/federation/allowlist", &login, None)
        .await;
    assert_eq!(get.status, StatusCode::OK, "{}", get.body);
    assert_eq!(
        (&get.body["source"], &get.body["read_only"]),
        (&json!("file"), &json!(true))
    );
    assert!(get.body["path"]
        .as_str()
        .unwrap()
        .ends_with("allowlist.conf"));
    let other = HubIdentity::from_seed(&[10; 32]).hub_id().clone();
    let put = admin
        .call(
            Method::PUT,
            "/admin/api/federation/allowlist",
            &login,
            Some(&json!({ "text": format!("{other}\n") })),
        )
        .await;
    assert_eq!(put.status, StatusCode::CONFLICT, "{}", put.body);
    assert_eq!(put.code(), "conflict");
    assert!(admin
        .hub
        .state
        .db
        .read(gim_hub_db::settings::allowlist)
        .await
        .unwrap()
        .is_empty());
    federation.shutdown();
}
