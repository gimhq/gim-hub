use std::sync::Mutex as StdMutex;

use serde_json::json;

use super::*;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const KEY: &str = "/key/swarm/psk/1.0.0/\n/base16/\n\
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";

fn vars(pairs: &[(&str, &str)]) -> Vars {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

async fn sources(db: &Db, env: &Vars) -> Sources {
    let env = env.clone();
    db.read(move |conn| Sources::read(conn, env)).await.unwrap()
}

fn get(sources: &Sources, key: &str) -> SettingState {
    state(sources, find(key).unwrap(), None)
}

#[tokio::test]
async fn precedence_is_env_then_stored_then_default_for_every_type() {
    let db = Db::open_in_memory().unwrap();
    // (key, env value, stored JSON value, expected default, env JSON, stored JSON)
    let cases: &[(&str, &str, Value, Value, Value, Value)] = &[
        (
            "GIM_HUB_EVENT_RETENTION_DAYS",
            "30",
            json!(14),
            json!(7),
            json!(30),
            json!(14),
        ),
        (
            "GIM_HUB_PUSH_MINIMAL",
            "true",
            json!(true),
            json!(false),
            json!(true),
            json!(true),
        ),
        (
            "GIM_HUB_PUBLIC_URL",
            "https://hub-a.example.eu",
            json!("https://hub-b.example.eu"),
            Value::Null,
            json!("https://hub-a.example.eu"),
            json!("https://hub-b.example.eu"),
        ),
        (
            "GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS",
            "3",
            json!(5),
            json!(10),
            json!(3),
            json!(5),
        ),
        (
            "GIM_HUB_P2P_BOOTSTRAP",
            "/dns4/a.example.eu/tcp/4001,/dns4/b.example.eu/tcp/4001",
            json!(["/dns4/c.example.eu/tcp/4001"]),
            Value::Null,
            json!(["/dns4/a.example.eu/tcp/4001", "/dns4/b.example.eu/tcp/4001"]),
            json!(["/dns4/c.example.eu/tcp/4001"]),
        ),
        (
            "GIM_HUB_FEDERATION_ALLOWLIST",
            "/config/allowlist",
            json!("/srv/allowlist"),
            Value::Null,
            json!("/config/allowlist"),
            json!("/srv/allowlist"),
        ),
        (
            "GIM_HUB_USER_POLICY",
            "allow",
            json!("deny"),
            json!("open"),
            json!("allow"),
            json!("deny"),
        ),
    ];
    for (key, env_value, stored, default, from_env, from_stored) in cases {
        let empty = Vars::new();
        let s = get(&sources(&db, &empty).await, key);
        assert_eq!(
            (&s.value, s.source, s.is_set),
            (default, Source::Default, false),
            "{key}"
        );
        set(&db, &empty, key, stored, "token", 1_000).await.unwrap();
        let s = get(&sources(&db, &empty).await, key);
        assert_eq!(
            (&s.value, s.source, s.is_set),
            (from_stored, Source::Stored, true),
            "{key}"
        );
        assert_eq!(
            (s.updated_at, s.updated_by.as_deref()),
            (Some(1_000), Some("token"))
        );
        let env = vars(&[(key, env_value)]);
        let s = get(&sources(&db, &env).await, key);
        assert_eq!((&s.value, s.source), (from_env, Source::Env), "{key}");
    }
    // The stored values reach the configuration; the environment wins.
    let effective = load(&sources(&db, &Vars::new()).await).unwrap();
    assert_eq!(effective.config.event_retention_days, 14);
    assert!(effective.config.push.minimal);
    assert_eq!(effective.config.user_policy, user_policy::Mode::Deny);
    let env = vars(&[("GIM_HUB_USER_POLICY", "allow")]);
    assert_eq!(
        load(&sources(&db, &env).await).unwrap().config.user_policy,
        user_policy::Mode::Allow
    );
    assert_eq!(
        effective.config.public_url.as_deref(),
        Some("https://hub-b.example.eu")
    );
    let env = vars(&[("GIM_HUB_EVENT_RETENTION_DAYS", "30")]);
    assert_eq!(
        load(&sources(&db, &env).await)
            .unwrap()
            .config
            .event_retention_days,
        30
    );
    // Back to the default.
    unset(&db, &Vars::new(), "GIM_HUB_EVENT_RETENTION_DAYS")
        .await
        .unwrap();
    let effective = load(&sources(&db, &Vars::new()).await).unwrap();
    assert_eq!(effective.config.event_retention_days, 7);
}

#[tokio::test]
async fn secrets_are_write_only() {
    let db = Db::open_in_memory().unwrap();
    let empty = Vars::new();
    let key = "GIM_HUB_PUSH_WEBHOOK_SECRET";
    let s = get(&sources(&db, &empty).await, key);
    assert_eq!(
        (s.value, s.is_set, s.source),
        (Value::Null, false, Source::Default)
    );
    let detail = set(&db, &empty, key, &json!(SECRET), "cli", 1)
        .await
        .unwrap();
    assert_eq!(detail, "null -> ***");
    let s = get(&sources(&db, &empty).await, key);
    assert_eq!(
        (s.value, s.is_set, s.source),
        (Value::Null, true, Source::Stored)
    );
    let detail = set(
        &db,
        &empty,
        "GIM_HUB_PUSH_WEBHOOK_URL",
        &json!("https://push.example.eu/hook"),
        "cli",
        2,
    )
    .await
    .unwrap();
    assert_eq!(detail, "null -> \"https://push.example.eu/hook\"");
    let effective = load(&sources(&db, &empty).await).unwrap();
    assert_eq!(effective.config.push.webhook.unwrap().secret, SECRET);
    // Changing it: still redacted.
    let other = SECRET.replace('0', "x");
    let detail = set(&db, &empty, key, &json!(other), "cli", 3)
        .await
        .unwrap();
    assert_eq!(detail, "*** -> ***");
    // An env secret is set but never shown.
    let env = vars(&[(key, SECRET)]);
    let s = get(&sources(&db, &env).await, key);
    assert_eq!(
        (s.value, s.is_set, s.source),
        (Value::Null, true, Source::Env)
    );

    // A bad PSK names the setting, never the value.
    let bad = KEY.replace("0001", "zz01");
    let err = set(&db, &empty, "GIM_HUB_P2P_PSK", &json!(bad), "cli", 4)
        .await
        .unwrap_err();
    assert!(matches!(err, SettingsError::Invalid(_)));
    assert!(err.to_string().contains("GIM_HUB_P2P_PSK"), "{err}");
    assert!(!err.to_string().contains("zz01"), "{err}");
}

#[tokio::test]
async fn invalid_values_are_refused_and_nothing_is_stored() {
    let db = Db::open_in_memory().unwrap();
    let empty = Vars::new();
    let cases: &[(&str, Value, &str)] = &[
        (
            "GIM_HUB_EVENT_RETENTION_DAYS",
            json!(0),
            "must be at least 1",
        ),
        (
            "GIM_HUB_EVENT_RETENTION_DAYS",
            json!("many"),
            "invalid digit",
        ),
        (
            "GIM_HUB_EVENT_RETENTION_DAYS",
            json!(true),
            "expected a value of type integer",
        ),
        (
            "GIM_HUB_PUSH_MINIMAL",
            json!("yes"),
            "provided string was not",
        ),
        (
            "GIM_HUB_PUBLIC_URL",
            json!("ftp://hub"),
            "scheme must be http or https",
        ),
        // Needs the secret first.
        (
            "GIM_HUB_PUSH_WEBHOOK_URL",
            json!("https://push.example.eu"),
            "GIM_HUB_PUSH_WEBHOOK_URL",
        ),
        // Needs the public URL first.
        (
            "GIM_HUB_FEDERATION",
            json!(true),
            "required when GIM_HUB_FEDERATION=true",
        ),
        // Federation settings are checked while federation is off.
        ("GIM_HUB_OUTBOX_TTL_HOURS", json!(0), "must be at least 1"),
        (
            "GIM_HUB_P2P_LISTEN",
            json!(["not-an-addr"]),
            "GIM_HUB_P2P_LISTEN",
        ),
        // A PSK rules out the default QUIC listen address.
        ("GIM_HUB_P2P_PSK", json!(KEY), "QUIC is not available"),
        (
            "GIM_HUB_P2P_PSK_FILE",
            json!("/nonexistent/swarm.key"),
            "GIM_HUB_P2P_PSK_FILE",
        ),
        ("GIM_HUB_PUSH_MINIMAL", Value::Null, "a value is required"),
        ("GIM_HUB_PUSH_MINIMAL", json!(""), "empty value"),
    ];
    for (key, value, message) in cases {
        let err = set(&db, &empty, key, value, "token", 1).await.unwrap_err();
        match &err {
            SettingsError::Invalid(got) => assert!(got.contains(message), "{key}: {got}"),
            other => panic!("{key}: {other:?}"),
        }
    }
    assert!(db.read(db::list).await.unwrap().is_empty());
    assert_eq!(db.read(db::version).await.unwrap(), 0);

    assert!(matches!(
        set(&db, &empty, "GIM_HUB_NOPE", &json!(1), "token", 1).await,
        Err(SettingsError::NotFound(_))
    ));
    assert!(matches!(
        set(
            &db,
            &empty,
            "GIM_HUB_LISTEN",
            &json!("0.0.0.0:1"),
            "token",
            1
        )
        .await,
        Err(SettingsError::NotFound(_))
    ));
    // Env-set keys are read-only.
    let env = vars(&[("GIM_HUB_EVENT_RETENTION_DAYS", "3")]);
    assert!(matches!(
        set(
            &db,
            &env,
            "GIM_HUB_EVENT_RETENTION_DAYS",
            &json!(4),
            "token",
            1
        )
        .await,
        Err(SettingsError::SetByEnv)
    ));
    assert!(matches!(
        unset(&db, &env, "GIM_HUB_EVENT_RETENTION_DAYS").await,
        Err(SettingsError::SetByEnv)
    ));

    // In order, dependent values are accepted; unsetting a needed one is not.
    set(
        &db,
        &empty,
        "GIM_HUB_PUBLIC_URL",
        &json!("HTTPS://Hub.Example.EU/"),
        "token",
        1,
    )
    .await
    .unwrap();
    set(&db, &empty, "GIM_HUB_FEDERATION", &json!(true), "token", 1)
        .await
        .unwrap();
    let err = unset(&db, &empty, "GIM_HUB_PUBLIC_URL").await.unwrap_err();
    assert!(err
        .to_string()
        .contains("required when GIM_HUB_FEDERATION=true"));
}

/// An environment-only deployment upgraded to stored settings (empty
/// tables) is configured exactly as by the pre-H14 environment parsing.
#[tokio::test]
async fn env_only_deployment_is_configured_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().display().to_string();
    let psk = dir.path().join("swarm.key");
    std::fs::write(&psk, KEY).unwrap();
    let psk = psk.display().to_string();
    let allowlist = dir.path().join("allowlist.txt").display().to_string();
    let env_sets: Vec<Vec<(&str, &str)>> = vec![
        // The lode example (deploy/lode/lode.toml).
        vec![
            ("GIM_HUB_DATA_DIR", &data_dir),
            ("GIM_HUB_LISTEN", "0.0.0.0:8080"),
        ],
        // The federation compose (deploy/federation), with a PSK.
        vec![
            ("GIM_HUB_DATA_DIR", &data_dir),
            ("GIM_HUB_LISTEN", "0.0.0.0:8080"),
            ("GIM_HUB_PUBLIC_URL", "http://hub-a:8080"),
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
            ("GIM_HUB_P2P_EXTERNAL_ADDRS", "/dns4/hub-a/tcp/4001"),
            ("GIM_HUB_P2P_BOOTSTRAP", "/dns4/hub-b/tcp/4001"),
            ("GIM_HUB_FEDERATION_ALLOWLIST", &allowlist),
            ("GIM_HUB_P2P_PSK_FILE", &psk),
            ("GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS", "5"),
            ("GIM_HUB_HOSTING_CACHE_SECONDS", "0"),
            ("GIM_HUB_PUSH_FAILOVER_SECONDS", "3"),
            ("GIM_HUB_UNHOSTED_GRACE_HOURS", "1"),
        ],
        // Everything else away from its default.
        vec![
            ("GIM_HUB_DATA_DIR", &data_dir),
            ("GIM_HUB_DATABASE_PATH", "/var/lib/gim/other.db"),
            ("GIM_HUB_EVENT_RETENTION_DAYS", "30"),
            ("GIM_HUB_KEYPACKAGE_LOW_THRESHOLD", "3"),
            ("GIM_HUB_MAX_MESSAGE_BYTES", "1000"),
            ("GIM_HUB_MAX_BLOB_BYTES", "2000"),
            ("GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS", "5"),
            ("GIM_HUB_SESSION_TTL_DAYS", "2"),
            ("GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN", "5"),
            ("GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN", "6"),
            ("GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN", "7"),
            ("GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN", "8"),
            ("GIM_HUB_TRUST_FORWARDED_FOR", "true"),
            ("GIM_HUB_PUSH_MEMBER_EVENTS", "true"),
            ("GIM_HUB_PUSH_MINIMAL", "true"),
            ("GIM_HUB_PUSH_QUEUE_CAPACITY", "9"),
            ("GIM_HUB_PUSH_LOG_ENDPOINT", "true"),
            ("GIM_HUB_PUSH_WEBHOOK_URL", "http://push:8080/v1/push"),
            ("GIM_HUB_PUSH_WEBHOOK_SECRET", SECRET),
            ("GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS", "4"),
            ("GIM_HUB_ADMIN_LISTEN", "127.0.0.1:8081"),
            ("LODE_ACTIVE_VERSION", "0.3.1"),
            ("GIM_HUB_PUBLIC_URL", "https://hub.example.eu"),
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_PSK", KEY),
            ("GIM_HUB_P2P_LISTEN", "/ip6/::/tcp/4001"),
            ("GIM_HUB_FEDERATION_ALLOWLIST", &allowlist),
            ("GIM_HUB_RUNTIME_CERT_DAYS", "3"),
            ("GIM_HUB_S2S_TIMEOUT_SECONDS", "4"),
            ("GIM_HUB_DHT_REPUBLISH_HOURS", "5"),
            ("GIM_HUB_DEVICE_LIST_CACHE_HOURS", "6"),
            ("GIM_HUB_OUTBOX_TTL_HOURS", "7"),
            ("GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER", "8"),
            ("GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER", "9"),
            ("GIM_HUB_FETCH_BLOB_PER_MINUTE", "10"),
        ],
    ];
    for pairs in env_sets {
        let env: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            // Variables of other programs and empty ones are ignored, as before.
            .chain([
                ("PATH".to_owned(), "/usr/bin".to_owned()),
                ("GIM_HUB_MAX_BLOB_BYTES_X".to_owned(), String::new()),
            ])
            .collect();
        let before_config = Config::from_vars(env.clone()).unwrap();
        let before_federation =
            FederationConfig::from_vars(env.clone(), &before_config.data_dir).unwrap();

        let db = Db::open_in_memory().unwrap();
        let (runtime, effective) = Runtime::load(db, env_vars(env)).await.unwrap();
        assert_eq!(effective.config, before_config, "{pairs:?}");
        assert_eq!(effective.federation, before_federation, "{pairs:?}");
        // Nothing pending, nothing to change on a reload.
        let sources = runtime.sources().await.unwrap();
        assert!(SETTINGS
            .iter()
            .all(|setting| !runtime.state(&sources, setting).restart_pending));
        assert_eq!(runtime.applied(&sources).unwrap(), effective);
    }
}

#[tokio::test]
async fn invalid_stored_value_falls_back_to_the_default() {
    let db = Db::open_in_memory().unwrap();
    // A manual database edit, bypassing validation.
    db.write(|tx| {
        for (key, value) in [
            ("GIM_HUB_EVENT_RETENTION_DAYS", "0"),
            ("GIM_HUB_MAX_BLOB_BYTES", "\"huge\""),
            ("GIM_HUB_SESSION_TTL_DAYS", "not json"),
            ("GIM_HUB_OUTBOX_TTL_HOURS", "5"),
            ("GIM_HUB_UNKNOWN", "1"),
        ] {
            db::put(
                tx,
                &StoredSetting {
                    key: key.into(),
                    value: value.into(),
                    updated_at: 0,
                    updated_by: "cli".into(),
                },
            )?;
        }
        Ok::<_, DbError>(())
    })
    .await
    .unwrap();
    let effective = load(&sources(&db, &Vars::new()).await).unwrap();
    assert_eq!(effective.config.event_retention_days, 7);
    assert_eq!(effective.config.max_blob_bytes, 104_857_600);
    assert_eq!(effective.config.session_ttl_days, 30);
    assert!(!effective.vars.contains_key("GIM_HUB_UNKNOWN"));
    // An invalid environment variable still stops startup.
    let env = vars(&[("GIM_HUB_EVENT_RETENTION_DAYS", "0")]);
    assert!(matches!(
        load(&sources(&db, &env).await),
        Err(LoadError::Config(_))
    ));
}

#[tokio::test]
async fn live_settings_apply_on_reload_and_restart_settings_wait() {
    let db = Db::open_in_memory().unwrap();
    let env = vars(&[
        ("GIM_HUB_FEDERATION", "true"),
        ("GIM_HUB_PUBLIC_URL", "https://hub.example.eu"),
        ("GIM_HUB_FEDERATION_ALLOWLIST", "/config/allowlist"),
    ]);
    let (runtime, startup) = Runtime::load(db.clone(), env.clone()).await.unwrap();
    let applied: Arc<StdMutex<Vec<Effective>>> = Arc::default();
    let sink = applied.clone();
    runtime.on_apply(move |effective| sink.lock().unwrap().push(effective.clone()));
    assert!(!runtime.check().await.unwrap());

    set(
        &db,
        &env,
        "GIM_HUB_EVENT_RETENTION_DAYS",
        &json!(2),
        "cli",
        1,
    )
    .await
    .unwrap();
    set(&db, &env, "GIM_HUB_RUNTIME_CERT_DAYS", &json!(5), "cli", 1)
        .await
        .unwrap();
    set(&db, &env, "GIM_HUB_OUTBOX_TTL_HOURS", &json!(3), "cli", 1)
        .await
        .unwrap();
    // Another process wrote: the version changed.
    assert!(runtime.check().await.unwrap());
    assert!(!runtime.check().await.unwrap());
    let last = applied.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.config.event_retention_days, 2);
    assert_eq!(last.federation.outbox_ttl_hours, 3);
    // The restart setting keeps its startup value and is pending.
    assert_eq!(
        last.federation.runtime_cert_days,
        startup.federation.runtime_cert_days
    );
    let sources = runtime.sources().await.unwrap();
    let days = runtime.state(&sources, find("GIM_HUB_RUNTIME_CERT_DAYS").unwrap());
    assert!(days.restart_pending);
    assert_eq!(days.value, json!(5));
    let retention = runtime.state(&sources, find("GIM_HUB_EVENT_RETENTION_DAYS").unwrap());
    assert!(!retention.restart_pending);

    // After a restart it applies and nothing is pending.
    let (restarted, effective) = Runtime::load(db.clone(), env).await.unwrap();
    assert_eq!(effective.federation.runtime_cert_days, 5);
    let sources = restarted.sources().await.unwrap();
    assert!(
        !restarted
            .state(&sources, find("GIM_HUB_RUNTIME_CERT_DAYS").unwrap())
            .restart_pending
    );
}

#[test]
fn allowlist_source_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowlist");
    let file = |read_only| AllowlistSource::File {
        path: path.clone(),
        read_only,
    };
    // GIM_HUB_FEDERATION_ALLOWLIST set: the file, read-only.
    assert_eq!(allowlist_source(true, &path, false), file(true));
    assert_eq!(
        allowlist_source(false, &path, true),
        AllowlistSource::Stored
    );
    std::fs::write(&path, "x").unwrap();
    // The default file of an existing deployment until something is stored.
    assert_eq!(allowlist_source(false, &path, true), file(false));
    assert_eq!(
        allowlist_source(false, &path, false),
        AllowlistSource::Stored
    );
}

#[tokio::test]
async fn stored_allowlist_is_used_without_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().display().to_string();
    let env = vars(&[
        ("GIM_HUB_DATA_DIR", &data_dir),
        ("GIM_HUB_FEDERATION", "true"),
        ("GIM_HUB_PUBLIC_URL", "https://hub.example.eu"),
    ]);
    let db = Db::open_in_memory().unwrap();
    // Nothing anywhere: the empty stored allowlist (startup then fails).
    let effective = load(&sources(&db, &env).await).unwrap();
    assert_eq!(effective.federation.allowlist_text.as_deref(), Some(""));

    let own = HubId::from_root_pubkey(
        &gim_hub_identity::SigningKey::from_bytes(&[1; 32]).verifying_key(),
    );
    let peer = HubId::from_root_pubkey(
        &gim_hub_identity::SigningKey::from_bytes(&[2; 32]).verifying_key(),
    );
    assert!(parse_allowlist_entries(&format!("{own}\n"), &own, false)
        .unwrap_err()
        .contains("lists no other hub"));
    let entries = parse_allowlist_entries(
        &format!("# peers\n{own}\n{peer} /dns4/hub-b.example.eu/tcp/4001\n"),
        &own,
        false,
    )
    .unwrap();
    assert_eq!(
        entries,
        [(
            peer.to_string(),
            vec!["/dns4/hub-b.example.eu/tcp/4001".to_owned()]
        )]
    );
    set_allowlist(&db, &env, entries).await.unwrap();
    let effective = load(&sources(&db, &env).await).unwrap();
    assert_eq!(
        effective.federation.allowlist_text,
        Some(format!("{peer} /dns4/hub-b.example.eu/tcp/4001\n"))
    );

    // With GIM_HUB_FEDERATION_ALLOWLIST the file wins and the table is read-only.
    let file_env = vars(&[
        ("GIM_HUB_DATA_DIR", &data_dir),
        ("GIM_HUB_FEDERATION", "true"),
        ("GIM_HUB_PUBLIC_URL", "https://hub.example.eu"),
        ("GIM_HUB_FEDERATION_ALLOWLIST", "/config/allowlist"),
    ]);
    let effective = load(&sources(&db, &file_env).await).unwrap();
    assert_eq!(effective.federation.allowlist_text, None);
    assert!(matches!(
        set_allowlist(&db, &file_env, Vec::new()).await,
        Err(SettingsError::AllowlistFile)
    ));
}

#[tokio::test]
async fn user_policy_mode_is_validated() {
    let db = Db::open_in_memory().unwrap();
    let err = set(
        &db,
        &Vars::new(),
        "GIM_HUB_USER_POLICY",
        &json!("closed"),
        "cli",
        1,
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid GIM_HUB_USER_POLICY: expected one of open, allow, deny"
    );
    let env = vars(&[("GIM_HUB_USER_POLICY", "deny")]);
    assert!(matches!(
        set(&db, &env, "GIM_HUB_USER_POLICY", &json!("open"), "cli", 1).await,
        Err(SettingsError::SetByEnv)
    ));
    assert!(sources(&db, &Vars::new()).await.stored.is_empty());
    // An invalid environment value fails startup, as for every setting.
    let env = vars(&[("GIM_HUB_USER_POLICY", "closed")]);
    assert!(matches!(
        load(&sources(&db, &env).await),
        Err(LoadError::Config(_))
    ));
}

#[tokio::test]
async fn user_policy_applies_on_reload_and_revokes_sessions() {
    use gim_hub_db::user_policy::{self as list, ListEntry};

    let hub = crate::testing::TestHub::new();
    let db = hub.state.db.clone();
    let (alice, bob) = ("u-alice", "u-bob");
    hub.create_session(alice, "d1").await;
    hub.create_session(bob, "d1").await;
    let sessions = || {
        db.read(|conn| {
            Ok::<i64, DbError>(
                conn.query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))?,
            )
        })
    };
    let (runtime, effective) = Runtime::load(db.clone(), Vars::new()).await.unwrap();
    assert!(effective.user_list.is_empty());
    install(&runtime, hub.state.clone(), None, None);

    // Another process lists alice and switches to deny mode.
    let entry = ListEntry {
        user_id: alice.into(),
        added_at: 1,
        added_by: CLI_ACTOR.into(),
        note: None,
    };
    db.write(move |tx| list::add(tx, &entry)).await.unwrap();
    set(
        &db,
        &Vars::new(),
        "GIM_HUB_USER_POLICY",
        &json!("deny"),
        "cli",
        1,
    )
    .await
    .unwrap();
    assert!(runtime.check().await.unwrap());
    assert_eq!(hub.state.user_policy.mode(), user_policy::Mode::Deny);
    assert!(!hub.state.user_policy.admitted(alice));
    assert!(hub.state.user_policy.admitted(bob));
    assert_eq!(sessions().await.unwrap(), 1, "alice's session deleted");

    // Allow mode: only alice is admitted; bob loses his session.
    set(
        &db,
        &Vars::new(),
        "GIM_HUB_USER_POLICY",
        &json!("allow"),
        "cli",
        1,
    )
    .await
    .unwrap();
    assert!(runtime.check().await.unwrap());
    assert!(hub.state.user_policy.admitted(alice));
    assert!(!hub.state.user_policy.admitted(bob));
    assert_eq!(sessions().await.unwrap(), 0);

    // Allow mode with an empty list admits nobody.
    db.write(|tx| list::replace(tx, &[])).await.unwrap();
    assert!(runtime.check().await.unwrap());
    assert!(!hub.state.user_policy.admitted(alice));

    // The environment overrides the stored mode.
    let env = vars(&[("GIM_HUB_USER_POLICY", "open")]);
    let (_, effective) = Runtime::load(db.clone(), env).await.unwrap();
    assert_eq!(effective.config.user_policy, user_policy::Mode::Open);
}
