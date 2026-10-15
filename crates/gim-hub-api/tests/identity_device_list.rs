//! DeviceList upload and the user lookups: PUT/GET device-list,
//! GET /v2/users/{user_id}, GET /v2/me.

mod identity_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use gim_hub_db::{events, users};
use serde_json::{json, Value};

use identity_support::{b64, code, device_id, device_list, put_device_list, send, user_id};

#[tokio::test]
async fn vendored_vector_creates_the_user() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/identity/identity.json"
    );
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let user = vectors["user_id"].as_str().unwrap();
    let signed = hex::decode(vectors["device_list"]["signed"].as_str().unwrap()).unwrap();
    let device = vectors["device_list"]["certs"][0].as_str().unwrap();

    let hub = TestHub::new();
    let (status, body) = put_device_list(&hub, user, &signed).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body,
        json!({ "user_id": user, "device_list": b64(&signed) })
    );

    let token = hub.create_session(user, device).await;
    let (status, body) = send(
        &hub,
        Method::GET,
        &format!("/v2/users/{user}/device-list"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["device_list"], b64(&signed));

    let (status, body) = send(
        &hub,
        Method::GET,
        &format!("/v2/users/{user}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "user_id": user, "device_list": b64(&signed) })
    );

    // The same list under another user's path.
    let (status, body) = put_device_list(&hub, &user_id(9), &signed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "invalid_device_list");
}

#[tokio::test]
async fn seq_ordering() {
    let hub = TestHub::new();
    let user = user_id(1);
    let v1 = device_list(1, 1, &[2], &[]);
    let v2 = device_list(1, 2, &[2, 3], &[]);

    assert_eq!(
        put_device_list(&hub, &user, &v1).await.0,
        StatusCode::CREATED
    );
    // Identical re-upload is idempotent.
    assert_eq!(put_device_list(&hub, &user, &v1).await.0, StatusCode::OK);
    assert_eq!(put_device_list(&hub, &user, &v2).await.0, StatusCode::OK);

    let (status, body) = put_device_list(&hub, &user, &v1).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&body), "stale_device_list");

    let other_v2 = device_list(1, 2, &[2], &[]);
    let (status, body) = put_device_list(&hub, &user, &other_v2).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&body), "stale_device_list");

    let stored = hub
        .state
        .db
        .read(move |conn| users::get_device_list(conn, &user))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.seq, 2);
    assert_eq!(stored.device_list, v2);
}

#[tokio::test]
async fn invalid_uploads_are_rejected() {
    let hub = TestHub::new();
    let user = user_id(1);

    let mut tampered = device_list(1, 1, &[2], &[]);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let (status, body) = put_device_list(&hub, &user, &tampered).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "invalid_device_list");

    let valid = device_list(1, 1, &[2], &[]);
    for path_user in [user_id(2), "not-a-user-id".to_owned()] {
        let (status, body) = put_device_list(&hub, &path_user, &valid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path_user}");
        assert_eq!(code(&body), "invalid_device_list");
    }

    let uri = format!("/v2/users/{user}/device-list");
    let (status, body) = send(
        &hub,
        Method::PUT,
        &uri,
        None,
        Some(json!({ "device_list": "%%%" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "invalid_device_list");

    let (status, body) = send(&hub, Method::PUT, &uri, None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "validation_failed");

    // Nothing was stored.
    assert!(hub
        .state
        .db
        .read(move |conn| users::get_device_list(conn, &user))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn update_revokes_dropped_devices_and_notifies_the_rest() {
    let hub = TestHub::new();
    let user = user_id(1);
    let (d2, d3, d4) = (device_id(2), device_id(3), device_id(4));
    assert_eq!(
        put_device_list(&hub, &user, &device_list(1, 1, &[2, 3, 4], &[]))
            .await
            .0,
        StatusCode::CREATED
    );
    let t2 = hub.create_session(&user, &d2).await;
    let t3 = hub.create_session(&user, &d3).await;
    let t4 = hub.create_session(&user, &d4).await;
    let me = |token: String| {
        let hub = &hub;
        async move { send(hub, Method::GET, "/v2/me", Some(&token), None).await }
    };
    assert_eq!(me(t3.clone()).await.0, StatusCode::OK);

    let mut wake = hub.state.notifier.subscribe(&user, &d2);
    // d3 is revoked, d4 silently dropped.
    let v2 = device_list(1, 2, &[2], &[3]);
    assert_eq!(put_device_list(&hub, &user, &v2).await.0, StatusCode::OK);
    assert!(wake.has_changed().unwrap());
    wake.mark_unchanged();

    let (status, body) = me(t2.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "user_id": user, "device_id": d2 }));
    for token in [t3, t4] {
        let (status, body) = me(token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code(&body), "unauthorized");
    }

    let (u, d) = (user.clone(), d2.clone());
    let (active, sessions, d2_events, d3_events) = hub
        .state
        .db
        .read(move |conn| {
            let sessions: i64 = conn.query_row(
                "SELECT count(*) FROM sessions WHERE user_id = ?1",
                [&u],
                |row| row.get(0),
            )?;
            Ok::<_, gim_hub_db::DbError>((
                users::active_device_ids(conn, &u)?,
                sessions,
                events::list_after(conn, &u, &d, 0, 10)?,
                events::list_after(conn, &u, &device_id(3), 0, 10)?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(active, std::slice::from_ref(&d2));
    assert_eq!(sessions, 1);
    assert!(d3_events.is_empty());
    assert_eq!(d2_events.len(), 1);
    assert_eq!(d2_events[0].event_type, "device_list.updated");
    let payload: Value = serde_json::from_str(&d2_events[0].payload).unwrap();
    assert_eq!(payload, json!({ "user_id": user, "device_list": b64(&v2) }));

    // An idempotent re-upload emits nothing.
    assert_eq!(put_device_list(&hub, &user, &v2).await.0, StatusCode::OK);
    assert!(!wake.has_changed().unwrap());
}

#[tokio::test]
async fn lookups_require_auth_and_report_missing_users() {
    let hub = TestHub::new();
    let user = user_id(1);
    put_device_list(&hub, &user, &device_list(1, 1, &[2], &[])).await;
    let token = hub.create_session(&user, &device_id(2)).await;

    for uri in [
        format!("/v2/users/{user}"),
        format!("/v2/users/{user}/device-list"),
    ] {
        let (status, body) = send(&hub, Method::GET, &uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(code(&body), "unauthorized");
    }
    let missing = user_id(5);
    for uri in [
        format!("/v2/users/{missing}"),
        format!("/v2/users/{missing}/device-list"),
    ] {
        let (status, body) = send(&hub, Method::GET, &uri, Some(&token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(code(&body), "not_found");
    }

    let (status, _) = send(&hub, Method::PUT, "/v2/handles/alice", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(
        &hub,
        Method::GET,
        &format!("/v2/users/{user}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body["handle"], "alice");
    let (_, body) = send(&hub, Method::GET, "/v2/me", Some(&token), None).await;
    assert_eq!(
        body,
        json!({ "user_id": user, "device_id": device_id(2), "handle": "alice" })
    );
}
