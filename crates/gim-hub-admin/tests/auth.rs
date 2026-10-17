//! Admin authentication: token login, the throttle, session expiry, logout,
//! CSRF on every route, trusted-proxy identity, and no admin routes on the
//! client API listener.

mod support;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use gim_hub_admin::{state::SESSION_TTL_MS, AdminDoc};
use gim_hub_api::testing::TestHub;
use serde_json::{json, Value};
use support::{session_cookie, Admin, Login, Options, PEER};
use tower::ServiceExt;
use utoipa::OpenApi;

#[tokio::test]
async fn login_session_and_logout() {
    let admin = Admin::new();
    let response = admin.login_from(PEER, &admin.token).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.body["actor"], "token");
    let now_s = admin.hub.state.clock.now_ms() / 1000;
    assert_eq!(response.body["expires_at"], now_s + SESSION_TTL_MS / 1000);
    let set_cookie = response.headers[header::SET_COOKIE].to_str().unwrap();
    for attribute in [
        "HttpOnly",
        "SameSite=Strict",
        "Path=/admin",
        "Max-Age=28800",
    ] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    assert!(!set_cookie.contains("Secure"));
    let cookie = session_cookie(&response.headers).unwrap();
    assert_eq!(cookie.len(), 64);
    let login = Login {
        cookie,
        csrf: response.body["csrf_token"].as_str().unwrap().to_owned(),
    };

    let session = admin
        .call(Method::GET, "/admin/api/session", &login, None)
        .await;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(
        session.body,
        json!({
            "actor": "token",
            "auth": "token",
            "csrf_token": login.csrf,
            "expires_at": now_s + SESSION_TTL_MS / 1000,
        })
    );

    let logout = admin
        .call(Method::POST, "/admin/api/logout", &login, None)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let cleared = logout.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(cleared.starts_with("gim_admin_session=;") && cleared.contains("Max-Age=0"));
    let after = admin
        .call(Method::GET, "/admin/api/session", &login, None)
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.code(), "unauthorized");

    let login = admin.login().await;
    let actions: Vec<Value> = admin
        .audit(&login)
        .await
        .iter()
        .map(|e| json!([e["actor"], e["action"], e["result"], e["source_ip"]]))
        .collect();
    assert_eq!(
        actions,
        [
            json!(["token", "login_ok", "ok", "127.0.0.1"]),
            json!(["token", "logout", "ok", "127.0.0.1"]),
            json!(["token", "login_ok", "ok", "127.0.0.1"]),
        ]
    );
}

#[tokio::test]
async fn secure_cookie_when_configured() {
    let admin = Admin::with(
        TestHub::new(),
        Options {
            vars: vec![("GIM_HUB_ADMIN_COOKIE_SECURE", "true".into())],
            ..Options::default()
        },
    );
    let response = admin.login_from(PEER, &admin.token).await;
    let set_cookie = response.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.ends_with("; Secure"), "{set_cookie}");
}

#[tokio::test]
async fn failed_login_is_audited_without_the_token() {
    let admin = Admin::new();
    let wrong = "wrong-token-".repeat(4);
    let response = admin.login_from(PEER, &wrong).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "unauthorized");
    assert!(session_cookie(&response.headers).is_none());
    let malformed = admin
        .send(
            Method::POST,
            "/admin/api/login",
            PEER,
            &[],
            Some(&json!({ "tok": 1 })),
        )
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.code(), "validation_failed");

    let login = admin.login().await;
    let audit = admin.audit(&login).await;
    let failed = audit
        .iter()
        .find(|e| e["action"] == "login_failed")
        .unwrap();
    assert_eq!(failed["actor"], "anonymous");
    assert_eq!(failed["result"], "error");
    assert_eq!(failed["source_ip"], "127.0.0.1");
    let text = Value::Array(audit).to_string();
    assert!(!text.contains(&wrong) && !text.contains(&admin.token));
}

#[tokio::test]
async fn sixth_failed_login_per_minute_is_rate_limited() {
    let admin = Admin::new();
    let wrong = "x".repeat(40);
    for _ in 0..5 {
        let response = admin.login_from(PEER, &wrong).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    let sixth = admin.login_from(PEER, &wrong).await;
    assert_eq!(sixth.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(sixth.code(), "rate_limited");
    assert_eq!(sixth.headers[header::RETRY_AFTER], "60");
    // Even the right token waits; another IP does not.
    let right = admin.login_from(PEER, &admin.token).await;
    assert_eq!(right.status, StatusCode::TOO_MANY_REQUESTS);
    let other = admin.login_from("192.0.2.10:1234", &admin.token).await;
    assert_eq!(other.status, StatusCode::OK);

    admin.hub.state.clock.advance(60_000);
    let later = admin.login_from(PEER, &admin.token).await;
    assert_eq!(later.status, StatusCode::OK);
}

#[tokio::test]
async fn session_expires_after_eight_hours() {
    let admin = Admin::new();
    let login = admin.login().await;
    admin.hub.state.clock.advance(SESSION_TTL_MS - 1);
    let alive = admin
        .call(Method::GET, "/admin/api/overview", &login, None)
        .await;
    assert_eq!(alive.status, StatusCode::OK);
    admin.hub.state.clock.advance(1);
    let expired = admin
        .call(Method::GET, "/admin/api/overview", &login, None)
        .await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert_eq!(expired.code(), "unauthorized");
}

#[tokio::test]
async fn token_login_disabled_without_token_file() {
    let admin = Admin::with(
        TestHub::new(),
        Options {
            token_file: false,
            vars: vec![
                ("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-Forwarded-User".into()),
                ("GIM_HUB_ADMIN_TRUSTED_PROXIES", "10.0.0.0/8".into()),
            ],
            ..Options::default()
        },
    );
    let response = admin.login_from(PEER, &admin.token).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.code(), "forbidden");
}

/// Fills `{param}` placeholders with sample values.
fn concrete(template: &str) -> String {
    template
        .replace("{user_id}", "uexample")
        .replace("{device_id}", "dexample")
        .replace("{handle}", "alice")
}

fn operations() -> Vec<(Method, String)> {
    let mut operations = Vec::new();
    for (template, item) in &AdminDoc::openapi().paths.paths {
        for (method, operation) in [
            (Method::GET, &item.get),
            (Method::PUT, &item.put),
            (Method::POST, &item.post),
            (Method::DELETE, &item.delete),
            (Method::PATCH, &item.patch),
        ] {
            if operation.is_some() {
                operations.push((method, concrete(template)));
            }
        }
    }
    operations
}

#[tokio::test]
async fn every_route_requires_a_session_and_csrf() {
    let admin = Admin::new();
    let login = admin.login().await;
    let cookie = format!("gim_admin_session={}", login.cookie);
    let operations = operations();
    assert_eq!(operations.len(), 20);
    let mut mutations = 0;
    for (method, uri) in operations {
        if uri == "/admin/api/login" {
            continue;
        }
        let anonymous = admin.send(method.clone(), &uri, PEER, &[], None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(anonymous.code(), "unauthorized", "{method} {uri}");
        let bogus = admin
            .send(
                method.clone(),
                &uri,
                PEER,
                &[("cookie", "gim_admin_session=bogus")],
                None,
            )
            .await;
        assert_eq!(bogus.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        if method == Method::GET {
            continue;
        }
        mutations += 1;
        let without = admin
            .send(method.clone(), &uri, PEER, &[("cookie", &cookie)], None)
            .await;
        assert_eq!(without.status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(without.code(), "csrf_failed", "{method} {uri}");
        let wrong = admin
            .send(
                method.clone(),
                &uri,
                PEER,
                &[("cookie", &cookie), ("x-csrf-token", "nope")],
                None,
            )
            .await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(wrong.code(), "csrf_failed", "{method} {uri}");
    }
    assert_eq!(mutations, 10);
    // Unknown API paths, too.
    let unknown = admin
        .send(Method::GET, "/admin/api/nope", PEER, &[], None)
        .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    let unknown = admin
        .call(Method::GET, "/admin/api/nope", &login, None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code(), "not_found");
}

#[tokio::test]
async fn root_redirects_to_the_ui() {
    let admin = Admin::new();
    let response = admin.send(Method::GET, "/", PEER, &[], None).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.headers[header::LOCATION], "/admin/");
}

fn header_admin() -> Admin {
    Admin::with(
        TestHub::new(),
        Options {
            vars: vec![
                ("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-Forwarded-User".into()),
                ("GIM_HUB_ADMIN_TRUSTED_PROXIES", "10.0.0.0/8".into()),
            ],
            ..Options::default()
        },
    )
}

#[tokio::test]
async fn trusted_header_is_honoured_only_from_a_trusted_proxy() {
    let admin = header_admin();
    let identity = [
        ("x-forwarded-user", "alice@example.eu"),
        ("x-forwarded-for", "198.51.100.7, 10.0.0.2"),
    ];
    let untrusted = admin
        .send(
            Method::GET,
            "/admin/api/session",
            "192.0.2.5:4000",
            &identity,
            None,
        )
        .await;
    assert_eq!(untrusted.status, StatusCode::UNAUTHORIZED);
    assert!(session_cookie(&untrusted.headers).is_none());
    // Only GET /session creates a session.
    let other = admin
        .send(
            Method::GET,
            "/admin/api/overview",
            "10.1.2.3:4000",
            &identity,
            None,
        )
        .await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);

    let trusted = admin
        .send(
            Method::GET,
            "/admin/api/session",
            "10.1.2.3:4000",
            &identity,
            None,
        )
        .await;
    assert_eq!(trusted.status, StatusCode::OK, "{}", trusted.body);
    assert_eq!(trusted.body["actor"], "header:alice@example.eu");
    assert_eq!(trusted.body["auth"], "header");
    let login = Login {
        cookie: session_cookie(&trusted.headers).unwrap(),
        csrf: trusted.body["csrf_token"].as_str().unwrap().to_owned(),
    };
    // Mutations still need the cookie and CSRF.
    let cookie = format!("gim_admin_session={}", login.cookie);
    let no_csrf = admin
        .send(
            Method::POST,
            "/admin/api/lode/check",
            "10.1.2.3:4000",
            &[identity[0], ("cookie", &cookie)],
            None,
        )
        .await;
    assert_eq!(no_csrf.code(), "csrf_failed");

    // The source IP is the X-Forwarded-For client behind a trusted proxy,
    // the peer otherwise.
    let audit = admin.audit(&login).await;
    let login_ok = audit.iter().find(|e| e["action"] == "login_ok").unwrap();
    assert_eq!(login_ok["actor"], "header:alice@example.eu");
    assert_eq!(login_ok["source_ip"], "198.51.100.7");
    let spoofed = admin
        .send(
            Method::POST,
            "/admin/api/login",
            "192.0.2.5:4000",
            &[("x-forwarded-for", "203.0.113.1")],
            Some(&json!({ "token": "nope" })),
        )
        .await;
    assert_eq!(spoofed.status, StatusCode::UNAUTHORIZED);
    let audit = admin.audit(&login).await;
    assert_eq!(audit[0]["action"], "login_failed");
    assert_eq!(audit[0]["source_ip"], "192.0.2.5");
}

#[tokio::test]
async fn client_api_listener_has_no_admin_routes() {
    let hub = TestHub::new();
    for path in [
        "/admin/",
        "/admin",
        "/admin/api/session",
        "/admin/api/overview",
        "/admin/api/login",
    ] {
        let response = hub
            .router()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}
