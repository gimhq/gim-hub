//! The embedded admin UI on the admin listener.

mod support;

use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Method, Request, StatusCode},
};
use support::{Admin, PEER};
use tower::ServiceExt;

/// GET `path`; returns status, headers and the raw body.
async fn get(admin: &Admin, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = admin
        .router()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, body.to_vec())
}

fn is_index(headers: &HeaderMap, body: &[u8]) -> bool {
    headers[header::CONTENT_TYPE] == "text/html; charset=utf-8"
        && headers[header::CACHE_CONTROL] == "no-cache"
        && String::from_utf8_lossy(body).contains("<div id=\"root\"")
}

#[tokio::test]
async fn index_at_the_root_and_on_deep_links() {
    let admin = Admin::new();
    for path in [
        "/admin/",
        "/admin/users/u-x",
        "/admin/login",
        "/admin/nope.js",
    ] {
        let (status, headers, body) = get(&admin, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(is_index(&headers, &body), "{path}");
    }
    let (status, headers, _) = get(&admin, "/admin").await;
    assert!(status.is_redirection());
    assert_eq!(headers[header::LOCATION], "/admin/");
}

#[tokio::test]
async fn assets_have_their_type_and_a_long_cache() {
    let admin = Admin::new();
    let (_, _, index) = get(&admin, "/admin/").await;
    let index = String::from_utf8(index).unwrap();
    for ext in [".js", ".css"] {
        let asset = index
            .split('"')
            .find(|s| s.starts_with("/admin/assets/") && s.ends_with(ext))
            .unwrap_or_else(|| panic!("no {ext} asset in index.html"));
        let (status, headers, body) = get(&admin, asset).await;
        assert_eq!(status, StatusCode::OK, "{asset}");
        let want = if ext == ".js" {
            "text/javascript; charset=utf-8"
        } else {
            "text/css; charset=utf-8"
        };
        assert_eq!(headers[header::CONTENT_TYPE], want, "{asset}");
        assert_eq!(
            headers[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert!(!body.is_empty());
    }
}

#[tokio::test]
async fn unknown_api_paths_are_never_the_ui() {
    let admin = Admin::new();
    for path in ["/admin/api/unknown", "/admin/api/", "/admin/api"] {
        let response = admin.send(Method::GET, path, PEER, &[], None).await;
        assert!(
            response.status == StatusCode::UNAUTHORIZED || response.status == StatusCode::NOT_FOUND,
            "{path}: {}",
            response.status
        );
        assert_ne!(response.body, serde_json::Value::Null, "{path}: not JSON");
    }
    let unknown = admin
        .send(Method::GET, "/admin/api/unknown", PEER, &[], None)
        .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.code(), "unauthorized");

    let login = admin.login().await;
    let unknown = admin
        .call(Method::GET, "/admin/api/unknown", &login, None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code(), "not_found");
}
