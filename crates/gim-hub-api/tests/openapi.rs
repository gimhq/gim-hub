//! Contract tests: the committed `openapi.json` matches the code, and every
//! documented operation is routed behind the documented authentication.

use std::path::Path;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;
use utoipa::{
    openapi::{path::Operation, RefOr},
    OpenApi,
};

use gim_hub_api::{dto::GID_EXAMPLE, openapi_json, testing::TestHub, ApiDoc};

#[test]
fn committed_openapi_json_is_up_to_date() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../openapi.json");
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == openapi_json(),
        "{} is out of date; run scripts/gen-openapi.sh and commit the result",
        path.display()
    );
}

/// Fills `{param}` placeholders with sample values (the gid percent-encoded).
fn concrete_path(template: &str) -> String {
    let gid = GID_EXAMPLE.replace('/', "%2F");
    template
        .replace("{gid}", &gid)
        .replace("{user_id}", "uexample")
        .replace("{device_id}", "dexample")
        .replace("{handle}", "alice")
        .replace("{link_id}", "wgy33neayyoqouya3g77pwolne")
        .replace("{blob_id}", "b_example")
}

/// Whether the operation requires a bearer token checked by `AuthDevice`.
/// `/v2/stream` authenticates after the WebSocket upgrade (close code 4401).
fn requires_token(template: &str, operation: &Operation) -> bool {
    let secured = operation.security.is_some() && template != "/v2/stream";
    let documents_401 = match operation.responses.responses.get("401") {
        Some(RefOr::T(response)) => response.description.contains("`unauthorized`"),
        _ => false,
    };
    assert_eq!(secured, documents_401, "401 contract of {template}");
    secured
}

async fn call(
    hub: &TestHub,
    method: &Method,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method.clone()).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = hub
        .router()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn every_documented_operation_is_routed() {
    let hub = TestHub::new();
    let token = hub.create_session("uexample", "dexample").await;
    let doc = ApiDoc::openapi();
    let mut operations = 0;
    let mut authenticated = 0;
    for (template, item) in &doc.paths.paths {
        let methods = [
            (Method::GET, &item.get),
            (Method::PUT, &item.put),
            (Method::POST, &item.post),
            (Method::DELETE, &item.delete),
            (Method::PATCH, &item.patch),
        ];
        for (method, operation) in methods {
            let Some(operation) = operation else {
                continue;
            };
            operations += 1;
            let uri = concrete_path(template);
            assert!(!uri.contains('{'), "unhandled path parameter in {template}");

            if template == "/healthz" {
                let (status, value) = call(&hub, &method, &uri, None).await;
                assert_eq!(status, StatusCode::OK, "{method} {template}");
                assert_eq!(value["status"], "ok");
                continue;
            }

            if requires_token(template, operation) {
                authenticated += 1;
                let (status, value) = call(&hub, &method, &uri, None).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {template}");
                assert_eq!(value["error"]["code"], "unauthorized");
            }
            // Routed: the router's own 404/405 fallbacks have no JSON body.
            let (status, value) = call(&hub, &method, &uri, Some(&token)).await;
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {template}"
            );
            assert!(
                status != StatusCode::NOT_FOUND || value["error"]["code"] == "not_found",
                "{method} {template}"
            );
        }
    }
    assert_eq!(operations, 31);
    assert_eq!(authenticated, 24);
}
