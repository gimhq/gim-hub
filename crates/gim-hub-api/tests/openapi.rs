//! Contract tests: the committed `openapi.json` matches the code, and every
//! documented operation is routed.

use std::path::Path;

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;
use utoipa::OpenApi;

use gim_hub_api::{dto::GID_EXAMPLE, openapi_json, router, ApiDoc};

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

#[tokio::test]
async fn every_documented_operation_is_routed() {
    let doc = ApiDoc::openapi();
    let mut operations = 0;
    for (template, item) in &doc.paths.paths {
        let methods = [
            (Method::GET, item.get.is_some()),
            (Method::PUT, item.put.is_some()),
            (Method::POST, item.post.is_some()),
            (Method::DELETE, item.delete.is_some()),
            (Method::PATCH, item.patch.is_some()),
        ];
        for (method, documented) in methods {
            if !documented {
                continue;
            }
            operations += 1;
            let uri = concrete_path(template);
            assert!(!uri.contains('{'), "unhandled path parameter in {template}");
            let response = router()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(&uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            if template == "/healthz" {
                assert_eq!(status, StatusCode::OK, "{method} {template}");
                assert_eq!(value["status"], "ok");
            } else {
                assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{method} {template}");
                assert_eq!(value["error"]["code"], "not_implemented");
            }
        }
    }
    assert_eq!(operations, 31);
}
