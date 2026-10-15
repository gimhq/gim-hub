//! Bearer-token authentication through `AuthDevice`, observed on GET /v2/me.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

use gim_hub_api::testing::{TestHub, TEST_SESSION_TTL_MS};

async fn get_me(hub: &TestHub, authorization: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::get("/v2/me");
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    let response = hub
        .router()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let outcome = value["error"]["code"]
        .as_str()
        .or(value["device_id"].as_str())
        .unwrap();
    (status, outcome.to_owned())
}

fn unauthorized() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "unauthorized".to_owned())
}

#[tokio::test]
async fn missing_or_malformed_credentials_are_rejected() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    assert_eq!(get_me(&hub, None).await, unauthorized());
    assert_eq!(get_me(&hub, Some("Bearer")).await, unauthorized());
    assert_eq!(get_me(&hub, Some("Bearer ")).await, unauthorized());
    assert_eq!(
        get_me(&hub, Some(&format!("Basic {token}"))).await,
        unauthorized()
    );
    assert_eq!(
        get_me(&hub, Some("Bearer not-a-token")).await,
        unauthorized()
    );
}

#[tokio::test]
async fn valid_token_passes_authentication() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let expected = (StatusCode::OK, "d1".to_owned());
    assert_eq!(
        get_me(&hub, Some(&format!("Bearer {token}"))).await,
        expected
    );
    assert_eq!(
        get_me(&hub, Some(&format!("bearer {token}"))).await,
        expected
    );
}

#[tokio::test]
async fn expired_session_is_rejected() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    hub.state.clock.advance(TEST_SESSION_TTL_MS);
    assert_eq!(
        get_me(&hub, Some(&format!("Bearer {token}"))).await,
        unauthorized()
    );
}

#[tokio::test]
async fn inactive_device_is_rejected() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    hub.set_device_active("u1", "d1", false).await;
    assert_eq!(
        get_me(&hub, Some(&format!("Bearer {token}"))).await,
        unauthorized()
    );
}
