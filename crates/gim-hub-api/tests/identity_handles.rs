//! Handle directory: claim, release, lookup.

mod identity_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use serde_json::json;

use identity_support::{code, send};

#[tokio::test]
async fn claim_release_and_lookup() {
    let hub = TestHub::new();
    let alice = hub.create_session("u1", "d1").await;
    let bob = hub.create_session("u2", "d2").await;
    let call = |method: Method, handle: &str, token: &str| {
        let (hub, uri, token) = (&hub, format!("/v2/handles/{handle}"), token.to_owned());
        async move { send(hub, method, &uri, Some(&token), None).await }
    };

    let (status, body) = call(Method::PUT, "alice", &alice).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "handle": "alice", "user_id": "u1" }));
    // Re-claiming the own handle is a no-op.
    assert_eq!(call(Method::PUT, "alice", &alice).await.0, StatusCode::OK);

    let (status, body) = call(Method::PUT, "alice", &bob).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&body), "handle_taken");

    let (status, body) = call(Method::GET, "alice", &bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "handle": "alice", "user_id": "u1" }));

    // Claiming a new handle releases the old one.
    assert_eq!(call(Method::PUT, "alice_2", &alice).await.0, StatusCode::OK);
    let (status, body) = call(Method::GET, "alice", &bob).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
    assert_eq!(call(Method::PUT, "alice", &bob).await.0, StatusCode::OK);

    let (status, body) = call(Method::DELETE, "alice_2", &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "forbidden");
    let (status, body) = call(Method::DELETE, "alice_2", &alice).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_null());
    let (status, body) = call(Method::DELETE, "alice_2", &alice).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
    assert_eq!(
        call(Method::GET, "alice_2", &alice).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn invalid_handles_are_rejected() {
    let hub = TestHub::new();
    let token = hub.create_session("u1", "d1").await;
    let long = "a".repeat(33);
    for handle in ["ab", "Alice", "al-ice", "al%20ice", long.as_str()] {
        for method in [Method::PUT, Method::GET, Method::DELETE] {
            let uri = format!("/v2/handles/{handle}");
            let (status, body) = send(&hub, method.clone(), &uri, Some(&token), None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {handle}");
            assert_eq!(code(&body), "validation_failed");
        }
    }
    let ok = "a".repeat(32);
    let (status, _) = send(
        &hub,
        Method::PUT,
        &format!("/v2/handles/{ok}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
