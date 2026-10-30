//! GET / and GET /status: the human-readable status page, switched by
//! GIM_HUB_STATUS_PAGE.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use gim_hub_api::testing::TestHub;
use tower::ServiceExt;

async fn get(hub: &TestHub, uri: &str) -> (StatusCode, Option<String>, String) {
    let request = Request::get(uri).body(Body::empty()).unwrap();
    let response = hub.router().oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

fn configure(hub: &TestHub, edit: impl FnOnce(&mut gim_hub_api::config::Config)) {
    let mut config = (*hub.state.config.load()).clone();
    edit(&mut config);
    hub.state.config.store(config);
}

#[tokio::test]
async fn root_and_status_show_the_version_and_system_information() {
    let hub = TestHub::new();
    configure(&hub, |c| {
        c.public_url = Some("https://hub.example.eu".to_owned())
    });
    let version = hub.state.config.load().release_version.clone();

    for uri in ["/", "/status"] {
        let (status, content_type, body) = get(&hub, uri).await;

        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(content_type.unwrap().starts_with("text/html"), "{uri}");
        assert!(body.contains("<title>gim hub</title>"), "{body}");
        assert!(body.contains("Operational"), "{body}");
        assert!(body.contains(&version), "{body}");
        assert!(body.contains(hub.state.hub.hub_id().as_ref()), "{body}");
        assert!(body.contains("https://hub.example.eu"), "{body}");
        assert!(body.contains("Revision"), "{body}");
        let platform = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);
        assert!(body.contains(&platform), "{body}");
    }
}

#[tokio::test]
async fn the_status_page_escapes_the_public_url() {
    let hub = TestHub::new();
    configure(&hub, |c| {
        c.public_url = Some("https://hub.example.eu/<script>".to_owned())
    });

    let (_, _, body) = get(&hub, "/status").await;

    assert!(!body.contains("<script>"), "{body}");
    assert!(body.contains("&lt;script&gt;"), "{body}");
}

#[tokio::test]
async fn the_status_page_is_404_when_switched_off() {
    let hub = TestHub::new();
    configure(&hub, |c| c.status_page = false);

    for uri in ["/", "/status"] {
        let (status, _, body) = get(&hub, uri).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert!(!body.contains("gim hub"), "{body}");
    }
}

#[tokio::test]
async fn the_status_page_is_on_by_default() {
    assert!(TestHub::new().state.config.load().status_page);
}
