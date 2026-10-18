//! Client HTTP/WebSocket API v2 for the gim hub.
//!
//! [`ApiDoc`] is the OpenAPI contract (committed as `openapi.json` at the
//! repository root); [`router`] serves it on an [`AppState`].

pub mod auth;
pub mod config;
pub mod dto;
pub mod error;
pub mod handlers;
pub mod hub;
pub mod mls;
pub mod notifier;
pub mod ratelimit;
pub mod settings;
pub mod state;
#[cfg(feature = "testing")]
pub mod testing;
pub mod user_policy;

pub use auth::AuthDevice;
pub use config::Config;
pub use error::ApiError;
pub use hub::HubIdentity;
pub use notifier::Notifier;
pub use state::{AppState, Clock, SharedConfig};

use axum::{
    routing::{get, post, put},
    Router,
};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::handlers as h;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "gim-hub client API",
        version = "2.0.0",
        description = "Client API of the gim hub, the delivery service for MLS (RFC 9420) end-to-end \
encrypted IM clients. The hub stores and fans out opaque MLS messages and encrypted blobs and \
never sees plaintext or keys.\n\n\
JSON fields are snake_case, timestamps are integer milliseconds since the Unix epoch, binary \
values are standard base64. Identity objects (DeviceList, AuthChallenge, recovery backup, link \
bundle) are gim-core CBOR wire formats carried as opaque base64 strings. User and device IDs are \
opaque strings whose format is owned by gim-core. Every non-2xx JSON response has the shape \
`{\"error\":{\"code\",\"message\"}}`.",
    ),
    paths(
        h::healthz,
        h::get_hub,
        h::create_auth_challenge,
        h::create_session,
        h::put_device_list,
        h::get_device_list,
        h::get_user,
        h::get_me,
        h::put_handle,
        h::delete_handle,
        h::get_handle,
        h::put_recovery_backup,
        h::get_recovery_backup,
        h::create_link_bundle,
        h::get_link_bundle,
        h::upload_key_packages,
        h::count_key_packages,
        h::claim_key_packages,
        h::create_group,
        h::list_groups,
        h::get_group,
        h::submit_commit,
        h::send_message,
        h::list_messages,
        h::list_events,
        h::stream,
        h::list_pending_welcomes,
        h::ack_welcome,
        h::upload_blob,
        h::download_blob,
        h::put_push_registration,
        h::delete_push_registration,
        h::create_hosting_entry,
        h::put_hosting_record,
        h::get_hosting_record,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Liveness"),
        (name = "auth", description = "Device sign-in by signature challenge"),
        (name = "identity", description = "Users and their self-certifying DeviceLists"),
        (name = "handles", description = "Optional per-hub handle directory"),
        (name = "recovery", description = "Encrypted recovery backups"),
        (name = "linking", description = "Link-bundle relay for adding a device"),
        (name = "keypackages", description = "MLS KeyPackages"),
        (name = "groups", description = "Groups and MLS Commits"),
        (name = "messages", description = "MLS application messages"),
        (name = "events", description = "Per-device event stream"),
        (name = "blobs", description = "Encrypted attachments"),
        (name = "push", description = "Push registration"),
        (name = "hosting", description = "Hosting records: which hubs host a user (federation)"),
    ),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("Device token from POST /v2/auth/session"))
                    .build(),
            ),
        );
    }
}

/// The OpenAPI document as committed in `openapi.json`: pretty JSON with a
/// trailing newline.
pub fn openapi_json() -> String {
    let mut json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("OpenAPI document serializes");
    json.push('\n');
    json
}

/// Routes of the client API, including `/healthz`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(h::healthz))
        .route("/v2/hub", get(h::get_hub))
        .route("/v2/auth/challenge", post(h::create_auth_challenge))
        .route("/v2/auth/session", post(h::create_session))
        .route(
            "/v2/users/{user_id}/device-list",
            put(h::put_device_list).get(h::get_device_list),
        )
        .route("/v2/users/{user_id}", get(h::get_user))
        .route("/v2/me", get(h::get_me))
        .route(
            "/v2/handles/{handle}",
            put(h::put_handle)
                .delete(h::delete_handle)
                .get(h::get_handle),
        )
        .route(
            "/v2/users/{user_id}/recovery-backup",
            put(h::put_recovery_backup).get(h::get_recovery_backup),
        )
        .route("/v2/link-bundles", post(h::create_link_bundle))
        .route("/v2/link-bundles/{link_id}", get(h::get_link_bundle))
        .route("/v2/keypackages", post(h::upload_key_packages))
        .route("/v2/keypackages/count", get(h::count_key_packages))
        .route("/v2/keypackages/claim", post(h::claim_key_packages))
        .route("/v2/groups", post(h::create_group).get(h::list_groups))
        .route("/v2/groups/{gid}", get(h::get_group))
        .route("/v2/groups/{gid}/commits", post(h::submit_commit))
        .route(
            "/v2/groups/{gid}/messages",
            post(h::send_message).get(h::list_messages),
        )
        .route("/v2/events", get(h::list_events))
        .route("/v2/stream", get(h::stream))
        .route("/v2/welcomes/pending", get(h::list_pending_welcomes))
        .route("/v2/welcomes/{gid}/ack", post(h::ack_welcome))
        .route("/v2/blobs", post(h::upload_blob))
        .route("/v2/blobs/{blob_id}", get(h::download_blob))
        .route(
            "/v2/push/registration",
            put(h::put_push_registration).delete(h::delete_push_registration),
        )
        // Test-only, outside the contract; 404 unless GIM_HUB_PUSH_LOG_ENDPOINT=true.
        .route("/v2/debug/push-log", get(h::get_push_log))
        .route(
            "/v2/users/{user_id}/hosting-entry",
            post(h::create_hosting_entry),
        )
        .route(
            "/v2/users/{user_id}/hosting-record",
            put(h::put_hosting_record).get(h::get_hosting_record),
        )
        .with_state(state)
}
