//! Admin API of the gim hub (docs/admin.md), served only on the separate
//! `GIM_HUB_ADMIN_LISTEN` listener, never on the client API listener.
//!
//! [`AdminDoc`] is the contract (committed as `admin-openapi.json` at the
//! repository root). [`api_router`] serves `/admin/api/*` behind the session
//! and CSRF checks; [`router`] adds `GET /` → `/admin/` and the admin UI
//! (`admin-ui/dist`, embedded at compile time by `build.rs`) on the other
//! `/admin/` paths.

pub mod auth;
pub mod config;
pub mod dto;
pub mod error;
pub mod handlers;
#[path = "../../gim-hub/src/lode.rs"]
mod lode;
pub mod state;
mod ui;

pub use config::AdminConfig;
pub use error::AdminError;
pub use state::AdminState;

use axum::{
    http::{header, StatusCode},
    middleware,
    routing::{delete, get, post},
    Router,
};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};

use crate::handlers as h;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "gim-hub admin API",
        version = "1.0.0",
        description = "Admin API of the gim hub, served only on `GIM_HUB_ADMIN_LISTEN`. Metadata \
only: messages are end-to-end encrypted and the API never shows who talks to whom.\n\n\
Every route except POST /admin/api/login needs the `gim_admin_session` cookie; every non-GET \
request also needs `X-CSRF-Token` equal to the session's `csrf_token` (403 `csrf_failed`). \
Timestamps are integer seconds since the Unix epoch, except lode's, which are passed through \
from `state.json`. Every non-2xx JSON response has the shape `{\"error\":{\"code\",\"message\"}}`.",
    ),
    paths(
        auth::login,
        auth::logout,
        auth::get_session,
        h::overview::get_overview,
        h::users::list_users,
        h::users::get_user,
        h::users::suspend_user,
        h::users::unsuspend_user,
        h::users::revoke_device_sessions,
        h::users::release_handle,
        h::user_policy::get_user_policy,
        h::user_policy::put_user_policy,
        h::user_policy::add_user_policy_entry,
        h::user_policy::remove_user_policy_entry,
        h::federation::get_federation,
        h::federation::get_allowlist,
        h::federation::put_allowlist,
        h::lode::get_lode,
        h::lode::lode_check,
        h::lode::lode_update,
        h::lode::lode_restart,
        h::lode::lode_rollback,
        h::config::get_config,
        h::settings::list_settings,
        h::settings::get_setting,
        h::settings::put_setting,
        h::settings::delete_setting,
        h::audit::list_audit,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Admin sessions"),
        (name = "overview", description = "Hub overview"),
        (name = "users", description = "Users, devices, sessions, handles and the user policy"),
        (name = "federation", description = "Federation status and allowlist"),
        (name = "lode", description = "The lode supervisor"),
        (name = "config", description = "Effective configuration"),
        (name = "settings", description = "Stored settings"),
        (name = "audit", description = "Admin audit log"),
    ),
)]
pub struct AdminDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "adminSession",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                auth::COOKIE_NAME,
                "Session cookie from POST /admin/api/login (or GET /admin/api/session behind a \
trusted proxy). Non-GET requests also send X-CSRF-Token.",
            ))),
        );
    }
}

/// The admin OpenAPI document as committed in `admin-openapi.json`: pretty
/// JSON with a trailing newline.
pub fn admin_openapi_json() -> String {
    let mut json = AdminDoc::openapi()
        .to_pretty_json()
        .expect("OpenAPI document serializes");
    json.push('\n');
    json
}

/// The `/admin/api/*` routes, behind [`auth`]'s session and CSRF checks.
/// Unknown `/admin/api/` paths answer 404 `not_found` (401 without a
/// session).
pub fn api_router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/api/login", post(auth::login))
        .route("/admin/api/logout", post(auth::logout))
        .route("/admin/api/session", get(auth::get_session))
        .route("/admin/api/overview", get(h::overview::get_overview))
        .route("/admin/api/users", get(h::users::list_users))
        .route(
            "/admin/api/users/policy",
            get(h::user_policy::get_user_policy).put(h::user_policy::put_user_policy),
        )
        .route(
            "/admin/api/users/policy/entries",
            post(h::user_policy::add_user_policy_entry),
        )
        .route(
            "/admin/api/users/policy/entries/{user_id}",
            delete(h::user_policy::remove_user_policy_entry),
        )
        .route("/admin/api/users/{user_id}", get(h::users::get_user))
        .route(
            "/admin/api/users/{user_id}/suspend",
            post(h::users::suspend_user),
        )
        .route(
            "/admin/api/users/{user_id}/unsuspend",
            post(h::users::unsuspend_user),
        )
        .route(
            "/admin/api/users/{user_id}/devices/{device_id}/sessions",
            delete(h::users::revoke_device_sessions),
        )
        .route(
            "/admin/api/handles/{handle}/release",
            post(h::users::release_handle),
        )
        .route("/admin/api/federation", get(h::federation::get_federation))
        .route(
            "/admin/api/federation/allowlist",
            get(h::federation::get_allowlist).put(h::federation::put_allowlist),
        )
        .route("/admin/api/lode", get(h::lode::get_lode))
        .route("/admin/api/lode/check", post(h::lode::lode_check))
        .route("/admin/api/lode/update", post(h::lode::lode_update))
        .route("/admin/api/lode/restart", post(h::lode::lode_restart))
        .route("/admin/api/lode/rollback", post(h::lode::lode_rollback))
        .route("/admin/api/config", get(h::config::get_config))
        .route("/admin/api/settings", get(h::settings::list_settings))
        .route(
            "/admin/api/settings/{key}",
            get(h::settings::get_setting)
                .put(h::settings::put_setting)
                .delete(h::settings::delete_setting),
        )
        .route("/admin/api/audit", get(h::audit::list_audit))
        .route("/admin/api/{*rest}", axum::routing::any(not_found))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ))
        .with_state(state)
}

async fn not_found() -> AdminError {
    AdminError::NotFound
}

/// [`api_router`] plus `GET /` redirecting to `/admin/` and the embedded
/// admin UI on every other `/admin/` path (`index.html` for client-side
/// routes; never for `/admin/api/*`).
pub fn router(state: AdminState) -> Router {
    api_router(state)
        .route(
            "/",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/admin/")]) }),
        )
        .merge(ui::router())
}
