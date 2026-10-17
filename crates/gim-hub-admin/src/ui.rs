//! The admin UI: the SPA from `admin-ui/dist`, embedded at compile time by
//! `build.rs`, served under `/admin/`.

use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};

use crate::AdminError;

include!(concat!(env!("OUT_DIR"), "/admin_ui.rs"));

/// Hashed file names under `assets/` never change content.
const ASSET_CACHE: &str = "public, max-age=31536000, immutable";
/// `index.html` and other unhashed files are revalidated on every load.
const NO_CACHE: &str = "no-cache";

/// `GET /admin` → `/admin/`, and `GET /admin/{path}` → the file under dist,
/// else `index.html` (client-side routes). `/admin/api` paths not matched by
/// the API router answer 404, never the SPA.
pub(crate) fn router() -> Router {
    Router::new()
        .route("/admin", get(|| async { Redirect::to("/admin/") }))
        .route("/admin/", get(|| async { serve("") }))
        .route(
            "/admin/{*path}",
            get(|Path(path): Path<String>| async move { serve(&path) }),
        )
}

fn file(name: &str) -> Option<&'static [u8]> {
    FILES
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .map(|i| FILES[i].1)
}

fn serve(path: &str) -> Response {
    if path == "api" || path.starts_with("api/") {
        return AdminError::NotFound.into_response();
    }
    let (name, body) = match file(path) {
        Some(body) if !path.is_empty() => (path, body),
        _ => ("index.html", file("index.html").unwrap_or_default()),
    };
    let cache = if name.starts_with("assets/") {
        ASSET_CACHE
    } else {
        NO_CACHE
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type(name)),
            (header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response()
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
