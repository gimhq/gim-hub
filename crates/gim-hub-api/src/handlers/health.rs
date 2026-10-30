//! Liveness probe and hub identity.

use axum::{
    extract::{rejection::QueryRejection, Query, State},
    response::Html,
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

use crate::{
    dto::{Error, Health, HealthStatus, HubInfo, HubQuery},
    error::ApiError,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    summary = "Liveness probe",
    responses((status = 200, description = "Hub is up", body = Health)),
)]
pub async fn healthz(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: HealthStatus::Ok,
        version: state.config.load().release_version.clone(),
    })
}

/// Human-readable status page at `/` and `/status`: version and system
/// information, so a browser does not land on a 404. 404 unless
/// `GIM_HUB_STATUS_PAGE` (on by default). Not part of the API, so not in the
/// OpenAPI document.
pub async fn status_page(State(state): State<AppState>) -> Result<Html<String>, ApiError> {
    let config = state.config.load();
    if !config.status_page {
        return Err(ApiError::NotFound);
    }
    let public_url = config.public_url.as_deref().unwrap_or("not set");
    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gim hub</title>
<style>
body {{ font: 15px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; color: #1f2328; }}
h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
.ok {{ color: #1a7f37; font-weight: 600; }}
dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1rem; }}
dt {{ color: #59636e; }}
dd {{ margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }}
@media (prefers-color-scheme: dark) {{ body {{ background: #0d1117; color: #e6edf3; }} dt {{ color: #9198a1; }} .ok {{ color: #3fb950; }} }}
</style>
</head>
<body>
<h1>gim hub</h1>
<p class="ok">Operational</p>
<dl>
<dt>Version</dt><dd>{version}</dd>
<dt>Revision</dt><dd>{revision}</dd>
<dt>Platform</dt><dd>{os}/{arch}</dd>
<dt>Hub ID</dt><dd>{hub_id}</dd>
<dt>Public URL</dt><dd>{public_url}</dd>
</dl>
<p>Machine-readable: <a href="/healthz">/healthz</a>, <a href="/v2/hub">/v2/hub</a>.</p>
</body>
</html>
"#,
        version = escape_html(&config.release_version),
        revision = escape_html(option_env!("GIM_HUB_BUILD_REV").unwrap_or("unknown")),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        hub_id = escape_html(state.hub.hub_id().as_ref()),
        public_url = escape_html(public_url),
    )))
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[utoipa::path(
    get,
    path = "/v2/hub",
    tag = "health",
    summary = "This hub's identity",
    description = "Unauthenticated. Lets a client check that a URL belongs to the `hub_id` \
listed in its hosting record before signing in. With `?nonce=` (32 random bytes, base64url \
without padding) the response also carries `proof`, the hub root key's Ed25519 signature over \
`\"gim-hub-proof-v1\" || 0x00 || nonce(32) || u16be(len(hub_id)) || hub_id || \
u16be(len(public_url)) || public_url` (UTF-8, lengths in bytes), base64url without padding; the client \
checks that `hub_id` derives from `hub_root_pubkey`, that `public_url` is the URL it called and \
verifies `proof` with `hub_root_pubkey`. A hub without a configured `public_url` cannot prove \
and answers a nonce with 400.",
    params(HubQuery),
    responses(
        (status = 200, description = "Hub identity", body = HubInfo),
        (status = 400, description = "Malformed nonce, or a nonce while this hub has no public URL (`validation_failed`)", body = Error),
    ),
)]
pub async fn get_hub(
    State(state): State<AppState>,
    query: Result<Query<HubQuery>, QueryRejection>,
) -> Result<Json<HubInfo>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::ValidationFailed(err.body_text()))?;
    let public_url = state.config.load().public_url.clone();
    let proof = match query.nonce {
        None => None,
        Some(nonce) => {
            let nonce: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&nonce)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    ApiError::ValidationFailed(
                        "nonce must be 32 bytes, base64url without padding".into(),
                    )
                })?;
            let url = public_url.as_deref().ok_or_else(|| {
                ApiError::ValidationFailed(
                    "proof unavailable: this hub has no public URL (GIM_HUB_PUBLIC_URL)".into(),
                )
            })?;
            let proof = state
                .hub
                .sign_proof(&nonce, url)
                .map_err(|err| ApiError::Internal(err.to_string()))?;
            Some(URL_SAFE_NO_PAD.encode(proof))
        }
    };
    Ok(Json(HubInfo {
        hub_id: state.hub.hub_id().to_string(),
        hub_root_pubkey: STANDARD.encode(state.hub.signing_key().verifying_key().as_bytes()),
        version: state.config.load().release_version.clone(),
        public_url,
        proof,
    }))
}
