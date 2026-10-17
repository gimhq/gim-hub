//! Federation status and the allowlist.

use std::{collections::BTreeMap, path::Path};

use axum::{
    extract::{rejection::JsonRejection, State},
    Extension, Json,
};
use gim_hub_api::dto::Error;
use gim_hub_db::admin;
use gim_hub_s2s::{policy::parse_allowlist, FederationService, PolicyError};

use crate::{
    auth::{seconds, Caller},
    dto::{Allowlist, AllowlistEntry, AllowlistUpdate, FederationStatus, PeerItem},
    error::AdminError,
    state::AdminState,
};

#[utoipa::path(
    get,
    path = "/admin/api/federation",
    tag = "federation",
    summary = "Federation status",
    description = "This hub's PeerID and addresses, and per peer hub (allowlisted, or known to \
the outbox) whether it is bound now, the queued outbox entries, delivery failures and the last \
connection.",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Status", body = FederationStatus),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_federation(
    State(state): State<AdminState>,
) -> Result<Json<FederationStatus>, AdminError> {
    let Some(federation) = &state.federation else {
        return Ok(Json(FederationStatus {
            enabled: false,
            peer_id: None,
            listen_addrs: Vec::new(),
            external_addrs: Vec::new(),
            peers: Vec::new(),
        }));
    };
    let known = state.app.db.read(admin::peer_statuses).await?;
    let bound = federation.transport().bound_hubs();
    let mut peers: BTreeMap<String, PeerItem> = federation
        .allowlist()
        .map(|allowlist| allowlist.hub_ids())
        .unwrap_or_default()
        .into_iter()
        .map(|hub_id| (hub_id.to_string(), peer_item(hub_id.to_string())))
        .collect();
    for status in known {
        let peer = peers
            .entry(status.hub_id.clone())
            .or_insert_with(|| peer_item(status.hub_id.clone()));
        peer.outbox_backlog = status.backlog;
        peer.last_seen = status.last_connected_at.map(seconds);
        peer.last_error = (status.failures > 0)
            .then(|| format!("{} consecutive delivery failures", status.failures));
    }
    for hub_id in bound {
        peers
            .entry(hub_id.to_string())
            .or_insert_with(|| peer_item(hub_id.to_string()))
            .connected = true;
    }
    Ok(Json(FederationStatus {
        enabled: true,
        peer_id: Some(federation.peer_id().to_owned()),
        listen_addrs: state
            .federation_config
            .listen
            .iter()
            .map(ToString::to_string)
            .collect(),
        external_addrs: federation
            .transport()
            .advertised_addrs()
            .iter()
            .map(ToString::to_string)
            .collect(),
        peers: peers.into_values().collect(),
    }))
}

fn peer_item(hub_id: String) -> PeerItem {
    PeerItem {
        hub_id,
        connected: false,
        outbox_backlog: 0,
        last_error: None,
        last_seen: None,
    }
}

#[utoipa::path(
    get,
    path = "/admin/api/federation/allowlist",
    tag = "federation",
    summary = "The federation allowlist",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "The allowlist file and its entries", body = Allowlist),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 404, description = "Federation is off (`not_found`)", body = Error),
    ),
)]
pub async fn get_allowlist(State(state): State<AdminState>) -> Result<Json<Allowlist>, AdminError> {
    let federation = state.federation.as_ref().ok_or(AdminError::NotFound)?;
    let path = state.federation_config.allowlist_path.clone();
    let text = tokio::fs::read_to_string(&path)
        .await
        .map_err(|err| AdminError::Internal(format!("{}: {err}", path.display())))?;
    let entries = entries(&state, federation, &text)
        .map_err(|err| AdminError::Internal(err.to_string()))?;
    Ok(Json(Allowlist {
        path: path.display().to_string(),
        text,
        entries,
    }))
}

/// The parsed entries of allowlist `text`, by hub ID. Same rules as the
/// allowlist loader: the own hub is skipped, and an allowlist naming no other
/// hub is invalid.
fn entries(
    state: &AdminState,
    federation: &FederationService,
    text: &str,
) -> Result<Vec<AllowlistEntry>, PolicyError> {
    let hubs = parse_allowlist(text, federation.hub_id(), state.federation_config.psk.is_some())?;
    if hubs.is_empty() {
        return Err(PolicyError::Empty(
            state.federation_config.allowlist_path.clone(),
        ));
    }
    let mut entries: Vec<_> = hubs
        .into_iter()
        .map(|(hub_id, addrs)| AllowlistEntry {
            hub_id: hub_id.to_string(),
            addrs: addrs.iter().map(ToString::to_string).collect(),
        })
        .collect();
    entries.sort_by(|a, b| a.hub_id.cmp(&b.hub_id));
    Ok(entries)
}

#[utoipa::path(
    put,
    path = "/admin/api/federation/allowlist",
    tag = "federation",
    summary = "Replace the federation allowlist",
    description = "Validates the text with the allowlist rules, writes it atomically to \
`GIM_HUB_FEDERATION_ALLOWLIST` and applies it at once, as SIGHUP does. On a validation error the \
file is unchanged. Audited as `allowlist_update`.",
    request_body = AllowlistUpdate,
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Applied", body = Allowlist),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Federation is off (`not_found`)", body = Error),
        (status = 422, description = "Invalid allowlist; the message is the parser's (`validation_failed`)", body = Error),
    ),
)]
pub async fn put_allowlist(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<AllowlistUpdate>, JsonRejection>,
) -> Result<Json<Allowlist>, AdminError> {
    let result = update_allowlist(&state, body).await;
    let detail = result
        .as_ref()
        .ok()
        .map(|Json(list)| format!("{} hubs", list.entries.len()));
    caller
        .audit(
            &state,
            "allowlist_update",
            Some(state.federation_config.allowlist_path.display().to_string()),
            &result,
            detail,
        )
        .await;
    result
}

async fn update_allowlist(
    state: &AdminState,
    body: Result<Json<AllowlistUpdate>, JsonRejection>,
) -> Result<Json<Allowlist>, AdminError> {
    let federation = state.federation.as_ref().ok_or(AdminError::NotFound)?;
    let Json(AllowlistUpdate { text }) =
        body.map_err(|err| AdminError::BadRequest(err.body_text()))?;
    let entries = entries(state, federation, &text)
        .map_err(|err| AdminError::Unprocessable(err.to_string()))?;
    let _write = state.allowlist_write.lock().await;
    let path = state.federation_config.allowlist_path.clone();
    let service = federation.clone();
    let contents = text.clone();
    let written = path.clone();
    tokio::task::spawn_blocking(move || {
        write_atomically(&written, &contents)?;
        service
            .reload_allowlist()
            .map_err(|err| std::io::Error::other(err.to_string()))
    })
    .await
    .map_err(|err| AdminError::Internal(err.to_string()))?
    .map_err(|err| AdminError::Internal(format!("{}: {err}", path.display())))?;
    Ok(Json(Allowlist {
        path: path.display().to_string(),
        text,
        entries,
    }))
}

/// Writes `contents` to a temporary file next to `path`, then renames it
/// over `path`.
fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.admin-{}.tmp", std::process::id()));
    std::fs::write(&tmp, contents)?;
    if let Ok(meta) = std::fs::metadata(path) {
        // Keep the operator's permissions.
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}
