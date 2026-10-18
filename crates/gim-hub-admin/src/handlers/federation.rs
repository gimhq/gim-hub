//! Federation status and the allowlist.

use std::collections::BTreeMap;

use axum::{
    extract::{rejection::JsonRejection, State},
    Extension, Json,
};
use gim_hub_api::{
    dto::Error,
    settings::{self, AllowlistSource},
};
use gim_hub_db::admin;
use gim_hub_s2s::{policy::parse_allowlist, FederationService};

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
    description = "The allowlist in force. With `GIM_HUB_FEDERATION_ALLOWLIST` set it is that file \
(`source` `file`, `read_only`). Otherwise it is the stored allowlist (`source` `stored`, table \
`federation_allowlist`), except on a hub that still has the default file \
`$GIM_HUB_DATA_DIR/allowlist` and nothing stored: that file is shown (`source` `file`, not \
read-only) until the first PUT stores an allowlist.",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "The allowlist and its entries", body = Allowlist),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 404, description = "Federation is off (`not_found`)", body = Error),
    ),
)]
pub async fn get_allowlist(State(state): State<AdminState>) -> Result<Json<Allowlist>, AdminError> {
    let federation = state.federation.as_ref().ok_or(AdminError::NotFound)?;
    let sources = state.settings.sources().await?;
    match source(&state, sources.allowlist.is_empty()) {
        AllowlistSource::File { path, read_only } => {
            let text = tokio::fs::read_to_string(&path)
                .await
                .map_err(|err| AdminError::Internal(format!("{}: {err}", path.display())))?;
            let entries = entries(&state, federation, &text)?;
            Ok(Json(Allowlist {
                path: path.display().to_string(),
                text,
                entries,
                source: "file".into(),
                read_only,
            }))
        }
        AllowlistSource::Stored => Ok(Json(stored(&state, &sources.allowlist))),
    }
}

/// The allowlist source of the running hub; `table_empty` tells whether
/// nothing is stored.
fn source(state: &AdminState, table_empty: bool) -> AllowlistSource {
    settings::allowlist_source(
        state
            .settings
            .startup()
            .contains_key("GIM_HUB_FEDERATION_ALLOWLIST"),
        &state.federation_config.allowlist_path,
        table_empty,
    )
}

/// The response for the stored allowlist `entries`.
fn stored(state: &AdminState, entries: &[(String, Vec<String>)]) -> Allowlist {
    Allowlist {
        path: format!(
            "{}#federation_allowlist",
            state.app.config.load().database_path.display()
        ),
        text: settings::render_allowlist(entries),
        entries: entries
            .iter()
            .map(|(hub_id, addrs)| AllowlistEntry {
                hub_id: hub_id.clone(),
                addrs: addrs.clone(),
            })
            .collect(),
        source: "stored".into(),
        read_only: false,
    }
}

/// The parsed entries of allowlist file `text`, by hub ID (the own hub is
/// skipped).
fn entries(
    state: &AdminState,
    federation: &FederationService,
    text: &str,
) -> Result<Vec<AllowlistEntry>, AdminError> {
    let hubs = parse_allowlist(
        text,
        federation.hub_id(),
        state.federation_config.psk.is_some(),
    )
    .map_err(|err| AdminError::Internal(err.to_string()))?;
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
    summary = "Replace the stored federation allowlist",
    description = "Validates the text with the allowlist rules (file format; the own hub is \
skipped, an allowlist naming no other hub is invalid), stores it in the table \
`federation_allowlist` and applies it at once, as SIGHUP does for the file; comments are not \
kept. On a validation error nothing changes. 409 while `GIM_HUB_FEDERATION_ALLOWLIST` is set: \
the file is authoritative. Audited as `allowlist_update`.",
    request_body = AllowlistUpdate,
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Applied", body = Allowlist),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Federation is off (`not_found`)", body = Error),
        (status = 409, description = "The allowlist file is authoritative (`conflict`)", body = Error),
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
            Some("federation_allowlist".into()),
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
    let _write = state.allowlist_write.lock().await;
    if let AllowlistSource::File {
        read_only: true, ..
    } = source(state, true)
    {
        return Err(settings::SettingsError::AllowlistFile.into());
    }
    let entries = settings::parse_allowlist_entries(
        &text,
        federation.hub_id(),
        state.federation_config.psk.is_some(),
    )
    .map_err(AdminError::Unprocessable)?;
    settings::set_allowlist(state.settings.db(), state.settings.env(), entries.clone()).await?;
    federation
        .set_allowlist_text(&settings::render_allowlist(&entries))
        .map_err(|err| AdminError::Internal(err.to_string()))?;
    if let Err(err) = state.settings.reload().await {
        tracing::error!(%err, "stored settings not reloaded");
    }
    Ok(Json(stored(state, &entries)))
}
