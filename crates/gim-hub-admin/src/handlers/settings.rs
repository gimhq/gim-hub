//! Stored settings (docs/operations.md, "Stored settings"):
//! GET /admin/api/settings and GET, PUT, DELETE /admin/api/settings/{key}.

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    Extension, Json,
};
use gim_hub_api::{
    dto::Error,
    settings::{self, SettingState, SettingsError, SETTINGS},
};

use crate::{
    auth::{seconds, Caller},
    dto::{SettingItem, SettingList, SettingUpdate},
    error::AdminError,
    state::AdminState,
};

impl From<SettingsError> for AdminError {
    fn from(err: SettingsError) -> Self {
        match err {
            SettingsError::NotFound(_) => Self::NotFound,
            SettingsError::SetByEnv | SettingsError::AllowlistFile => {
                Self::Conflict(err.to_string())
            }
            SettingsError::Invalid(message) => Self::Unprocessable(message),
            SettingsError::Db(err) => err.into(),
        }
    }
}

fn item(state: SettingState) -> SettingItem {
    let setting = state.setting;
    SettingItem {
        key: setting.key.to_owned(),
        group: setting.group.to_owned(),
        kind: setting.kind.as_str().to_owned(),
        choices: setting
            .choices
            .map(|choices| choices.iter().map(|c| (*c).to_owned()).collect()),
        description: setting.description.to_owned(),
        default: setting.default_json(),
        value: state.value,
        is_set: state.is_set,
        source: state.source.as_str().to_owned(),
        read_only: state.source == settings::Source::Env,
        apply: setting.apply.as_str().to_owned(),
        restart_pending: state.restart_pending,
        updated_at: state.updated_at.map(seconds),
        updated_by: state.updated_by,
    }
}

/// The current item of `key`; 404 for an unknown key.
async fn current(state: &AdminState, key: &str) -> Result<SettingItem, AdminError> {
    let setting = settings::find(key).ok_or(AdminError::NotFound)?;
    let sources = state.settings.sources().await?;
    Ok(item(state.settings.state(&sources, setting)))
}

#[utoipa::path(
    get,
    path = "/admin/api/settings",
    tag = "settings",
    summary = "Stored settings",
    description = "Every stored setting with its effective value and source. Precedence: \
environment variable > stored value > default; a setting set by the environment is read-only. \
Secrets are never returned (`value` is `null`, `is_set` tells whether one exists). The bootstrap \
settings (listeners, data directory, database path, admin token and proxy settings) are \
environment-only and not listed here; see GET /admin/api/config.",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Settings", body = SettingList),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_settings(
    State(state): State<AdminState>,
) -> Result<Json<SettingList>, AdminError> {
    let sources = state.settings.sources().await?;
    let items: Vec<_> = SETTINGS
        .iter()
        .map(|setting| item(state.settings.state(&sources, setting)))
        .collect();
    Ok(Json(SettingList {
        restart_pending: items.iter().any(|item| item.restart_pending),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/admin/api/settings/{key}",
    tag = "settings",
    summary = "One stored setting",
    params(("key" = String, Path, description = "The environment variable name, e.g. GIM_HUB_EVENT_RETENTION_DAYS")),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "The setting", body = SettingItem),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 404, description = "Unknown or bootstrap key (`not_found`)", body = Error),
    ),
)]
pub async fn get_setting(
    State(state): State<AdminState>,
    Path(key): Path<String>,
) -> Result<Json<SettingItem>, AdminError> {
    Ok(Json(current(&state, &key).await?))
}

#[utoipa::path(
    put,
    path = "/admin/api/settings/{key}",
    tag = "settings",
    summary = "Store a setting",
    description = "Validates the value with the same parser as the environment variable, in the \
context of the other settings (dependent values are written in order: the webhook secret before \
the URL, the public URL before enabling federation), stores it and applies a `live` setting at \
once; a `restart` setting is reported as `restart_pending` until the hub restarts. Secrets take \
a string and are never returned. Audited as `setting_update` (detail `old -> new`, secrets as \
`***`).",
    params(("key" = String, Path, description = "The environment variable name")),
    request_body = SettingUpdate,
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Stored", body = SettingItem),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown or bootstrap key (`not_found`)", body = Error),
        (status = 409, description = "Set by the environment (`conflict`)", body = Error),
        (status = 422, description = "Invalid value; the message is the parser's (`validation_failed`)", body = Error),
    ),
)]
pub async fn put_setting(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    body: Result<Json<SettingUpdate>, JsonRejection>,
) -> Result<Json<SettingItem>, AdminError> {
    let result = async {
        let Json(SettingUpdate { value }) =
            body.map_err(|err| AdminError::BadRequest(err.body_text()))?;
        let detail = settings::set(
            state.settings.db(),
            state.settings.env(),
            &key,
            &value,
            caller.actor(),
            state.now_ms(),
        )
        .await?;
        Ok::<_, AdminError>(detail)
    }
    .await;
    finish(&state, &caller, "setting_update", key, result).await
}

#[utoipa::path(
    delete,
    path = "/admin/api/settings/{key}",
    tag = "settings",
    summary = "Unset a stored setting",
    description = "Deletes the stored value: the default applies (a `live` setting at once). The \
remaining settings must stay valid (e.g. the public URL cannot be unset while federation is \
enabled: 422). Audited as `setting_unset`.",
    params(("key" = String, Path, description = "The environment variable name")),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Unset", body = SettingItem),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown or bootstrap key (`not_found`)", body = Error),
        (status = 409, description = "Set by the environment (`conflict`)", body = Error),
        (status = 422, description = "The other settings need a value (`validation_failed`)", body = Error),
    ),
)]
pub async fn delete_setting(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
) -> Result<Json<SettingItem>, AdminError> {
    let result = settings::unset(state.settings.db(), state.settings.env(), &key)
        .await
        .map_err(AdminError::from);
    finish(&state, &caller, "setting_unset", key, result).await
}

/// Applies a successful write at once, audits the outcome and answers the
/// current item.
async fn finish(
    state: &AdminState,
    caller: &Caller,
    action: &'static str,
    key: String,
    result: Result<String, AdminError>,
) -> Result<Json<SettingItem>, AdminError> {
    if result.is_ok() {
        if let Err(err) = state.settings.reload().await {
            tracing::error!(%err, "stored settings not reloaded");
        }
    }
    let detail = result.as_ref().ok().cloned();
    caller
        .audit(state, action, Some(key.clone()), &result, detail)
        .await;
    result?;
    Ok(Json(current(state, &key).await?))
}
