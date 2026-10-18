//! The user policy list (docs/operations.md, "User policy"):
//! GET, PUT /admin/api/users/policy, POST /admin/api/users/policy/entries
//! and DELETE /admin/api/users/policy/entries/{user_id}. The mode is the
//! stored setting `GIM_HUB_USER_POLICY` (settings API).

use std::collections::BTreeMap;

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    Extension, Json,
};
use gim_hub_api::{
    dto::Error,
    settings,
    user_policy::{self as policy, MODE_KEY},
};
use gim_hub_db::{
    handles,
    user_policy::{self as db, ListEntry},
    DbError,
};

use crate::{
    auth::{seconds, Caller},
    dto::{UserPolicy, UserPolicyAdd, UserPolicyEntry, UserPolicyUpdate},
    error::AdminError,
    state::AdminState,
};

/// The policy in force and the stored list.
async fn current(state: &AdminState) -> Result<UserPolicy, AdminError> {
    let sources = state.settings.sources().await?;
    let setting = settings::find(MODE_KEY).expect("registered");
    let mode_state = state.settings.state(&sources, setting);
    let mode = state.app.user_policy.mode();
    let not_admitted_users = policy::count_not_admitted(&state.app.db, mode).await?;
    let entries = state.app.db.read(db::load).await?;
    Ok(UserPolicy {
        mode: mode.as_str().to_owned(),
        mode_source: mode_state.source.as_str().to_owned(),
        not_admitted_users,
        entries: entries
            .into_iter()
            .map(|listed| UserPolicyEntry {
                user_id: listed.entry.user_id,
                handle: listed.handle,
                added_at: seconds(listed.entry.added_at),
                added_by: listed.entry.added_by,
                note: listed.entry.note,
            })
            .collect(),
    })
}

/// Applies a list change at once (the policy in force and the session
/// cleanup), audits the outcome and answers the current policy.
async fn finish(
    state: &AdminState,
    caller: &Caller,
    action: &'static str,
    target: Option<String>,
    result: Result<Option<String>, AdminError>,
) -> Result<Json<UserPolicy>, AdminError> {
    if result.is_ok() {
        if let Err(err) = state.settings.reload().await {
            tracing::error!(%err, "user policy not reloaded");
        }
    }
    let detail = result.as_ref().ok().cloned().flatten();
    caller.audit(state, action, target, &result, detail).await;
    result?;
    Ok(Json(current(state).await?))
}

#[utoipa::path(
    get,
    path = "/admin/api/users/policy",
    tag = "users",
    summary = "The user policy",
    description = "The mode in force (`GIM_HUB_USER_POLICY`: `open`, `allow` or `deny`) with its \
source, the number of users of this hub it does not admit, and the user list (table \
`user_policy_list`) with each user's handle. The mode is changed through the settings API \
(PUT /admin/api/settings/GIM_HUB_USER_POLICY), unless the environment sets it.",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "The user policy", body = UserPolicy),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_user_policy(
    State(state): State<AdminState>,
) -> Result<Json<UserPolicy>, AdminError> {
    Ok(Json(current(&state).await?))
}

#[utoipa::path(
    put,
    path = "/admin/api/users/policy",
    tag = "users",
    summary = "Replace the user list",
    description = "Replaces the whole list with `text`: one user ID per line, `#` starts a \
comment, blank lines are skipped. Every line is validated with the user ID parser; on an invalid \
line nothing is stored (422, the message names the line number). Users that stay listed keep \
their `added_at`, `added_by` and `note`. Applied at once: users the policy no longer admits lose \
their sessions and pending sign-in challenges. Editable in every mode. Audited as \
`users_policy_update` (target `N entries`).",
    request_body = UserPolicyUpdate,
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Replaced and applied", body = UserPolicy),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 422, description = "Invalid line, e.g. `line 3: invalid user ID ...` (`validation_failed`)", body = Error),
    ),
)]
pub async fn put_user_policy(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<UserPolicyUpdate>, JsonRejection>,
) -> Result<Json<UserPolicy>, AdminError> {
    let parsed = body
        .map_err(|err| AdminError::BadRequest(err.body_text()))
        .and_then(|Json(UserPolicyUpdate { text })| {
            policy::parse_list(&text).map_err(AdminError::Unprocessable)
        });
    let target = parsed
        .as_ref()
        .ok()
        .map(|user_ids| format!("{} entries", user_ids.len()));
    let result = match parsed {
        Ok(user_ids) => {
            let (actor, now) = (caller.actor().to_owned(), state.now_ms());
            state
                .app
                .db
                .write(move |tx| {
                    let existing: BTreeMap<String, ListEntry> = db::load(tx)?
                        .into_iter()
                        .map(|listed| (listed.entry.user_id.clone(), listed.entry))
                        .collect();
                    let entries: Vec<ListEntry> = user_ids
                        .into_iter()
                        .map(|user_id| {
                            existing.get(&user_id).cloned().unwrap_or(ListEntry {
                                user_id,
                                added_at: now,
                                added_by: actor.clone(),
                                note: None,
                            })
                        })
                        .collect();
                    let added = entries
                        .iter()
                        .filter(|entry| !existing.contains_key(&entry.user_id))
                        .count();
                    let removed = existing.len() + added - entries.len();
                    db::replace(tx, &entries)?;
                    Ok::<_, DbError>(Some(format!("{added} added, {removed} removed")))
                })
                .await
                .map_err(AdminError::from)
        }
        Err(err) => Err(err),
    };
    finish(&state, &caller, "users_policy_update", target, result).await
}

#[utoipa::path(
    post,
    path = "/admin/api/users/policy/entries",
    tag = "users",
    summary = "Add a user to the list",
    description = "Adds one user by `user_id` (validated with the user ID parser) or by `handle` \
(a handle on this hub, resolved to its user ID; a leading `@` is ignored), with an optional \
`note`. Applied at once, as for PUT. Audited as `users_policy_add` (target the user ID).",
    request_body = UserPolicyAdd,
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Added and applied", body = UserPolicy),
        (status = 400, description = "Malformed body, or not exactly one of `user_id` and `handle` (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown handle (`not_found`)", body = Error),
        (status = 409, description = "The user is already listed (`conflict`)", body = Error),
        (status = 422, description = "Invalid user ID (`validation_failed`)", body = Error),
    ),
)]
pub async fn add_user_policy_entry(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<UserPolicyAdd>, JsonRejection>,
) -> Result<Json<UserPolicy>, AdminError> {
    let user_id = resolve(&state, body).await;
    let target = user_id.as_ref().ok().map(|(user_id, _)| user_id.clone());
    let result = match user_id {
        Ok((user_id, note)) => {
            let entry = ListEntry {
                user_id,
                added_at: state.now_ms(),
                added_by: caller.actor().to_owned(),
                note,
            };
            let detail = entry.note.clone();
            match state.app.db.write(move |tx| db::add(tx, &entry)).await {
                Ok(true) => Ok(detail),
                Ok(false) => Err(AdminError::Conflict("the user is already listed".into())),
                Err(err) => Err(err.into()),
            }
        }
        Err(err) => Err(err),
    };
    finish(&state, &caller, "users_policy_add", target, result).await
}

/// The user ID and note of an add request.
async fn resolve(
    state: &AdminState,
    body: Result<Json<UserPolicyAdd>, JsonRejection>,
) -> Result<(String, Option<String>), AdminError> {
    let Json(add) = body.map_err(|err| AdminError::BadRequest(err.body_text()))?;
    let note = add
        .note
        .map(|note| note.trim().to_owned())
        .filter(|note| !note.is_empty());
    let user_id = match (add.user_id, add.handle) {
        (Some(user_id), None) => {
            policy::parse_user_id(&user_id).map_err(AdminError::Unprocessable)?
        }
        (None, Some(handle)) => {
            let name = policy::handle_name(&handle);
            state
                .app
                .db
                .read(move |conn| handles::owner(conn, &name))
                .await?
                .ok_or(AdminError::NotFound)?
        }
        _ => {
            return Err(AdminError::BadRequest(
                "exactly one of user_id and handle is required".into(),
            ))
        }
    };
    Ok((user_id, note))
}

#[utoipa::path(
    delete,
    path = "/admin/api/users/policy/entries/{user_id}",
    tag = "users",
    summary = "Remove a user from the list",
    description = "Applied at once, as for PUT. Audited as `users_policy_remove` (target the user \
ID).",
    params(("user_id" = String, Path, description = "User ID")),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Removed and applied", body = UserPolicy),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "The user is not listed (`not_found`)", body = Error),
    ),
)]
pub async fn remove_user_policy_entry(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path(user_id): Path<String>,
) -> Result<Json<UserPolicy>, AdminError> {
    let id = user_id.clone();
    let result = match state.app.db.write(move |tx| db::remove(tx, &id)).await {
        Ok(true) => Ok(None),
        Ok(false) => Err(AdminError::NotFound),
        Err(err) => Err(err.into()),
    };
    finish(
        &state,
        &caller,
        "users_policy_remove",
        Some(user_id),
        result,
    )
    .await
}
