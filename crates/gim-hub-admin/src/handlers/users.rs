//! Users, devices, sessions and handles. Metadata only (no group
//! membership, peers or message metadata).

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gim_hub_api::dto::Error;
use gim_hub_db::{
    admin::{self, Suspension},
    handles, hosting,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::{
    auth::{seconds, Caller},
    dto::{DeviceItem, Revoked, SessionItem, SuspendRequest, UserDetail, UserItem, UserList},
    error::AdminError,
    state::AdminState,
};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 100;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UserQuery {
    /// Case-insensitive substring of the user ID or handle.
    pub q: Option<String>,
    /// 1 to 100, default 50.
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// `limit` within `1..=max`, or 400.
pub(crate) fn page_limit(limit: Option<u32>, default: u32, max: u32) -> Result<u32, AdminError> {
    let limit = limit.unwrap_or(default);
    if (1..=max).contains(&limit) {
        Ok(limit)
    } else {
        Err(AdminError::BadRequest(format!(
            "limit must be between 1 and {max}"
        )))
    }
}

#[utoipa::path(
    get,
    path = "/admin/api/users",
    tag = "users",
    summary = "Search users",
    description = "Users by user ID, optionally filtered by a substring of the user ID or handle.",
    params(UserQuery),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "A page of users", body = UserList),
        (status = 400, description = "Invalid limit or cursor (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_users(
    State(state): State<AdminState>,
    query: Result<Query<UserQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<UserList>, AdminError> {
    let Query(query) = query.map_err(|err| AdminError::BadRequest(err.body_text()))?;
    let limit = page_limit(query.limit, DEFAULT_LIMIT, MAX_LIMIT)?;
    let after = query
        .cursor
        .filter(|cursor| !cursor.is_empty())
        .map(|cursor| {
            URL_SAFE_NO_PAD
                .decode(&cursor)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| AdminError::BadRequest("invalid cursor".into()))
        })
        .transpose()?;
    let q = query.q.filter(|q| !q.is_empty());
    let mut users = state
        .app
        .db
        .read(move |conn| admin::list_users(conn, q.as_deref(), after.as_deref(), limit + 1))
        .await?;
    let more = users.len() > limit as usize;
    users.truncate(limit as usize);
    let next_cursor = users
        .last()
        .filter(|_| more)
        .map(|user| URL_SAFE_NO_PAD.encode(&user.user_id));
    Ok(Json(UserList {
        items: users
            .into_iter()
            .map(|user| UserItem {
                user_id: user.user_id,
                handle: user.handle,
                suspended: user.suspended_at.is_some(),
                created_at: seconds(user.created_at),
                device_count: user.device_count,
                last_seen: user.last_seen.map(seconds),
            })
            .collect(),
        next_cursor,
    }))
}

#[utoipa::path(
    get,
    path = "/admin/api/users/{user_id}",
    tag = "users",
    summary = "A user with devices and sessions",
    description = "The user's devices with their unexpired sessions (by non-secret `session_ref`) \
and the hubs listed in the user's hosting record. Never group membership, peers or message \
metadata.",
    params(("user_id" = String, Path, description = "User ID")),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "The user", body = UserDetail),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 404, description = "Unknown user (`not_found`)", body = Error),
    ),
)]
pub async fn get_user(
    State(state): State<AdminState>,
    Path(user_id): Path<String>,
) -> Result<Json<UserDetail>, AdminError> {
    let now = state.now_ms();
    let (user, devices, record) = state
        .app
        .db
        .read(move |conn| {
            Ok::<_, gim_hub_db::DbError>((
                admin::user(conn, &user_id)?,
                admin::devices(conn, &user_id, now)?,
                hosting::get(conn, &user_id)?,
            ))
        })
        .await?;
    let user = user.ok_or(AdminError::NotFound)?;
    Ok(Json(UserDetail {
        user_id: user.user_id,
        handle: user.handle,
        suspended: user.suspended_at.is_some(),
        suspended_at: user.suspended_at.map(seconds),
        created_at: seconds(user.created_at),
        hosting_hubs: record.map(|record| record.hub_ids).unwrap_or_default(),
        devices: devices
            .into_iter()
            .map(|device| DeviceItem {
                device_id: device.device_id,
                created_at: seconds(device.created_at),
                last_seen: device
                    .sessions
                    .iter()
                    .map(|session| session.created_at)
                    .max()
                    .map(seconds),
                active: device.active,
                sessions: device
                    .sessions
                    .into_iter()
                    .map(|session| SessionItem {
                        session_ref: session_ref(&session.token_hash),
                        created_at: seconds(session.created_at),
                        expires_at: seconds(session.expires_at),
                    })
                    .collect(),
            })
            .collect(),
    }))
}

/// The first 16 hex characters of the SHA-256 of the session token. The
/// sessions table stores exactly that digest, so this is its prefix.
fn session_ref(token_hash: &[u8]) -> String {
    let mut hex = hex::encode(token_hash);
    hex.truncate(16);
    hex
}

#[utoipa::path(
    post,
    path = "/admin/api/users/{user_id}/suspend",
    tag = "users",
    summary = "Suspend a user",
    description = "Sets the suspension, revokes every session of the user's devices and refuses \
new sign-ins (POST /v2/auth/challenge and /v2/auth/session answer 403 `user_suspended`). Audited \
as `user_suspend` with the optional reason.",
    params(("user_id" = String, Path, description = "User ID")),
    request_body(content = SuspendRequest, description = "Optional", content_type = "application/json"),
    security(("adminSession" = [])),
    responses(
        (status = 204, description = "Suspended"),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown user (`not_found`)", body = Error),
        (status = 409, description = "Already suspended (`conflict`)", body = Error),
    ),
)]
pub async fn suspend_user(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let request: Result<SuspendRequest, AdminError> = optional_json(&body);
    let reason = request.as_ref().ok().and_then(|r| r.reason.clone());
    let result = match request {
        Err(err) => Err(err),
        Ok(_) => {
            let now = state.now_ms();
            let id = user_id.clone();
            match state
                .app
                .db
                .write(move |tx| admin::suspend(tx, &id, now))
                .await?
            {
                Suspension::Changed => Ok(StatusCode::NO_CONTENT),
                Suspension::Unchanged => {
                    Err(AdminError::Conflict("user is already suspended".into()))
                }
                Suspension::NotFound => Err(AdminError::NotFound),
            }
        }
    };
    caller
        .audit(&state, "user_suspend", Some(user_id), &result, reason)
        .await;
    result
}

#[utoipa::path(
    post,
    path = "/admin/api/users/{user_id}/unsuspend",
    tag = "users",
    summary = "Lift a suspension",
    description = "The user can sign in again. Audited as `user_unsuspend`.",
    params(("user_id" = String, Path, description = "User ID")),
    security(("adminSession" = [])),
    responses(
        (status = 204, description = "Unsuspended"),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown user (`not_found`)", body = Error),
        (status = 409, description = "Not suspended (`conflict`)", body = Error),
    ),
)]
pub async fn unsuspend_user(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, AdminError> {
    let id = user_id.clone();
    let result = match state
        .app
        .db
        .write(move |tx| admin::unsuspend(tx, &id))
        .await?
    {
        Suspension::Changed => Ok(StatusCode::NO_CONTENT),
        Suspension::Unchanged => Err(AdminError::Conflict("user is not suspended".into())),
        Suspension::NotFound => Err(AdminError::NotFound),
    };
    caller
        .audit(&state, "user_unsuspend", Some(user_id), &result, None)
        .await;
    result
}

#[utoipa::path(
    delete,
    path = "/admin/api/users/{user_id}/devices/{device_id}/sessions",
    tag = "users",
    summary = "Revoke a device's sessions",
    description = "Deletes every session of the device; it must sign in again. Audited as \
`device_sessions_revoke` (target `<user_id>/<device_id>`).",
    params(
        ("user_id" = String, Path, description = "User ID"),
        ("device_id" = String, Path, description = "Device ID"),
    ),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Sessions revoked", body = Revoked),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown user or device (`not_found`)", body = Error),
    ),
)]
pub async fn revoke_device_sessions(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path((user_id, device_id)): Path<(String, String)>,
) -> Result<Json<Revoked>, AdminError> {
    let target = format!("{user_id}/{device_id}");
    let result = state
        .app
        .db
        .write(move |tx| admin::revoke_device_sessions(tx, &user_id, &device_id))
        .await
        .map_err(AdminError::from)
        .and_then(|revoked| revoked.ok_or(AdminError::NotFound))
        .map(|revoked| Json(Revoked { revoked }));
    let detail = result
        .as_ref()
        .ok()
        .map(|Json(r)| format!("{} sessions revoked", r.revoked));
    caller
        .audit(
            &state,
            "device_sessions_revoke",
            Some(target),
            &result,
            detail,
        )
        .await;
    result
}

#[utoipa::path(
    post,
    path = "/admin/api/handles/{handle}/release",
    tag = "users",
    summary = "Release a handle",
    description = "The handle becomes free; its user keeps existing without a handle. Audited as \
`handle_release`.",
    params(("handle" = String, Path, description = "Handle")),
    security(("adminSession" = [])),
    responses(
        (status = 204, description = "Released"),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
        (status = 404, description = "Unknown handle (`not_found`)", body = Error),
    ),
)]
pub async fn release_handle(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    Path(handle): Path<String>,
) -> Result<StatusCode, AdminError> {
    let name = handle.clone();
    let owner = state
        .app
        .db
        .write(move |tx| {
            let owner = handles::owner(tx, &name)?;
            if owner.is_some() {
                handles::release(tx, &name)?;
            }
            Ok::<_, gim_hub_db::DbError>(owner)
        })
        .await?;
    let detail = owner.as_ref().map(|owner| format!("owner {owner}"));
    let result = owner
        .map(|_| StatusCode::NO_CONTENT)
        .ok_or(AdminError::NotFound);
    caller
        .audit(&state, "handle_release", Some(handle), &result, detail)
        .await;
    result
}

/// An optional JSON body: empty means the default.
pub(crate) fn optional_json<T: Default + serde::de::DeserializeOwned>(
    body: &[u8],
) -> Result<T, AdminError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|err| AdminError::BadRequest(err.to_string()))
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn session_ref_is_a_digest_prefix() {
        assert_eq!(session_ref(&[0xab; 32]), "abababababababab");
        let token_hash: [u8; 32] = Sha256::digest(b"token").into();
        assert_eq!(session_ref(&token_hash).len(), 16);
    }

    #[test]
    fn limits_and_optional_bodies() {
        assert_eq!(page_limit(None, 50, 100).unwrap(), 50);
        assert!(page_limit(Some(0), 50, 100).is_err());
        assert!(page_limit(Some(101), 50, 100).is_err());
        assert_eq!(optional_json::<SuspendRequest>(b"").unwrap().reason, None);
        assert_eq!(
            optional_json::<SuspendRequest>(br#"{"reason":"spam"}"#)
                .unwrap()
                .reason
                .as_deref(),
            Some("spam")
        );
        assert!(optional_json::<SuspendRequest>(b"{").is_err());
    }
}
