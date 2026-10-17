//! GET /admin/api/audit.

use axum::{
    extract::{Query, State},
    Json,
};
use gim_hub_api::dto::Error;
use gim_hub_db::admin;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::{
    auth::seconds,
    dto::{AuditItem, AuditList},
    error::AdminError,
    handlers::users::page_limit,
    state::AdminState,
};

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// 1 to 200, default 50.
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

#[utoipa::path(
    get,
    path = "/admin/api/audit",
    tag = "audit",
    summary = "The admin audit log",
    description = "Every admin action, newest first.",
    params(AuditQuery),
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "A page of entries", body = AuditList),
        (status = 400, description = "Invalid limit or cursor (`validation_failed`)", body = Error),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_audit(
    State(state): State<AdminState>,
    query: Result<Query<AuditQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<AuditList>, AdminError> {
    let Query(query) = query.map_err(|err| AdminError::BadRequest(err.body_text()))?;
    let limit = page_limit(query.limit, 50, 200)?;
    let before = query
        .cursor
        .filter(|cursor| !cursor.is_empty())
        .map(|cursor| {
            cursor
                .parse::<i64>()
                .map_err(|_| AdminError::BadRequest("invalid cursor".into()))
        })
        .transpose()?;
    let mut entries = state
        .app
        .db
        .read(move |conn| admin::list_audit(conn, before, limit + 1))
        .await?;
    let more = entries.len() > limit as usize;
    entries.truncate(limit as usize);
    let next_cursor = entries
        .last()
        .filter(|_| more)
        .map(|entry| entry.id.to_string());
    Ok(Json(AuditList {
        items: entries
            .into_iter()
            .map(|entry| AuditItem {
                id: entry.id,
                at: seconds(entry.at),
                actor: entry.actor,
                action: entry.action,
                target: entry.target,
                source_ip: entry.source_ip,
                result: if entry.ok { "ok" } else { "error" }.to_owned(),
                detail: entry.detail,
            })
            .collect(),
        next_cursor,
    }))
}
