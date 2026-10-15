//! Encrypted recovery backups.

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_db::recovery;

use super::identity::{decode_base64, json_body};
use crate::{
    auth::AuthDevice,
    dto::{Error, PutRecoveryBackupRequest, RecoveryBackup},
    error::ApiError,
    state::AppState,
};

/// Largest accepted backup in decoded bytes.
const MAX_BACKUP_BYTES: usize = 65_536;

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/recovery-backup",
    tag = "recovery",
    summary = "Store the caller's recovery backup",
    description = "Replaces the stored backup. Only the caller's own `user_id` is accepted. The \
backup is opaque ciphertext (gim-core recovery backup CBOR) of at most 65536 decoded bytes.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutRecoveryBackupRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Backup stored", body = RecoveryBackup),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "`user_id` is not the caller's (`forbidden`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn put_recovery_backup(
    auth: AuthDevice,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    body: Result<Json<PutRecoveryBackupRequest>, JsonRejection>,
) -> Result<Json<RecoveryBackup>, ApiError> {
    if user_id != auth.user_id {
        return Err(ApiError::Forbidden(
            "can only store the caller's own backup".into(),
        ));
    }
    let body = json_body(body)?;
    let backup = decode_base64(&body.backup)
        .ok_or_else(|| ApiError::ValidationFailed("backup is not valid base64".into()))?;
    if backup.is_empty() {
        return Err(ApiError::ValidationFailed("backup is empty".into()));
    }
    if backup.len() > MAX_BACKUP_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    let now = state.clock.now_ms();
    let user_id_ = user_id.clone();
    state
        .db
        .write(move |tx| recovery::put(tx, &user_id_, &backup, now))
        .await?;
    Ok(Json(RecoveryBackup {
        user_id,
        backup: body.backup,
        updated_at: now,
    }))
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/recovery-backup",
    tag = "recovery",
    summary = "Fetch a recovery backup",
    description = "No authentication: this is the restore path of a user who lost every device. \
The backup is only useful with the recovery code. Requests will be rate limited per client \
address and per `user_id` (429 `rate_limited` with `Retry-After`).",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    responses(
        (status = 200, description = "Stored backup", body = RecoveryBackup),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 429, description = "Rate limited (`rate_limited`)", body = Error),
    ),
)]
pub async fn get_recovery_backup(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<RecoveryBackup>, ApiError> {
    let user_id_ = user_id.clone();
    let stored = state
        .db
        .read(move |conn| recovery::get(conn, &user_id_))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(RecoveryBackup {
        user_id,
        backup: STANDARD.encode(stored.backup),
        updated_at: stored.updated_at,
    }))
}
