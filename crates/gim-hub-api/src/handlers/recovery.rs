//! Encrypted recovery backups.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{Error, PutRecoveryBackupRequest, RecoveryBackup},
};

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
pub async fn put_recovery_backup(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
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
pub async fn get_recovery_backup() -> impl IntoResponse {
    not_implemented()
}
