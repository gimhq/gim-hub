//! API errors and their JSON bodies (`{"error":{"code","message"}}`).

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::dto::{CursorExpiredError, Error, StaleEpochError};

/// An error response of the client API. Codes and statuses follow
/// `openapi.json`.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    ValidationFailed(String),
    #[error("missing or invalid bearer token")]
    Unauthorized,
    #[error("unknown, used or expired challenge")]
    InvalidChallenge,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("{0}")]
    InvalidDeviceList(String),
    #[error("device is no longer active")]
    DeviceNotActive,
    #[error("{0}")]
    Forbidden(String),
    /// An admin suspended the user (docs/admin.md): no sign-in.
    #[error("user is suspended")]
    UserSuspended,
    /// The hub's user policy does not admit the user
    /// (docs/operations.md, "User policy"): no registration, no sign-in.
    #[error("user is not admitted on this hub")]
    UserNotAdmitted,
    /// The owning hub of a group, or the target user's hub, refused the
    /// request because its user policy does not admit the caller
    /// (S2S `UNAUTHORIZED`, `client_code` `user_not_admitted`).
    #[error("a peer hub does not admit this user")]
    NotAdmittedByPeer,
    #[error("not a member of the group")]
    NotMember,
    #[error("not found")]
    NotFound,
    #[error("handle is taken")]
    HandleTaken,
    #[error("{0}")]
    Conflict(String),
    /// A KeyPackage of the upload was already claimed from another hub
    /// through this hub (multi-homing).
    #[error("key package was already claimed from another hub")]
    DuplicateKeyPackage,
    #[error("stale DeviceList")]
    StaleDeviceList,
    #[error("message is not for the current epoch {current_epoch}")]
    StaleEpoch { current_epoch: u64 },
    #[error("cursor is older than the retention window")]
    CursorExpired { cursor: u64 },
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("range not satisfiable")]
    RangeNotSatisfiable,
    /// Over a rate limit; retry after `retry_after` seconds.
    #[error("rate limited")]
    RateLimited { retry_after: u64 },
    #[error("{0}")]
    InvalidHostingRecord(String),
    #[error("stale hosting record")]
    StaleHostingRecord,
    #[error("no valid hosting record lists this hub")]
    HostingRecordRequired,
    /// A peer hub needed for the request refused it.
    #[error("{0}")]
    PeerRefused(String),
    /// A peer hub needed for the request did not answer; retry after
    /// `retry_after` seconds.
    #[error("peer hub unavailable")]
    PeerUnavailable { retry_after: u64 },
    #[error("endpoint not implemented yet")]
    NotImplemented,
    /// Unexpected failure; details are logged, not returned.
    #[error("internal error")]
    Internal(String),
}

impl ApiError {
    /// HTTP status of this error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::ValidationFailed(_)
            | Self::InvalidDeviceList(_)
            | Self::InvalidHostingRecord(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized
            | Self::InvalidChallenge
            | Self::InvalidSignature
            | Self::DeviceNotActive => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_)
            | Self::UserSuspended
            | Self::UserNotAdmitted
            | Self::NotAdmittedByPeer
            | Self::NotMember
            | Self::HostingRecordRequired => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::HandleTaken
            | Self::Conflict(_)
            | Self::DuplicateKeyPackage
            | Self::StaleDeviceList
            | Self::StaleHostingRecord
            | Self::StaleEpoch { .. } => StatusCode::CONFLICT,
            Self::CursorExpired { .. } => StatusCode::GONE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::PeerRefused(_) => StatusCode::BAD_GATEWAY,
            Self::PeerUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ValidationFailed(_) => "validation_failed",
            Self::Unauthorized => "unauthorized",
            Self::InvalidChallenge => "invalid_challenge",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidDeviceList(_) => "invalid_device_list",
            Self::DeviceNotActive => "device_not_active",
            Self::Forbidden(_) => "forbidden",
            Self::UserSuspended => "user_suspended",
            Self::UserNotAdmitted => "user_not_admitted",
            Self::NotAdmittedByPeer => "not_admitted_by_peer",
            Self::NotMember => "not_member",
            Self::NotFound => "not_found",
            Self::HandleTaken => "handle_taken",
            Self::Conflict(_) => "conflict",
            Self::DuplicateKeyPackage => "duplicate_key_package",
            Self::StaleDeviceList => "stale_device_list",
            Self::StaleEpoch { .. } => "stale_epoch",
            Self::CursorExpired { .. } => "cursor_expired",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RangeNotSatisfiable => "range_not_satisfiable",
            Self::RateLimited { .. } => "rate_limited",
            Self::InvalidHostingRecord(_) => "invalid_hosting_record",
            Self::StaleHostingRecord => "stale_hosting_record",
            Self::HostingRecordRequired => "hosting_record_required",
            Self::PeerRefused(_) => "peer_refused",
            Self::PeerUnavailable { .. } => "peer_unavailable",
            Self::NotImplemented => "not_implemented",
            Self::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(detail) = &self {
            tracing::error!(%detail, "internal error");
        }
        let status = self.status();
        let body = Error::new(self.code(), self.to_string());
        match self {
            Self::StaleEpoch { current_epoch } => (
                status,
                Json(StaleEpochError {
                    error: body.error,
                    current_epoch,
                }),
            )
                .into_response(),
            Self::CursorExpired { cursor } => (
                status,
                Json(CursorExpiredError {
                    error: body.error,
                    cursor,
                }),
            )
                .into_response(),
            Self::PeerUnavailable { retry_after } | Self::RateLimited { retry_after } => (
                status,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(body),
            )
                .into_response(),
            _ => (status, Json(body)).into_response(),
        }
    }
}

/// Seconds a client waits before retrying after 503 `peer_unavailable`.
pub const PEER_UNAVAILABLE_RETRY_AFTER: u64 = 5;

impl From<gim_hub_s2s::HostingError> for ApiError {
    fn from(err: gim_hub_s2s::HostingError) -> Self {
        use gim_hub_s2s::HostingError;
        match err {
            HostingError::NotFound => Self::NotFound,
            HostingError::Required => Self::HostingRecordRequired,
            HostingError::Unavailable(reason) => {
                tracing::info!(%reason, "hosting record resolution failed");
                Self::PeerUnavailable {
                    retry_after: PEER_UNAVAILABLE_RETRY_AFTER,
                }
            }
            HostingError::Db(err) => err.into(),
        }
    }
}

impl From<gim_hub_db::DbError> for ApiError {
    fn from(err: gim_hub_db::DbError) -> Self {
        Self::Internal(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use serde_json::{json, Value};

    use super::*;

    async fn render(err: ApiError) -> (StatusCode, Value) {
        let response = err.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn plain_error_body() {
        let (status, body) = render(ApiError::Unauthorized).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body,
            json!({ "error": { "code": "unauthorized", "message": "missing or invalid bearer token" } })
        );
    }

    #[tokio::test]
    async fn errors_with_extra_fields() {
        let (status, body) = render(ApiError::StaleEpoch { current_epoch: 7 }).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "stale_epoch");
        assert_eq!(body["current_epoch"], 7);

        let (status, body) = render(ApiError::CursorExpired { cursor: 42 }).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["error"]["code"], "cursor_expired");
        assert_eq!(body["cursor"], 42);
    }

    #[tokio::test]
    async fn peer_unavailable_and_rate_limited_set_retry_after() {
        let response = ApiError::PeerUnavailable { retry_after: 5 }.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "5");
        let response = ApiError::RateLimited { retry_after: 3 }.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "3");
        let (status, body) = render(ApiError::PeerRefused("not allowlisted".into())).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"]["code"], "peer_refused");
        let (status, body) = render(gim_hub_s2s::HostingError::Required.into()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "hosting_record_required");
    }

    #[tokio::test]
    async fn user_suspended_is_403() {
        let (status, body) = render(ApiError::UserSuspended).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "user_suspended");
    }

    #[tokio::test]
    async fn user_policy_errors_are_403() {
        let (status, body) = render(ApiError::UserNotAdmitted).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            json!({ "error": { "code": "user_not_admitted", "message": "user is not admitted on this hub" } })
        );
        let (status, body) = render(ApiError::NotAdmittedByPeer).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            json!({ "error": { "code": "not_admitted_by_peer", "message": "a peer hub does not admit this user" } })
        );
    }

    #[tokio::test]
    async fn duplicate_key_package_is_409() {
        let (status, body) = render(ApiError::DuplicateKeyPackage).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "duplicate_key_package");
    }

    #[tokio::test]
    async fn internal_details_are_not_leaked() {
        let (status, body) = render(ApiError::Internal("disk on fire".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["message"], "internal error");
    }
}
