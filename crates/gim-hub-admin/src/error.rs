//! Admin API errors, in the hub's `{"error":{"code","message"}}` envelope.

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gim_hub_api::dto::Error;

/// An error response of the admin API.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("missing or expired admin session")]
    Unauthorized,
    #[error("missing or wrong X-CSRF-Token")]
    CsrfFailed,
    #[error("{0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    /// 400 `validation_failed`: a malformed request.
    #[error("{0}")]
    BadRequest(String),
    /// 422 `validation_failed`: a well-formed request with invalid content.
    #[error("{0}")]
    Unprocessable(String),
    #[error("{0}")]
    Conflict(String),
    #[error("too many failed logins; retry later")]
    RateLimited { retry_after: u64 },
    #[error("{0}")]
    Unavailable(String),
    /// Unexpected failure; details are logged, not returned.
    #[error("internal error")]
    Internal(String),
}

impl AdminError {
    /// HTTP status of this error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::CsrfFailed | Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::CsrfFailed => "csrf_failed",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound => "not_found",
            Self::BadRequest(_) | Self::Unprocessable(_) => "validation_failed",
            Self::Conflict(_) => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::Unavailable(_) => "unavailable",
            Self::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        if let Self::Internal(detail) = &self {
            tracing::error!(%detail, "admin API internal error");
        }
        let body = Json(Error::new(self.code(), self.to_string()));
        match self {
            Self::RateLimited { retry_after } => (
                self.status(),
                [(header::RETRY_AFTER, retry_after.to_string())],
                body,
            )
                .into_response(),
            _ => (self.status(), body).into_response(),
        }
    }
}

impl From<gim_hub_db::DbError> for AdminError {
    fn from(err: gim_hub_db::DbError) -> Self {
        Self::Internal(err.to_string())
    }
}
