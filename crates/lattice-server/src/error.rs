//! Application error type mapped to HTTP responses.
//!
//! Follows the pattern from the `rust-backend` skill: domain variants
//! produce specific HTTP statuses; `Internal` swallows infrastructure errors
//! and logs the chain before returning a generic 500.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tracing::error;

/// Application-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Requested resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// Input failed validation.
    #[error("validation error: {0}")]
    Validation(String),

    /// Authentication missing or invalid.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated but not permitted.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// State conflict (duplicate, version mismatch, etc.).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Wraps anything from infrastructure. Logs full chain server-side,
    /// returns generic 500 client-side.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            Self::Validation(m) => (StatusCode::UNPROCESSABLE_ENTITY, m.clone()),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            Self::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            Self::Internal(err) => {
                error!(error = %err, chain = ?err, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_owned(),
                )
            }
        };

        (
            status,
            Json(json!({
                "error": {
                    "status": status.as_u16(),
                    "message": message,
                }
            })),
        )
            .into_response()
    }
}

/// Convenience alias.
pub type AppResult<T> = std::result::Result<T, AppError>;
