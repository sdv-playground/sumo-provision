//! What the tower refuses, and with which status.
//!
//! Three arms and plain text, the way Tower 2's `AppError` answers: a status a
//! client branches on, and a sentence a human reads. `Internal` is the only arm
//! that does not say what happened — the caller is told "internal error" and the
//! reason goes to the log, because a database's words are not a client's
//! business.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Errors surfaced by the configuration API.
#[derive(Debug)]
pub enum AppError {
    /// No schema, no assignment, or no set of that id in the schema.
    NotFound,
    /// The request was understood and refused — a value the set's JSON Schema
    /// rejects, or a body that is not a schema at all.
    BadRequest(String),
    /// The tower is broken, which is not the caller's fault and not the
    /// caller's information.
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, msg).into_response()
    }
}
