use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::Forbidden(m)    => (StatusCode::FORBIDDEN, m.clone()),
            AppError::NotFound(m)     => (StatusCode::NOT_FOUND, m.clone()),
            AppError::BadRequest(m)   => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Internal(e)     => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Build an ACME error response body with RFC 8555 URN.
pub fn acme_error_body(type_slug: &str, detail: &str) -> serde_json::Value {
    json!({
        "type": format!("urn:ietf:params:acme:error:{}", type_slug),
        "detail": detail,
    })
}
