use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

pub use credo_lib::log::LogIdentity;

pub async fn agent_log_middleware(req: Request, next: Next) -> Response {
    credo_lib::log::log_request("C", req, next).await
}

pub async fn api_log_middleware(req: Request, next: Next) -> Response {
    credo_lib::log::log_request("S", req, next).await
}
