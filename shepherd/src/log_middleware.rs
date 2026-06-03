use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use credo_lib::log::RequestLogEntry;
use std::net::SocketAddr;
use std::time::Instant;

/// Carries the authenticated identity from inner auth middleware back to the
/// outer logging middleware via response extensions.
#[derive(Clone)]
pub struct LogIdentity(pub String);

pub async fn agent_log_middleware(req: Request, next: Next) -> Response {
    log_request("C", req, next).await
}

pub async fn api_log_middleware(req: Request, next: Next) -> Response {
    log_request("S", req, next).await
}

async fn log_request(code: &'static str, req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_else(|| "-".to_string());
    let peer_ip = req
        .extensions()
        .get::<SocketAddr>()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "-".to_string());

    let start = Instant::now();
    let response = next.run(req).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();
    let identity = response.extensions().get::<LogIdentity>().map(|i| i.0.clone());

    RequestLogEntry {
        code,
        direction: ">",
        status,
        method: &method,
        path: &path,
        host: &host,
        peer_ip: &peer_ip,
        identity: identity.as_deref(),
        duration_ms,
    }
    .log();

    response
}
