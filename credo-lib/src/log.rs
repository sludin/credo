use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;
use std::time::Instant;
use tracing_subscriber::EnvFilter;

/// Carries the authenticated identity from auth middleware to the log middleware
/// via response extensions. Auth layers insert it; log middleware reads it.
#[derive(Clone)]
pub struct LogIdentity(pub String);

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Fatal,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_tracing_filter(self) -> &'static str {
        match self {
            LogLevel::Fatal => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "fatal" => LogLevel::Fatal,
            "warn" => LogLevel::Warn,
            "debug" => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }
}

pub fn init_logging(level: LogLevel) {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| level.as_tracing_filter().to_string());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .compact()
        .init();
}

// ---------------------------------------------------------------------------
// Shared request logging middleware
// ---------------------------------------------------------------------------

/// Axum middleware that emits one structured log line per request.
/// `code` is the service prefix: "S" = Shepherd API, "C" = Corgi/Shepherd-agent, "V" = Vigil.
pub async fn log_request(code: &'static str, req: Request, next: Next) -> Response {
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
    let identity = response
        .extensions()
        .get::<LogIdentity>()
        .map(|i| i.0.clone());

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

// ---------------------------------------------------------------------------
// Structured request log — matches the credo one-line format:
//   <code> <dir> <status> <method> <path> <host> <peer_ip> <uri_name> <ms>
// Service codes: V=Vigil, C=Corgi, S=Shepherd, F=outbound client call
// Direction:     >= inbound, <= outbound
// ---------------------------------------------------------------------------

pub struct RequestLogEntry<'a> {
    pub code: &'a str,
    pub direction: &'a str,
    pub status: u16,
    pub method: &'a str,
    pub path: &'a str,
    pub host: &'a str,
    pub peer_ip: &'a str,
    pub identity: Option<&'a str>,
    pub duration_ms: f64,
}

impl<'a> RequestLogEntry<'a> {
    pub fn log(&self) {
        tracing::info!(
            "{} {} {} {} {} {} {} {} {:.2}",
            self.code,
            self.direction,
            self.status,
            self.method,
            self.path,
            self.host,
            self.peer_ip,
            self.identity.unwrap_or("-"),
            self.duration_ms,
        );
    }
}
