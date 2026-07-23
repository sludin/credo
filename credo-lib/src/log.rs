use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;
use std::time::Instant;
use tracing_subscriber::EnvFilter;

use crate::rotating_log::{LoggingConfig, RotatingFileWriter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

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

/// Returned by `init_logging_with_config`. Keep this alive for the process
/// lifetime (e.g. bind it in `main()`) - dropping it flushes and stops the
/// non-blocking file writer.
#[must_use = "dropping the handle stops file logging and the live tail"]
pub struct LoggingHandle {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    writer: Option<RotatingFileWriter>,
    log_dir: Option<std::path::PathBuf>,
    log_basename: Option<String>,
}

impl LoggingHandle {
    /// Subscribe to a live feed of this service's log lines. Returns `None`
    /// if rotating-file logging is not enabled in `config`.
    pub fn subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<String>> {
        self.writer.as_ref().map(|w| w.subscribe())
    }

    /// Directory containing this service's rotating log file, if file
    /// logging is enabled.
    pub fn log_dir(&self) -> Option<&std::path::Path> {
        self.log_dir.as_deref()
    }

    /// Basename (without extension) of this service's rotating log file,
    /// if file logging is enabled.
    pub fn log_basename(&self) -> Option<&str> {
        self.log_basename.as_deref()
    }
}

/// Like `init_logging`, but config-driven: when `config.enabled` is true,
/// also writes to a size-rotated file and exposes a live broadcast of
/// completed lines via the returned `LoggingHandle`. When `config.enabled`
/// is false, behavior is identical to `init_logging` (stdout only).
pub fn init_logging_with_config(
    level: LogLevel,
    config: &LoggingConfig,
    service_name: &str,
) -> LoggingHandle {
    if !config.enabled {
        init_logging(level);
        return LoggingHandle {
            _guard: None,
            writer: None,
            log_dir: None,
            log_basename: None,
        };
    }

    let filter_str =
        std::env::var("RUST_LOG").unwrap_or_else(|_| level.as_tracing_filter().to_string());

    let writer = RotatingFileWriter::new(
        std::path::Path::new(&config.dir),
        service_name,
        &config.rotate_on,
    )
    .expect("failed to open rotating log file");
    let (non_blocking, guard) = tracing_appender::non_blocking(writer.clone());

    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .with_writer(non_blocking)
        .with_filter(EnvFilter::new(filter_str.clone()));

    // `config.also_stdout` selects whether the stdout layer is present, but
    // both arms must produce the same registry type for `.init()` to type
    // check. `Option<Layer>` itself implements `Layer` (a no-op when `None`),
    // so folding the condition into an `Option` keeps this to one `.with()`
    // chain instead of two differently-shaped ones.
    let stdout_layer = config.also_stdout.then(|| {
        tracing_subscriber::fmt::layer()
            .with_target(false)
            .compact()
            .with_writer(std::io::stdout)
            .with_filter(EnvFilter::new(filter_str))
    });

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    LoggingHandle {
        _guard: Some(guard),
        writer: Some(writer),
        log_dir: Some(std::path::Path::new(&config.dir).to_path_buf()),
        log_basename: Some(service_name.to_string()),
    }
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
