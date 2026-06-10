use tracing_subscriber::EnvFilter;

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
