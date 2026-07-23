use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use credo_lib::log_query::{historical_logs, LogQueryParams};
use credo_lib::{
    init_logging_with_config, AppError, LogLevel, LoggingConfig, LoggingHandle, RotationConfig,
};
use std::sync::Arc;

pub async fn logs_handler(
    State(handle): State<Arc<LoggingHandle>>,
    Query(params): Query<LogQueryParams>,
) -> Result<Json<Vec<String>>, AppError> {
    historical_logs(&handle, &params).await
}

pub async fn start_test_server(handle: LoggingHandle) -> (std::net::SocketAddr, reqwest::Client) {
    let router = Router::new()
        .route("/logs", get(logs_handler))
        .with_state(Arc::new(handle));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (addr, reqwest::Client::new())
}

pub fn make_handle(dir: &std::path::Path, basename: &str) -> LoggingHandle {
    let config = LoggingConfig {
        enabled: true,
        dir: dir.to_string_lossy().to_string(),
        rotate_on: RotationConfig {
            size_mb: 100,
            keep_files: 12,
        },
        also_stdout: false,
    };
    init_logging_with_config(LogLevel::Info, &config, basename)
}
