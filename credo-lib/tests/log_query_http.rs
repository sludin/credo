use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use credo_lib::log_query::{historical_logs, LogQueryParams};
use credo_lib::{
    init_logging_with_config, AppError, LogLevel, LoggingConfig, LoggingHandle, RotationConfig,
};
use std::sync::Arc;

async fn logs_handler(
    State(handle): State<Arc<LoggingHandle>>,
    Query(params): Query<LogQueryParams>,
) -> Result<Json<Vec<String>>, AppError> {
    historical_logs(&handle, &params).await
}

async fn start_test_server(handle: LoggingHandle) -> (std::net::SocketAddr, reqwest::Client) {
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

fn make_handle(dir: &std::path::Path, basename: &str) -> LoggingHandle {
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

// Content is written directly to the log file rather than via tracing
// macros, so this test doesn't depend on the non-blocking writer's
// worker-thread flush timing - it only needs to prove the HTTP handler
// correctly reads and filters whatever is already on disk.
#[tokio::test]
async fn get_logs_over_http_applies_text_filter() {
    std::env::remove_var("RUST_LOG");
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = make_handle(dir.path(), "httptest");
    std::fs::write(
        dir.path().join("httptest.log"),
        "2024-01-15T10:00:00Z  INFO first line for http test\n\
         2024-01-15T10:00:01Z  WARN second line for http test\n",
    )
    .expect("write log file");

    let (addr, client) = start_test_server(handle).await;
    let resp = client
        .get(format!("http://{addr}/logs?q=second"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    let lines: Vec<String> = resp.json().await.expect("json body");
    assert_eq!(
        lines,
        vec!["2024-01-15T10:00:01Z  WARN second line for http test".to_string()]
    );
}

#[tokio::test]
async fn get_logs_over_http_applies_level_filter() {
    std::env::remove_var("RUST_LOG");
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = make_handle(dir.path(), "httptest2");
    std::fs::write(
        dir.path().join("httptest2.log"),
        "2024-01-15T10:00:00Z ERROR failure one\n\
         2024-01-15T10:00:01Z  WARN risky thing\n\
         2024-01-15T10:00:02Z  INFO normal thing\n",
    )
    .expect("write log file");

    let (addr, client) = start_test_server(handle).await;
    let resp = client
        .get(format!("http://{addr}/logs?level=warn"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    let lines: Vec<String> = resp.json().await.expect("json body");
    assert_eq!(
        lines,
        vec![
            "2024-01-15T10:00:00Z ERROR failure one".to_string(),
            "2024-01-15T10:00:01Z  WARN risky thing".to_string(),
        ]
    );
}
