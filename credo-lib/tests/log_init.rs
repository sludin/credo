use credo_lib::{init_logging_with_config, LogLevel, LoggingConfig, RotationConfig};
use std::time::Duration;

#[tokio::test]
async fn init_logging_with_config_writes_file_and_broadcasts_live() {
    // Ambient RUST_LOG in the dev/CI shell could otherwise override the
    // level this test expects - keep the test deterministic.
    std::env::remove_var("RUST_LOG");

    let dir = tempfile::tempdir().expect("tempdir");
    let config = LoggingConfig {
        enabled: true,
        dir: dir.path().to_string_lossy().to_string(),
        rotate_on: RotationConfig {
            size_mb: 100,
            keep_files: 12,
        },
        also_stdout: false,
    };

    let handle = init_logging_with_config(LogLevel::Info, &config, "testsvc");
    let mut rx = handle
        .subscribe()
        .expect("logging enabled, subscribe must succeed");

    tracing::info!("hello from log_init test");

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for broadcast line")
        .expect("channel closed unexpectedly");
    assert!(received.contains("hello from log_init test"));

    drop(handle); // flush the non-blocking writer before reading the file

    let contents = std::fs::read_to_string(dir.path().join("testsvc.log")).expect("read log file");
    assert!(contents.contains("hello from log_init test"));
}
