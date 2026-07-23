use credo_lib::{init_logging_with_config, LogLevel, LoggingConfig, RotationConfig};
use std::time::Duration;

// Separate integration-test binary from log_init.rs: init_logging_with_config
// calls .init() on the global tracing subscriber, which can only succeed once
// per process, so the also_stdout: true and also_stdout: false paths can't
// share a test binary.
#[tokio::test]
async fn init_logging_with_config_with_also_stdout_still_writes_file_and_broadcasts() {
    std::env::remove_var("RUST_LOG");

    let dir = tempfile::tempdir().expect("tempdir");
    let config = LoggingConfig {
        enabled: true,
        dir: dir.path().to_string_lossy().to_string(),
        rotate_on: RotationConfig {
            size_mb: 100,
            keep_files: 12,
        },
        also_stdout: true,
    };

    // Must not panic: this exercises the Some(stdout_layer) arm of the
    // Option<Layer> combinator, which log_init.rs's also_stdout: false test
    // never constructs.
    let handle = init_logging_with_config(LogLevel::Info, &config, "testsvc");
    let mut rx = handle
        .subscribe()
        .expect("logging enabled, subscribe must succeed");

    tracing::info!("hello from log_init_stdout test");

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for broadcast line")
        .expect("channel closed unexpectedly");
    assert!(received.contains("hello from log_init_stdout test"));

    drop(handle); // flush the non-blocking writer before reading the file

    let contents = std::fs::read_to_string(dir.path().join("testsvc.log")).expect("read log file");
    assert!(contents.contains("hello from log_init_stdout test"));
}
