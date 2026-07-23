use credo_lib::log_query::{build_follow_stream, LogQueryParams};
use credo_lib::{init_logging_with_config, LogLevel, LoggingConfig, RotationConfig};
use futures_util::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn build_follow_stream_replays_history_then_continues_live() {
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
    let handle = init_logging_with_config(LogLevel::Info, &config, "followtest");

    // Historical content is written directly to the file, bypassing
    // tracing, so the replay half of this test doesn't depend on the
    // non-blocking writer's worker-thread flush timing.
    std::fs::write(
        dir.path().join("followtest.log"),
        "2024-01-15T10:00:00Z  INFO historical line\n",
    )
    .expect("write log file");

    let stream = build_follow_stream(&handle, &LogQueryParams::default())
        .await
        .expect("build stream");
    let mut stream = Box::pin(stream);

    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for replayed line")
        .expect("stream ended unexpectedly");
    assert_eq!(first, "2024-01-15T10:00:00Z  INFO historical line");

    // The live-continuation half genuinely needs to go through tracing
    // (there's no public API to inject a line into the broadcast
    // directly), so it depends on the non-blocking worker's async flush -
    // bounded by a generous timeout rather than a fixed sleep, matching
    // the pattern already used in log_init.rs for the same reason.
    tracing::info!("brand new live line");

    let second = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for live line")
        .expect("stream ended unexpectedly");
    assert!(second.contains("brand new live line"));
}
