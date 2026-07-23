mod support;

use support::{make_handle, start_test_server};

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
