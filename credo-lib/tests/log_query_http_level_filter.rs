mod support;

use support::{make_handle, start_test_server};

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
