mod support;

use std::time::Duration;
use support::{make_handle, start_test_server};

#[tokio::test]
async fn get_logs_over_http_streams_replay_as_sse() {
    std::env::remove_var("RUST_LOG");
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = make_handle(dir.path(), "ssetest");
    std::fs::write(
        dir.path().join("ssetest.log"),
        "2024-01-15T10:00:00Z  INFO sse replay line\n",
    )
    .expect("write log file");

    let (addr, client) = start_test_server(handle).await;
    let mut resp = client
        .get(format!("http://{addr}/logs?follow=true"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    // Read chunks off the streaming response until a complete SSE frame
    // (terminated by a blank line) has arrived.
    let mut collected = String::new();
    let event = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(idx) = collected.find("\n\n") {
                return collected[..idx].to_string();
            }
            let chunk = resp
                .chunk()
                .await
                .expect("chunk read")
                .expect("stream ended before a full event arrived");
            collected.push_str(std::str::from_utf8(&chunk).expect("utf8 chunk"));
        }
    })
    .await
    .expect("timed out waiting for the first SSE event");

    let data_line = event
        .lines()
        .find(|line| line.starts_with("data: "))
        .expect("event has a data: line");
    let payload: serde_json::Value =
        serde_json::from_str(&data_line["data: ".len()..]).expect("data line is JSON");
    assert_eq!(
        payload["line"],
        "2024-01-15T10:00:00Z  INFO sse replay line"
    );
    assert_eq!(payload["source"], "ssetest");
}
