# Log Live Tail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add live tail (SSE `follow=true`) to `credo-lib`'s log query, completing Phase 1 of the on-demand log retrieval design (`docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`). This is the harder half deferred from the historical-query plan (`docs/superpowers/plans/2026-07-23-log-query-historical.md`), which shipped `historical_logs`/`read_historical_lines`/`line_passes_filter` and deliberately left `LogQueryParams` without a `follow` field.

**Architecture:** `LogQueryParams` gains `follow: bool`. `build_follow_stream` does the actual sequencing: subscribe to the service's live broadcast *before* reading the historical backlog (so no line can be missed in the gap), read history, drain whatever arrived on the broadcast during that read (non-blocking, via `try_recv`), dedup that buffer against the tail of the historical read (an exact-match heuristic — a line read from disk and also delivered live in the same window is far more likely a double-count than a genuine repeat), then chain into an unbounded live tail built from `tokio::sync::broadcast::Receiver` via `futures_util::stream::unfold`. `follow_logs` wraps that plain `Stream<Item = String>` into axum's `Sse` response type (JSON-wrapped events: `{"line": ..., "source": ...}`), and `respond_to_log_query` is the single entry point a future service route will call after its own auth check — branching on `params.follow` between this and the already-shipped `historical_logs`. Verified directly against the pinned crate sources before writing this plan (not from memory): axum 0.7.9's `Sse::new`/`Event::data`/`KeepAlive::default` (`~/.cargo/registry/.../axum-0.7.9/src/response/sse.rs`), `futures-util` 0.3.32's `stream::unfold`/`stream::iter`/`StreamExt::chain` (already a transitive dependency of this workspace, confirmed in `Cargo.lock`), and `reqwest` 0.12.28's unconditional `Response::chunk()` (not feature-gated, unlike `bytes_stream()` — used for the E2E SSE test without needing a new Cargo feature).

**Tech Stack:** Rust, `axum`'s `response::sse` module (already a dependency via `axum`), `futures-util` (new direct dependency — already resolved transitively, cheap to add), `tokio::sync::broadcast` (already used by `LoggingHandle`).

## Global Constraints

- This plan touches `credo-lib` only.
- `cargo fmt --check` and `cargo clippy -- -D warnings` must pass for every commit (use `--all-targets` when self-checking — a plain `cargo clippy -p credo-lib` misses `#[cfg(test)]`/`tests/` code, which has caused real regressions in every prior plan in this series).
- Commit after each task with a message explaining *why*, not just what.
- No placeholder/TODO code. Every function must be fully implemented and covered by a test in the same task.
- Do not modify `credo-lib/src/log.rs`'s `init_logging`/`init_logging_with_config` control flow — a previous task in this series already had to revert an over-broad change there (swapping `.init()` for `.try_init()` to paper over a test-isolation problem); the fix was process isolation between test files, not touching that shared code. If a new test needs its own process, give it its own file — do not touch `log.rs`'s subscriber-init logic to work around it.
- Each integration test file under `credo-lib/tests/` that calls `init_logging_with_config` gets its own file (its own process) — a global tracing subscriber can only be installed once per process, and this constraint has bitten every plan in this series that didn't respect it up front.

---

### Task 1: `follow` param, the `futures-util` dependency, and the dedup heuristic

**Files:**
- Modify: `credo-lib/src/log_query.rs`
- Modify: `credo-lib/Cargo.toml`
- Modify: `Cargo.toml` (workspace root)

**Interfaces:**
- Produces (used by Task 2): `LogQueryParams.follow: bool` (new field), `pub fn dedup_buffered_against_tail(historical: &[String], buffered: Vec<String>, tail_window: usize) -> Vec<String>`, `pub const DEDUP_TAIL_WINDOW: usize = 50;`.

- [ ] **Step 1: Add the `futures-util` dependency**

In `Cargo.toml` (workspace root), add this line to the `[workspace.dependencies]` block — put it near `reqwest`/other HTTP-adjacent deps, e.g. right after the `# HTTP client` section (currently `reqwest = { version = "0.12", ... }`):

```toml
# Streams
futures-util = "0.3"
```

In `credo-lib/Cargo.toml`, add a matching entry — put it near the other HTTP/axum-adjacent dependencies (after the `# Async runtime + HTTP` block):

```toml
futures-util = { workspace = true }
```

Run: `cargo build -p credo-lib`
Expected: builds successfully (already a transitive dependency of this workspace via axum/tokio, so nothing new is fetched — this just makes it directly usable from credo-lib's own code).

- [ ] **Step 2: Write the failing tests**

Add `follow: bool` to `LogQueryParams` in `credo-lib/src/log_query.rs` — change the struct from:

```rust
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct LogQueryParams {
    pub since: Option<String>,
    pub until: Option<String>,
    pub last: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}
```

to:

```rust
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct LogQueryParams {
    pub since: Option<String>,
    pub until: Option<String>,
    pub last: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
    /// When true, respond with a live-tailing SSE stream instead of a
    /// historical JSON array (see `respond_to_log_query`/`follow_logs`).
    #[serde(default)]
    pub follow: bool,
}
```

Also update the struct's doc comment (directly above `#[derive(...)]`) to mention `follow` — append this sentence to the existing doc comment block: `` `follow` requests a live-tailing SSE stream instead of a historical JSON array (see `respond_to_log_query`). ``

Add this test module content inside the existing `#[cfg(test)] mod tests` block in `credo-lib/src/log_query.rs` (append after the last existing test function, before the closing `}` of `mod tests`):

```rust
    #[test]
    fn dedup_buffered_against_tail_drops_exact_matches_in_window() {
        let historical = vec![
            "2024-01-15T10:00:00Z  INFO line a".to_string(),
            "2024-01-15T10:00:01Z  INFO line b".to_string(),
            "2024-01-15T10:00:02Z  INFO line c".to_string(),
        ];
        let buffered = vec![
            "2024-01-15T10:00:02Z  INFO line c".to_string(), // duplicate of tail
            "2024-01-15T10:00:03Z  INFO line d".to_string(), // genuinely new
        ];
        let result = dedup_buffered_against_tail(&historical, buffered, 50);
        assert_eq!(result, vec!["2024-01-15T10:00:03Z  INFO line d".to_string()]);
    }

    #[test]
    fn dedup_buffered_against_tail_keeps_everything_when_no_overlap() {
        let historical = vec!["2024-01-15T10:00:00Z  INFO line a".to_string()];
        let buffered = vec![
            "2024-01-15T10:00:01Z  INFO line b".to_string(),
            "2024-01-15T10:00:02Z  INFO line c".to_string(),
        ];
        let result = dedup_buffered_against_tail(&historical, buffered.clone(), 50);
        assert_eq!(result, buffered);
    }

    #[test]
    fn dedup_buffered_against_tail_drops_everything_on_full_overlap() {
        let historical = vec![
            "2024-01-15T10:00:00Z  INFO line a".to_string(),
            "2024-01-15T10:00:01Z  INFO line b".to_string(),
        ];
        let buffered = historical.clone();
        let result = dedup_buffered_against_tail(&historical, buffered, 50);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_buffered_against_tail_only_checks_within_window() {
        // "line a" is outside the 1-line tail window, so it's treated as
        // not-recent and a buffered duplicate of it is kept, not dropped -
        // the window bounds how far back "this is probably the same line"
        // is a reasonable assumption.
        let historical = vec![
            "2024-01-15T10:00:00Z  INFO line a".to_string(),
            "2024-01-15T10:00:01Z  INFO line b".to_string(),
        ];
        let buffered = vec!["2024-01-15T10:00:00Z  INFO line a".to_string()];
        let result = dedup_buffered_against_tail(&historical, buffered.clone(), 1);
        assert_eq!(result, buffered);
    }

    #[test]
    fn dedup_buffered_against_tail_empty_inputs() {
        assert!(dedup_buffered_against_tail(&[], vec![], 50).is_empty());
        assert!(dedup_buffered_against_tail(&["x".to_string()], vec![], 50).is_empty());
        let buffered = vec!["x".to_string()];
        assert_eq!(dedup_buffered_against_tail(&[], buffered.clone(), 50), buffered);
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p credo-lib log_query`
Expected: compile error — `dedup_buffered_against_tail` is referenced but not yet defined. (The `follow` field itself doesn't need a dedicated test — it's exercised structurally by every test in Tasks 2-3 that constructs `LogQueryParams` and by axum's `Query` deserialization in Task 3's E2E test.)

- [ ] **Step 4: Implement `dedup_buffered_against_tail`**

Insert this code in `credo-lib/src/log_query.rs`, directly above the `#[cfg(test)] mod tests` block (after `historical_logs`, the last function from the previous plan):

```rust
/// How many of the most recent historical lines count as "the tail" when
/// deduping the live-broadcast buffer against them (see
/// `dedup_buffered_against_tail`).
pub const DEDUP_TAIL_WINDOW: usize = 50;

/// Filters `buffered` (lines that arrived on the live broadcast while the
/// historical backlog was being read) down to genuinely new lines: drops
/// any exact match against the last `tail_window` lines of `historical`,
/// since a line that shows up both on disk and on the live broadcast in
/// the same narrow window is far more likely double-counted (read once
/// from the file, delivered again live) than a real repeat. Order is
/// preserved; this is a heuristic, not a guarantee — two genuinely
/// identical log lines within the window are indistinguishable from a
/// double-count and one of them is dropped either way.
pub fn dedup_buffered_against_tail(
    historical: &[String],
    buffered: Vec<String>,
    tail_window: usize,
) -> Vec<String> {
    let recent: std::collections::HashSet<&str> = historical
        .iter()
        .rev()
        .take(tail_window)
        .map(|s| s.as_str())
        .collect();
    buffered
        .into_iter()
        .filter(|line| !recent.contains(line.as_str()))
        .collect()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p credo-lib log_query`
Expected: all tests pass, including the 5 new ones (`dedup_buffered_against_tail_drops_exact_matches_in_window`, `dedup_buffered_against_tail_keeps_everything_when_no_overlap`, `dedup_buffered_against_tail_drops_everything_on_full_overlap`, `dedup_buffered_against_tail_only_checks_within_window`, `dedup_buffered_against_tail_empty_inputs`).

- [ ] **Step 6: Lint and format**

Run: `cargo fmt -p credo-lib && cargo clippy -p credo-lib --all-targets -- -D warnings`
Expected: clean, no diff.

- [ ] **Step 7: Confirm the whole workspace still builds**

Run: `cargo build && cargo test`
Expected: workspace builds and all tests pass — confirms the new workspace-level `futures-util` dependency doesn't cause a feature-unification surprise.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock credo-lib/Cargo.toml credo-lib/src/log_query.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): add follow param and the replay/live dedup heuristic

follow on LogQueryParams is the switch a future /logs route will use to
choose historical JSON vs live-tail SSE. dedup_buffered_against_tail is
the trickiest piece of the sequencing this enables - subscribing to the
live broadcast before reading history means whatever arrives during
that read needs deduping against the tail of what was just read, or a
line lands twice. Isolating it as a pure function makes the one place a
subtle off-by-one would hide trivially testable, without needing to
force the actual race in an async test.
EOF
)"
```

---

### Task 2: The live-tail sequencing (`tail_stream` + `build_follow_stream`)

**Files:**
- Modify: `credo-lib/src/log_query.rs`
- Create: `credo-lib/tests/follow_stream.rs`

**Interfaces:**
- Consumes (from Task 1): `dedup_buffered_against_tail`, `DEDUP_TAIL_WINDOW`, `LogQueryParams.follow`.
- Consumes (from the historical-query plan): `read_historical_lines`, `line_passes_filter`, `parse_level_filter` (private, same module), `LoggingHandle::{subscribe, log_dir, log_basename}`.
- Produces (used by Task 3): `pub async fn build_follow_stream(handle: &LoggingHandle, params: &LogQueryParams) -> Result<impl futures_util::Stream<Item = String>, AppError>`.

- [ ] **Step 1: Write the failing tests**

Add these imports to the top of `credo-lib/src/log_query.rs` (alongside the existing `use` block):

```rust
use futures_util::StreamExt;
```

Add this test module content inside the existing `#[cfg(test)] mod tests` block (append after Task 1's dedup tests, before the closing `}`):

```rust
    #[tokio::test]
    async fn tail_stream_yields_only_lines_passing_filter_in_order() {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let mut stream = Box::pin(tail_stream(rx, Some(LogLevel::Warn), None));

        tx.send("2024-01-15T10:00:00Z ERROR bad".to_string())
            .expect("send");
        tx.send("2024-01-15T10:00:01Z  INFO ignored".to_string())
            .expect("send");
        tx.send("2024-01-15T10:00:02Z  WARN risky".to_string())
            .expect("send");

        assert_eq!(
            stream.next().await,
            Some("2024-01-15T10:00:00Z ERROR bad".to_string())
        );
        assert_eq!(
            stream.next().await,
            Some("2024-01-15T10:00:02Z  WARN risky".to_string())
        );
    }

    #[tokio::test]
    async fn tail_stream_ends_when_sender_dropped() {
        let (tx, rx) = tokio::sync::broadcast::channel::<String>(16);
        let mut stream = Box::pin(tail_stream(rx, None, None));
        drop(tx);
        assert_eq!(stream.next().await, None);
    }
```

Create `credo-lib/tests/follow_stream.rs`:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p credo-lib log_query && cargo test -p credo-lib --test follow_stream`
Expected: compile errors — `tail_stream` and `build_follow_stream` are referenced but not yet defined.

- [ ] **Step 3: Implement `tail_stream` and `build_follow_stream`**

Insert this code in `credo-lib/src/log_query.rs`, directly above the `#[cfg(test)] mod tests` block (after Task 1's `dedup_buffered_against_tail`):

```rust
/// Turns a live broadcast receiver into a `Stream` of lines that already
/// pass the level/text filter, skipping non-matching lines and recovering
/// from `Lagged` (falling behind the broadcast buffer) by simply resuming
/// from wherever the channel now stands, rather than erroring the whole
/// stream.
fn tail_stream(
    rx: tokio::sync::broadcast::Receiver<String>,
    level: Option<LogLevel>,
    q: Option<String>,
) -> impl futures_util::Stream<Item = String> {
    futures_util::stream::unfold((rx, level, q), move |(mut rx, level, q)| async move {
        loop {
            match rx.recv().await {
                Ok(line) => {
                    if line_passes_filter(&line, level, q.as_deref()) {
                        return Some((line, (rx, level, q)));
                    }
                    // Didn't pass the filter - keep waiting, don't yield.
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

/// Builds the full replay-then-continue line stream for live tail: the
/// historical backlog matching `params`, then anything that arrived on
/// the broadcast while that backlog was being read (deduped against the
/// backlog's tail), then an unbounded live feed of new matching lines.
/// Subscribes to the broadcast *before* reading the backlog specifically
/// so no line can be missed in the gap between "finish reading the file"
/// and "start tailing new lines."
pub async fn build_follow_stream(
    handle: &LoggingHandle,
    params: &LogQueryParams,
) -> Result<impl futures_util::Stream<Item = String>, AppError> {
    let mut live_rx = handle
        .subscribe()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?;
    let dir = handle
        .log_dir()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?;
    let basename = handle
        .log_basename()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?;

    let historical = read_historical_lines(dir, basename, params, Utc::now())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("reading log file: {e}")))?;

    let level = params.level.as_deref().map(parse_level_filter);
    let q = params.q.clone();

    let mut buffered = Vec::new();
    loop {
        match live_rx.try_recv() {
            Ok(line) => {
                if line_passes_filter(&line, level, q.as_deref()) {
                    buffered.push(line);
                }
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
        }
    }
    let buffered = dedup_buffered_against_tail(&historical, buffered, DEDUP_TAIL_WINDOW);

    let replay = futures_util::stream::iter(historical.into_iter().chain(buffered));
    let tail = tail_stream(live_rx, level, q);
    Ok(replay.chain(tail))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p credo-lib log_query && cargo test -p credo-lib --test follow_stream`
Expected: all pass — `tail_stream_yields_only_lines_passing_filter_in_order`, `tail_stream_ends_when_sender_dropped`, `build_follow_stream_replays_history_then_continues_live`.

- [ ] **Step 5: Lint and format**

Run: `cargo fmt -p credo-lib && cargo clippy -p credo-lib --all-targets -- -D warnings`
Expected: clean, no diff.

- [ ] **Step 6: Run the full credo-lib suite and confirm the workspace still builds**

Run: `cargo test -p credo-lib --all-targets && cargo build && cargo test`
Expected: every test in credo-lib passes, whole workspace passes.

- [ ] **Step 7: Commit**

```bash
git add credo-lib/src/log_query.rs credo-lib/tests/follow_stream.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): build the replay-then-continue live tail stream

build_follow_stream is the core of live tail: subscribe to the
broadcast before reading history (so nothing can be missed in the
gap), replay the filtered backlog, drain and dedup whatever arrived
during that read, then hand off to an unbounded live feed. Proven with
a real subscribe -> replay -> new-line-via-tracing sequence, not just
unit tests of the pieces, since the sequencing itself is the risk here.
EOF
)"
```

---

### Task 3: SSE wrapping, the unified dispatcher, and an end-to-end HTTP test

**Files:**
- Modify: `credo-lib/src/log_query.rs`
- Modify: `credo-lib/tests/support/mod.rs`
- Create: `credo-lib/tests/log_query_http_follow.rs`

**Interfaces:**
- Consumes (from Task 2): `build_follow_stream`.
- Consumes (from the historical-query plan): `historical_logs`.
- Produces: `pub async fn follow_logs(handle: &LoggingHandle, params: &LogQueryParams) -> Result<axum::response::sse::Sse<impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>>, AppError>`, `pub async fn respond_to_log_query(handle: &LoggingHandle, params: &LogQueryParams) -> Result<axum::response::Response, AppError>` — the single entry point a future service `/logs` route calls after its own auth check.

- [ ] **Step 1: Write the failing tests**

Update `credo-lib/tests/support/mod.rs` so the shared test handler routes through the new dispatcher instead of calling `historical_logs` directly — replace its entire current content with:

```rust
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use credo_lib::log_query::{respond_to_log_query, LogQueryParams};
use credo_lib::{
    init_logging_with_config, AppError, LogLevel, LoggingConfig, LoggingHandle, RotationConfig,
};
use std::sync::Arc;

pub async fn logs_handler(
    State(handle): State<Arc<LoggingHandle>>,
    Query(params): Query<LogQueryParams>,
) -> Result<Response, AppError> {
    respond_to_log_query(&handle, &params).await
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
```

(This changes `logs_handler`'s return type from `Result<Json<Vec<String>>, AppError>` to `Result<Response, AppError>` — the response body/status for the existing non-follow tests is unaffected, since `respond_to_log_query`'s non-follow branch calls `historical_logs(...).await?.into_response()` internally, producing the identical JSON response the old code did directly.)

Create `credo-lib/tests/log_query_http_follow.rs`:

```rust
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
    assert_eq!(payload["line"], "2024-01-15T10:00:00Z  INFO sse replay line");
    assert_eq!(payload["source"], "ssetest");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p credo-lib --test log_query_http_text_filter --test log_query_http_level_filter --test log_query_http_error_level_filter --test log_query_http_follow`
Expected: compile errors — `respond_to_log_query` is referenced (from `support/mod.rs`) but not yet defined, and the new follow test can't build against it either.

- [ ] **Step 3: Implement `follow_logs` and `respond_to_log_query`**

Insert this code in `credo-lib/src/log_query.rs`, directly above the `#[cfg(test)] mod tests` block (after Task 2's `build_follow_stream`):

```rust
fn build_sse_event(line: &str, source: &str) -> axum::response::sse::Event {
    let payload = serde_json::json!({ "line": line, "source": source });
    let data = serde_json::to_string(&payload).unwrap_or_else(|_| line.to_string());
    axum::response::sse::Event::default().data(data)
}

/// Live tail as Server-Sent Events: replays the matching historical
/// backlog, then streams new matching lines indefinitely. Each event's
/// data is a JSON object `{"line": "...", "source": "<service>"}` -
/// `source` is this handle's own log basename. It isn't needed until a
/// future plan has shepherd re-stream another service's `/logs?follow`
/// response, but adding it now costs nothing and means the wire format
/// never has to change once a real client depends on it.
pub async fn follow_logs(
    handle: &LoggingHandle,
    params: &LogQueryParams,
) -> Result<
    axum::response::sse::Sse<
        impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    AppError,
> {
    let source = handle
        .log_basename()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?
        .to_string();
    let lines = build_follow_stream(handle, params).await?;
    let events = lines.map(
        move |line| -> Result<axum::response::sse::Event, std::convert::Infallible> {
            Ok(build_sse_event(&line, &source))
        },
    );
    Ok(axum::response::sse::Sse::new(events).keep_alive(axum::response::sse::KeepAlive::default()))
}

/// Single entry point for a service's `/logs` route to call after its own
/// auth check: historical JSON when `params.follow` is false, a
/// live-tailing SSE stream when true.
pub async fn respond_to_log_query(
    handle: &LoggingHandle,
    params: &LogQueryParams,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;
    if params.follow {
        Ok(follow_logs(handle, params).await?.into_response())
    } else {
        Ok(historical_logs(handle, params).await?.into_response())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p credo-lib --test log_query_http_text_filter --test log_query_http_level_filter --test log_query_http_error_level_filter --test log_query_http_follow`
Expected: all 4 pass — the 3 pre-existing historical-query HTTP tests (proving the `support/mod.rs` update didn't change their observable behavior) plus the new `get_logs_over_http_streams_replay_as_sse`.

- [ ] **Step 5: Run the full credo-lib suite plus lint**

Run: `cargo test -p credo-lib --all-targets && cargo fmt -p credo-lib -- --check && cargo clippy -p credo-lib --all-targets -- -D warnings`
Expected: every test in the crate passes (all of Tasks 1-2's tests, all 4 HTTP test files, `log_init.rs`/`log_init_stdout.rs`, and the credo-lib unit tests), clean lint, clean fmt.

- [ ] **Step 6: Confirm the whole workspace still builds**

Run: `cargo build && cargo test`
Expected: workspace builds and all tests pass.

- [ ] **Step 7: Commit**

```bash
git add credo-lib/src/log_query.rs credo-lib/tests/support/mod.rs credo-lib/tests/log_query_http_follow.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): wrap live tail as SSE, add the unified /logs dispatcher

respond_to_log_query is what a future service's /logs route will
actually call after its own auth check - branches on follow between
the already-shipped historical_logs and the new SSE follow_logs, so
mounting this later is genuinely just auth-check-then-delegate, not a
redesign. Proven over a real HTTP round-trip reading raw SSE framing
off the wire, not just at the Rust-stream level Task 2 already covers.
EOF
)"
```

---

## Verification (whole plan)

1. `cargo build && cargo test && cargo fmt --check && cargo clippy -- -D warnings` — full workspace, must be clean.
2. Confirm no files outside `credo-lib/` changed except the two `Cargo.toml`/`Cargo.lock` at the workspace root: `git diff --stat <plan-start-commit>..HEAD`.
3. Manual sanity check (optional but recommended given this is genuinely novel machinery): run `cargo test -p credo-lib --test follow_stream -- --nocapture` a few times in a row to build confidence the timeout-bounded live-continuation assertion isn't flaky under normal machine load.

## Next Plan (not in this one)

With this, `credo_lib::log_query::respond_to_log_query` is a complete, fully-tested, self-contained log retrieval API (historical + live tail, filtered, all in one function) that nothing outside `credo-lib` calls yet. The next plan mounts it: add `logging: LoggingConfig` to each service's config struct, call `init_logging_with_config` from each service's startup path and store the resulting `LoggingHandle` on `AppState`, then add a `/logs` route to corgi and vigil (mechanical — each just needs its own auth-extension-to-`Role` adapter before calling `respond_to_log_query`), then shepherd's own `/admin/logs` plus the proxy/aggregation logic for `target=vigil`/`target=corgi:<name>` described in the design doc's Phase 3.
