# Historical Log Query Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `credo-lib` a shared, fully-tested function that answers "give me the log lines for this service matching this time range / level / text filter" by reading the rotating log file(s) built in the log-rotation-foundation plan — this is the historical (non-live-tail) half of Phase 1 from the on-demand log retrieval design (`docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`). Live tail (SSE `follow=true`) is deliberately out of scope for this plan — it's the harder, riskier half (subscribe-before-read sequencing, replay/drain, ongoing broadcast forwarding) and gets its own follow-up plan once this lands, mirroring how the foundation plan split into rotation (Phase 0) then broadcast (Phase 0b).

**Architecture:** A new `credo-lib/src/log_query.rs` module holds: pure parsing/filtering helpers (duration shorthand, RFC3339 timestamps, level/text matching — no I/O, trivially unit-testable), a file reader that walks a service's current + rotated log files in chronological order and returns the most recent N matching lines (memory-bounded via a capped `VecDeque`, independent of total log volume), and a thin `historical_logs(&LoggingHandle, &LogQueryParams) -> Result<Json<Vec<String>>, AppError>` that ties it together. `LoggingHandle` (from the foundation plan) gains two small accessors (`log_dir()`, `log_basename()`) so callers don't need to separately thread `LoggingConfig`/`service_name` around. Deliberately **not** a generic axum `Handler` or a custom `HasRole`/`HasLoggingHandle` trait: each service's own `/logs` route (added in a later plan) will be a normal 4-line handler that does its own auth check (exactly like every other per-service handler in this codebase already does with `check_min_role`) and then calls this one shared function — matching how `check_min_role`/`identity_from_der`/`log_request` are already shared via plain credo-lib functions today, not via a generic trait abstraction. This codebase has no `tower::ServiceExt::oneshot`-style router test anywhere (confirmed by search) — the established pattern (`credo_test::shepherd_harness::TestShepherd`) is a real `axum::serve` on a `127.0.0.1:0` `TcpListener` driven by a real `reqwest::Client`; this plan's end-to-end test follows that same idiom with a minimal test-only router, since the shared function isn't mounted into any real service's `AppState` yet.

**Tech Stack:** Rust, `axum` (already a dependency), `chrono` (already a dependency, `serde` feature enabled), `tokio` (already a dependency).

## Global Constraints

- This plan touches `credo-lib` only. No changes to `shepherd/`, `corgi/`, `vigil/`, or any config file.
- Do not implement `follow`/SSE in this plan — `LogQueryParams` in this plan has no `follow` field. Adding it now with no behavior behind it would be dead code; it's added in the follow-up plan alongside the code that uses it.
- `cargo fmt --check` and `cargo clippy -- -D warnings` must pass for every commit.
- Commit after each task with a message explaining *why*, not just what.
- No placeholder/TODO code. Every function must be fully implemented and covered by a test in the same task.
- `LoggingHandle`'s existing public API (`subscribe()`) and its `#[must_use]` attribute must be preserved exactly — only additive changes to that struct.

---

### Task 1: Query params, duration/window parsing, level and text filters

**Files:**
- Create: `credo-lib/src/log_query.rs`
- Modify: `credo-lib/src/lib.rs`

**Interfaces:**
- Produces (used by Task 2): `pub struct LogQueryParams { pub since: Option<String>, pub until: Option<String>, pub last: Option<String>, pub level: Option<String>, pub q: Option<String>, pub limit: Option<usize> }` (`Debug + Deserialize + Default + PartialEq`), `pub const DEFAULT_LOG_LIMIT: usize = 5000;`, `pub fn parse_rfc3339(s: &str) -> Option<chrono::DateTime<chrono::Utc>>`, `pub fn parse_last_duration(s: &str) -> Option<chrono::Duration>`, `pub fn resolve_window(params: &LogQueryParams, now: DateTime<Utc>) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>)`, `pub fn line_timestamp(line: &str) -> Option<DateTime<Utc>>`, `pub fn line_in_window(line: &str, since: Option<DateTime<Utc>>, until: Option<DateTime<Utc>>) -> bool`, `pub fn line_passes_filter(line: &str, level: Option<LogLevel>, q: Option<&str>) -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `credo-lib/src/log_query.rs` with only this content (the functions under test don't exist yet — deliberate RED step):

```rust
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::log::LogLevel;

/// Query parameters for historical log retrieval. `since`/`until` are RFC
/// 3339 strings, parsed via `parse_rfc3339` (not axum's Query-level chrono
/// support) so parsing stays explicit and independently testable. `last`
/// is a duration shorthand ("5m", "1h", "24h") that overrides
/// `since`/`until` when present and valid. `level` is a minimum severity
/// ("error"/"warn"/"info"/"debug"), matching `LogLevel`'s existing mental
/// model (parsed via `LogLevel::from_str`). `q` is a case-insensitive
/// substring filter.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct LogQueryParams {
    pub since: Option<String>,
    pub until: Option<String>,
    pub last: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}

/// Cap on returned lines when `limit` isn't specified.
pub const DEFAULT_LOG_LIMIT: usize = 5000;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dt(s: &str) -> DateTime<Utc> {
        parse_rfc3339(s).unwrap_or_else(|| panic!("test fixture timestamp must parse: {s}"))
    }

    #[test]
    fn parse_rfc3339_accepts_valid_and_rejects_garbage() {
        assert_eq!(
            parse_rfc3339("2024-01-15T10:00:00Z"),
            Some(Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap())
        );
        assert_eq!(parse_rfc3339("not-a-timestamp"), None);
        assert_eq!(parse_rfc3339(""), None);
    }

    #[test]
    fn parse_last_duration_accepts_known_units() {
        assert_eq!(parse_last_duration("30s"), Some(chrono::Duration::seconds(30)));
        assert_eq!(parse_last_duration("5m"), Some(chrono::Duration::minutes(5)));
        assert_eq!(parse_last_duration("1h"), Some(chrono::Duration::hours(1)));
        assert_eq!(parse_last_duration("2d"), Some(chrono::Duration::days(2)));
    }

    #[test]
    fn parse_last_duration_rejects_invalid_input() {
        assert_eq!(parse_last_duration(""), None);
        assert_eq!(parse_last_duration("m"), None);
        assert_eq!(parse_last_duration("5"), None);
        assert_eq!(parse_last_duration("5x"), None);
        assert_eq!(parse_last_duration("0m"), None);
        assert_eq!(parse_last_duration("-5m"), None);
    }

    #[test]
    fn resolve_window_last_overrides_explicit_since_until() {
        let now = dt("2024-01-15T12:00:00Z");
        let params = LogQueryParams {
            since: Some("2024-01-01T00:00:00Z".to_string()),
            until: Some("2024-01-02T00:00:00Z".to_string()),
            last: Some("5m".to_string()),
            ..Default::default()
        };
        let (since, until) = resolve_window(&params, now);
        assert_eq!(since, Some(dt("2024-01-15T11:55:00Z")));
        assert_eq!(until, Some(now));
    }

    #[test]
    fn resolve_window_falls_back_to_explicit_since_until() {
        let now = dt("2024-01-15T12:00:00Z");
        let params = LogQueryParams {
            since: Some("2024-01-01T00:00:00Z".to_string()),
            until: Some("2024-01-02T00:00:00Z".to_string()),
            ..Default::default()
        };
        let (since, until) = resolve_window(&params, now);
        assert_eq!(since, Some(dt("2024-01-01T00:00:00Z")));
        assert_eq!(until, Some(dt("2024-01-02T00:00:00Z")));
    }

    #[test]
    fn resolve_window_unbounded_when_nothing_given() {
        let now = dt("2024-01-15T12:00:00Z");
        let (since, until) = resolve_window(&LogQueryParams::default(), now);
        assert_eq!(since, None);
        assert_eq!(until, None);
    }

    #[test]
    fn line_timestamp_reads_leading_token() {
        assert_eq!(
            line_timestamp("2024-01-15T10:00:00Z  INFO something happened"),
            Some(dt("2024-01-15T10:00:00Z"))
        );
        assert_eq!(line_timestamp("garbage line with no timestamp"), None);
        assert_eq!(line_timestamp(""), None);
    }

    #[test]
    fn line_in_window_bounds_both_directions() {
        let line = "2024-01-15T10:00:00Z  INFO x";
        assert!(line_in_window(line, None, None));
        assert!(line_in_window(line, Some(dt("2024-01-15T09:00:00Z")), None));
        assert!(!line_in_window(line, Some(dt("2024-01-15T11:00:00Z")), None));
        assert!(line_in_window(line, None, Some(dt("2024-01-15T11:00:00Z"))));
        assert!(!line_in_window(line, None, Some(dt("2024-01-15T09:00:00Z"))));
        assert!(line_in_window(
            line,
            Some(dt("2024-01-15T09:00:00Z")),
            Some(dt("2024-01-15T11:00:00Z"))
        ));
    }

    #[test]
    fn line_in_window_fails_closed_for_unparseable_line_when_bounded() {
        let line = "garbage line with no timestamp";
        assert!(!line_in_window(line, Some(dt("2024-01-15T09:00:00Z")), None));
        // Unbounded window still passes anything, timestamp or not.
        assert!(line_in_window(line, None, None));
    }

    #[test]
    fn line_passes_filter_level_is_minimum_severity() {
        let error_line = "2024-01-15T10:00:00Z ERROR bad thing";
        let warn_line = "2024-01-15T10:00:00Z  WARN risky thing";
        let info_line = "2024-01-15T10:00:00Z  INFO normal thing";
        let debug_line = "2024-01-15T10:00:00Z DEBUG verbose thing";

        // level=warn (LogLevel::Warn) must include error+warn, exclude info+debug.
        assert!(line_passes_filter(error_line, Some(LogLevel::Warn), None));
        assert!(line_passes_filter(warn_line, Some(LogLevel::Warn), None));
        assert!(!line_passes_filter(info_line, Some(LogLevel::Warn), None));
        assert!(!line_passes_filter(debug_line, Some(LogLevel::Warn), None));

        // level=debug (LogLevel::Debug, most permissive) includes everything above.
        assert!(line_passes_filter(debug_line, Some(LogLevel::Debug), None));

        // level=fatal (maps to "error" threshold) only includes error lines.
        assert!(line_passes_filter(error_line, Some(LogLevel::Fatal), None));
        assert!(!line_passes_filter(warn_line, Some(LogLevel::Fatal), None));
    }

    #[test]
    fn line_passes_filter_text_is_case_insensitive_substring() {
        let line = "2024-01-15T10:00:00Z  INFO Corgi sync completed";
        assert!(line_passes_filter(line, None, Some("corgi")));
        assert!(line_passes_filter(line, None, Some("SYNC")));
        assert!(!line_passes_filter(line, None, Some("vigil")));
        // Empty needle means no text filter.
        assert!(line_passes_filter(line, None, Some("")));
        assert!(line_passes_filter(line, None, None));
    }

    #[test]
    fn line_passes_filter_combines_level_and_text() {
        let warn_about_corgi = "2024-01-15T10:00:00Z  WARN corgi unreachable";
        let info_about_corgi = "2024-01-15T10:00:00Z  INFO corgi synced";
        assert!(line_passes_filter(warn_about_corgi, Some(LogLevel::Warn), Some("corgi")));
        assert!(!line_passes_filter(info_about_corgi, Some(LogLevel::Warn), Some("corgi")));
    }
}
```

Add `pub mod log_query;` to `credo-lib/src/lib.rs` (insert alphabetically, after `pub mod log;` and before `pub mod pid;`), so the module list reads:

```rust
pub mod archive;
pub mod auth;
pub mod config;
pub mod error;
pub mod file_policy;
pub mod log;
pub mod log_query;
pub mod pid;
pub mod rotating_log;
pub mod timing;
pub mod tls;
pub mod types;

// Convenience re-exports used by every service
pub use error::AppError;
pub use log::{init_logging_with_config, LogIdentity, LogLevel, LoggingHandle};
pub use rotating_log::{LoggingConfig, RotationConfig};
pub use tls::PeerCertDer;
pub use types::{ClientIdentity, HookRef, Role};
```

(`log_query`'s own types stay accessed via `credo_lib::log_query::...` rather than being re-exported at crate root — matches this codebase's existing convention where cohesive subsystems like `auth`/`tls` stay module-scoped, and only a few universally-used types like `AppError`/`Role`/`LogLevel` get root re-exports.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p credo-lib log_query`
Expected: compile errors — `parse_rfc3339`, `parse_last_duration`, `resolve_window`, `line_timestamp`, `line_in_window`, `line_passes_filter` are referenced but not yet defined.

- [ ] **Step 3: Implement the parsing and filter functions**

Insert this code in `credo-lib/src/log_query.rs`, directly above the `#[cfg(test)] mod tests` block (i.e. after the `LogQueryParams`/`DEFAULT_LOG_LIMIT` declarations already written in Step 1):

```rust
/// Parses an RFC 3339 timestamp string (e.g. "2024-01-15T10:00:00Z").
pub fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Parses a duration shorthand: digits followed by a unit (`s`/`m`/`h`/`d`).
/// Returns `None` for anything else (empty, no unit, non-numeric, zero or
/// negative).
pub fn parse_last_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.len() < 2 {
        return None;
    }
    let (digits, unit) = s.split_at(s.len() - 1);
    let n: i64 = digits.parse().ok()?;
    if n <= 0 {
        return None;
    }
    match unit {
        "s" => Some(chrono::Duration::seconds(n)),
        "m" => Some(chrono::Duration::minutes(n)),
        "h" => Some(chrono::Duration::hours(n)),
        "d" => Some(chrono::Duration::days(n)),
        _ => None,
    }
}

/// Resolves the effective (since, until) window: `last`, if present and
/// valid, overrides `since`/`until`; otherwise falls back to whatever
/// `since`/`until` parse to (either may be `None`, meaning unbounded on
/// that side).
pub fn resolve_window(
    params: &LogQueryParams,
    now: DateTime<Utc>,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    if let Some(last) = params.last.as_deref().and_then(parse_last_duration) {
        return (Some(now - last), Some(now));
    }
    let since = params.since.as_deref().and_then(parse_rfc3339);
    let until = params.until.as_deref().and_then(parse_rfc3339);
    (since, until)
}

/// Extracts the RFC 3339 timestamp from the leading token of a formatted
/// log line (the credo one-line format always starts with the timestamp).
pub fn line_timestamp(line: &str) -> Option<DateTime<Utc>> {
    line.split_whitespace().next().and_then(parse_rfc3339)
}

/// Whether a line's timestamp falls within `[since, until]` (either bound
/// `None` means unbounded on that side). A line with no parseable
/// timestamp only matches when the window itself is fully unbounded (fails
/// closed once any bound is set, rather than guessing).
pub fn line_in_window(line: &str, since: Option<DateTime<Utc>>, until: Option<DateTime<Utc>>) -> bool {
    if since.is_none() && until.is_none() {
        return true;
    }
    let Some(ts) = line_timestamp(line) else {
        return false;
    };
    if let Some(s) = since {
        if ts < s {
            return false;
        }
    }
    if let Some(u) = until {
        if ts > u {
            return false;
        }
    }
    true
}

fn line_level_rank(line: &str) -> Option<u8> {
    line.split_whitespace().find_map(|tok| match tok {
        "ERROR" => Some(0),
        "WARN" => Some(1),
        "INFO" => Some(2),
        "DEBUG" => Some(3),
        "TRACE" => Some(4),
        _ => None,
    })
}

fn min_level_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Fatal => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
    }
}

/// Whether a line passes the level (minimum severity) and free-text
/// filters. `level: None` means no level filter; `q: None` or `Some("")`
/// means no text filter.
pub fn line_passes_filter(line: &str, level: Option<LogLevel>, q: Option<&str>) -> bool {
    if let Some(lvl) = level {
        match line_level_rank(line) {
            Some(rank) if rank <= min_level_rank(lvl) => {}
            _ => return false,
        }
    }
    if let Some(needle) = q {
        if !needle.is_empty() && !line.to_lowercase().contains(&needle.to_lowercase()) {
            return false;
        }
    }
    true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p credo-lib log_query`
Expected: all tests pass (`parse_rfc3339_accepts_valid_and_rejects_garbage`, `parse_last_duration_accepts_known_units`, `parse_last_duration_rejects_invalid_input`, `resolve_window_last_overrides_explicit_since_until`, `resolve_window_falls_back_to_explicit_since_until`, `resolve_window_unbounded_when_nothing_given`, `line_timestamp_reads_leading_token`, `line_in_window_bounds_both_directions`, `line_in_window_fails_closed_for_unparseable_line_when_bounded`, `line_passes_filter_level_is_minimum_severity`, `line_passes_filter_text_is_case_insensitive_substring`, `line_passes_filter_combines_level_and_text`).

- [ ] **Step 5: Lint and format**

Run: `cargo fmt -p credo-lib && cargo clippy -p credo-lib --all-targets -- -D warnings`
Expected: no warnings, no diff from `cargo fmt`. (Use `--all-targets` — a plain `cargo clippy -p credo-lib` does not type-check `#[cfg(test)]` code and can miss real warnings; this bit the previous plan.)

- [ ] **Step 6: Commit**

```bash
git add credo-lib/src/log_query.rs credo-lib/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): add log query params, window resolution, and filters

Pure, independently-testable building blocks for historical log
retrieval: duration-shorthand parsing ("5m"/"1h"), time-window
resolution, and the level+text filter that will be applied identically
to historical reads (this plan) and live tail (a follow-up plan) so
filtering behavior can't drift between the two paths.
EOF
)"
```

---

### Task 2: Historical multi-file reader

**Files:**
- Modify: `credo-lib/src/log_query.rs`

**Interfaces:**
- Consumes (from Task 1): `LogQueryParams`, `DEFAULT_LOG_LIMIT`, `resolve_window`, `line_in_window`, `line_passes_filter`.
- Produces (used by Task 3): `pub fn historical_file_paths(dir: &Path, basename: &str) -> Vec<PathBuf>` (oldest file first, current file last, only existing files included), `pub fn read_historical_lines(dir: &Path, basename: &str, params: &LogQueryParams, now: DateTime<Utc>) -> std::io::Result<Vec<String>>` (chronological order, most recent `limit` matching lines kept).

- [ ] **Step 1: Write the failing tests**

Add this test module content inside the existing `#[cfg(test)] mod tests` block in `credo-lib/src/log_query.rs` (append these `#[test]` functions after `line_passes_filter_combines_level_and_text`, before the closing `}` of the `mod tests` block):

```rust
    fn write_log_file(dir: &std::path::Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).expect("write test log file");
    }

    #[test]
    fn historical_file_paths_orders_oldest_first_then_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(dir.path(), "svc.log", "current\n");
        write_log_file(dir.path(), "svc.1.log", "newest backup\n");
        write_log_file(dir.path(), "svc.2.log", "oldest backup\n");

        let paths = historical_file_paths(dir.path(), "svc");
        let names: Vec<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["svc.2.log", "svc.1.log", "svc.log"]);
    }

    #[test]
    fn historical_file_paths_skips_missing_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(dir.path(), "svc.log", "current\n");
        // No .1.log or .2.log written - fresh service, no rotations yet.
        let paths = historical_file_paths(dir.path(), "svc");
        let names: Vec<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["svc.log"]);
    }

    #[test]
    fn historical_file_paths_empty_dir_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(historical_file_paths(dir.path(), "svc").is_empty());
    }

    #[test]
    fn read_historical_lines_reads_in_chronological_order_across_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(
            dir.path(),
            "svc.1.log",
            "2024-01-15T10:00:00Z  INFO older line\n",
        );
        write_log_file(
            dir.path(),
            "svc.log",
            "2024-01-15T10:05:00Z  INFO newer line\n",
        );
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &LogQueryParams::default(), now)
            .expect("read");
        assert_eq!(
            lines,
            vec![
                "2024-01-15T10:00:00Z  INFO older line".to_string(),
                "2024-01-15T10:05:00Z  INFO newer line".to_string(),
            ]
        );
    }

    #[test]
    fn read_historical_lines_applies_time_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(
            dir.path(),
            "svc.log",
            "2024-01-15T09:00:00Z  INFO too early\n\
             2024-01-15T10:00:00Z  INFO in window\n\
             2024-01-15T11:00:00Z  INFO too late\n",
        );
        let params = LogQueryParams {
            since: Some("2024-01-15T09:30:00Z".to_string()),
            until: Some("2024-01-15T10:30:00Z".to_string()),
            ..Default::default()
        };
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &params, now).expect("read");
        assert_eq!(lines, vec!["2024-01-15T10:00:00Z  INFO in window".to_string()]);
    }

    #[test]
    fn read_historical_lines_applies_level_and_text_filters() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(
            dir.path(),
            "svc.log",
            "2024-01-15T10:00:00Z  INFO corgi synced\n\
             2024-01-15T10:01:00Z  WARN corgi unreachable\n\
             2024-01-15T10:02:00Z  WARN vigil unreachable\n",
        );
        let params = LogQueryParams {
            level: Some("warn".to_string()),
            q: Some("corgi".to_string()),
            ..Default::default()
        };
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &params, now).expect("read");
        assert_eq!(
            lines,
            vec!["2024-01-15T10:01:00Z  WARN corgi unreachable".to_string()]
        );
    }

    #[test]
    fn read_historical_lines_caps_at_limit_keeping_most_recent() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(
            dir.path(),
            "svc.log",
            "2024-01-15T10:00:00Z  INFO line one\n\
             2024-01-15T10:01:00Z  INFO line two\n\
             2024-01-15T10:02:00Z  INFO line three\n",
        );
        let params = LogQueryParams {
            limit: Some(2),
            ..Default::default()
        };
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &params, now).expect("read");
        assert_eq!(
            lines,
            vec![
                "2024-01-15T10:01:00Z  INFO line two".to_string(),
                "2024-01-15T10:02:00Z  INFO line three".to_string(),
            ]
        );
    }

    #[test]
    fn read_historical_lines_missing_dir_returns_empty_not_error() {
        let missing = std::path::Path::new("/nonexistent/credo-log-query-test-dir");
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(missing, "svc", &LogQueryParams::default(), now)
            .expect("missing dir must not error");
        assert!(lines.is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p credo-lib log_query`
Expected: compile errors — `historical_file_paths` and `read_historical_lines` are referenced but not yet defined.

- [ ] **Step 3: Implement the file reader**

Insert this code in `credo-lib/src/log_query.rs`, directly above the `#[cfg(test)] mod tests` block (after the Task 1 filter functions), and add `use std::path::{Path, PathBuf};` to the file's top-level `use` block (alongside the existing `use chrono::{DateTime, Utc};` and `use serde::Deserialize;`):

```rust
/// Lists this basename's log files in chronological order (oldest first,
/// current file last). Only includes files that actually exist - a
/// freshly started service may have no rotated backups yet. A missing
/// directory yields an empty list rather than an error.
pub fn historical_file_paths(dir: &Path, basename: &str) -> Vec<PathBuf> {
    let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        let prefix = format!("{basename}.");
        let suffix = ".log";
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(middle) = name.strip_prefix(&prefix).and_then(|s| s.strip_suffix(suffix)) {
                if let Ok(n) = middle.parse::<u32>() {
                    rotated.push((n, entry.path()));
                }
            }
        }
    }
    rotated.sort_by(|a, b| b.0.cmp(&a.0)); // oldest (highest N) first
    let mut paths: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    let current = dir.join(format!("{basename}.log"));
    if current.exists() {
        paths.push(current);
    }
    paths
}

/// Reads matching lines across all of this basename's log files (oldest to
/// newest), applying the time window, level, and text filters, keeping at
/// most the most recent `limit` matching lines - memory-bounded regardless
/// of total log volume on disk. `now` anchors `last`-shorthand windows;
/// callers pass `chrono::Utc::now()` in production and a fixed value in
/// tests for determinism.
pub fn read_historical_lines(
    dir: &Path,
    basename: &str,
    params: &LogQueryParams,
    now: DateTime<Utc>,
) -> std::io::Result<Vec<String>> {
    let (since, until) = resolve_window(params, now);
    let level = params.level.as_deref().map(LogLevel::from_str);
    let q = params.q.as_deref();
    let limit = params.limit.unwrap_or(DEFAULT_LOG_LIMIT).max(1);

    let mut kept: std::collections::VecDeque<String> =
        std::collections::VecDeque::with_capacity(limit.min(1024));
    for path in historical_file_paths(dir, basename) {
        let contents = std::fs::read_to_string(&path)?;
        for line in contents.lines() {
            if line.is_empty() {
                continue;
            }
            if !line_in_window(line, since, until) {
                continue;
            }
            if !line_passes_filter(line, level, q) {
                continue;
            }
            if kept.len() == limit {
                kept.pop_front();
            }
            kept.push_back(line.to_string());
        }
    }
    Ok(kept.into_iter().collect())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p credo-lib log_query`
Expected: all tests pass, including Task 1's tests plus the 7 new ones (`historical_file_paths_orders_oldest_first_then_current`, `historical_file_paths_skips_missing_files`, `historical_file_paths_empty_dir_returns_empty`, `read_historical_lines_reads_in_chronological_order_across_files`, `read_historical_lines_applies_time_window`, `read_historical_lines_applies_level_and_text_filters`, `read_historical_lines_caps_at_limit_keeping_most_recent`, `read_historical_lines_missing_dir_returns_empty_not_error`).

- [ ] **Step 5: Lint and format**

Run: `cargo fmt -p credo-lib && cargo clippy -p credo-lib --all-targets -- -D warnings`
Expected: no warnings, no diff from `cargo fmt`.

- [ ] **Step 6: Commit**

```bash
git add credo-lib/src/log_query.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): read rotated log files in chronological order

Walks a service's current + rotated log files oldest-to-newest and
keeps only the most recent N matching lines via a capped VecDeque, so
memory use is bounded by the query's limit rather than total log
volume on disk - important once retention reaches the ~1.2GB ceiling
the foundation plan sized per service.
EOF
)"
```

---

### Task 3: `LoggingHandle` file-location accessors, the historical-logs function, and an end-to-end HTTP test

**Files:**
- Modify: `credo-lib/src/log.rs`
- Modify: `credo-lib/src/log_query.rs`
- Modify: `credo-lib/tests/log_init.rs`
- Create: `credo-lib/tests/log_query_http.rs`

**Interfaces:**
- Consumes (from Tasks 1-2): `LogQueryParams`, `read_historical_lines`.
- Produces: `LoggingHandle::log_dir(&self) -> Option<&std::path::Path>`, `LoggingHandle::log_basename(&self) -> Option<&str>`; `pub async fn historical_logs(handle: &LoggingHandle, params: &LogQueryParams) -> Result<axum::Json<Vec<String>>, AppError>`.

- [ ] **Step 1: Write the failing tests**

Append this to the existing `#[tokio::test]` in `credo-lib/tests/log_init.rs` — add two assertions right after the `let mut rx = handle.subscribe()...` line and before `tracing::info!("hello from log_init test");`:

```rust
    assert_eq!(handle.log_dir(), Some(dir.path()));
    assert_eq!(handle.log_basename(), Some("testsvc"));
```

Create `credo-lib/tests/log_query_http.rs`:

```rust
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use credo_lib::log_query::{historical_logs, LogQueryParams};
use credo_lib::{init_logging_with_config, AppError, LogLevel, LoggingConfig, LoggingHandle, RotationConfig};
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p credo-lib --test log_init --test log_query_http`
Expected: compile errors — `LoggingHandle::log_dir`/`log_basename` don't exist yet, and `credo_lib::log_query::historical_logs` doesn't exist yet.

- [ ] **Step 3: Add the `LoggingHandle` accessors**

In `credo-lib/src/log.rs`, replace the `LoggingHandle` struct and its `impl` block with this (adds two private fields and two public accessors; `subscribe()` is unchanged):

```rust
/// Returned by `init_logging_with_config`. Keep this alive for the process
/// lifetime (e.g. bind it in `main()`) - dropping it flushes and stops the
/// non-blocking file writer.
#[must_use = "dropping the handle stops file logging and the live tail"]
pub struct LoggingHandle {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    writer: Option<RotatingFileWriter>,
    log_dir: Option<std::path::PathBuf>,
    log_basename: Option<String>,
}

impl LoggingHandle {
    /// Subscribe to a live feed of this service's log lines. Returns `None`
    /// if rotating-file logging is not enabled in `config`.
    pub fn subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<String>> {
        self.writer.as_ref().map(|w| w.subscribe())
    }

    /// Directory containing this service's rotating log file, if file
    /// logging is enabled.
    pub fn log_dir(&self) -> Option<&std::path::Path> {
        self.log_dir.as_deref()
    }

    /// Basename (without extension) of this service's rotating log file,
    /// if file logging is enabled.
    pub fn log_basename(&self) -> Option<&str> {
        self.log_basename.as_deref()
    }
}
```

Then update both `LoggingHandle { .. }` construction sites inside `init_logging_with_config` in the same file:

Change the disabled-path return (currently `return LoggingHandle { _guard: None, writer: None };`) to:

```rust
        return LoggingHandle {
            _guard: None,
            writer: None,
            log_dir: None,
            log_basename: None,
        };
```

Change the enabled-path return (currently `LoggingHandle { _guard: Some(guard), writer: Some(writer) }`) to:

```rust
    LoggingHandle {
        _guard: Some(guard),
        writer: Some(writer),
        log_dir: Some(std::path::Path::new(&config.dir).to_path_buf()),
        log_basename: Some(service_name.to_string()),
    }
```

- [ ] **Step 4: Add the `historical_logs` function**

Insert this code in `credo-lib/src/log_query.rs`, directly above the `#[cfg(test)] mod tests` block (after Task 2's `read_historical_lines`), and add these two imports to the file's top-level `use` block:

```rust
use crate::error::AppError;
use crate::log::LoggingHandle;
```

```rust
/// Historical log query: reads and filters lines from `handle`'s rotating
/// log file. Returns `AppError::BadRequest` if `handle` has no file
/// logging enabled (nothing to read).
pub async fn historical_logs(
    handle: &LoggingHandle,
    params: &LogQueryParams,
) -> Result<axum::Json<Vec<String>>, AppError> {
    let dir = handle
        .log_dir()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?;
    let basename = handle
        .log_basename()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?;
    let lines = read_historical_lines(dir, basename, params, Utc::now())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("reading log file: {e}")))?;
    Ok(axum::Json(lines))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p credo-lib --test log_init --test log_query_http`
Expected: all pass — `init_logging_with_config_writes_file_and_broadcasts_live` (now with the two new assertions), `get_logs_over_http_applies_text_filter`, `get_logs_over_http_applies_level_filter`.

- [ ] **Step 6: Run the full credo-lib suite plus lint**

Run: `cargo test -p credo-lib --all-targets && cargo fmt -p credo-lib -- --check && cargo clippy -p credo-lib --all-targets -- -D warnings`
Expected: every test in the crate passes (Task 1 + Task 2's unit tests, both integration test files, plus any pre-existing tests), no clippy warnings, no fmt diff.

- [ ] **Step 7: Confirm the whole workspace still builds**

Run: `cargo build && cargo test`
Expected: workspace builds and all tests pass — confirms the `LoggingHandle` struct-literal change didn't break anything outside `credo-lib` (nothing outside it constructs `LoggingHandle` directly today — only `init_logging_with_config` does — but this is the cheap way to be sure).

- [ ] **Step 8: Commit**

```bash
git add credo-lib/src/log.rs credo-lib/src/log_query.rs credo-lib/tests/log_init.rs credo-lib/tests/log_query_http.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): expose historical log query as a plain async function

LoggingHandle now remembers its own log_dir/log_basename so a caller
holding just the handle can query history without separately threading
LoggingConfig/service_name around. historical_logs() is a plain async
function, not a generic axum Handler or a custom trait - each service's
own /logs route (added in a follow-up plan) does its own auth check
and then calls this, the same way check_min_role/identity_from_der are
already shared today. Proven end-to-end with a real axum::serve +
reqwest test, following this codebase's established router-testing
idiom (no service is wired to mount this yet).
EOF
)"
```

---

## Verification (whole plan)

1. `cargo build && cargo test && cargo fmt --check && cargo clippy -- -D warnings` — full workspace, must be clean.
2. Confirm no files outside `credo-lib/` changed: `git diff --stat <plan-start-commit>..HEAD` should show only `credo-lib/**` paths.
3. Confirm `LogQueryParams` has no `follow` field and `log_query.rs` has no SSE/streaming code — this plan is historical-only by design.

## Next Plan (not in this one)

Once this lands, the follow-up plan adds live tail: `follow` on `LogQueryParams`, an SSE response path in `log_query.rs` using axum's `Sse` type with the subscribe-before-historical-read / buffer / replay / drain sequencing described in the design doc's Phase 1 section, and its own tests (replay-then-continue with no gaps/dupes under scripted concurrent writes). After that, mounting into corgi/vigil (Phase 2) and shepherd + aggregation (Phase 3) can begin — those are where `historical_logs`/the SSE equivalent actually get called from a real per-service `/logs` route for the first time.
