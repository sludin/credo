use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::Deserialize;

use crate::error::AppError;
use crate::log::{LogLevel, LoggingHandle};

/// Query parameters for historical log retrieval. `since`/`until` are RFC
/// 3339 strings, parsed via `parse_rfc3339` (not axum's Query-level chrono
/// support) so parsing stays explicit and independently testable. `last`
/// is a duration shorthand ("5m", "1h", "24h") that overrides
/// `since`/`until` when present and valid. `level` is a minimum severity
/// ("error"/"warn"/"info"/"debug"), matching `LogLevel`'s existing mental
/// model (parsed via `parse_level_filter`, not `LogLevel::from_str` directly
/// — see that function's doc for why). `q` is a case-insensitive substring
/// filter. `follow` requests a live-tailing SSE stream instead of a
/// historical JSON array (see `respond_to_log_query`).
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

/// Cap on returned lines when `limit` isn't specified.
pub const DEFAULT_LOG_LIMIT: usize = 5000;

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
    // Split on the last *character*, not the last byte: a multi-byte unit
    // char (e.g. "5µ") would otherwise land `split_at` mid-codepoint and
    // panic with "byte index is not a char boundary".
    let last_char = s.chars().last()?;
    let split_at = s.len() - last_char.len_utf8();
    if split_at == 0 {
        return None;
    }
    let (digits, unit) = s.split_at(split_at);
    let n: i64 = digits.parse().ok()?;
    if n <= 0 {
        return None;
    }
    // Use chrono's fallible constructors: `digits.parse::<i64>()` accepts
    // values far larger than chrono's internal bound, and the panicking
    // constructors (`Duration::seconds`/etc.) would abort on oversized input.
    match unit {
        "s" => chrono::Duration::try_seconds(n),
        "m" => chrono::Duration::try_minutes(n),
        "h" => chrono::Duration::try_hours(n),
        "d" => chrono::Duration::try_days(n),
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
pub fn line_in_window(
    line: &str,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
) -> bool {
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

/// Parses a `level` query value into the minimum severity to include.
/// Same vocabulary as `LogLevel::from_str`, plus `"error"` as a synonym
/// for `LogLevel::Fatal` — `LogLevel::from_str` alone maps `"error"` to
/// `Info` like any other unrecognized string, which silently returns far
/// more than an error-only filter should. `"error"` is the vocabulary
/// this module's own docs promise callers, so it needs to actually mean
/// error-and-above here, not fall through to `from_str`'s generic default.
fn parse_level_filter(s: &str) -> LogLevel {
    match s.trim().to_lowercase().as_str() {
        "error" | "fatal" => LogLevel::Fatal,
        "warn" => LogLevel::Warn,
        "debug" => LogLevel::Debug,
        _ => LogLevel::Info,
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
            if let Some(middle) = name
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(suffix))
            {
                if let Ok(n) = middle.parse::<u32>() {
                    rotated.push((n, entry.path()));
                }
            }
        }
    }
    rotated.sort_by_key(|(n, _)| std::cmp::Reverse(*n)); // oldest (highest N) first
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
    let level = params.level.as_deref().map(parse_level_filter);
    let q = params.q.as_deref();
    let limit = params.limit.unwrap_or(DEFAULT_LOG_LIMIT).max(1);

    let mut kept: std::collections::VecDeque<String> =
        std::collections::VecDeque::with_capacity(limit.min(1024));
    for path in historical_file_paths(dir, basename) {
        // Best-effort per file: a log directory is actively written and
        // rotated concurrently with queries, so a file that existed when
        // `historical_file_paths` listed it can vanish (or otherwise fail
        // to read) before this loop reaches it. Skip that one file rather
        // than discarding every line already gathered from the others -
        // "give me what's available" is the whole point of this query.
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
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
        assert_eq!(
            parse_last_duration("30s"),
            Some(chrono::Duration::seconds(30))
        );
        assert_eq!(
            parse_last_duration("5m"),
            Some(chrono::Duration::minutes(5))
        );
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
    fn parse_last_duration_rejects_non_ascii_unit_without_panicking() {
        assert_eq!(parse_last_duration("5µ"), None);
    }

    #[test]
    fn parse_last_duration_rejects_oversized_duration_without_panicking() {
        assert_eq!(parse_last_duration("999999999999d"), None);
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
        assert!(!line_in_window(
            line,
            Some(dt("2024-01-15T11:00:00Z")),
            None
        ));
        assert!(line_in_window(line, None, Some(dt("2024-01-15T11:00:00Z"))));
        assert!(!line_in_window(
            line,
            None,
            Some(dt("2024-01-15T09:00:00Z"))
        ));
        assert!(line_in_window(
            line,
            Some(dt("2024-01-15T09:00:00Z")),
            Some(dt("2024-01-15T11:00:00Z"))
        ));
    }

    #[test]
    fn line_in_window_fails_closed_for_unparseable_line_when_bounded() {
        let line = "garbage line with no timestamp";
        assert!(!line_in_window(
            line,
            Some(dt("2024-01-15T09:00:00Z")),
            None
        ));
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
    fn parse_level_filter_error_means_error_only() {
        let error_line = "2024-01-15T10:00:00Z ERROR bad thing";
        let warn_line = "2024-01-15T10:00:00Z  WARN risky thing";
        assert!(line_passes_filter(
            error_line,
            Some(parse_level_filter("error")),
            None
        ));
        assert!(!line_passes_filter(
            warn_line,
            Some(parse_level_filter("error")),
            None
        ));
    }

    #[test]
    fn read_historical_lines_level_error_returns_error_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(
            dir.path(),
            "svc.log",
            "2024-01-15T10:00:00Z ERROR failure\n\
             2024-01-15T10:00:01Z  WARN risky\n\
             2024-01-15T10:00:02Z  INFO normal\n",
        );
        let params = LogQueryParams {
            level: Some("error".to_string()),
            ..Default::default()
        };
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &params, now).expect("read");
        assert_eq!(
            lines,
            vec!["2024-01-15T10:00:00Z ERROR failure".to_string()]
        );
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
        assert!(line_passes_filter(
            warn_about_corgi,
            Some(LogLevel::Warn),
            Some("corgi")
        ));
        assert!(!line_passes_filter(
            info_about_corgi,
            Some(LogLevel::Warn),
            Some("corgi")
        ));
    }

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
        assert_eq!(
            lines,
            vec!["2024-01-15T10:00:00Z  INFO in window".to_string()]
        );
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
    fn read_historical_lines_skips_unreadable_file_instead_of_failing_whole_query() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_log_file(
            dir.path(),
            "svc.log",
            "2024-01-15T10:00:00Z  INFO current line\n",
        );
        // A directory matching the rotated-file naming pattern reliably
        // fails `fs::read_to_string` with a real IO error on all platforms,
        // deterministically standing in for a file that vanished (or
        // otherwise became unreadable) between listing and read time -
        // without relying on a timing race.
        std::fs::create_dir(dir.path().join("svc.1.log")).expect("create dir stand-in");

        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &LogQueryParams::default(), now)
            .expect("must not fail whole query because one file is unreadable");
        assert_eq!(
            lines,
            vec!["2024-01-15T10:00:00Z  INFO current line".to_string()]
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
        assert_eq!(
            result,
            vec!["2024-01-15T10:00:03Z  INFO line d".to_string()]
        );
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
        assert_eq!(
            dedup_buffered_against_tail(&[], buffered.clone(), 50),
            buffered
        );
    }

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
}
