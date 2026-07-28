use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::error::AppError;
use crate::log::LoggingHandle;

use super::filter::{line_in_window, line_passes_filter, parse_level_filter, resolve_window};
use super::{LogQueryParams, DEFAULT_LOG_LIMIT, MAX_LOG_LIMIT};

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
    let limit = params
        .limit
        .unwrap_or(DEFAULT_LOG_LIMIT)
        .clamp(1, MAX_LOG_LIMIT);

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
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?
        .to_path_buf();
    let basename = handle
        .log_basename()
        .ok_or_else(|| AppError::BadRequest("file logging is not enabled".to_string()))?
        .to_string();
    let params = params.clone();
    // Reading (potentially many) log files is blocking I/O; run it on a
    // blocking-pool thread instead of directly in this async fn, so a large
    // or slow query can't stall the Tokio worker thread handling other
    // concurrent requests.
    let lines = tokio::task::spawn_blocking(move || {
        read_historical_lines(&dir, &basename, &params, Utc::now())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("log query task panicked: {e}")))?
    .map_err(|e| AppError::Internal(anyhow::anyhow!("reading log file: {e}")))?;
    Ok(axum::Json(lines))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_query::filter::parse_rfc3339;

    fn dt(s: &str) -> DateTime<Utc> {
        parse_rfc3339(s).unwrap_or_else(|| panic!("test fixture timestamp must parse: {s}"))
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

    /// Regression test for a Medium finding: a caller-supplied `limit` had
    /// no upper bound, so a huge `limit` could make one query read and hold
    /// the service's entire retained log history in memory. `limit` must be
    /// clamped to `MAX_LOG_LIMIT` regardless of what's requested — verified
    /// here by writing more lines than the cap and requesting far more than
    /// that, then checking only `MAX_LOG_LIMIT` (the most recent) come back.
    #[test]
    fn read_historical_lines_clamps_limit_to_max() {
        let dir = tempfile::tempdir().expect("tempdir");
        let total = MAX_LOG_LIMIT + 5;
        let mut contents = String::with_capacity(total * 40);
        for i in 0..total {
            contents.push_str(&format!("2024-01-15T10:00:00Z  INFO line {i}\n"));
        }
        write_log_file(dir.path(), "svc.log", &contents);

        let params = LogQueryParams {
            limit: Some(MAX_LOG_LIMIT * 100),
            ..Default::default()
        };
        let now = dt("2024-01-15T12:00:00Z");
        let lines = read_historical_lines(dir.path(), "svc", &params, now).expect("read");
        assert_eq!(
            lines.len(),
            MAX_LOG_LIMIT,
            "requested limit far above MAX_LOG_LIMIT must still be clamped"
        );
        // Kept the most recent MAX_LOG_LIMIT lines, not the oldest.
        assert!(lines[0].contains(&format!("line {}", total - MAX_LOG_LIMIT)));
        assert!(lines[lines.len() - 1].contains(&format!("line {}", total - 1)));
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
}
