use chrono::Utc;
use futures_util::StreamExt;

use crate::error::AppError;
use crate::log::{LogLevel, LoggingHandle};

use super::filter::{line_passes_filter, parse_level_filter};
use super::historical::read_historical_lines;
use super::LogQueryParams;

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
    // Serializing two plain strings cannot fail; this fallback is
    // defensive only, not a real degradation path this code expects to hit.
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

#[cfg(test)]
mod tests {
    use super::*;

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
