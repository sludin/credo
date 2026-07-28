//! Log query API: historical retrieval and live tail (SSE), shared across
//! all three Rust services. See `respond_to_log_query` for the single
//! entry point a service's `/logs` route calls after its own auth check.
//!
//! Split into submodules by concern: `filter` (pure parsing/filtering, no
//! I/O), `historical` (multi-file reading), `follow` (live-tail streaming
//! and SSE wrapping) — each with its own tests, co-located with the code
//! they cover.

mod filter;
mod follow;
mod historical;

pub use filter::{
    line_in_window, line_passes_filter, line_timestamp, parse_last_duration, parse_rfc3339,
    resolve_window,
};
pub use follow::{
    build_follow_stream, dedup_buffered_against_tail, follow_logs, DEDUP_TAIL_WINDOW,
};
pub use historical::{historical_file_paths, historical_logs, read_historical_lines};

use serde::Deserialize;

use crate::error::AppError;
use crate::log::LoggingHandle;

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
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
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

/// Hard ceiling on `limit`, regardless of what a caller requests — without
/// this, a large `limit` query would read and hold the service's entire
/// retained log history in memory in one response, a resource-exhaustion
/// vector on `/admin/logs`, `/logs`.
pub const MAX_LOG_LIMIT: usize = 20_000;

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
