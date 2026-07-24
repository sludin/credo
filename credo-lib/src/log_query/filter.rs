use chrono::{DateTime, Utc};

use crate::log::LogLevel;

use super::LogQueryParams;

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
///
/// `pub(crate)` rather than private: both `historical` and `follow` (sibling
/// submodules) need it to parse `LogQueryParams.level` themselves.
pub(crate) fn parse_level_filter(s: &str) -> LogLevel {
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
}
