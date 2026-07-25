// src/lib/logs.ts
// Pure logic behind the Logs page: URL building, SSE parsing, buffering,
// and reconnect policy. Kept free of React/DOM so it's unit-testable in
// the repo's node-environment vitest setup (same split as lib/columns).

export type LogsParams = {
  source: string;
  /** Duration shorthand ("5m", "1h") - overrides since/until server-side. */
  last?: string;
  /** RFC 3339 timestamps. */
  since?: string;
  until?: string;
  /** Minimum severity: "error" | "warn" | "info" | "debug". */
  level?: string;
  /** Case-insensitive substring filter. */
  q?: string;
  limit?: number;
};

/** Client-side viewer buffer cap - matches the server's DEFAULT_LOG_LIMIT. */
export const LOG_BUFFER_MAX = 5000;

export const RANGE_PRESETS = ['5m', '15m', '1h', '24h'] as const;

// ── Timestamp display (timezone + format) ─────────────────────────────────
// Purely a rendering concern: every line's leading token is always an
// RFC3339 UTC timestamp with 6-digit microseconds (credo-lib's tracing
// timer is hardcoded to that shape - see log_query::filter::line_timestamp).
// These helpers reformat that leading token for display; the rest of the
// line, and everything sent to the server, is untouched.

export type SelectOption = { value: string; label: string };

/** Sentinel for "the browser's detected zone" - resolved at format time
 * (never cached at import time) so a session survives a laptop's timezone
 * changing without a page reload. */
export const LOCAL_TIMEZONE_VALUE = 'local';

const NAMED_TIMEZONES = [
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Berlin',
  'Asia/Tokyo',
  'Australia/Sydney',
] as const;

export function resolveTimezone(value: string): string {
  return value === LOCAL_TIMEZONE_VALUE ? Intl.DateTimeFormat().resolvedOptions().timeZone : value;
}

export function localTimezoneLabel(): string {
  return `Local (${Intl.DateTimeFormat().resolvedOptions().timeZone})`;
}

export function timezoneOptions(): SelectOption[] {
  return [
    { value: 'UTC', label: 'UTC' },
    { value: LOCAL_TIMEZONE_VALUE, label: localTimezoneLabel() },
    ...NAMED_TIMEZONES.map((tz) => ({ value: tz, label: tz })),
  ];
}

export const DEFAULT_TIMEZONE = 'UTC';

export const TIME_FORMAT_OPTIONS: SelectOption[] = [
  { value: 'YYYY-MM-DD HH:MM:SS.UUUUUU', label: 'YYYY-MM-DD HH:MM:SS.UUUUUU' },
  { value: 'HH:MM:SS.UUUUUU', label: 'HH:MM:SS.UUUUUU' },
  { value: 'HH:MM:SS', label: 'HH:MM:SS' },
  { value: 'YYYY-MM-DD HH:MM:SS', label: 'YYYY-MM-DD HH:MM:SS' },
];

export const DEFAULT_TIME_FORMAT = TIME_FORMAT_OPTIONS[0].value;

const LEADING_TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z/;

/**
 * Renders a UTC instant (as whole-second epoch ms + a separate 6-digit
 * microsecond string) into the requested timezone/format. Kept as two
 * inputs rather than one `Date` because `Date` only holds millisecond
 * precision - the microsecond fraction is carried through untouched since
 * a timezone conversion never changes the sub-second part, only the
 * calendar/clock fields.
 */
export function formatTimestamp(utcMs: number, micros: string, timezone: string, format: string): string {
  const resolvedTz = resolveTimezone(timezone);
  const date = new Date(utcMs);
  let y: string;
  let mo: string;
  let d: string;
  let h: string;
  let mi: string;
  let s: string;
  if (resolvedTz === 'UTC') {
    y = String(date.getUTCFullYear()).padStart(4, '0');
    mo = String(date.getUTCMonth() + 1).padStart(2, '0');
    d = String(date.getUTCDate()).padStart(2, '0');
    h = String(date.getUTCHours()).padStart(2, '0');
    mi = String(date.getUTCMinutes()).padStart(2, '0');
    s = String(date.getUTCSeconds()).padStart(2, '0');
  } else {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: resolvedTz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).formatToParts(date);
    const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? '00';
    y = get('year');
    mo = get('month');
    d = get('day');
    // Some engines render midnight as "24" under hour12:false; normalize.
    h = get('hour') === '24' ? '00' : get('hour');
    mi = get('minute');
    s = get('second');
  }
  const datePart = `${y}-${mo}-${d}`;
  const timePart = `${h}:${mi}:${s}.${micros}`;
  switch (format) {
    case 'HH:MM:SS.UUUUUU':
      return timePart;
    case 'HH:MM:SS':
      return `${h}:${mi}:${s}`;
    case 'YYYY-MM-DD HH:MM:SS':
      return `${datePart} ${h}:${mi}:${s}`;
    default:
      return `${datePart} ${timePart}`;
  }
}

/**
 * Splits a log line's leading RFC3339 timestamp token from the rest of the
 * line and reformats it. Returns `timestamp: null` unchanged for lines that
 * don't start with one (never throws on odd input).
 */
export function formatLogLine(
  line: string,
  timezone: string,
  format: string,
): { timestamp: string | null; rest: string } {
  const match = LEADING_TIMESTAMP_RE.exec(line);
  if (!match) return { timestamp: null, rest: line };
  const [, yStr, moStr, dStr, hStr, miStr, sStr, micros] = match;
  const rest = line.slice(match[0].length).replace(/^\s+/, '');
  const utcMs = Date.UTC(
    Number(yStr),
    Number(moStr) - 1,
    Number(dStr),
    Number(hStr),
    Number(miStr),
    Number(sStr),
  );
  return { timestamp: formatTimestamp(utcMs, micros, timezone, format), rest };
}

// ── Level / status highlighting ─────────────────────────────────────────────
// Two independent, non-overlapping things get colored in a line:
//  - tracing's level word (ERROR/WARN/DEBUG/TRACE - INFO is the common case
//    and stays uncolored to avoid visual noise)
//  - the structured request-log format's numeric HTTP status, e.g.
//    "S > 200 GET /flock ..." (see CLAUDE.md: "<code> <dir> <status> ...").
//    Every request-log line logs at tracing::info!, so the two never
//    collide within one line.

export type LineSegment = { text: string; className?: string };

const LEVEL_CLASS: Record<string, string> = {
  ERROR: 'text-red',
  WARN: 'text-yellow',
  WARNING: 'text-yellow',
  DEBUG: 'text-muted',
  TRACE: 'text-muted',
};

function statusClassName(status: string): string {
  const code = Number(status);
  if (code >= 500) return 'text-red';
  if (code >= 400) return 'text-yellow';
  if (code >= 200 && code < 300) return 'text-green';
  return 'text-blue'; // 1xx/3xx
}

// `status` only matches the 3 digits, via a lookbehind on the "<code> <dir> "
// prefix - so just the status number gets colored, not the whole triplet.
// Code letters: S=Shepherd, C=Corgi, F=outbound client call, V=Vigil (see
// CLAUDE.md), plus D=dashboard BFF (server/logging.ts - not yet in that table).
const HIGHLIGHT_RE =
  /\b(?<level>ERROR|WARN|WARNING|DEBUG|TRACE)\b|(?<=\b[SCFVD] [<>] )(?<status>\d{3})\b/g;

/**
 * Splits a line into segments so the renderer can color a level keyword and/or
 * a structured-request-log status code. Lines with neither - most lines -
 * come back as a single unstyled segment.
 */
export function highlightLevel(text: string): LineSegment[] {
  const segments: LineSegment[] = [];
  let lastIndex = 0;
  for (const match of text.matchAll(HIGHLIGHT_RE)) {
    const idx = match.index;
    if (idx > lastIndex) segments.push({ text: text.slice(lastIndex, idx) });
    const word = match[0];
    const className = match.groups?.level ? LEVEL_CLASS[match.groups.level] : statusClassName(word);
    segments.push({ text: word, className });
    lastIndex = idx + word.length;
  }
  if (lastIndex < text.length) segments.push({ text: text.slice(lastIndex) });
  return segments.length > 0 ? segments : [{ text }];
}

function buildQuery(params: LogsParams): string {
  const qs = new URLSearchParams();
  qs.set('source', params.source);
  if (params.last) qs.set('last', params.last);
  if (params.since) qs.set('since', params.since);
  if (params.until) qs.set('until', params.until);
  if (params.level) qs.set('level', params.level);
  if (params.q) qs.set('q', params.q);
  if (params.limit !== undefined) qs.set('limit', String(params.limit));
  return qs.toString();
}

export function logsUrl(params: LogsParams): string {
  return `/api/logs?${buildQuery(params)}`;
}

export function logsStreamUrl(params: LogsParams): string {
  return `/api/logs/stream?${buildQuery(params)}`;
}

/** The three fixed sources, then one entry per corgi, sorted by name. */
export function sourceOptionsFromFlock(corgis: Array<{ name: string }>): string[] {
  const corgiSources = corgis
    .map((c) => c.name)
    .sort((a, b) => a.localeCompare(b))
    .map((name) => `corgi:${name}`);
  return ['dashboard', 'shepherd', 'vigil', ...corgiSources];
}

/**
 * Parses one SSE data payload in the wire shape every source emits
 * ({"line": ..., "source": ...} - credo-lib's build_sse_event and the
 * BFF's sseFrame). Returns null for anything malformed - a bad frame
 * must never throw inside an EventSource onmessage handler.
 */
export function parseSseEvent(data: string): { line: string; source: string } | null {
  try {
    const parsed: unknown = JSON.parse(data);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      typeof (parsed as { line?: unknown }).line === 'string' &&
      typeof (parsed as { source?: unknown }).source === 'string'
    ) {
      return { line: (parsed as { line: string }).line, source: (parsed as { source: string }).source };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Appends keeping at most `max` lines, dropping the oldest first. Generic
 * so the page can buffer `{id, text}` entries - stable ids matter for
 * React keys: with index keys, every drop-from-the-front at the cap would
 * shift all indices and force React to re-diff the entire viewer per
 * incoming line.
 */
export function appendLines<T>(existing: T[], incoming: T[], max = LOG_BUFFER_MAX): T[] {
  const combined = existing.concat(incoming);
  return combined.length > max ? combined.slice(-max) : combined;
}

/**
 * Params for reopening a dropped live stream: same source and filters,
 * window trimmed to the last 30 seconds. Reopening with the ORIGINAL
 * window would re-replay the full historical backlog into the viewer on
 * every network blip - the reason the page manages reconnection manually
 * instead of letting EventSource's built-in auto-reconnect reuse the URL.
 */
export function reconnectParams(params: LogsParams): LogsParams {
  const { since: _since, until: _until, ...rest } = params;
  return { ...rest, last: '30s' };
}

/** datetime-local input value -> RFC 3339 UTC instant, or undefined. */
export function localInputToRfc3339(value: string): string | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/**
 * Whether the viewer is scrolled to (or within `slackPx` of) the bottom -
 * the autoscroll-on-new-lines condition. Scrolling up past the slack
 * pauses autoscroll so the user can read history while the tail runs.
 */
export function isPinnedToBottom(
  scrollTop: number,
  scrollHeight: number,
  clientHeight: number,
  slackPx = 40,
): boolean {
  return scrollHeight - (scrollTop + clientHeight) <= slackPx;
}
