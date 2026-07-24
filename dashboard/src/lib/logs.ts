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
