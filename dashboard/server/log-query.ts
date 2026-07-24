import fs from 'fs';
import path from 'path';

/**
 * Node-side mirror of credo-lib's log_query filter/historical modules
 * (credo-lib/src/log_query/{filter,historical,follow}.rs). Semantics are
 * intentionally identical - same inputs keep the same lines - so the
 * dashboard's own logs filter exactly like shepherd/corgi/vigil's when a
 * user flips between sources in the UI.
 */

export type LogQueryParams = {
  since?: string;
  until?: string;
  last?: string;
  level?: string;
  q?: string;
  limit?: number;
};

/** Cap on returned lines when `limit` isn't specified. */
export const DEFAULT_LOG_LIMIT = 5000;

/** How many recent historical lines count as "the tail" for deduping. */
export const DEDUP_TAIL_WINDOW = 50;

// new Date() accepts far too much ("2024", "2024-01-15"); require a full
// RFC 3339 timestamp like chrono's parse_from_rfc3339 does on the Rust
// side - including the forms chrono documents beyond the uppercase-only
// common case: 't' or ' ' as the date/time separator and 'z' for Zulu.
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

export function parseRfc3339(s: string): Date | null {
  const trimmed = s.trim();
  if (!RFC3339.test(trimmed)) return null;
  // new Date() itself only accepts the uppercase-T ISO form; normalize the
  // separator (Date handles lowercase 'z' fine, but not ' ' or 't').
  const d = new Date(trimmed[10] === 'T' ? trimmed : `${trimmed.slice(0, 10)}T${trimmed.slice(11)}`);
  return Number.isNaN(d.getTime()) ? null : d;
}

// JS Date's representable range is +/-8.64e15 ms from the epoch; any
// `last` window larger than that could never produce a valid `since`.
const MAX_DURATION_MS = 8.64e15;

/**
 * Duration shorthand (digits + s/m/h/d) in milliseconds, or null. Rejects
 * oversized values outright - mirroring chrono's try_seconds/etc. returning
 * None on overflow - so an absurd `last=999999999999999d` falls back to an
 * unbounded window instead of poisoning it with an Invalid Date, which
 * would flip the fail-closed timestamp check to excluding everything.
 */
export function parseLastDuration(s: string): number | null {
  const m = /^(\d+)([smhd])$/.exec(s.trim());
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unitMs = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as 's' | 'm' | 'h' | 'd'];
  const ms = n * unitMs;
  return ms > MAX_DURATION_MS ? null : ms;
}

/** `last`, when present and valid, overrides `since`/`until`. */
export function resolveWindow(
  params: LogQueryParams,
  now: Date,
): { since: Date | null; until: Date | null } {
  const lastMs = params.last !== undefined ? parseLastDuration(params.last) : null;
  if (lastMs !== null) {
    return { since: new Date(now.getTime() - lastMs), until: now };
  }
  return {
    since: params.since !== undefined ? parseRfc3339(params.since) : null,
    until: params.until !== undefined ? parseRfc3339(params.until) : null,
  };
}

/** The credo one-line format always starts with the timestamp. */
export function lineTimestamp(line: string): Date | null {
  const first = line.split(/\s+/)[0];
  return first ? parseRfc3339(first) : null;
}

/**
 * Inclusive window check. A line with no parseable timestamp only matches
 * when the window is fully unbounded (fails closed once any bound is set).
 */
export function lineInWindow(line: string, since: Date | null, until: Date | null): boolean {
  if (since === null && until === null) return true;
  const ts = lineTimestamp(line);
  if (ts === null) return false;
  if (since !== null && ts < since) return false;
  if (until !== null && ts > until) return false;
  return true;
}

const LINE_RANKS: Record<string, number> = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3, TRACE: 4 };

function lineLevelRank(line: string): number | null {
  for (const tok of line.split(/\s+/)) {
    const rank = LINE_RANKS[tok];
    if (rank !== undefined) return rank;
  }
  return null;
}

/**
 * Minimum severity rank for a `level` query value. Same vocabulary as the
 * Rust side's parse_level_filter: error/fatal -> 0, warn -> 1, debug -> 3,
 * anything else (including "info" and unrecognized strings) -> 2.
 */
export function parseLevelFilter(s: string): number {
  switch (s.trim().toLowerCase()) {
    case 'error':
    case 'fatal':
      return 0;
    case 'warn':
      return 1;
    case 'debug':
      return 3;
    default:
      return 2;
  }
}

/** Level (minimum severity) + case-insensitive substring filter. */
export function linePassesFilter(line: string, minRank: number | null, q: string | null): boolean {
  if (minRank !== null) {
    const rank = lineLevelRank(line);
    if (rank === null || rank > minRank) return false;
  }
  if (q !== null && q !== '' && !line.toLowerCase().includes(q.toLowerCase())) return false;
  return true;
}

/**
 * This basename's log files in chronological order: rotated backups oldest
 * (highest N) first, current file last. Missing directory -> empty list.
 */
export function historicalFilePaths(dir: string, basename: string): string[] {
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const rotated: Array<{ n: number; p: string }> = [];
  const prefix = `${basename}.`;
  for (const name of names) {
    if (!name.startsWith(prefix) || !name.endsWith('.log')) continue;
    const middle = name.slice(prefix.length, -'.log'.length);
    if (!/^\d+$/.test(middle)) continue;
    rotated.push({ n: Number(middle), p: path.join(dir, name) });
  }
  rotated.sort((a, b) => b.n - a.n); // oldest (highest N) first
  const paths = rotated.map((r) => r.p);
  const current = path.join(dir, `${basename}.log`);
  if (fs.existsSync(current)) paths.push(current);
  return paths;
}

/**
 * Matching lines across all of this basename's files (oldest to newest),
 * keeping at most the most recent `limit` matches. Files that vanish
 * between listing and reading are skipped, not fatal - the log dir is
 * actively written and rotated concurrently with queries.
 */
export function readHistoricalLines(
  dir: string,
  basename: string,
  params: LogQueryParams,
  now: Date,
): string[] {
  const { since, until } = resolveWindow(params, now);
  const minRank = params.level !== undefined ? parseLevelFilter(params.level) : null;
  const q = params.q ?? null;
  // NaN or non-finite limits fall back to the default rather than turning
  // slice(-NaN) into a no-op; zero/negative clamp to 1 like Rust's .max(1).
  const limitRaw = params.limit ?? DEFAULT_LOG_LIMIT;
  const limit = Number.isFinite(limitRaw) ? Math.max(Math.floor(limitRaw), 1) : DEFAULT_LOG_LIMIT;

  let kept: string[] = [];
  for (const p of historicalFilePaths(dir, basename)) {
    let contents: string;
    try {
      contents = fs.readFileSync(p, 'utf8');
    } catch {
      continue;
    }
    for (const line of contents.split('\n')) {
      if (line === '') continue;
      if (!lineInWindow(line, since, until)) continue;
      if (!linePassesFilter(line, minRank, q)) continue;
      kept.push(line);
    }
    // Re-cap after each file so accumulation across files stays bounded
    // by limit. (Within a single file, matches are buffered in full
    // before this trim - a looser bound than the Rust side's per-line
    // VecDeque eviction, but the returned lines are identical.)
    if (kept.length > limit) kept = kept.slice(-limit);
  }
  return kept;
}

/**
 * Drops buffered live lines that exactly match one of the last
 * `tailWindow` historical lines - a line seen both on disk and on the
 * live broadcast in the same narrow window is far more likely
 * double-counted than a real repeat. Order preserved; heuristic, same as
 * the Rust side's dedup_buffered_against_tail.
 */
export function dedupBufferedAgainstTail(
  historical: string[],
  buffered: string[],
  tailWindow: number,
): string[] {
  // Guard tailWindow <= 0 explicitly: slice(-0) is slice(0) in JS (the
  // WHOLE array), which would silently invert "check nothing" into
  // "check everything" - Rust's .rev().take(0) correctly yields nothing.
  const recent = tailWindow > 0 ? new Set(historical.slice(-tailWindow)) : new Set<string>();
  return buffered.filter((line) => !recent.has(line));
}
