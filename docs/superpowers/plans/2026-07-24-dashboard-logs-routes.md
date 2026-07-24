# Dashboard BFF Log Routes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GET /api/logs` (historical JSON) and `GET /api/logs/stream` (live-tail SSE) to the dashboard BFF, completing Phase 4 of `docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`. `source=dashboard` serves the BFF's own logs from the `LoggingHandle` foundation merged in the previous slice; `source=shepherd|vigil|corgi:<name>` proxies to shepherd's `GET /admin/logs` (which itself proxies onward to vigil/corgi — all already shipped on the Rust side).

**Architecture:** Three pieces. (1) `dashboard/server/log-query.ts`: pure functions mirroring `credo-lib/src/log_query/filter.rs` + `historical.rs` + the dedup helper from `follow.rs` — window resolution (`last` overrides `since`/`until`), fail-closed timestamp filtering, level-rank filtering (`ERROR`=0 … `TRACE`=4, include when rank ≤ min), case-insensitive substring, chronological multi-file reads capped at the most recent `limit` matches. The line format compatibility is already guaranteed: the BFF's request-log middleware emits `<ISO8601> INFO D > …` lines whose first token parses as RFC 3339 and whose level is a standalone token, exactly what these filters key on. (2) `dashboard/server/routes-logs.ts`: an Express `Router` factory `createLogsRouter({ handle, shepherdApi })` — dependency-injected so tests mount it on a bare Express app with a mock upstream, no BFF `main()` or session machinery needed. (3) SSE: `source=dashboard` builds replay-then-continue exactly like `credo-lib`'s `build_follow_stream` (subscribe **before** reading the backlog, buffer, replay, dedup buffered lines against the backlog's last 50, then live), emitting the identical wire shape (`data: {"line":"...","source":"dashboard"}\n\n` + periodic comment keep-alives) so Phase 5's frontend parses one format everywhere; proxied sources pipe shepherd's SSE bytes through **verbatim** (never re-framed — same invariant as every other hop in this feature) with a per-request axios `timeout: 0` override and an `AbortController` wired to the client request's `'close'` event so a closed browser tab can't leak an upstream connection (this codebase has no long-lived request today, so nothing else guards this).

**Tech Stack:** TypeScript/Node, Express (existing), axios (existing, `responseType: 'stream'`), Vitest (existing). No new npm dependencies.

## Global Constraints

- Touches only: `dashboard/server/log-query.ts` (new), `log-query.test.ts` (new), `routes-logs.ts` (new), `routes-logs.test.ts` (new), `index.ts`, and `dashboard/docs/config.md` (one sentence).
- No new npm dependencies.
- `npm run typecheck` and `npm test` (from `dashboard/`) must both pass cleanly — the repo's pre-commit gates for dashboard changes.
- No placeholder/TODO code. Every function fully implemented and covered by a test in the same task.
- Filter semantics must match `credo-lib/src/log_query/` exactly (same inputs → same lines kept): `last` shorthand `<digits><s|m|h|d>` overriding `since`/`until`; lines with no parseable leading timestamp fail closed once any window bound is set; level vocabulary `error|fatal→0, warn→1, debug→3, anything else→2 (info)`; line ranks `ERROR 0, WARN 1, INFO 2, DEBUG 3, TRACE 4` from the first matching whitespace token; `q` case-insensitive substring; default limit 5000 keeping the **most recent** matches; dedup tail window 50, exact-match drop, order preserved.
- SSE wire shape for `source=dashboard` must be byte-compatible with what `credo-lib`'s `follow_logs` emits: each event is one `data: <json>\n\n` frame whose JSON is `{"line": <line>, "source": <basename>}`; comment frames (lines starting `:`) are keep-alives clients ignore.
- Proxied SSE is verbatim byte passthrough of shepherd's response — never parsed and re-framed at the BFF hop.
- The routes must be reachable only through the existing `/api` auth stack (session + role refresh + shepherd-token middleware) — mount the router under `/api/logs` in `index.ts` *after* those `app.use('/api', ...)` calls, alongside the existing routes. No auth logic inside the router itself (shepherd additionally enforces Readonly+ on its end for proxied sources).
- Upstream (axios) errors on the buffered JSON route propagate through the existing app-level error handler (`normalizeError` preserves upstream status codes) — throw/reject, don't hand-roll error JSON in the router.

---

### Task 1: `log-query.ts` — pure filter/window/read functions

**Files:**
- Create: `dashboard/server/log-query.ts`
- Create: `dashboard/server/log-query.test.ts`

**Interfaces:**
- Produces (used by Task 2/3): `type LogQueryParams = { since?: string; until?: string; last?: string; level?: string; q?: string; limit?: number }`, `DEFAULT_LOG_LIMIT = 5000`, `DEDUP_TAIL_WINDOW = 50`, `parseRfc3339(s: string): Date | null`, `parseLastDuration(s: string): number | null` (milliseconds), `resolveWindow(params: LogQueryParams, now: Date): { since: Date | null; until: Date | null }`, `lineTimestamp(line: string): Date | null`, `lineInWindow(line: string, since: Date | null, until: Date | null): boolean`, `parseLevelFilter(s: string): number` (minimum rank), `linePassesFilter(line: string, minRank: number | null, q: string | null): boolean`, `historicalFilePaths(dir: string, basename: string): string[]`, `readHistoricalLines(dir: string, basename: string, params: LogQueryParams, now: Date): string[]`, `dedupBufferedAgainstTail(historical: string[], buffered: string[], tailWindow: number): string[]`.

- [ ] **Step 1: Write the failing tests**

Create `dashboard/server/log-query.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  parseRfc3339,
  parseLastDuration,
  resolveWindow,
  lineTimestamp,
  lineInWindow,
  parseLevelFilter,
  linePassesFilter,
  historicalFilePaths,
  readHistoricalLines,
  dedupBufferedAgainstTail,
  DEFAULT_LOG_LIMIT,
} from './log-query';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-log-query-test-'));
}

const NOW = new Date('2024-01-15T12:00:00Z');

describe('parseRfc3339', () => {
  it('accepts full RFC 3339 timestamps and rejects everything else', () => {
    expect(parseRfc3339('2024-01-15T10:00:00Z')?.toISOString()).toBe('2024-01-15T10:00:00.000Z');
    expect(parseRfc3339('2024-01-15T10:00:00.123Z')?.toISOString()).toBe('2024-01-15T10:00:00.123Z');
    expect(parseRfc3339('2024-01-15T10:00:00+02:00')?.toISOString()).toBe('2024-01-15T08:00:00.000Z');
    // new Date() alone would accept these; the parser must not.
    expect(parseRfc3339('2024')).toBeNull();
    expect(parseRfc3339('2024-01-15')).toBeNull();
    expect(parseRfc3339('not-a-timestamp')).toBeNull();
    expect(parseRfc3339('')).toBeNull();
  });
});

describe('parseLastDuration', () => {
  it('parses digit+unit shorthands into milliseconds', () => {
    expect(parseLastDuration('30s')).toBe(30_000);
    expect(parseLastDuration('5m')).toBe(300_000);
    expect(parseLastDuration('2h')).toBe(7_200_000);
    expect(parseLastDuration('1d')).toBe(86_400_000);
  });

  it('rejects empty, unitless, non-numeric, zero, and negative input', () => {
    expect(parseLastDuration('')).toBeNull();
    expect(parseLastDuration('5')).toBeNull();
    expect(parseLastDuration('m')).toBeNull();
    expect(parseLastDuration('xm')).toBeNull();
    expect(parseLastDuration('0m')).toBeNull();
    expect(parseLastDuration('-5m')).toBeNull();
    expect(parseLastDuration('5w')).toBeNull();
  });
});

describe('resolveWindow', () => {
  it('last overrides since/until when valid', () => {
    const w = resolveWindow({ last: '1h', since: '2020-01-01T00:00:00Z' }, NOW);
    expect(w.since?.toISOString()).toBe('2024-01-15T11:00:00.000Z');
    expect(w.until?.toISOString()).toBe(NOW.toISOString());
  });

  it('falls back to since/until when last is absent or invalid', () => {
    const w = resolveWindow({ last: 'bogus', since: '2024-01-15T10:00:00Z' }, NOW);
    expect(w.since?.toISOString()).toBe('2024-01-15T10:00:00.000Z');
    expect(w.until).toBeNull();
  });

  it('is fully unbounded when nothing is set', () => {
    expect(resolveWindow({}, NOW)).toEqual({ since: null, until: null });
  });
});

describe('lineInWindow', () => {
  const line = '2024-01-15T10:00:00Z INFO D > 200 GET /api/flock host ip alice 1.00';

  it('always passes when the window is fully unbounded', () => {
    expect(lineInWindow('no timestamp here', null, null)).toBe(true);
  });

  it('fails closed for unparseable timestamps once any bound is set', () => {
    expect(lineInWindow('no timestamp here', new Date('2024-01-15T09:00:00Z'), null)).toBe(false);
  });

  it('applies both bounds inclusively', () => {
    expect(lineInWindow(line, new Date('2024-01-15T10:00:00Z'), new Date('2024-01-15T10:00:00Z'))).toBe(true);
    expect(lineInWindow(line, new Date('2024-01-15T10:00:01Z'), null)).toBe(false);
    expect(lineInWindow(line, null, new Date('2024-01-15T09:59:59Z'))).toBe(false);
  });
});

describe('level filtering', () => {
  it('parseLevelFilter maps the shared vocabulary onto minimum ranks', () => {
    expect(parseLevelFilter('error')).toBe(0);
    expect(parseLevelFilter('fatal')).toBe(0);
    expect(parseLevelFilter('WARN')).toBe(1);
    expect(parseLevelFilter('debug')).toBe(3);
    expect(parseLevelFilter('info')).toBe(2);
    expect(parseLevelFilter('anything-else')).toBe(2);
  });

  it('linePassesFilter includes lines at or above the minimum severity', () => {
    const err = '2024-01-15T10:00:00Z ERROR something failed';
    const info = '2024-01-15T10:00:00Z INFO all fine';
    const debug = '2024-01-15T10:00:00Z DEBUG details';
    expect(linePassesFilter(err, 0, null)).toBe(true);
    expect(linePassesFilter(info, 0, null)).toBe(false);
    expect(linePassesFilter(info, 2, null)).toBe(true);
    expect(linePassesFilter(debug, 2, null)).toBe(false);
    // No recognizable level token -> excluded once a level filter is set.
    expect(linePassesFilter('no level token', 2, null)).toBe(false);
    // No level filter -> level is ignored entirely.
    expect(linePassesFilter('no level token', null, null)).toBe(true);
  });

  it('linePassesFilter applies q as a case-insensitive substring', () => {
    const line = '2024-01-15T10:00:00Z INFO GET /api/Flock done';
    expect(linePassesFilter(line, null, 'flock')).toBe(true);
    expect(linePassesFilter(line, null, 'FLOCK')).toBe(true);
    expect(linePassesFilter(line, null, 'missing')).toBe(false);
    expect(linePassesFilter(line, null, '')).toBe(true);
  });
});

describe('historicalFilePaths', () => {
  it('returns rotated files oldest-first, then the current file, skipping unrelated names', () => {
    const dir = tmpDir();
    for (const name of ['dashboard.log', 'dashboard.1.log', 'dashboard.2.log', 'other.log', 'dashboard.x.log']) {
      fs.writeFileSync(path.join(dir, name), '');
    }
    expect(historicalFilePaths(dir, 'dashboard')).toEqual([
      path.join(dir, 'dashboard.2.log'),
      path.join(dir, 'dashboard.1.log'),
      path.join(dir, 'dashboard.log'),
    ]);
  });

  it('returns an empty list for a missing directory', () => {
    expect(historicalFilePaths(path.join(os.tmpdir(), 'nope-does-not-exist'), 'dashboard')).toEqual([]);
  });
});

describe('readHistoricalLines', () => {
  it('reads across rotated + current files in order, applying window, level, and q filters', () => {
    const dir = tmpDir();
    fs.writeFileSync(
      path.join(dir, 'dashboard.1.log'),
      '2024-01-15T09:00:00Z INFO old line\n2024-01-15T10:30:00Z ERROR rotated error\n',
    );
    fs.writeFileSync(
      path.join(dir, 'dashboard.log'),
      '2024-01-15T11:00:00Z INFO current line\n2024-01-15T11:30:00Z DEBUG noisy detail\n',
    );

    expect(readHistoricalLines(dir, 'dashboard', { last: '2h' }, NOW)).toEqual([
      '2024-01-15T10:30:00Z ERROR rotated error',
      '2024-01-15T11:00:00Z INFO current line',
      '2024-01-15T11:30:00Z DEBUG noisy detail',
    ]);
    expect(readHistoricalLines(dir, 'dashboard', { level: 'error' }, NOW)).toEqual([
      '2024-01-15T10:30:00Z ERROR rotated error',
    ]);
    expect(readHistoricalLines(dir, 'dashboard', { q: 'CURRENT' }, NOW)).toEqual([
      '2024-01-15T11:00:00Z INFO current line',
    ]);
  });

  it('caps at the most recent limit matches', () => {
    const dir = tmpDir();
    const lines = Array.from({ length: 10 }, (_, i) => `2024-01-15T10:00:0${i}Z INFO line ${i}`);
    fs.writeFileSync(path.join(dir, 'dashboard.log'), lines.join('\n') + '\n');

    expect(readHistoricalLines(dir, 'dashboard', { limit: 3 }, NOW)).toEqual([
      '2024-01-15T10:00:07Z INFO line 7',
      '2024-01-15T10:00:08Z INFO line 8',
      '2024-01-15T10:00:09Z INFO line 9',
    ]);
  });

  it('defaults the cap to DEFAULT_LOG_LIMIT', () => {
    expect(DEFAULT_LOG_LIMIT).toBe(5000);
  });
});

describe('dedupBufferedAgainstTail', () => {
  it('drops exact matches against the historical tail, preserving order', () => {
    const historical = ['a', 'b', 'c'];
    expect(dedupBufferedAgainstTail(historical, ['c', 'd'], 50)).toEqual(['d']);
  });

  it('only checks the last tailWindow historical lines', () => {
    const historical = ['a', 'b', 'c'];
    expect(dedupBufferedAgainstTail(historical, ['a'], 1)).toEqual(['a']);
    expect(dedupBufferedAgainstTail(historical, ['c'], 1)).toEqual([]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run server/log-query.test.ts`
Expected: FAIL — `Cannot find module './log-query'`.

- [ ] **Step 3: Implement `dashboard/server/log-query.ts`**

```typescript
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
// RFC 3339 timestamp like chrono's parse_from_rfc3339 does on the Rust side.
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export function parseRfc3339(s: string): Date | null {
  const trimmed = s.trim();
  if (!RFC3339.test(trimmed)) return null;
  const d = new Date(trimmed);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Duration shorthand (digits + s/m/h/d) in milliseconds, or null. */
export function parseLastDuration(s: string): number | null {
  const m = /^(\d+)([smhd])$/.exec(s.trim());
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unitMs = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as 's' | 'm' | 'h' | 'd'];
  return n * unitMs;
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
  const limit = Math.max(params.limit ?? DEFAULT_LOG_LIMIT, 1);

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
    // Re-cap after each file so memory stays bounded by limit, not by
    // total matching volume on disk.
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
  const recent = new Set(historical.slice(-tailWindow));
  return buffered.filter((line) => !recent.has(line));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd dashboard && npx vitest run server/log-query.test.ts`
Expected: all tests pass.

- [ ] **Step 5: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add dashboard/server/log-query.ts dashboard/server/log-query.test.ts
git commit -m "$(cat <<'EOF'
feat(dashboard): add log-query, a Node mirror of credo-lib's log filters

Pure window/level/text filtering and multi-file historical reads with
semantics deliberately identical to credo-lib/src/log_query (same
inputs keep the same lines), so the dashboard's own logs behave
exactly like shepherd/corgi/vigil's when the UI flips between sources:
last-shorthand overriding since/until, fail-closed timestamp
filtering, error/fatal->0 warn->1 debug->3 else-info level vocabulary,
most-recent-limit capping, and the same 50-line dedup heuristic for
the replay/live seam.

Nothing calls this yet - the /api/logs routes land next.
EOF
)"
```

---

### Task 2: `routes-logs.ts` — router factory + historical JSON route

**Files:**
- Create: `dashboard/server/routes-logs.ts`
- Create: `dashboard/server/routes-logs.test.ts`
- Modify: `dashboard/server/index.ts`

**Interfaces:**
- Consumes (Task 1): `readHistoricalLines`, `LogQueryParams`. Consumes (previous slice): `LoggingHandle` (`isEnabled()`, `logDir()`, `logBasename()`).
- Produces: `createLogsRouter(deps: { handle: LoggingHandle; shepherdApi: AxiosInstance }): express.Router` with `GET /` (this task) and `GET /stream` (Task 3).

- [ ] **Step 1: Write the failing tests**

Create `dashboard/server/routes-logs.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import express from 'express';
import axios, { isAxiosError } from 'axios';
import { LoggingHandle } from './logging';
import { createLogsRouter } from './routes-logs';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-routes-logs-test-'));
}

/**
 * Boots a bare Express app with the logs router mounted at /api/logs (no
 * session/auth stack - the router itself is auth-agnostic by design) plus
 * the same error-shape the real BFF's app-level handler produces for
 * upstream failures, and a mock shepherd standing in for /admin/logs.
 */
async function startServers(handle: LoggingHandle, mockShepherd: express.Express) {
  const upstream = http.createServer(mockShepherd);
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;

  const shepherdApi = axios.create({ baseURL: `http://127.0.0.1:${upstreamPort}` });
  const app = express();
  app.use('/api/logs', createLogsRouter({ handle, shepherdApi }));
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = isAxiosError(err) && typeof err.response?.status === 'number' ? err.response.status : 500;
    res.status(status).json({ error: 'proxied failure' });
  });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;

  return {
    base: `http://127.0.0.1:${port}`,
    close: async () => {
      await new Promise((r) => server.close(r));
      await new Promise((r) => upstream.close(r));
    },
  };
}

describe('GET /api/logs', () => {
  describe('source=dashboard', () => {
    it('serves filtered lines from the local log files', async () => {
      const dir = tmpDir();
      fs.writeFileSync(
        path.join(dir, 'dashboard.log'),
        '2024-01-15T10:00:00Z INFO D > 200 GET /api/flock h ip alice 1.00\n' +
          '2024-01-15T10:00:01Z INFO D > 500 GET /api/certs h ip bob 2.00\n',
      );
      const handle = LoggingHandle.init(
        { enabled: true, dir, rotateOn: { sizeMb: 100, keepFiles: 12 }, alsoStdout: false },
        'dashboard',
      );
      const servers = await startServers(handle, express());

      const all = await axios.get(`${servers.base}/api/logs?source=dashboard`);
      expect(all.data).toHaveLength(2);
      const filtered = await axios.get(`${servers.base}/api/logs?source=dashboard&q=flock`);
      expect(filtered.data).toEqual([
        '2024-01-15T10:00:00Z INFO D > 200 GET /api/flock h ip alice 1.00',
      ]);

      await servers.close();
    });

    it('returns 400 when file logging is not enabled', async () => {
      const servers = await startServers(LoggingHandle.disabled(), express());
      const resp = await axios.get(`${servers.base}/api/logs?source=dashboard`, { validateStatus: () => true });
      expect(resp.status).toBe(400);
      expect(resp.data.error).toContain('not enabled');
      await servers.close();
    });

    it('defaults source to dashboard when omitted', async () => {
      const servers = await startServers(LoggingHandle.disabled(), express());
      const resp = await axios.get(`${servers.base}/api/logs`, { validateStatus: () => true });
      expect(resp.status).toBe(400); // reached the dashboard branch, which rejects (disabled)
      await servers.close();
    });
  });

  describe('proxied sources', () => {
    it('maps source to target and forwards the filter params to shepherd', async () => {
      const mock = express();
      let seenQuery: Record<string, unknown> = {};
      mock.get('/admin/logs', (req, res) => {
        seenQuery = req.query;
        res.json(['upstream line 1', 'upstream line 2']);
      });
      const servers = await startServers(LoggingHandle.disabled(), mock);

      const resp = await axios.get(
        `${servers.base}/api/logs?source=corgi:web-1&last=5m&level=error&q=tls&limit=100`,
      );
      expect(resp.data).toEqual(['upstream line 1', 'upstream line 2']);
      expect(seenQuery).toEqual({ target: 'corgi:web-1', last: '5m', level: 'error', q: 'tls', limit: '100' });

      await servers.close();
    });

    it('propagates upstream error statuses through the error middleware', async () => {
      const mock = express();
      mock.get('/admin/logs', (_req, res) => {
        res.status(404).json({ error: "Corgi 'nope' not found" });
      });
      const servers = await startServers(LoggingHandle.disabled(), mock);

      const resp = await axios.get(`${servers.base}/api/logs?source=corgi:nope`, { validateStatus: () => true });
      expect(resp.status).toBe(404);

      await servers.close();
    });
  });

  it('rejects an unknown source with 400', async () => {
    const servers = await startServers(LoggingHandle.disabled(), express());
    const resp = await axios.get(`${servers.base}/api/logs?source=bogus`, { validateStatus: () => true });
    expect(resp.status).toBe(400);
    expect(resp.data.error).toContain('unknown source');
    await servers.close();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run server/routes-logs.test.ts`
Expected: FAIL — `Cannot find module './routes-logs'`.

- [ ] **Step 3: Implement `dashboard/server/routes-logs.ts` (JSON route only) and mount it**

Create `dashboard/server/routes-logs.ts`:

```typescript
import express, { NextFunction, Request, Response, Router } from 'express';
import type { AxiosInstance } from 'axios';
import { LoggingHandle } from './logging';
import { readHistoricalLines, type LogQueryParams } from './log-query';

type LogsRouterDeps = {
  handle: LoggingHandle;
  shepherdApi: AxiosInstance;
};

function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };
}

function queryString(req: Request, key: string): string | undefined {
  const v = req.query[key];
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/** The filter params shared by both routes, straight off the query string. */
function filterParams(req: Request): LogQueryParams {
  const limitRaw = queryString(req, 'limit');
  const limit = limitRaw !== undefined ? Number(limitRaw) : undefined;
  return {
    since: queryString(req, 'since'),
    until: queryString(req, 'until'),
    last: queryString(req, 'last'),
    level: queryString(req, 'level'),
    q: queryString(req, 'q'),
    limit: limit !== undefined && Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : undefined,
  };
}

/** The same params as an object to forward on a proxied shepherd request. */
function forwardParams(params: LogQueryParams): Record<string, string> {
  const out: Record<string, string> = {};
  if (params.since !== undefined) out.since = params.since;
  if (params.until !== undefined) out.until = params.until;
  if (params.last !== undefined) out.last = params.last;
  if (params.level !== undefined) out.level = params.level;
  if (params.q !== undefined) out.q = params.q;
  if (params.limit !== undefined) out.limit = String(params.limit);
  return out;
}

/**
 * source=dashboard (default) is served locally; shepherd/vigil/corgi:<name>
 * map 1:1 onto shepherd's /admin/logs target param (shepherd proxies
 * onward to vigil/corgi itself). Anything else -> null.
 */
function resolveSource(req: Request): { kind: 'dashboard' } | { kind: 'proxy'; target: string } | null {
  const source = queryString(req, 'source') ?? 'dashboard';
  if (source === 'dashboard') return { kind: 'dashboard' };
  if (source === 'shepherd' || source === 'vigil' || source.startsWith('corgi:')) {
    return { kind: 'proxy', target: source };
  }
  return null;
}

/**
 * GET /        - historical JSON (array of raw log lines)
 * GET /stream  - live tail as SSE (added in the next task)
 *
 * Auth-agnostic by design: mounted under /api in index.ts, so the existing
 * session/role/token middlewares run first; shepherd additionally enforces
 * Readonly+ on its end for proxied sources.
 */
export function createLogsRouter(deps: LogsRouterDeps): Router {
  const router = express.Router();

  router.get(
    '/',
    asyncHandler(async (req: Request, res: Response) => {
      const source = resolveSource(req);
      if (source === null) {
        res.status(400).json({ error: `unknown source '${String(req.query.source)}'` });
        return;
      }
      const params = filterParams(req);

      if (source.kind === 'dashboard') {
        const dir = deps.handle.logDir();
        const basename = deps.handle.logBasename();
        if (!deps.handle.isEnabled()) {
          res.status(400).json({ error: 'file logging is not enabled' });
          return;
        }
        res.json(readHistoricalLines(dir, basename, params, new Date()));
        return;
      }

      const response = await deps.shepherdApi.get('/admin/logs', {
        params: { target: source.target, ...forwardParams(params) },
      });
      res.json(response.data);
    }),
  );

  return router;
}
```

In `dashboard/server/index.ts`, mount the router. Add the import:

```typescript
import { LoggingHandle, createRequestLogMiddleware } from './logging';
```

becomes:

```typescript
import { LoggingHandle, createRequestLogMiddleware } from './logging';
import { createLogsRouter } from './routes-logs';
```

Mount it alongside the existing `/api` routes. Change:

```typescript
  app.get('/api/flock', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/flock');
    res.json(response.data);
  }));
```

to:

```typescript
  app.get('/api/flock', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/flock');
    res.json(response.data);
  }));

  // On-demand log retrieval: source=dashboard is served locally from
  // loggingHandle; other sources proxy through shepherd's /admin/logs.
  app.use('/api/logs', createLogsRouter({ handle: loggingHandle, shepherdApi: clients.api }));
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd dashboard && npx vitest run server/routes-logs.test.ts`
Expected: all tests pass.

- [ ] **Step 5: Full suite and typecheck**

Run: `cd dashboard && npm test && npm run typecheck`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add dashboard/server/routes-logs.ts dashboard/server/routes-logs.test.ts dashboard/server/index.ts
git commit -m "$(cat <<'EOF'
feat(dashboard): add GET /api/logs - local historical + shepherd proxy

source=dashboard (the default) reads the BFF's own rotating log files
through the log-query filters; shepherd/vigil/corgi:<name> map 1:1
onto shepherd's /admin/logs target param, which already fans out to
the right service. The router factory takes its LoggingHandle and
axios instance as explicit deps so tests mount it on a bare Express
app against a real mock upstream over HTTP - no session machinery or
BFF main() needed - while the production mount under /api picks up the
existing auth stack unchanged.

Upstream failures propagate as rejections into the app-level error
handler, which already preserves upstream status codes (a 404 for an
unknown corgi stays a 404, not a generic 500).
EOF
)"
```

---

### Task 3: `GET /api/logs/stream` — live-tail SSE (local + verbatim proxy)

**Files:**
- Modify: `dashboard/server/routes-logs.ts`
- Modify: `dashboard/server/routes-logs.test.ts`
- Modify: `dashboard/docs/config.md`

**Interfaces:**
- Consumes (Task 1): `readHistoricalLines`, `dedupBufferedAgainstTail`, `DEDUP_TAIL_WINDOW`, `parseLevelFilter`, `linePassesFilter`. Consumes (previous slice): `LoggingHandle.subscribe`.
- Produces: `GET /stream` on the same router. SSE wire shape identical to credo-lib's `follow_logs`: `data: {"line":"...","source":"<name>"}\n\n` per line, `:ka\n\n` comment keep-alives every 15s.

- [ ] **Step 1: Write the failing tests**

Append to `dashboard/server/routes-logs.test.ts`:

```typescript
/**
 * Minimal SSE reader: collects raw bytes from an open HTTP response until
 * `count` data events have arrived (ignoring comment/keep-alive frames),
 * then destroys the connection and returns the parsed event payloads.
 */
function readSseEvents(url: string, count: number, onOpen?: () => void): Promise<Array<{ line: string; source: string }>> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`unexpected status ${res.statusCode}`));
        return;
      }
      onOpen?.();
      let buf = '';
      const events: Array<{ line: string; source: string }> = [];
      res.on('data', (chunk: Buffer) => {
        buf += chunk.toString('utf8');
        let idx: number;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (frame.startsWith('data: ')) {
            events.push(JSON.parse(frame.slice('data: '.length)));
            if (events.length >= count) {
              req.destroy();
              resolve(events);
              return;
            }
          }
        }
      });
      res.on('error', () => resolve(events));
    });
    req.on('error', reject);
  });
}

describe('GET /api/logs/stream', () => {
  it('replays the historical backlog then continues with live lines, in the shared SSE shape', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'dashboard.log'), '2024-01-15T10:00:00Z INFO historical line\n');
    const handle = LoggingHandle.init(
      { enabled: true, dir, rotateOn: { sizeMb: 100, keepFiles: 12 }, alsoStdout: false },
      'dashboard',
    );
    const servers = await startServers(handle, express());

    const events = await readSseEvents(
      `${servers.base}/api/logs/stream?source=dashboard`,
      2,
      // Fires once the response is open - the live write must land after
      // the subscription exists, proving replay-then-continue end to end.
      () => setTimeout(() => handle.write('2024-01-15T10:00:01Z INFO live line'), 20),
    );

    expect(events).toEqual([
      { line: '2024-01-15T10:00:00Z INFO historical line', source: 'dashboard' },
      { line: '2024-01-15T10:00:01Z INFO live line', source: 'dashboard' },
    ]);

    await servers.close();
  });

  it('applies the level filter to live lines, not just the backlog', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'dashboard.log'), '2024-01-15T10:00:00Z ERROR old failure\n');
    const handle = LoggingHandle.init(
      { enabled: true, dir, rotateOn: { sizeMb: 100, keepFiles: 12 }, alsoStdout: false },
      'dashboard',
    );
    const servers = await startServers(handle, express());

    const events = await readSseEvents(
      `${servers.base}/api/logs/stream?source=dashboard&level=error`,
      2,
      () =>
        setTimeout(() => {
          handle.write('2024-01-15T10:00:01Z INFO filtered out');
          handle.write('2024-01-15T10:00:02Z ERROR new failure');
        }, 20),
    );

    expect(events.map((e) => e.line)).toEqual([
      '2024-01-15T10:00:00Z ERROR old failure',
      '2024-01-15T10:00:02Z ERROR new failure',
    ]);

    await servers.close();
  });

  it('returns 400 for source=dashboard when file logging is not enabled', async () => {
    const servers = await startServers(LoggingHandle.disabled(), express());
    const resp = await axios.get(`${servers.base}/api/logs/stream?source=dashboard`, { validateStatus: () => true });
    expect(resp.status).toBe(400);
    await servers.close();
  });

  it('pipes a proxied stream through verbatim and forwards follow=true', async () => {
    const mock = express();
    let seenQuery: Record<string, unknown> = {};
    mock.get('/admin/logs', (req, res) => {
      seenQuery = req.query;
      res.setHeader('Content-Type', 'text/event-stream');
      res.write('data: {"line":"upstream live","source":"vigil"}\n\n');
      res.end();
    });
    const servers = await startServers(LoggingHandle.disabled(), mock);

    const events = await readSseEvents(`${servers.base}/api/logs/stream?source=vigil&last=5m`, 1);
    expect(events).toEqual([{ line: 'upstream live', source: 'vigil' }]);
    expect(seenQuery).toEqual({ target: 'vigil', last: '5m', follow: 'true' });

    await servers.close();
  });

  it('aborts the upstream request when the client disconnects', async () => {
    const mock = express();
    let upstreamClosed = false;
    mock.get('/admin/logs', (req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.write('data: {"line":"first","source":"vigil"}\n\n');
      // Hold the connection open; only the client abort should end it.
      req.on('close', () => {
        upstreamClosed = true;
      });
    });
    const servers = await startServers(LoggingHandle.disabled(), mock);

    // readSseEvents destroys the client connection after the first event.
    await readSseEvents(`${servers.base}/api/logs/stream?source=vigil`, 1);
    await vi.waitFor(() => {
      expect(upstreamClosed).toBe(true);
    });

    await servers.close();
  });
});
```

Also add `vi` to the vitest import at the top of the file:

```typescript
import { describe, it, expect, vi } from 'vitest';
```

(replacing Task 2's `import { describe, it, expect } from 'vitest';`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run server/routes-logs.test.ts`
Expected: the new `/stream` tests fail with 404 (route doesn't exist); Task 2's tests still pass.

- [ ] **Step 3: Implement the stream route**

In `dashboard/server/routes-logs.ts`, extend the imports:

```typescript
import { readHistoricalLines, type LogQueryParams } from './log-query';
```

becomes:

```typescript
import {
  readHistoricalLines,
  dedupBufferedAgainstTail,
  linePassesFilter,
  parseLevelFilter,
  DEDUP_TAIL_WINDOW,
  type LogQueryParams,
} from './log-query';
```

Add these constants and helpers above `createLogsRouter`:

```typescript
/** Comment frames keep intermediaries from timing out an idle tail. */
const SSE_KEEP_ALIVE_MS = 15_000;

/**
 * One SSE data frame in the shared wire shape every hop of this feature
 * uses (credo-lib's build_sse_event): {"line": ..., "source": ...}.
 */
function sseFrame(line: string, source: string): string {
  return `data: ${JSON.stringify({ line, source })}\n\n`;
}
```

Inside `createLogsRouter`, add the route after the existing `router.get('/', ...)`:

```typescript
  router.get(
    '/stream',
    asyncHandler(async (req: Request, res: Response) => {
      const source = resolveSource(req);
      if (source === null) {
        res.status(400).json({ error: `unknown source '${String(req.query.source)}'` });
        return;
      }
      const params = filterParams(req);

      if (source.kind === 'dashboard') {
        if (!deps.handle.isEnabled()) {
          res.status(400).json({ error: 'file logging is not enabled' });
          return;
        }

        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.flushHeaders();

        const minRank = params.level !== undefined ? parseLevelFilter(params.level) : null;
        const q = params.q ?? null;
        const basename = deps.handle.logBasename();

        // Subscribe BEFORE reading the backlog so no line can be missed in
        // the gap between "finish reading the file" and "start tailing" -
        // same sequencing as credo-lib's build_follow_stream. Lines that
        // arrive during the read are buffered, deduped against the
        // backlog's tail, and replayed before going live. With today's
        // synchronous readHistoricalLines nothing can actually interleave
        // (single-threaded JS), so the buffer stays empty in practice -
        // the sequencing exists so a future swap to async file reads
        // can't silently open a lose-a-line gap.
        let replaying = true;
        const buffered: string[] = [];
        const unsubscribe = deps.handle.subscribe((line) => {
          if (!linePassesFilter(line, minRank, q)) return;
          if (replaying) {
            buffered.push(line);
          } else {
            res.write(sseFrame(line, basename));
          }
        });

        const keepAlive = setInterval(() => {
          res.write(':ka\n\n');
        }, SSE_KEEP_ALIVE_MS);

        req.on('close', () => {
          unsubscribe();
          clearInterval(keepAlive);
        });

        const historical = readHistoricalLines(deps.handle.logDir(), basename, params, new Date());
        for (const line of historical) {
          res.write(sseFrame(line, basename));
        }
        for (const line of dedupBufferedAgainstTail(historical, buffered, DEDUP_TAIL_WINDOW)) {
          res.write(sseFrame(line, basename));
        }
        replaying = false;
        return;
      }

      // Proxied live tail: shepherd's /admin/logs?follow=true is already
      // SSE - pipe its bytes through verbatim (never re-framed; only the
      // innermost service constructs SSE events). timeout: 0 overrides the
      // client's default (a live tail must outlive requestTimeoutSeconds),
      // and the AbortController tied to the client's 'close' event is what
      // stops a closed browser tab from leaking an upstream connection.
      const controller = new AbortController();
      req.on('close', () => controller.abort());

      const upstream = await deps.shepherdApi.get('/admin/logs', {
        params: { target: source.target, ...forwardParams(params), follow: 'true' },
        responseType: 'stream',
        timeout: 0,
        signal: controller.signal,
      });

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.flushHeaders();

      const body = upstream.data as NodeJS.ReadableStream & { destroy?: () => void };
      body.pipe(res);
      req.on('close', () => {
        body.destroy?.();
      });
    }),
  );
```

Also update the router doc comment: change

```typescript
/**
 * GET /        - historical JSON (array of raw log lines)
 * GET /stream  - live tail as SSE (added in the next task)
 *
```

to

```typescript
/**
 * GET /        - historical JSON (array of raw log lines)
 * GET /stream  - live tail as SSE, replay-then-continue
 *
```

In `dashboard/docs/config.md`, the `## Logging` section's intro sentence still points at a "later plan". Change:

```markdown
Opt-in rotating log file + live tail, backing `GET /api/logs` (see a later plan for the routes themselves). Omit entirely for stdout-only (current behavior). Requires a BFF restart to pick up changes.
```

to:

```markdown
Opt-in rotating log file + live tail, backing `GET /api/logs?source=dashboard` (historical JSON) and `GET /api/logs/stream?source=dashboard` (live-tail SSE). Other `source` values (`shepherd`, `vigil`, `corgi:<name>`) proxy through Shepherd's `/admin/logs` and work regardless of this block. Omit entirely for stdout-only (current behavior). Requires a BFF restart to pick up changes.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd dashboard && npx vitest run server/routes-logs.test.ts`
Expected: all tests pass (Task 2's + the 5 new stream tests).

- [ ] **Step 5: Full suite and typecheck**

Run: `cd dashboard && npm test && npm run typecheck`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add dashboard/server/routes-logs.ts dashboard/server/routes-logs.test.ts dashboard/docs/config.md
git commit -m "$(cat <<'EOF'
feat(dashboard): add GET /api/logs/stream - live-tail SSE

source=dashboard mirrors credo-lib's build_follow_stream sequencing:
subscribe to the live broadcast before reading the backlog, buffer
what arrives during the read, replay, dedup the buffer against the
backlog's tail, then stream live - so no line is lost in the seam and
the wire shape ({"line":...,"source":...} data frames plus comment
keep-alives) is byte-compatible with what the Rust services emit,
giving the upcoming frontend one SSE format for every source.

Proxied sources pipe shepherd's /admin/logs?follow=true bytes through
verbatim - never re-framed - with timeout: 0 overriding the axios
client's 15s default (a live tail must outlive it) and an
AbortController wired to the client request's 'close' event, so a
closed browser tab tears down the upstream connection instead of
leaking it; nothing else in this codebase has a long-lived request, so
no existing pattern guarded that.
EOF
)"
```

---

## Verification (whole plan)

1. `cd dashboard && npm test && npm run typecheck` — clean.
2. Confirm only the six named files changed: `git diff --stat <plan-start-commit>..HEAD`.
3. Manual end-to-end (requires the remote deployment or a local sandbox with shepherd reachable; the automated tests cover local + mock-upstream behavior, not the real mTLS/JWT chain — same accepted tradeoff as every prior slice): with `logging.enabled: true`, log in to the dashboard and `curl` with the session cookie:
   - `GET /api/logs?source=dashboard&last=5m` → JSON array of BFF request lines.
   - `curl -N /api/logs/stream?source=dashboard` → replay then live lines as you click around the UI; hold >30s and confirm `:ka` comments arrive and the connection survives.
   - `GET /api/logs?source=shepherd`, `source=vigil`, `source=corgi:<real-name>` → JSON from each service.
   - `curl -N /api/logs/stream?source=corgi:<real-name>&last=5m` → SSE proxied through shepherd; hold >15s (past `requestTimeoutSeconds`) to confirm the timeout override works through the BFF hop.
   - Kill a `curl -N` mid-stream and confirm (via shepherd's request log) the upstream connection closes promptly rather than leaking.
