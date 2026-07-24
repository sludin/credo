# Dashboard Logs Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the Logs tab to the dashboard SPA — source picker (dashboard/shepherd/vigil/one corgi), time-range presets + custom window, level/text filters, historical fetch, and live tail over SSE — completing Phase 5, the final phase, of `docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`. The BFF routes it consumes (`GET /api/logs`, `GET /api/logs/stream`) shipped in the previous slice.

**Architecture:** Two layers, following the codebase's established testing split (pure logic in `src/lib/` with vitest tests; UI components untested because the repo has no component-test infra — vitest runs in a node environment with no jsdom/testing-library, and adding them would violate the no-new-deps constraint). (1) `src/lib/logs.ts`: URL building (`/api/logs` + `/api/logs/stream` query strings), SSE event parsing (`{"line":...,"source":...}` — the one wire shape every source emits, by design), source-option derivation from the flock payload, bounded line-buffer append, reconnect-parameter trimming (on `EventSource` error, reopen with `last=30s` instead of the original window so a network blip doesn't re-replay and flood the viewer — the design doc's explicit requirement to NOT rely on `EventSource`'s built-in auto-reconnect, which reuses the original URL), datetime-local → RFC 3339 conversion, and the pinned-to-bottom autoscroll predicate. (2) `src/pages/Logs.tsx`: plain `useState`/`useEffect` page (no react-query anywhere in this codebase) that debounces control changes 500ms into one "apply" — historical mode does a JSON fetch; live mode closes any open `EventSource` and opens a new one with the current params (server-side filtering means a filter change while tailing MUST reopen the stream, per the design). A generation counter guards against stale async results and stale scheduled reconnects after the user changes controls or navigates away. Autoscroll pins to bottom on new lines unless the user has scrolled up to read history. Plus one nav item (new top-level "Logs" sidebar section — it spans all four sources, fitting none of the per-service groupings) and one lazy route.

**Tech Stack:** React 18 + react-router (existing), native `EventSource` (browser built-in; same-origin so session cookies flow automatically), Vitest (existing). No new npm dependencies.

## Global Constraints

- Touches only: `dashboard/src/lib/logs.ts` (new), `dashboard/src/lib/logs.test.ts` (new), `dashboard/src/api.ts`, `dashboard/src/api.test.ts`, `dashboard/src/pages/Logs.tsx` (new), `dashboard/src/App.tsx`, `dashboard/src/components/Shell.tsx`.
- No new npm dependencies.
- `npm run typecheck`, `npm test`, and `npm run build` (from `dashboard/`) must all pass — typecheck/test are the repo's pre-commit gates; build additionally proves the lazy route compiles into the production bundle.
- The SSE event payload shape is `{"line": string, "source": string}` (shared by every source — credo-lib's `build_sse_event` and the BFF's `sseFrame`). `parseSseEvent` must tolerate malformed frames by returning `null`, never throwing into the `onmessage` handler.
- Reconnection is manual: on `EventSource` `onerror`, close the stream and reopen after a short delay with the window trimmed to `last=30s` (other filters/source preserved) — never let the browser's built-in auto-reconnect replay the original historical window.
- Client-side line buffer capped at 5000 (matches `DEFAULT_LOG_LIMIT` server-side); oldest lines dropped first. No virtualization in v1 (YAGNI at this scale).
- Follow existing conventions: `requestJson` helper style in `api.ts`, lazy pages in `App.tsx`, `sections` array in `Shell.tsx`, form controls styled with the existing `form-select`/`form-input`/`btn` classes, `Topbar` from `components/Shell`.

---

### Task 1: `src/lib/logs.ts` — pure helpers + API functions

**Files:**
- Create: `dashboard/src/lib/logs.ts`
- Create: `dashboard/src/lib/logs.test.ts`
- Modify: `dashboard/src/api.ts`
- Modify: `dashboard/src/api.test.ts`

**Interfaces:**
- Produces (used by Task 2): `type LogsParams = { source: string; last?: string; since?: string; until?: string; level?: string; q?: string; limit?: number }`, `LOG_BUFFER_MAX = 5000`, `RANGE_PRESETS = ['5m', '15m', '1h', '24h']`, `logsUrl(params: LogsParams): string`, `logsStreamUrl(params: LogsParams): string`, `sourceOptionsFromFlock(corgis: Array<{ name: string }>): string[]`, `parseSseEvent(data: string): { line: string; source: string } | null`, `appendLines(existing: string[], incoming: string[], max?: number): string[]`, `reconnectParams(params: LogsParams): LogsParams`, `localInputToRfc3339(value: string): string | undefined`, `isPinnedToBottom(scrollTop: number, scrollHeight: number, clientHeight: number, slackPx?: number): boolean`. In `api.ts`: `fetchLogsHistorical(params: LogsParams): Promise<string[]>`, `openLogsStream(params: LogsParams): EventSource`.

- [ ] **Step 1: Write the failing tests**

Create `dashboard/src/lib/logs.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import {
  logsUrl,
  logsStreamUrl,
  sourceOptionsFromFlock,
  parseSseEvent,
  appendLines,
  reconnectParams,
  localInputToRfc3339,
  isPinnedToBottom,
  LOG_BUFFER_MAX,
} from './logs';

describe('logsUrl / logsStreamUrl', () => {
  it('builds the historical URL with only the params that are set', () => {
    expect(logsUrl({ source: 'shepherd', last: '15m' })).toBe('/api/logs?source=shepherd&last=15m');
    expect(logsUrl({ source: 'dashboard' })).toBe('/api/logs?source=dashboard');
  });

  it('percent-encodes values', () => {
    expect(logsUrl({ source: 'corgi:web-1', q: 'a b&c' })).toBe(
      '/api/logs?source=corgi%3Aweb-1&q=a+b%26c',
    );
  });

  it('drops empty-string filter values entirely', () => {
    expect(logsUrl({ source: 'vigil', level: '', q: '' })).toBe('/api/logs?source=vigil');
  });

  it('builds the stream URL on the /stream path with the same query rules', () => {
    expect(logsStreamUrl({ source: 'vigil', last: '5m', level: 'error' })).toBe(
      '/api/logs/stream?source=vigil&last=5m&level=error',
    );
  });

  it('includes since/until and limit when present', () => {
    expect(
      logsUrl({ source: 'shepherd', since: '2024-01-15T10:00:00.000Z', until: '2024-01-15T11:00:00.000Z', limit: 200 }),
    ).toBe(
      '/api/logs?source=shepherd&since=2024-01-15T10%3A00%3A00.000Z&until=2024-01-15T11%3A00%3A00.000Z&limit=200',
    );
  });
});

describe('sourceOptionsFromFlock', () => {
  it('lists the three fixed sources then corgis sorted by name', () => {
    expect(sourceOptionsFromFlock([{ name: 'web-2' }, { name: 'web-1' }])).toEqual([
      'dashboard',
      'shepherd',
      'vigil',
      'corgi:web-1',
      'corgi:web-2',
    ]);
  });

  it('handles an empty flock', () => {
    expect(sourceOptionsFromFlock([])).toEqual(['dashboard', 'shepherd', 'vigil']);
  });
});

describe('parseSseEvent', () => {
  it('parses the shared wire shape', () => {
    expect(parseSseEvent('{"line":"2024-01-15T10:00:00Z INFO hello","source":"vigil"}')).toEqual({
      line: '2024-01-15T10:00:00Z INFO hello',
      source: 'vigil',
    });
  });

  it('returns null for malformed JSON and wrong shapes instead of throwing', () => {
    expect(parseSseEvent('not json')).toBeNull();
    expect(parseSseEvent('{"nope":true}')).toBeNull();
    expect(parseSseEvent('{"line":42,"source":"x"}')).toBeNull();
    expect(parseSseEvent('')).toBeNull();
  });
});

describe('appendLines', () => {
  it('appends and preserves order', () => {
    expect(appendLines(['a'], ['b', 'c'])).toEqual(['a', 'b', 'c']);
  });

  it('drops the oldest lines beyond max', () => {
    expect(appendLines(['a', 'b'], ['c', 'd'], 3)).toEqual(['b', 'c', 'd']);
  });

  it('defaults max to LOG_BUFFER_MAX', () => {
    const many = Array.from({ length: LOG_BUFFER_MAX + 10 }, (_, i) => `line ${i}`);
    const result = appendLines([], many);
    expect(result).toHaveLength(LOG_BUFFER_MAX);
    expect(result[0]).toBe('line 10');
  });
});

describe('reconnectParams', () => {
  it('trims the window to last=30s, preserving source and filters', () => {
    expect(
      reconnectParams({ source: 'corgi:web-1', last: '24h', level: 'error', q: 'tls' }),
    ).toEqual({ source: 'corgi:web-1', last: '30s', level: 'error', q: 'tls' });
  });

  it('drops since/until (a custom window must not be re-replayed either)', () => {
    expect(
      reconnectParams({ source: 'shepherd', since: '2024-01-15T10:00:00Z', until: '2024-01-15T11:00:00Z' }),
    ).toEqual({ source: 'shepherd', last: '30s' });
  });
});

describe('localInputToRfc3339', () => {
  it('converts a datetime-local value to an RFC 3339 UTC instant', () => {
    const out = localInputToRfc3339('2024-01-15T10:00');
    // The exact instant depends on the test machine's timezone; the format
    // and round-trip are what matter.
    expect(out).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(new Date(out!).getTime()).toBe(new Date('2024-01-15T10:00').getTime());
  });

  it('returns undefined for empty or invalid input', () => {
    expect(localInputToRfc3339('')).toBeUndefined();
    expect(localInputToRfc3339('garbage')).toBeUndefined();
  });
});

describe('isPinnedToBottom', () => {
  it('is pinned when at or near the bottom within the slack', () => {
    expect(isPinnedToBottom(960, 1000, 40)).toBe(true); // exactly at bottom
    expect(isPinnedToBottom(930, 1000, 40)).toBe(true); // 30px up, inside 40px slack
  });

  it('is not pinned once scrolled up past the slack', () => {
    expect(isPinnedToBottom(900, 1000, 40)).toBe(false); // 60px up
    expect(isPinnedToBottom(0, 1000, 40)).toBe(false);
  });
});
```

Append to `dashboard/src/api.test.ts` (inside the existing `describe('api module exports', ...)` block, after the existing `it`):

```typescript
  it('exports fetchLogsHistorical and openLogsStream', async () => {
    const api = await import('./api');
    expect(typeof api.fetchLogsHistorical).toBe('function');
    expect(typeof api.openLogsStream).toBe('function');
  });
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run src/lib/logs.test.ts src/api.test.ts`
Expected: FAIL — `Cannot find module './logs'`; the api export test fails on missing exports.

- [ ] **Step 3: Implement `dashboard/src/lib/logs.ts` and the api.ts additions**

Create `dashboard/src/lib/logs.ts`:

```typescript
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

/** Appends keeping at most `max` lines, dropping the oldest first. */
export function appendLines(existing: string[], incoming: string[], max = LOG_BUFFER_MAX): string[] {
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
```

In `dashboard/src/api.ts`, add the import at the top of the file, directly after the existing `import type { ... } from './types';` block:

```typescript
import { logsUrl, logsStreamUrl, type LogsParams } from './lib/logs';
```

Then add at the end of the file:

```typescript
// ── Logs ───────────────────────────────────────────────────────────────────
export function fetchLogsHistorical(params: LogsParams): Promise<string[]> {
  return requestJson<string[]>(logsUrl(params));
}

/**
 * Opens the live-tail SSE stream. Same-origin, so the session cookie
 * flows automatically. Callers own the returned EventSource's lifecycle -
 * including closing it on unmount and managing reconnection manually
 * (see lib/logs reconnectParams).
 */
export function openLogsStream(params: LogsParams): EventSource {
  return new EventSource(logsStreamUrl(params));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd dashboard && npx vitest run src/lib/logs.test.ts src/api.test.ts`
Expected: all pass.

- [ ] **Step 5: Typecheck and full suite**

Run: `cd dashboard && npm run typecheck && npm test`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/lib/logs.ts dashboard/src/lib/logs.test.ts dashboard/src/api.ts dashboard/src/api.test.ts
git commit -m "$(cat <<'EOF'
feat(dashboard): add logs lib - URL building, SSE parsing, reconnect policy

Pure logic behind the upcoming Logs page, kept React-free so it's
testable in the repo's node-environment vitest setup (same split as
lib/columns): query-string building for /api/logs and
/api/logs/stream, tolerant parsing of the shared SSE wire shape (a
malformed frame returns null rather than throwing inside onmessage),
a bounded viewer buffer, and the manual-reconnect policy - reopen a
dropped stream with last=30s instead of the original window, so a
network blip can't re-replay the full historical backlog into the
viewer (the reason the page won't use EventSource's built-in
auto-reconnect, which reuses the original URL).

api.ts gains fetchLogsHistorical and openLogsStream on top.
EOF
)"
```

---

### Task 2: Logs page, route, and nav

**Files:**
- Create: `dashboard/src/pages/Logs.tsx`
- Modify: `dashboard/src/App.tsx`
- Modify: `dashboard/src/components/Shell.tsx`

**Interfaces:**
- Consumes (Task 1): everything exported from `lib/logs`, plus `fetchLogsHistorical`/`openLogsStream` from `api.ts`, plus existing `fetchFlock` and `Topbar`.
- Produces: the `/logs` route and "Logs" sidebar section.

No unit tests in this task: the repo has no component-test infrastructure (node-env vitest, no jsdom/testing-library, and adding them is out of scope per the no-new-deps constraint). All page logic with branching behavior lives in `lib/logs` (Task 1, fully tested); this task is wiring. Gates: `npm run typecheck`, `npm test` (no regressions), `npm run build` (proves the lazy route bundles), plus the manual walkthrough in the plan-level Verification section.

- [ ] **Step 1: Create `dashboard/src/pages/Logs.tsx`**

```tsx
// src/pages/Logs.tsx
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { fetchFlock, fetchLogsHistorical, openLogsStream } from '../api';
import { Topbar } from '../components/Shell';
import {
  RANGE_PRESETS,
  appendLines,
  isPinnedToBottom,
  localInputToRfc3339,
  parseSseEvent,
  reconnectParams,
  sourceOptionsFromFlock,
  type LogsParams,
} from '../lib/logs';

const APPLY_DEBOUNCE_MS = 500;
const RECONNECT_DELAY_MS = 2000;

type StreamState = 'off' | 'connecting' | 'live' | 'reconnecting';

export default function Logs(): React.ReactElement {
  const [sources, setSources] = useState<string[]>(sourceOptionsFromFlock([]));
  const [source, setSource] = useState('shepherd');
  const [preset, setPreset] = useState<string>('15m'); // one of RANGE_PRESETS or 'custom'
  const [sinceLocal, setSinceLocal] = useState('');
  const [untilLocal, setUntilLocal] = useState('');
  const [level, setLevel] = useState('');
  const [q, setQ] = useState('');
  const [live, setLive] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<StreamState>('off');

  const esRef = useRef<EventSource | null>(null);
  const viewerRef = useRef<HTMLDivElement | null>(null);
  const pinnedRef = useRef(true);
  // Bumped on every (re)apply and on unmount: async results and scheduled
  // reconnects check it and drop themselves when stale, so an old stream
  // or fetch can never write into a newer view.
  const generationRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Corgi list for the source picker - base sources stay usable if the
  // flock fetch fails.
  useEffect(() => {
    let cancelled = false;
    fetchFlock()
      .then((flock) => {
        if (!cancelled) setSources(sourceOptionsFromFlock(flock.corgis));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const currentParams = useCallback((): LogsParams => {
    const params: LogsParams = { source, level: level || undefined, q: q || undefined };
    if (preset === 'custom') {
      params.since = localInputToRfc3339(sinceLocal);
      params.until = localInputToRfc3339(untilLocal);
    } else {
      params.last = preset;
    }
    return params;
  }, [source, preset, sinceLocal, untilLocal, level, q]);

  const closeStream = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    esRef.current?.close();
    esRef.current = null;
  }, []);

  const openStream = useCallback(
    (params: LogsParams, generation: number) => {
      closeStream();
      setStreamState('connecting');
      const es = openLogsStream(params);
      esRef.current = es;
      es.onopen = () => {
        if (generation === generationRef.current) setStreamState('live');
      };
      es.onmessage = (event: MessageEvent<string>) => {
        if (generation !== generationRef.current) return;
        const parsed = parseSseEvent(event.data);
        if (parsed === null) return;
        setLines((prev) => appendLines(prev, [parsed.line]));
      };
      es.onerror = () => {
        if (generation !== generationRef.current) return;
        // Manual reconnection with a trimmed window - never let the
        // browser's built-in auto-reconnect replay the original range.
        es.close();
        if (esRef.current === es) esRef.current = null;
        setStreamState('reconnecting');
        reconnectTimerRef.current = setTimeout(() => {
          if (generation === generationRef.current) {
            openStream(reconnectParams(params), generation);
          }
        }, RECONNECT_DELAY_MS);
      };
    },
    [closeStream],
  );

  // One debounced "apply" for every control change: historical fetch when
  // live is off, stream (re)open when on. Server-side filtering means a
  // level/q change while tailing must close and reopen the stream.
  useEffect(() => {
    const timer = setTimeout(() => {
      generationRef.current += 1;
      const generation = generationRef.current;
      const params = currentParams();
      setError(null);
      setLines([]);
      pinnedRef.current = true;

      if (live) {
        openStream(params, generation);
      } else {
        closeStream();
        setStreamState('off');
        setLoading(true);
        fetchLogsHistorical(params)
          .then((result) => {
            if (generation === generationRef.current) setLines(result);
          })
          .catch((e: unknown) => {
            if (generation === generationRef.current) {
              setError(e instanceof Error ? e.message : 'Failed to fetch logs');
            }
          })
          .finally(() => {
            if (generation === generationRef.current) setLoading(false);
          });
      }
    }, APPLY_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [live, currentParams, openStream, closeStream]);

  // Teardown on unmount: invalidate the generation so scheduled reconnects
  // and in-flight fetches drop themselves, then close the stream.
  useEffect(() => {
    return () => {
      generationRef.current += 1;
      closeStream();
    };
  }, [closeStream]);

  // Autoscroll while pinned to the bottom.
  useEffect(() => {
    const viewer = viewerRef.current;
    if (viewer && pinnedRef.current) {
      viewer.scrollTop = viewer.scrollHeight;
    }
  }, [lines]);

  function handleViewerScroll(): void {
    const viewer = viewerRef.current;
    if (viewer) {
      pinnedRef.current = isPinnedToBottom(viewer.scrollTop, viewer.scrollHeight, viewer.clientHeight);
    }
  }

  const streamBadge =
    streamState === 'live' ? (
      <span style={{ color: 'var(--ok, #3fb950)' }}>● live</span>
    ) : streamState === 'connecting' ? (
      <span style={{ color: 'var(--muted)' }}>● connecting…</span>
    ) : streamState === 'reconnecting' ? (
      <span style={{ color: 'var(--warn, #d29922)' }}>● reconnecting…</span>
    ) : null;

  return (
    <>
      <Topbar title="Logs" subtitle="on-demand service log retrieval" />
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, height: 'calc(100vh - 64px)', boxSizing: 'border-box' }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <select className="form-select" value={source} onChange={(e) => setSource(e.target.value)} title="Log source">
            {sources.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select className="form-select" value={preset} onChange={(e) => setPreset(e.target.value)} title="Time range">
            {RANGE_PRESETS.map((p) => (
              <option key={p} value={p}>last {p}</option>
            ))}
            <option value="custom">custom range</option>
          </select>
          {preset === 'custom' && (
            <>
              <input className="form-input" type="datetime-local" value={sinceLocal} onChange={(e) => setSinceLocal(e.target.value)} title="Since" />
              <input className="form-input" type="datetime-local" value={untilLocal} onChange={(e) => setUntilLocal(e.target.value)} title="Until" />
            </>
          )}
          <select className="form-select" value={level} onChange={(e) => setLevel(e.target.value)} title="Minimum level">
            <option value="">all levels</option>
            <option value="error">error</option>
            <option value="warn">warn</option>
            <option value="info">info</option>
            <option value="debug">debug</option>
          </select>
          <input
            className="form-input"
            type="text"
            placeholder="filter text…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ minWidth: 160 }}
          />
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
            Live tail
          </label>
          {streamBadge}
          <div style={{ flex: 1 }} />
          <button className="btn btn-ghost btn-sm" onClick={() => setLines([])}>Clear</button>
        </div>

        {error && <div style={{ color: 'var(--danger, #f85149)' }}>{error}</div>}

        <div
          ref={viewerRef}
          onScroll={handleViewerScroll}
          style={{
            flex: 1,
            overflow: 'auto',
            background: 'var(--panel, #0d1117)',
            border: '1px solid var(--border, #30363d)',
            borderRadius: 6,
            padding: 12,
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
            fontSize: 12,
            lineHeight: 1.5,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {loading && <div style={{ color: 'var(--muted)' }}>Loading…</div>}
          {!loading && lines.length === 0 && (
            <div style={{ color: 'var(--muted)' }}>
              {live ? 'Waiting for log lines…' : 'No log lines in the selected window.'}
            </div>
          )}
          {lines.map((line, i) => (
            <div key={i}>{line}</div>
          ))}
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 2: Add the route in `dashboard/src/App.tsx`**

Change:

```typescript
const Tools        = lazy(() => import('./pages/Tools'));
```

to:

```typescript
const Tools        = lazy(() => import('./pages/Tools'));
const Logs         = lazy(() => import('./pages/Logs'));
```

And change:

```tsx
                      <Route path="/tools/*"      element={<Tools />} />
```

to:

```tsx
                      <Route path="/tools/*"      element={<Tools />} />
                      <Route path="/logs"         element={<Logs />} />
```

- [ ] **Step 3: Add the nav section in `dashboard/src/components/Shell.tsx`**

Change:

```typescript
  {
    label: 'Vigil',
    items: [{ to: '/vigil-ca', icon: '⊙', label: 'CA' }],
  },
```

to:

```typescript
  {
    label: 'Vigil',
    items: [{ to: '/vigil-ca', icon: '⊙', label: 'CA' }],
  },
  {
    label: 'Logs',
    items: [{ to: '/logs', icon: '≣', label: 'Logs' }],
  },
```

- [ ] **Step 4: Gates**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: all clean; the build output includes a lazy chunk for the Logs page.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/pages/Logs.tsx dashboard/src/App.tsx dashboard/src/components/Shell.tsx
git commit -m "$(cat <<'EOF'
feat(dashboard): add the Logs tab - source picker, filters, live tail

The final phase of on-demand log retrieval: a /logs page with a
source picker (dashboard/shepherd/vigil/one corgi, corgis from the
flock), time presets + custom range, level/text filters, and a Live
tail toggle. All control changes funnel through one 500ms-debounced
apply: historical mode fetches JSON, live mode closes and reopens the
EventSource with the new params (filtering is server-side, so a
filter change while tailing must reopen the stream).

Reconnection is manual by design: on stream error the page reopens
with last=30s instead of the original window, so a network blip
can't re-replay the full backlog - EventSource's built-in
auto-reconnect (which reuses the original URL) is never engaged. A
generation counter drops stale fetches, stale stream events, and
stale scheduled reconnects after controls change or the page
unmounts. The viewer autoscrolls while pinned to the bottom and
pauses when the user scrolls up to read history.

No component tests: the repo has no jsdom/testing-library infra and
adding it is out of scope - all branching logic lives in lib/logs
(tested in the previous commit); this is wiring, gated by typecheck,
the full suite, and a production build.
EOF
)"
```

---

## Verification (whole plan)

1. `cd dashboard && npm run typecheck && npm test && npm run build` — all clean.
2. Only the seven named files changed: `git diff --stat <plan-start-commit>..HEAD`.
3. Manual browser walkthrough (needs the remote deployment or a local sandbox with shepherd reachable and `logging.enabled: true` on the services being viewed — same accepted tradeoff as every prior slice):
   - "Logs" appears in the sidebar; `/logs` loads.
   - Source picker lists dashboard/shepherd/vigil plus every corgi from the flock.
   - Historical: pick `source=dashboard`, `last 15m` → BFF request lines appear. Level `error` narrows; text filter narrows; custom range with since/until works.
   - Live tail ON → stream badge goes `connecting… → live`; clicking around the UI in another tab produces new dashboard lines within a second; backlog appears first (replay-then-continue), then live lines.
   - Change the level filter while tailing → stream visibly reopens (badge blips through connecting) and only matching lines flow afterward.
   - Scroll up while tailing → view stops auto-scrolling; scroll back to bottom → autoscroll resumes.
   - Kill the BFF (or drop the network) mid-tail → badge shows `reconnecting…`; restore → stream resumes with only the last ~30s replayed, not the original window.
   - Navigate away from `/logs` mid-tail → the EventSource actually closes (devtools Network tab or BFF connection count).
   - Repeat a quick tail against `source=corgi:<real-name>` to confirm the full four-hop path (browser → BFF → shepherd → corgi) streams end to end.
