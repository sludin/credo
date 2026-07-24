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
