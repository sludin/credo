// src/hooks/usePoller.ts
import { useCallback, useEffect, useRef, useState } from 'react';

const DEFAULT_POLL_INTERVAL_MS = 30_000;

/** Parse the /ui-config payload into a poll interval, falling back to 30s. */
export function resolvePollIntervalMs(payload: unknown): number {
  if (payload && typeof payload === 'object') {
    const seconds = (payload as { pollIntervalSeconds?: unknown }).pollIntervalSeconds;
    if (typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0) {
      return Math.floor(seconds * 1000);
    }
  }
  return DEFAULT_POLL_INTERVAL_MS;
}

// Fetched once per page load and shared by every usePoller instance.
let pollIntervalPromise: Promise<number> | null = null;
function getPollIntervalMs(): Promise<number> {
  if (!pollIntervalPromise) {
    pollIntervalPromise = fetch('/ui-config')
      .then((res) => (res.ok ? res.json() : null))
      .then(resolvePollIntervalMs)
      .catch(() => DEFAULT_POLL_INTERVAL_MS);
  }
  return pollIntervalPromise;
}

type UsePollerResult = {
  /** Seconds since last successful poll. */
  secondsAgo: number;
  /** Call this to immediately re-run the fetch and reset the timer. */
  refresh: () => void;
};

/**
 * Calls `fetchFn` immediately on mount, then on the configured poll interval
 * (BFF `pollIntervalSeconds`, default 30s).
 * Returns `refresh()` to trigger an immediate re-fetch and `secondsAgo`
 * for the topbar "Last polled Xs ago" display.
 */
export function usePoller(fetchFn: () => Promise<void>): UsePollerResult {
  const [lastFetchedAt, setLastFetchedAt] = useState<number>(0);
  const [secondsAgo, setSecondsAgo] = useState<number>(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const intervalMsRef = useRef<number>(DEFAULT_POLL_INTERVAL_MS);
  const fetchRef = useRef(fetchFn);
  fetchRef.current = fetchFn;

  const runFetch = useCallback(async () => {
    await fetchRef.current();
    setLastFetchedAt(Date.now());
  }, []);

  const startTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
    }
    timerRef.current = setInterval(() => { void runFetch(); }, intervalMsRef.current);
  }, [runFetch]);

  // Auto-poll on the configured interval
  useEffect(() => {
    let cancelled = false;
    void runFetch();
    startTimer();
    void getPollIntervalMs().then((ms) => {
      if (cancelled || ms === intervalMsRef.current) {
        return;
      }
      intervalMsRef.current = ms;
      startTimer();
    });
    return () => {
      cancelled = true;
      if (timerRef.current !== null) {
        clearInterval(timerRef.current);
      }
    };
  }, [runFetch, startTimer]);

  // "X seconds ago" counter, ticks every second
  useEffect(() => {
    if (lastFetchedAt === 0) {
      return;
    }
    const id = setInterval(() => {
      setSecondsAgo(Math.floor((Date.now() - lastFetchedAt) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, [lastFetchedAt]);

  const refresh = useCallback(() => {
    void runFetch();
    startTimer();
  }, [runFetch, startTimer]);

  return { secondsAgo, refresh };
}
