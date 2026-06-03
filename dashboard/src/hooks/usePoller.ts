// src/hooks/usePoller.ts
import { useCallback, useEffect, useRef, useState } from 'react';

const POLL_INTERVAL_MS = 30_000;

type UsePollerResult = {
  /** Seconds since last successful poll. */
  secondsAgo: number;
  /** Call this to immediately re-run the fetch and reset the timer. */
  refresh: () => void;
};

/**
 * Calls `fetchFn` immediately on mount, then every 30 seconds.
 * Returns `refresh()` to trigger an immediate re-fetch and `secondsAgo`
 * for the topbar "Last polled Xs ago" display.
 */
export function usePoller(fetchFn: () => Promise<void>): UsePollerResult {
  const [lastFetchedAt, setLastFetchedAt] = useState<number>(0);
  const [secondsAgo, setSecondsAgo] = useState<number>(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const fetchRef = useRef(fetchFn);
  fetchRef.current = fetchFn;

  const runFetch = useCallback(async () => {
    await fetchRef.current();
    setLastFetchedAt(Date.now());
  }, []);

  // Auto-poll every 30s
  useEffect(() => {
    void runFetch();
    timerRef.current = setInterval(() => { void runFetch(); }, POLL_INTERVAL_MS);
    return () => {
      if (timerRef.current !== null) {
        clearInterval(timerRef.current);
      }
    };
  }, [runFetch]);

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
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
    }
    void runFetch();
    timerRef.current = setInterval(() => { void runFetch(); }, POLL_INTERVAL_MS);
  }, [runFetch]);

  return { secondsAgo, refresh };
}
