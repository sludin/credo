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
