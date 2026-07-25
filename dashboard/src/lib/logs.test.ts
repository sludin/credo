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
  formatTimestamp,
  formatLogLine,
  highlightLevel,
  timezoneOptions,
  resolveTimezone,
  LOCAL_TIMEZONE_VALUE,
  TIME_FORMAT_OPTIONS,
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

describe('timezoneOptions / resolveTimezone', () => {
  it('lists UTC and Local first, then the curated named zones', () => {
    const values = timezoneOptions().map((o) => o.value);
    expect(values.slice(0, 2)).toEqual(['UTC', LOCAL_TIMEZONE_VALUE]);
    expect(values).toContain('Europe/London');
  });

  it('resolves the "local" sentinel to a real IANA zone, and passes named zones through', () => {
    expect(resolveTimezone('Europe/London')).toBe('Europe/London');
    expect(resolveTimezone(LOCAL_TIMEZONE_VALUE)).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone);
  });
});

describe('formatTimestamp', () => {
  const utcMs = Date.UTC(2024, 0, 15, 10, 30, 45); // 2024-01-15T10:30:45Z
  const micros = '128391';

  it('formats in UTC across all four formats', () => {
    expect(formatTimestamp(utcMs, micros, 'UTC', 'YYYY-MM-DD HH:MM:SS.UUUUUU')).toBe(
      '2024-01-15 10:30:45.128391',
    );
    expect(formatTimestamp(utcMs, micros, 'UTC', 'HH:MM:SS.UUUUUU')).toBe('10:30:45.128391');
    expect(formatTimestamp(utcMs, micros, 'UTC', 'HH:MM:SS')).toBe('10:30:45');
    expect(formatTimestamp(utcMs, micros, 'UTC', 'YYYY-MM-DD HH:MM:SS')).toBe('2024-01-15 10:30:45');
  });

  it('converts into a named zone, keeping the microsecond fraction untouched', () => {
    // 2024-01-15T10:30:45Z is 05:30:45 in America/New_York (EST, UTC-5) in January.
    expect(formatTimestamp(utcMs, micros, 'America/New_York', 'YYYY-MM-DD HH:MM:SS.UUUUUU')).toBe(
      '2024-01-15 05:30:45.128391',
    );
  });

  it('handles a DST-crossing zone correctly (America/New_York in July is UTC-4)', () => {
    const julyUtcMs = Date.UTC(2024, 6, 15, 10, 30, 45);
    expect(formatTimestamp(julyUtcMs, micros, 'America/New_York', 'HH:MM:SS')).toBe('06:30:45');
  });
});

describe('formatLogLine', () => {
  it('splits and reformats the leading RFC3339 timestamp, leaving the rest untouched', () => {
    const line = '2024-01-15T10:30:45.128391Z  INFO shepherd::routes: something happened';
    const { timestamp, rest } = formatLogLine(line, 'UTC', 'HH:MM:SS');
    expect(timestamp).toBe('10:30:45');
    expect(rest).toBe('INFO shepherd::routes: something happened');
  });

  it('returns timestamp: null for a line with no parseable leading timestamp', () => {
    const line = 'garbage line with no timestamp';
    expect(formatLogLine(line, 'UTC', 'HH:MM:SS')).toEqual({ timestamp: null, rest: line });
  });
});

describe('highlightLevel', () => {
  it('highlights ERROR/WARN/DEBUG as their own segment', () => {
    expect(highlightLevel('INFO shepherd::routes: something happened')).toEqual([
      { text: 'INFO shepherd::routes: something happened' },
    ]);
    expect(highlightLevel('ERROR failed to renew cert')).toEqual([
      { text: 'ERROR', className: 'text-red' },
      { text: ' failed to renew cert' },
    ]);
    expect(highlightLevel('shepherd::poll: WARN retrying')).toEqual([
      { text: 'shepherd::poll: ' },
      { text: 'WARN', className: 'text-yellow' },
      { text: ' retrying' },
    ]);
  });

  it('leaves plain lines with no level keyword or status code as one segment', () => {
    const line = 'shepherd starting up, config loaded';
    expect(highlightLevel(line)).toEqual([{ text: line }]);
  });

  it('colors the numeric HTTP status in the structured request-log format, not the whole triplet', () => {
    expect(highlightLevel('S > 200 GET /flock shepherd.local 10.0.0.1 corgi-1 12.34')).toEqual([
      { text: 'S > ' },
      { text: '200', className: 'text-green' },
      { text: ' GET /flock shepherd.local 10.0.0.1 corgi-1 12.34' },
    ]);
    expect(highlightLevel('C > 401 GET /assignments corgi.local 10.0.0.2 - 0.01')).toEqual([
      { text: 'C > ' },
      { text: '401', className: 'text-yellow' },
      { text: ' GET /assignments corgi.local 10.0.0.2 - 0.01' },
    ]);
    expect(highlightLevel('F < 500 POST /issue vigil.local 10.0.0.3 shepherd 2.00')).toEqual([
      { text: 'F < ' },
      { text: '500', className: 'text-red' },
      { text: ' POST /issue vigil.local 10.0.0.3 shepherd 2.00' },
    ]);
    expect(highlightLevel('V > 301 GET /ca vigil.local 10.0.0.4 - 0.00')).toEqual([
      { text: 'V > ' },
      { text: '301', className: 'text-blue' },
      { text: ' GET /ca vigil.local 10.0.0.4 - 0.00' },
    ]);
  });

  it('colors the status in the dashboard BFF\'s own "D" service code lines', () => {
    expect(highlightLevel('D > 200 GET /api/flock dashboard.example.com 10.0.0.5 alice 0.00')).toEqual([
      { text: 'D > ' },
      { text: '200', className: 'text-green' },
      { text: ' GET /api/flock dashboard.example.com 10.0.0.5 alice 0.00' },
    ]);
  });

  it('does not mistake an unrelated 3-digit number for a status code', () => {
    const line = 'retrying in 500ms, no code/direction prefix present';
    expect(highlightLevel(line)).toEqual([{ text: line }]);
  });
});

describe('TIME_FORMAT_OPTIONS', () => {
  it('defaults to the full date+microseconds format first', () => {
    expect(TIME_FORMAT_OPTIONS[0].value).toBe('YYYY-MM-DD HH:MM:SS.UUUUUU');
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
