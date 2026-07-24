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
    expect(lineInWindow(line, new Date('2024-01-15T10:01:00Z'), null)).toBe(false);
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
