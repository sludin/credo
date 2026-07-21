import { describe, it, expect } from 'vitest';
import { CORGI_COLUMNS, DEFAULT_VISIBLE_CORGI_COLUMNS, visibleCorgiColumns, corgiHost, type CorgiColumnKey } from './corgiColumns';

describe('visibleCorgiColumns', () => {
  it('always keeps the pinned name column, even when not in the visible set', () => {
    expect(visibleCorgiColumns(new Set<CorgiColumnKey>()).map((c) => c.key)).toEqual(['name']);
  });

  it('returns all 5 base columns for the default visibility set, in registry order', () => {
    const cols = visibleCorgiColumns(new Set(DEFAULT_VISIBLE_CORGI_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['name', 'host', 'status', 'certs', 'lastSeen']);
  });

  it('every column key in the base registry is reachable via visibility toggling', () => {
    const allKeys = CORGI_COLUMNS.map((c) => c.key);
    expect(visibleCorgiColumns(new Set(allKeys)).map((c) => c.key)).toEqual(allKeys);
  });
});

describe('corgiHost', () => {
  it('extracts the hostname from a well-formed URL', () => {
    expect(corgiHost({ url: 'https://corgi-a.internal:7001' } as Parameters<typeof corgiHost>[0])).toBe('corgi-a.internal');
  });

  it('falls back to the raw string when the URL is malformed', () => {
    expect(corgiHost({ url: 'not-a-url' } as Parameters<typeof corgiHost>[0])).toBe('not-a-url');
  });
});
