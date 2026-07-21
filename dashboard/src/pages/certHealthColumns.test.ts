import { describe, it, expect } from 'vitest';
import { CERT_COLUMNS, DEFAULT_VISIBLE_CERT_COLUMNS, visibleCertColumns, type CertColumnKey } from './certHealthColumns';

describe('visibleCertColumns', () => {
  it('always keeps the pinned domain column, even when not in the visible set', () => {
    const cols = visibleCertColumns(new Set<CertColumnKey>());
    expect(cols.map((c) => c.key)).toEqual(['domain']);
  });

  it('returns the default 6 columns for the default visibility set, in registry order', () => {
    const cols = visibleCertColumns(new Set(DEFAULT_VISIBLE_CERT_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['domain', 'corgi', 'ca', 'daysLeft', 'expires', 'status']);
  });

  it('adds optional columns when toggled on, without dropping defaults', () => {
    const cols = visibleCertColumns(new Set<CertColumnKey>([...DEFAULT_VISIBLE_CERT_COLUMNS, 'monitorStatus']));
    expect(cols.map((c) => c.key)).toContain('monitorStatus');
    expect(cols).toHaveLength(7);
  });

  it('ignores unknown/no-longer-existing keys gracefully', () => {
    const cols = visibleCertColumns(new Set(['not-a-real-key'] as unknown as CertColumnKey[]));
    expect(cols.map((c) => c.key)).toEqual(['domain']);
  });

  it('every non-pinned column key in the registry is reachable via visibility toggling', () => {
    const allKeys = CERT_COLUMNS.map((c) => c.key);
    const cols = visibleCertColumns(new Set(allKeys));
    expect(cols.map((c) => c.key)).toEqual(allKeys);
  });
});
