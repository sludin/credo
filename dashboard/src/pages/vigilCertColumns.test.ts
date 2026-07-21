import { describe, it, expect } from 'vitest';
import {
  VIGIL_CERT_COLUMNS,
  DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS,
  visibleVigilCertColumns,
  type VigilCertColumnKey,
} from './vigilCertColumns';

describe('visibleVigilCertColumns', () => {
  it('always keeps the pinned certName column, even when not in the visible set', () => {
    expect(visibleVigilCertColumns(new Set<VigilCertColumnKey>()).map((c) => c.key)).toEqual(['certName']);
  });

  it('returns all 5 columns for the default visibility set, in registry order', () => {
    const cols = visibleVigilCertColumns(new Set(DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['certName', 'corgi', 'domain', 'daysLeft', 'status']);
  });

  it('every column key in the registry is reachable via visibility toggling', () => {
    const allKeys = VIGIL_CERT_COLUMNS.map((c) => c.key);
    expect(visibleVigilCertColumns(new Set(allKeys)).map((c) => c.key)).toEqual(allKeys);
  });
});
