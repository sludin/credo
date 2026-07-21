import { describe, it, expect } from 'vitest';
import {
  CERTIFICATE_LIST_COLUMNS,
  DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS,
  visibleCertificateListColumns,
  type CertificateListColumnKey,
} from './certificateListColumns';

describe('visibleCertificateListColumns', () => {
  it('always keeps the pinned name column, even when not in the visible set', () => {
    expect(visibleCertificateListColumns(new Set<CertificateListColumnKey>()).map((c) => c.key)).toEqual(['name']);
  });

  it('returns all 5 columns for the default visibility set, in registry order', () => {
    const cols = visibleCertificateListColumns(new Set(DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['name', 'corgi', 'ca', 'status', 'expires']);
  });

  it('every column key in the registry is reachable via visibility toggling', () => {
    const allKeys = CERTIFICATE_LIST_COLUMNS.map((c) => c.key);
    expect(visibleCertificateListColumns(new Set(allKeys)).map((c) => c.key)).toEqual(allKeys);
  });
});
