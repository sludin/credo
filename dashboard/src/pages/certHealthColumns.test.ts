import { describe, it, expect } from 'vitest';
import { CERT_COLUMNS, DEFAULT_VISIBLE_CERT_COLUMNS, visibleCertColumns, type CertColumnKey, type CertRow } from './certHealthColumns';
import type { FlockCert } from '../types';

function makeRow(overrides: Partial<FlockCert>): CertRow {
  const cert: FlockCert = {
    name: 'hermes.ludin.org',
    lifetimeDays: 85,
    status: 'ok',
    sanNames: ['claw.ludin.org', 'hermes.ludin.org'],
    ...overrides,
  };
  return { corgi: 'corgi-04', cert, daysLeft: 85 };
}

describe('domain column', () => {
  const domainColumn = CERT_COLUMNS.find((c) => c.key === 'domain')!;

  it('prefers the cert\'s actual name over its first SAN, even when SANs are present', () => {
    const row = makeRow({ name: 'hermes.ludin.org', sanNames: ['claw.ludin.org', 'hermes.ludin.org'] });
    expect(domainColumn.sortValue!(row)).toBe('hermes.ludin.org');
  });

  it('falls back to the first SAN only when the cert has no name', () => {
    const row = makeRow({ name: '', sanNames: ['claw.ludin.org', 'hermes.ludin.org'] });
    expect(domainColumn.sortValue!(row)).toBe('claw.ludin.org');
  });
});

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
