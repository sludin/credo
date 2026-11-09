import type { Assignment, CertStoreEntry, FlockCert } from '../types';

export type UnifiedStatus = 'valid' | 'renewing' | 'error' | 'invalid';

export function deriveStatus(
  assignment: Assignment,
  flockCert: FlockCert | null,
  certEntry: CertStoreEntry | null,
  daysLeft: number | null,
  isRenewing: boolean,
  actualDnsSans: string[] | null,
  lastFailed: boolean,
): UnifiedStatus {
  if (isRenewing) return 'renewing';
  // certEntry is only ever present when shepherd's /admin/certstore actually
  // has an entry for this cert name (read_cert_store_entry returns None, and
  // the entry is filtered out, when nothing exists on disk) -- no separate
  // "exists" flag is sent over the wire.
  if (!flockCert && !certEntry) return 'invalid';
  if (flockCert?.status === 'not-ok') return 'invalid';
  if (daysLeft !== null && daysLeft < 0) return 'invalid';
  if (flockCert?.installIssue) return 'error';
  if (actualDnsSans && actualDnsSans.length > 0) {
    const configured = [
      ...new Set(
        [assignment.domain ?? assignment.certName, ...(assignment.sans ?? [])].filter(Boolean) as string[]
      ),
    ];
    const configSet = new Set(configured);
    const actualSet = new Set(actualDnsSans);
    if (configured.some(s => !actualSet.has(s)) || actualDnsSans.some(s => !configSet.has(s))) {
      return 'error';
    }
  }
  if (lastFailed) return 'error';
  return 'valid';
}

export function statusTone(s: UnifiedStatus): 'green' | 'yellow' | 'red' | 'blue' {
  if (s === 'valid') return 'green';
  if (s === 'error') return 'yellow';
  if (s === 'invalid') return 'red';
  return 'blue';
}

export function statusLabel(s: UnifiedStatus, _daysLeft: number | null): string {
  if (s === 'valid') return 'Valid';
  if (s === 'renewing') return 'Renewing';
  if (s === 'error') return 'Error';
  return 'Invalid';
}
