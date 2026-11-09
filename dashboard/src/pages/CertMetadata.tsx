// src/pages/CertMetadata.tsx
import React, { useState } from 'react';
import { usePoller } from '../hooks/usePoller';
import { fetchAssignments, fetchFlock, fetchCerts } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { monitorLabel, monitorTone } from '../utils/monitor';
import { Topbar } from '../components/Shell';
import type { ColumnDef } from '../lib/columns';
import type { Assignment, CertStoreEntry, CorgiState, FlockCert } from '../types';

const DEFAULT_RENEW_BEFORE_DAYS = 30;

type MetadataRow = {
  assignment: Assignment;
  flockCert: FlockCert | null;
  reportingCorgi: string | null;
  certEntry: CertStoreEntry | null;
  daysLeft: number | null;
};

type SortDir = 'asc' | 'desc';

function willRenewIn(row: MetadataRow): number | null {
  if (row.daysLeft === null) return null;
  return row.daysLeft - (row.assignment.renewBeforeDays ?? DEFAULT_RENEW_BEFORE_DAYS);
}

function hooksLabel(a: Assignment): string {
  if (a.hooks === undefined) return 'default';
  if (a.hooks.length === 0) return 'none';
  return a.hooks.join(', ');
}

/** "Apr 30 14:51:20 2027 GMT" (corgi's OpenSSL-style FlockCert.validTo) → "Apr 30, 2027" */
function fmtDate(s: string | undefined | null): string {
  if (!s) return '—';
  const p = s.split(' ').filter(Boolean);
  return p.length >= 4 ? `${p[0]} ${p[1]}, ${p[3]}` : s;
}

/** ISO 8601 (shepherd's own CertStoreEntry.validTo) → "Jan 11, 2027" */
function fmtIsoDate(s: string | undefined | null): string {
  if (!s) return '—';
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

const COLUMNS: ColumnDef<string, MetadataRow>[] = [
  { key: 'certName', header: 'Cert Name', pinned: true, sortable: true,
    sortValue: (r) => r.assignment.certName,
    render: (r) => <td className="fw-500">{r.assignment.certName}</td> },
  { key: 'corgi', header: 'Corgi', sortable: true,
    sortValue: (r) => r.assignment.corgi,
    render: (r) => <td className="text-muted">{r.assignment.corgi}</td> },
  { key: 'ca', header: 'CA', sortable: true,
    sortValue: (r) => r.assignment.ca ?? '',
    render: (r) => <td className="text-muted">{r.assignment.ca ?? '—'}</td> },
  { key: 'caTarget', header: 'CA Target', sortable: true,
    sortValue: (r) => r.assignment.caTarget ?? '',
    render: (r) => <td className="text-muted">{r.assignment.caTarget ?? '—'}</td> },
  { key: 'letsEncryptTarget', header: "Let's Encrypt Target", sortable: true,
    sortValue: (r) => r.assignment.letsEncryptTarget ?? '',
    render: (r) => <td className="text-muted">{r.assignment.letsEncryptTarget ?? '—'}</td> },
  { key: 'domain', header: 'Domain', sortable: true,
    sortValue: (r) => r.assignment.domain ?? '',
    render: (r) => <td>{r.assignment.domain ?? '—'}</td> },
  { key: 'identityUri', header: 'Identity URI', sortable: true,
    sortValue: (r) => r.assignment.identityUri ?? '',
    render: (r) => <td className="mono text-muted">{r.assignment.identityUri ?? '—'}</td> },
  { key: 'sans', header: 'SANs (configured)', sortable: false,
    render: (r) => <td className="text-muted">{(r.assignment.sans ?? []).join(', ') || '—'}</td> },
  { key: 'renewBeforeDays', header: 'Renew Before (d)', sortable: true,
    sortValue: (r) => r.assignment.renewBeforeDays ?? DEFAULT_RENEW_BEFORE_DAYS,
    render: (r) => <td>{r.assignment.renewBeforeDays ?? DEFAULT_RENEW_BEFORE_DAYS}</td> },
  { key: 'willRenewIn', header: 'Will Renew In', sortable: true,
    sortValue: (r) => willRenewIn(r) ?? Infinity,
    render: (r) => {
      const n = willRenewIn(r);
      if (n === null) return <td className="text-muted">—</td>;
      return <td className={n <= 0 ? 'text-yellow' : undefined}>{n <= 0 ? 'Due' : `${n}d`}</td>;
    } },
  { key: 'validationType', header: 'Validation Type', sortable: true,
    sortValue: (r) => r.assignment.validation?.type ?? 'none-01',
    render: (r) => <td className="text-muted">{r.assignment.validation?.type ?? 'none-01'}</td> },
  { key: 'validationProvider', header: 'Validation Provider', sortable: true,
    sortValue: (r) => r.assignment.validation?.methods?.['dns-01']?.provider ?? '',
    render: (r) => <td className="text-muted">{r.assignment.validation?.methods?.['dns-01']?.provider ?? '—'}</td> },
  { key: 'hooks', header: 'Hooks', sortable: true,
    sortValue: (r) => hooksLabel(r.assignment),
    render: (r) => <td className="mono text-muted">{hooksLabel(r.assignment)}</td> },
  { key: 'monitorHost', header: 'Monitor Host', sortable: true,
    sortValue: (r) => r.assignment.monitor?.host ?? '',
    render: (r) => <td className="text-muted">{r.assignment.monitor?.host ?? '—'}</td> },
  { key: 'monitorPort', header: 'Monitor Port', sortable: true,
    sortValue: (r) => r.assignment.monitor?.port ?? 0,
    render: (r) => <td className="text-muted">{r.assignment.monitor?.port ?? '—'}</td> },
  { key: 'monitorProtocol', header: 'Monitor Protocol', sortable: true,
    sortValue: (r) => r.assignment.monitor?.protocol ?? '',
    render: (r) => <td className="text-muted">{r.assignment.monitor?.protocol ?? '—'}</td> },
  { key: 'assignedFingerprint', header: 'Assignment Fingerprint', sortable: false,
    render: (r) => <td className="mono text-muted">{r.assignment.fingerprint256 ? `${r.assignment.fingerprint256.slice(0, 16)}…` : '—'}</td> },
  { key: 'liveStatus', header: 'Live Status', sortable: true,
    sortValue: (r) => r.flockCert?.status ?? '',
    render: (r) => r.flockCert
      ? <td><StatusBadge label={r.flockCert.status === 'ok' ? 'OK' : 'Not OK'} tone={r.flockCert.status === 'ok' ? 'green' : 'red'} /></td>
      : <td className="text-muted">—</td> },
  { key: 'daysLeft', header: 'Days Left', sortable: true,
    sortValue: (r) => r.daysLeft ?? Infinity,
    render: (r) => <td>{r.daysLeft !== null ? r.daysLeft : '—'}</td> },
  { key: 'validTo', header: 'Valid To', sortable: true,
    sortValue: (r) => (r.flockCert?.validTo ? new Date(r.flockCert.validTo).getTime() : 0),
    render: (r) => <td className="text-muted">{fmtDate(r.flockCert?.validTo)}</td> },
  { key: 'liveFingerprint', header: 'Live Fingerprint', sortable: false,
    render: (r) => <td className="mono text-muted">{r.flockCert?.fingerprint256 ? `${r.flockCert.fingerprint256.slice(0, 16)}…` : '—'}</td> },
  { key: 'liveSans', header: 'SANs (live)', sortable: false,
    render: (r) => <td className="text-muted">{(r.flockCert?.sanNames ?? []).join(', ') || '—'}</td> },
  { key: 'installIssue', header: 'Install Issue', sortable: true,
    sortValue: (r) => r.flockCert?.installIssue?.reason ?? '',
    render: (r) => {
      const issue = r.flockCert?.installIssue;
      if (!issue) return <td className="text-muted">—</td>;
      return <td className="text-red">{issue.reason} ({issue.attempts}×)</td>;
    } },
  { key: 'monitorStatus', header: 'Monitor Status', sortable: true,
    sortValue: (r) => r.flockCert?.monitor?.status ?? 'unmonitored',
    render: (r) => {
      const status = r.flockCert?.monitor?.status ?? 'unmonitored';
      return <td><StatusBadge label={monitorLabel(status)} tone={monitorTone(status)} /></td>;
    } },
  { key: 'monitorCheckedAt', header: 'Monitor Checked At', sortable: true,
    sortValue: (r) => (r.flockCert?.monitor?.checkedAt ? new Date(r.flockCert.monitor.checkedAt).getTime() : 0),
    render: (r) => <td className="text-muted">{r.flockCert?.monitor?.checkedAt ? new Date(r.flockCert.monitor.checkedAt).toLocaleString() : '—'}</td> },
  { key: 'monitorSeenFingerprint', header: 'Monitor Seen Fingerprint', sortable: false,
    render: (r) => <td className="mono text-muted">{r.flockCert?.monitor?.seenFingerprint ? `${r.flockCert.monitor.seenFingerprint.slice(0, 16)}…` : '—'}</td> },
  { key: 'monitorError', header: 'Monitor Error', sortable: false,
    render: (r) => <td className="text-red">{r.flockCert?.monitor?.error ?? '—'}</td> },
  { key: 'storeSubject', header: 'Store Subject', sortable: true,
    sortValue: (r) => r.certEntry?.subject ?? '',
    render: (r) => <td className="mono text-muted">{r.certEntry?.subject ?? '—'}</td> },
  { key: 'storeExpiresInDays', header: 'Store Days Left', sortable: true,
    sortValue: (r) => r.certEntry?.expiresInDays ?? Infinity,
    render: (r) => <td className="text-muted">{r.certEntry?.expiresInDays ?? '—'}</td> },
  { key: 'storeValidTo', header: 'Store Valid To', sortable: true,
    sortValue: (r) => (r.certEntry?.validTo ? new Date(r.certEntry.validTo).getTime() : 0),
    render: (r) => <td className="text-muted">{fmtIsoDate(r.certEntry?.validTo)}</td> },
  { key: 'storeFingerprint', header: 'Store Fingerprint', sortable: false,
    render: (r) => <td className="mono text-muted">{r.certEntry?.fingerprint256 ? `${r.certEntry.fingerprint256.slice(0, 16)}…` : '—'}</td> },
];

export default function CertMetadata(): React.ReactElement {
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  const [certEntries, setCertEntries] = useState<CertStoreEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>({ key: 'certName', dir: 'asc' });

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const [a, f, c] = await Promise.all([fetchAssignments(), fetchFlock(), fetchCerts()]);
      setAssignments(a.assignments);
      setCorgis(f.corgis);
      setCertEntries(c.entries);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  const rows: MetadataRow[] = assignments.map((assignment) => {
    let flockCert: FlockCert | null = null;
    let reportingCorgi: string | null = null;
    for (const corgi of corgis) {
      const match = corgi.flock.find((c) => c.name === assignment.certName);
      if (match) {
        flockCert = match;
        reportingCorgi = corgi.name;
        break;
      }
    }
    const certEntry = certEntries.find((e) => e.certName === assignment.certName) ?? null;
    const daysLeft = flockCert && Number.isFinite(flockCert.lifetimeDays) ? Math.floor(flockCert.lifetimeDays) : null;
    return { assignment, flockCert, reportingCorgi, certEntry, daysLeft };
  });

  const columnByKey = new Map(COLUMNS.map((c) => [c.key, c]));
  const sortedRows = [...rows].sort((a, b) => {
    const sortValue = columnByKey.get(sort.key)?.sortValue;
    if (!sortValue) return 0;
    const av = sortValue(a);
    const bv = sortValue(b);
    const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return sort.dir === 'asc' ? cmp : -cmp;
  });

  function toggleSort(key: string): void {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  return (
    <>
      <Topbar title="Cert Metadata" subtitle="Every field, every certificate" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}
        <div className="card">
          <div className="card-header">
            <span className="card-title">All Certificate Metadata</span>
            <span className="card-subtitle">{rows.length} assignments — every tracked field, unfiltered</span>
          </div>
          <div className="table-wrap" style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  {COLUMNS.map((col) => (
                    col.sortable ? (
                      <th key={col.key} className="th-sort" onClick={() => toggleSort(col.key)} style={{ whiteSpace: 'nowrap' }}>
                        {col.header} <span>{sortIndicator(sort.key === col.key, sort.dir)}</span>
                      </th>
                    ) : (
                      <th key={col.key} style={{ whiteSpace: 'nowrap' }}>{col.header}</th>
                    )
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedRows.length === 0 && (
                  <tr>
                    <td colSpan={COLUMNS.length} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>
                      No assignments found
                    </td>
                  </tr>
                )}
                {sortedRows.map((row) => (
                  <tr key={row.assignment.certName}>
                    {COLUMNS.map((col) => (
                      <React.Fragment key={col.key}>{col.render(row)}</React.Fragment>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
