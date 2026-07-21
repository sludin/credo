// src/pages/certHealthColumns.tsx
import React from 'react';
import { StatusBadge, certTone } from '../components/StatusBadge';
import { monitorTone, monitorLabel } from '../utils/monitor';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import type { CertStoreEntry, FlockCert } from '../types';

export type CertColumnKey =
  | 'domain' | 'corgi' | 'ca' | 'daysLeft' | 'expires' | 'status'
  | 'monitorStatus' | 'monitorChecked' | 'fingerprint' | 'sanCount';

export type CertRow = { corgi: string; cert: FlockCert; store?: CertStoreEntry; daysLeft: number };

export type CertColumn = ColumnDef<CertColumnKey, CertRow>;

/** "Apr 30 14:51:20 2027 GMT" → "Apr 30, 2027" (handles single-digit day padding) */
export function fmtDate(s: string | undefined): string {
  if (!s) return '—';
  const p = s.split(' ').filter(Boolean);
  return p.length >= 4 ? `${p[0]} ${p[1]}, ${p[3]}` : s;
}

function certStatusLabel(row: CertRow): string {
  const tone = certTone(row.cert.status, row.daysLeft);
  return tone === 'yellow' ? `Expiring ${row.daysLeft}d` : tone === 'red' ? 'Error' : 'Valid';
}

export const CERT_COLUMNS: CertColumn[] = [
  {
    key: 'domain', header: 'Domain / Cert', pinned: true, sortable: true,
    sortValue: (row) => (row.cert.sanNames[0] ?? row.cert.name).toLowerCase(),
    render: (row) => <td className="fw-500">{row.cert.sanNames[0] ?? row.cert.name}</td>,
  },
  {
    key: 'corgi', header: 'Corgi', sortable: true,
    sortValue: (row) => row.corgi.toLowerCase(),
    render: (row) => <td className="text-muted">{row.corgi}</td>,
  },
  {
    key: 'ca', header: 'CA', sortable: true,
    sortValue: (row) => (row.store?.assignment?.ca ?? '').toLowerCase(),
    render: (row) => <td className="text-muted">{row.store?.assignment?.ca ?? '—'}</td>,
  },
  {
    key: 'daysLeft', header: 'Days Left', sortable: true,
    sortValue: (row) => row.daysLeft,
    render: (row) => {
      const tone = certTone(row.cert.status, row.daysLeft);
      const cls = tone === 'green' ? 'text-green' : tone === 'yellow' ? 'text-yellow' : 'text-red';
      return <td className={cls}>{row.daysLeft > 0 ? row.daysLeft : '—'}</td>;
    },
  },
  {
    key: 'expires', header: 'Expires', sortable: true,
    sortValue: (row) => (row.cert.validTo ? new Date(row.cert.validTo).getTime() : Number.MAX_SAFE_INTEGER),
    render: (row) => <td className="text-muted">{fmtDate(row.cert.validTo)}</td>,
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (row) => row.cert.status.toLowerCase(),
    render: (row) => {
      const tone = certTone(row.cert.status, row.daysLeft);
      return <td><StatusBadge label={certStatusLabel(row)} tone={tone} /></td>;
    },
  },
  {
    key: 'monitorStatus', header: 'Monitor Status', sortable: true,
    sortValue: (row) => row.cert.monitor?.status ?? 'unmonitored',
    render: (row) => {
      const status = row.cert.monitor?.status ?? 'unmonitored';
      return <td><StatusBadge label={monitorLabel(status)} tone={monitorTone(status)} /></td>;
    },
  },
  {
    key: 'monitorChecked', header: 'Monitor Last Checked', sortable: true,
    sortValue: (row) => (row.cert.monitor?.checkedAt ? new Date(row.cert.monitor.checkedAt).getTime() : 0),
    render: (row) => (
      <td className="text-muted">
        {row.cert.monitor?.checkedAt ? new Date(row.cert.monitor.checkedAt).toLocaleString() : '—'}
      </td>
    ),
  },
  {
    key: 'fingerprint', header: 'Fingerprint', sortable: false,
    render: (row) => (
      <td className="mono text-muted">
        {row.cert.fingerprint256 ? `${row.cert.fingerprint256.slice(0, 16)}…` : '—'}
      </td>
    ),
  },
  {
    key: 'sanCount', header: 'SAN Count', sortable: true,
    sortValue: (row) => row.cert.sanNames.length,
    render: (row) => <td className="text-muted">{row.cert.sanNames.length}</td>,
  },
];

export const DEFAULT_VISIBLE_CERT_COLUMNS: CertColumnKey[] = ['domain', 'corgi', 'ca', 'daysLeft', 'expires', 'status'];

export function visibleCertColumns(visible: ReadonlySet<CertColumnKey>): CertColumn[] {
  return visibleColumns(CERT_COLUMNS, visible);
}
