// src/pages/vigilCertColumns.tsx
import React from 'react';
import { StatusBadge, certTone } from '../components/StatusBadge';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import type { FlockCert } from '../types';

export type VigilCertColumnKey = 'certName' | 'corgi' | 'domain' | 'daysLeft' | 'status';
export type VigilCertRow = { corgi: string; cert: FlockCert; daysLeft: number };
export type VigilCertColumn = ColumnDef<VigilCertColumnKey, VigilCertRow>;

export const VIGIL_CERT_COLUMNS: VigilCertColumn[] = [
  {
    key: 'certName', header: 'Cert Name', pinned: true, sortable: true,
    sortValue: (r) => r.cert.name,
    render: (r) => <td className="fw-500">{r.cert.name}</td>,
  },
  {
    key: 'corgi', header: 'Corgi', sortable: true,
    sortValue: (r) => r.corgi,
    render: (r) => <td className="text-muted">{r.corgi}</td>,
  },
  {
    key: 'domain', header: 'Domain', sortable: true,
    sortValue: (r) => r.cert.sanNames[0] ?? '',
    render: (r) => <td className="text-muted">{r.cert.sanNames[0] ?? '—'}</td>,
  },
  {
    key: 'daysLeft', header: 'Days Left', sortable: true,
    sortValue: (r) => r.daysLeft,
    render: (r) => {
      const tone = certTone(r.cert.status, r.daysLeft);
      const cls = tone === 'green' ? 'text-green' : tone === 'yellow' ? 'text-yellow' : 'text-red';
      return <td className={cls}>{r.daysLeft > 0 && r.daysLeft < 999 ? r.daysLeft : '—'}</td>;
    },
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (r) => r.cert.status,
    render: (r) => {
      const tone = certTone(r.cert.status, r.daysLeft);
      const label = tone === 'yellow' ? `Expiring ${r.daysLeft}d` : tone === 'red' ? 'Error' : 'Valid';
      return <td><StatusBadge label={label} tone={tone} /></td>;
    },
  },
];

export const DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS: VigilCertColumnKey[] = ['certName', 'corgi', 'domain', 'daysLeft', 'status'];

export function visibleVigilCertColumns(visible: ReadonlySet<VigilCertColumnKey>): VigilCertColumn[] {
  return visibleColumns(VIGIL_CERT_COLUMNS, visible);
}
