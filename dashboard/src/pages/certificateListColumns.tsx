// src/pages/certificateListColumns.tsx
import React from 'react';
import { StatusBadge } from '../components/StatusBadge';
import { statusTone, statusLabel } from './Certificates.testable';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import { fmtDate, type UnifiedCertRow } from './Certificates';

export type CertificateListColumnKey = 'name' | 'corgi' | 'ca' | 'status' | 'expires';

export type CertificateListColumn = ColumnDef<CertificateListColumnKey, UnifiedCertRow>;

export const CERTIFICATE_LIST_COLUMNS: CertificateListColumn[] = [
  {
    key: 'name', header: 'Name', pinned: true, sortable: true,
    sortValue: (r) => r.certName,
    render: (r) => <td className="fw-500">{r.domain}</td>,
  },
  {
    key: 'corgi', header: 'Corgi', sortable: true,
    sortValue: (r) => r.corgi,
    render: (r) => <td className="text-muted">{r.corgi}</td>,
  },
  {
    key: 'ca', header: 'CA', sortable: true,
    sortValue: (r) => r.ca,
    render: (r) => <td className="text-muted">{r.ca}</td>,
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (r) => r.status,
    render: (r) => (
      <td>
        <StatusBadge label={statusLabel(r.status, r.daysLeft)} tone={statusTone(r.status)} spinning={r.status === 'renewing'} />
      </td>
    ),
  },
  {
    key: 'expires', header: 'Expires', sortable: true,
    sortValue: (r) => r.daysLeft ?? Infinity,
    render: (r) => <td className="text-muted">{r.validTo ? fmtDate(r.validTo) : '—'}</td>,
  },
];

export const DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS: CertificateListColumnKey[] = ['name', 'corgi', 'ca', 'status', 'expires'];

export function visibleCertificateListColumns(visible: ReadonlySet<CertificateListColumnKey>): CertificateListColumn[] {
  return visibleColumns(CERTIFICATE_LIST_COLUMNS, visible);
}
