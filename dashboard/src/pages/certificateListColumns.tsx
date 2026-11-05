// src/pages/certificateListColumns.tsx
import React from 'react';
import { Link } from 'react-router-dom';
import { StatusBadge } from '../components/StatusBadge';
import { statusTone, statusLabel } from './Certificates.testable';
import { monitorTone, monitorLabel, monitorCheckUrl } from '../utils/monitor';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import { fmtDate, type UnifiedCertRow } from './Certificates';

export type CertificateListColumnKey =
  | 'name' | 'corgi' | 'ca' | 'status' | 'expires'
  | 'monitorStatus' | 'monitorChecked' | 'fingerprint' | 'sanCount';

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
  {
    key: 'monitorStatus', header: 'Monitor Status', sortable: true,
    sortValue: (r) => r.flockCert?.monitor?.status ?? 'unmonitored',
    render: (r) => {
      const status = r.flockCert?.monitor?.status ?? 'unmonitored';
      return (
        <td>
          <Link to={monitorCheckUrl(r.certName)} onClick={(e) => e.stopPropagation()}>
            <StatusBadge label={monitorLabel(status)} tone={monitorTone(status)} />
          </Link>
        </td>
      );
    },
  },
  {
    key: 'monitorChecked', header: 'Monitor Last Checked', sortable: true,
    sortValue: (r) => (r.flockCert?.monitor?.checkedAt ? new Date(r.flockCert.monitor.checkedAt).getTime() : 0),
    render: (r) => (
      <td className="text-muted">
        {r.flockCert?.monitor?.checkedAt ? new Date(r.flockCert.monitor.checkedAt).toLocaleString() : '—'}
      </td>
    ),
  },
  {
    key: 'fingerprint', header: 'Fingerprint', sortable: false,
    render: (r) => (
      <td className="mono text-muted">
        {r.fingerprint256 ? `${r.fingerprint256.slice(0, 16)}…` : '—'}
      </td>
    ),
  },
  {
    key: 'sanCount', header: 'SAN Count', sortable: true,
    sortValue: (r) => r.sanNames.length,
    render: (r) => <td className="text-muted">{r.sanNames.length}</td>,
  },
];

export const DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS: CertificateListColumnKey[] = ['name', 'corgi', 'ca', 'status', 'expires'];

export function visibleCertificateListColumns(visible: ReadonlySet<CertificateListColumnKey>): CertificateListColumn[] {
  return visibleColumns(CERTIFICATE_LIST_COLUMNS, visible);
}
