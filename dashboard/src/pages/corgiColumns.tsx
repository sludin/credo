// src/pages/corgiColumns.tsx
import React from 'react';
import { StatusBadge, serviceTone } from '../components/StatusBadge';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import type { CorgiState } from '../types';

export type CorgiColumnKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen' | 'services';
export type CorgiRow = CorgiState;
export type CorgiColumn = ColumnDef<CorgiColumnKey, CorgiRow>;

export function corgiHost(corgi: CorgiRow): string {
  try {
    return new URL(corgi.url).hostname;
  } catch {
    return corgi.url;
  }
}

export const CORGI_COLUMNS: CorgiColumn[] = [
  {
    key: 'name', header: 'Name', pinned: true, sortable: true,
    sortValue: (r) => r.name,
    render: (r) => <td className="fw-500">{r.name}</td>,
  },
  {
    key: 'host', header: 'Host', sortable: true,
    sortValue: (r) => corgiHost(r),
    render: (r) => <td className="text-muted mono">{corgiHost(r)}</td>,
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (r) => r.status,
    render: (r) => {
      const tone = serviceTone(r.status);
      const label = r.status.charAt(0).toUpperCase() + r.status.slice(1);
      return <td><StatusBadge label={label} tone={tone} /></td>;
    },
  },
  {
    key: 'certs', header: 'Certs', sortable: true,
    sortValue: (r) => r.flock.length,
    render: (r) => <td>{r.flock.length}</td>,
  },
  {
    key: 'lastSeen', header: 'Last Seen', sortable: true,
    sortValue: (r) => (r.lastPolledAt ? new Date(r.lastPolledAt).getTime() : 0),
    render: (r) => <td className="text-muted">{r.lastPolledAt ? new Date(r.lastPolledAt).toLocaleTimeString() : '—'}</td>,
  },
];

export const DEFAULT_VISIBLE_CORGI_COLUMNS: CorgiColumnKey[] = ['name', 'host', 'status', 'certs', 'lastSeen'];

export function visibleCorgiColumns(visible: ReadonlySet<CorgiColumnKey>): CorgiColumn[] {
  return visibleColumns(CORGI_COLUMNS, visible);
}
