// src/pages/Overview.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePoller } from '../hooks/usePoller';
import { useColumnVisibility } from '../hooks/useColumnVisibility';
import { fetchHealth, fetchFlock, fetchCerts } from '../api';
import { StatusBadge, serviceTone } from '../components/StatusBadge';
import { StatBox } from '../components/StatBox';
import { Topbar } from '../components/Shell';
import { ColumnMenu } from '../components/ColumnMenu';
import { visibleColumns } from '../lib/columns';
import { CERT_COLUMNS, visibleCertColumns, type CertColumnKey, DEFAULT_VISIBLE_CERT_COLUMNS } from './certHealthColumns';
import { CORGI_COLUMNS, DEFAULT_VISIBLE_CORGI_COLUMNS, type CorgiColumnKey, type CorgiColumn } from './corgiColumns';
import type { CorgiState, CertStoreEntry, HealthPayload } from '../types';

type SortDir = 'asc' | 'desc';
type CertSortKey = CertColumnKey;
type CorgiSortKey = CorgiColumnKey;

const CERT_COLUMNS_STORAGE_KEY = 'credo.columns.overview.certHealth';
const CORGI_COLUMNS_STORAGE_KEY = 'credo.columns.overview.corgiFleet';

function buildServicesColumn(health: HealthPayload | null): CorgiColumn {
  return {
    key: 'services',
    header: 'Services',
    sortable: false,
    render: () => (
      <td>
        {health?.shepherdApi?.status && (
          <StatusBadge
            label={health.shepherdApi.status === 'healthy' ? 'API' : 'API down'}
            tone={serviceTone(health.shepherdApi.status)}
          />
        )}
      </td>
    ),
  };
}

export default function Overview(): React.ReactElement {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  const [certEntries, setCertEntries] = useState<CertStoreEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [certSort, setCertSort] = useState<{ key: CertSortKey; dir: SortDir }>({ key: 'daysLeft', dir: 'asc' });
  const [corgiSort, setCorgiSort] = useState<{ key: CorgiSortKey; dir: SortDir }>({ key: 'name', dir: 'asc' });
  const { visible: visibleCertColumnKeys, toggle: toggleCertColumn } =
    useColumnVisibility(CERT_COLUMNS_STORAGE_KEY, DEFAULT_VISIBLE_CERT_COLUMNS);
  const { visible: visibleCorgiColumnKeys, toggle: toggleCorgiColumn } =
    useColumnVisibility<CorgiColumnKey>(CORGI_COLUMNS_STORAGE_KEY, [...DEFAULT_VISIBLE_CORGI_COLUMNS, 'services']);

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const [h, f, c] = await Promise.all([fetchHealth(), fetchFlock(), fetchCerts()]);
      setHealth(h);
      setCorgis(f.corgis);
      setCertEntries(c.entries);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  const certRows = corgis.flatMap((corgi) =>
    corgi.flock.map((cert) => {
      const store = certEntries.find((e) => e.certName === cert.name);
      const daysLeft = Math.floor(cert.lifetimeDays);
      return { corgi: corgi.name, cert, store, daysLeft };
    })
  );

  const certColumnByKey = new Map(CERT_COLUMNS.map((c) => [c.key, c]));

  const sortedCertRows = [...certRows].sort((a, b) => {
    const sortValue = certColumnByKey.get(certSort.key)?.sortValue;
    if (!sortValue) return 0;
    const av = sortValue(a);
    const bv = sortValue(b);
    const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return certSort.dir === 'asc' ? cmp : -cmp;
  });

  const overviewCorgiColumns: CorgiColumn[] = [...CORGI_COLUMNS, buildServicesColumn(health)];
  const corgiColumnByKey = new Map(overviewCorgiColumns.map((c) => [c.key, c]));

  const sortedCorgis = [...corgis].sort((a, b) => {
    const sortValue = corgiColumnByKey.get(corgiSort.key)?.sortValue;
    if (!sortValue) return 0;
    const av = sortValue(a);
    const bv = sortValue(b);
    const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return corgiSort.dir === 'asc' ? cmp : -cmp;
  });

  function toggleCertSort(key: CertSortKey): void {
    setCertSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function toggleCorgiSort(key: CorgiSortKey): void {
    setCorgiSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  const visibleCols = visibleCertColumns(visibleCertColumnKeys);
  const visibleCorgiCols = visibleColumns(overviewCorgiColumns, visibleCorgiColumnKeys);

  const totalCerts   = certRows.length;
  const expiringSoon = certRows.filter((r) => r.daysLeft <= 30 && r.daysLeft > 0).length;
  const expired      = certRows.filter((r) => r.daysLeft <= 0 || r.cert.status === 'not-ok').length;
  const corgisOnline = corgis.filter((c) => c.status === 'reachable').length;

  return (
    <>
      <Topbar title="Dashboard" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}

        <div className="stats-row stats-4">
          <StatBox value={totalCerts}   label="Total certs" />
          <StatBox value={expiringSoon} label="Expiring ≤30d" tone={expiringSoon > 0 ? 'yellow' : 'default'} />
          <StatBox value={expired}      label="Expired / error" tone={expired > 0 ? 'red' : 'default'} />
          <StatBox value={`${corgisOnline}/${corgis.length}`} label="Corgis online" tone={corgisOnline < corgis.length ? 'yellow' : 'green'} />
        </div>

        {/* Cert health table */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Certificate Health</span>
            <span className="card-subtitle">{certRows.length} certs across {corgis.length} corgis</span>
            <ColumnMenu columns={CERT_COLUMNS} visible={visibleCertColumnKeys} onToggle={toggleCertColumn} />
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {visibleCols.map((col) =>
                    col.sortable ? (
                      <th key={col.key} className="th-sort" onClick={() => toggleCertSort(col.key)}>
                        {col.header} <span>{sortIndicator(certSort.key === col.key, certSort.dir)}</span>
                      </th>
                    ) : (
                      <th key={col.key}>{col.header}</th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {sortedCertRows.length === 0 && (
                  <tr>
                    <td colSpan={visibleCols.length} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>
                      No certs found
                    </td>
                  </tr>
                )}
                {sortedCertRows.map((row) => (
                  <tr
                    key={`${row.corgi}:${row.cert.name}`}
                    className="clickable"
                    onClick={() => navigate(`/certificates?cert=${encodeURIComponent(row.cert.name)}`)}
                  >
                    {visibleCols.map((col) => (
                      <React.Fragment key={col.key}>{col.render(row)}</React.Fragment>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Corgi fleet table */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Corgi Fleet</span>
            <span className="card-subtitle">{corgis.length} configured</span>
            <ColumnMenu columns={overviewCorgiColumns} visible={visibleCorgiColumnKeys} onToggle={toggleCorgiColumn} />
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {visibleCorgiCols.map((col) =>
                    col.sortable ? (
                      <th key={col.key} className="th-sort" onClick={() => toggleCorgiSort(col.key)}>
                        {col.header} <span>{sortIndicator(corgiSort.key === col.key, corgiSort.dir)}</span>
                      </th>
                    ) : (
                      <th key={col.key}>{col.header}</th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {sortedCorgis.length === 0 && (
                  <tr>
                    <td colSpan={visibleCorgiCols.length} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>
                      No corgis found
                    </td>
                  </tr>
                )}
                {sortedCorgis.map((corgi) => (
                  <tr
                    key={corgi.name}
                    className="clickable"
                    onClick={() => navigate(`/corgis?corgi=${encodeURIComponent(corgi.name)}`)}
                  >
                    {visibleCorgiCols.map((col) => (
                      <React.Fragment key={col.key}>{col.render(corgi)}</React.Fragment>
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
