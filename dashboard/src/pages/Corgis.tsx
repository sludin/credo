// src/pages/Corgis.tsx
import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { usePoller } from '../hooks/usePoller';
import { fetchFlock, renewCert } from '../api';
import { StatusBadge, certTone, serviceTone } from '../components/StatusBadge';
import { Topbar } from '../components/Shell';
import { usePermission } from '../hooks/usePermission';
import type { CorgiState } from '../types';

type SortDir = 'asc' | 'desc';
type CorgiSortKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen';
type CertSortKey = 'cert' | 'domain' | 'daysLeft' | 'status';

export default function Corgis(): React.ReactElement {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const autoExpand = searchParams.get('corgi');

  const canRenew = usePermission('cert:renew');

  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  // Pre-expand corgi from URL param (e.g. navigated from Overview)
  const [expandedCorgi, setExpandedCorgi] = useState<string | null>(autoExpand);
  const [renewingKey, setRenewingKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [corgiSort, setCorgiSort] = useState<{ key: CorgiSortKey; dir: SortDir }>({ key: 'name', dir: 'asc' });
  const [certSort, setCertSort] = useState<{ key: CertSortKey; dir: SortDir }>({ key: 'cert', dir: 'asc' });

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const data = await fetchFlock();
      setCorgis(data.corgis);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  function toggleExpand(name: string): void {
    setExpandedCorgi((prev) => (prev === name ? null : name));
  }

  async function handleRenew(certName: string, corgiName: string): Promise<void> {
    const key = `${corgiName}:${certName}`;
    setRenewingKey(key);
    setToast(null);
    try {
      await renewCert(certName, corgiName);
      setToast({ msg: `Renewal requested: ${certName} on ${corgiName}` });
      refresh();
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : 'Renewal failed', error: true });
    } finally {
      setRenewingKey(null);
    }
  }

  const sortedCorgis = [...corgis].sort((a, b) => {
    const aHost = (() => { try { return new URL(a.url).hostname; } catch { return a.url; } })().toLowerCase();
    const bHost = (() => { try { return new URL(b.url).hostname; } catch { return b.url; } })().toLowerCase();
    const aLast = a.lastPolledAt ? new Date(a.lastPolledAt).getTime() : 0;
    const bLast = b.lastPolledAt ? new Date(b.lastPolledAt).getTime() : 0;

    let cmp = 0;
    switch (corgiSort.key) {
      case 'name': cmp = a.name.localeCompare(b.name); break;
      case 'host': cmp = aHost.localeCompare(bHost); break;
      case 'status': cmp = a.status.localeCompare(b.status); break;
      case 'certs': cmp = a.flock.length - b.flock.length; break;
      case 'lastSeen': cmp = aLast - bLast; break;
    }
    return corgiSort.dir === 'asc' ? cmp : -cmp;
  });

  function sortedFlock(corgi: CorgiState): CorgiState['flock'] {
    return [...corgi.flock].sort((a, b) => {
      const aDays = Math.floor(a.lifetimeDays);
      const bDays = Math.floor(b.lifetimeDays);
      let cmp = 0;
      switch (certSort.key) {
        case 'cert': cmp = a.name.localeCompare(b.name); break;
        case 'domain': cmp = (a.sanNames[0] ?? '').localeCompare(b.sanNames[0] ?? ''); break;
        case 'daysLeft': cmp = aDays - bDays; break;
        case 'status': cmp = a.status.localeCompare(b.status); break;
      }
      return certSort.dir === 'asc' ? cmp : -cmp;
    });
  }

  function toggleCorgiSort(key: CorgiSortKey): void {
    setCorgiSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function toggleCertSort(key: CertSortKey): void {
    setCertSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  return (
    <>
      <Topbar title="Corgis" subtitle="Cert agents" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}
        {toast && <div className={`toast${toast.error ? ' toast-error' : ''}`}>{toast.msg}</div>}

        <div className="card">
          <div className="card-header">
            <span className="card-title">Corgi Fleet</span>
            <span className="card-subtitle">{corgis.length} registered</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 20 }} />
                  <th className="th-sort" onClick={() => toggleCorgiSort('name')}>Name <span>{sortIndicator(corgiSort.key === 'name', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('host')}>Host <span>{sortIndicator(corgiSort.key === 'host', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('status')}>Status <span>{sortIndicator(corgiSort.key === 'status', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('certs')}>Certs <span>{sortIndicator(corgiSort.key === 'certs', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('lastSeen')}>Last Seen <span>{sortIndicator(corgiSort.key === 'lastSeen', corgiSort.dir)}</span></th>
                </tr>
              </thead>
              <tbody>
                {sortedCorgis.length === 0 && (
                  <tr><td colSpan={6} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No corgis</td></tr>
                )}
                {sortedCorgis.map((corgi) => {
                  const isExpanded = expandedCorgi === corgi.name;
                  const tone = serviceTone(corgi.status);
                  const statusLabel = corgi.status.charAt(0).toUpperCase() + corgi.status.slice(1);
                  const host = (() => { try { return new URL(corgi.url).hostname; } catch { return corgi.url; } })();

                  return (
                    <React.Fragment key={corgi.name}>
                      <tr
                        className={`clickable${isExpanded ? ' expanded' : ''}`}
                        onClick={() => toggleExpand(corgi.name)}
                      >
                        <td style={{ color: 'var(--muted)', fontSize: 11 }}>{isExpanded ? '▾' : '▸'}</td>
                        <td className="fw-500">{corgi.name}</td>
                        <td className="text-muted mono">{host}</td>
                        <td><StatusBadge label={statusLabel} tone={tone} /></td>
                        <td>{corgi.flock.length}</td>
                        <td className="text-muted">
                          {corgi.lastPolledAt ? new Date(corgi.lastPolledAt).toLocaleTimeString() : '—'}
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr>
                          <td />
                          <td colSpan={5} style={{ padding: '0 0 8px 0' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', background: 'var(--surface2)' }}>
                              <thead>
                                <tr>
                                  {/* No border-bottom on inner th — removes the blue bars */}
                                  <th className="th-sort" style={{ borderBottom: 'none' }} onClick={() => toggleCertSort('cert')}>Cert <span>{sortIndicator(certSort.key === 'cert', certSort.dir)}</span></th>
                                  <th className="th-sort" style={{ borderBottom: 'none' }} onClick={() => toggleCertSort('domain')}>Domain <span>{sortIndicator(certSort.key === 'domain', certSort.dir)}</span></th>
                                  <th className="th-sort" style={{ borderBottom: 'none' }} onClick={() => toggleCertSort('daysLeft')}>Days Left <span>{sortIndicator(certSort.key === 'daysLeft', certSort.dir)}</span></th>
                                  <th className="th-sort" style={{ borderBottom: 'none' }} onClick={() => toggleCertSort('status')}>Status <span>{sortIndicator(certSort.key === 'status', certSort.dir)}</span></th>
                                  <th style={{ borderBottom: 'none' }}>Actions</th>
                                </tr>
                              </thead>
                              <tbody>
                                {corgi.flock.length === 0 && (
                                  <tr><td colSpan={5} className="text-muted" style={{ padding: '8px 10px' }}>No certs</td></tr>
                                )}
                                {sortedFlock(corgi).map((cert) => {
                                  const daysLeft = Math.floor(cert.lifetimeDays);
                                  const certStatusTone = certTone(cert.status, daysLeft);
                                  const certLabel = certStatusTone === 'yellow' ? `Expiring ${daysLeft}d` : certStatusTone === 'red' ? 'Error' : 'Valid';
                                  const renewKey = `${corgi.name}:${cert.name}`;
                                  const isRenewing = renewingKey === renewKey;
                                  return (
                                    <tr
                                      key={cert.name}
                                      className="clickable"
                                      onClick={() => navigate(`/certificates?cert=${encodeURIComponent(cert.name)}`)}
                                    >
                                      <td className="fw-500">{cert.name}</td>
                                      <td className="text-muted">{cert.sanNames[0] ?? '—'}</td>
                                      <td className={certStatusTone === 'green' ? 'text-green' : certStatusTone === 'yellow' ? 'text-yellow' : 'text-red'}>
                                        {daysLeft > 0 ? daysLeft : '—'}
                                      </td>
                                      <td><StatusBadge label={certLabel} tone={certStatusTone} /></td>
                                      <td onClick={(e) => e.stopPropagation()}>
                                        <details className="action-menu">
                                          <summary className="btn btn-ghost btn-sm">···</summary>
                                          <div className="action-menu-dropdown">
                                            <button
                                              className="action-menu-item"
                                              onClick={() => navigate(`/certificates?cert=${encodeURIComponent(cert.name)}`)}
                                            >
                                              View Details
                                            </button>
                                            <button
                                              className="action-menu-item"
                                              disabled={isRenewing || !canRenew}
                                              onClick={() => { void handleRenew(cert.name, corgi.name); }}
                                            >
                                              {isRenewing ? 'Renewing…' : 'Renew'}
                                            </button>
                                          </div>
                                        </details>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
