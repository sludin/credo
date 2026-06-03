// src/pages/Overview.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePoller } from '../hooks/usePoller';
import { fetchHealth, fetchFlock, fetchCerts } from '../api';
import { StatusBadge, certTone, serviceTone } from '../components/StatusBadge';
import { StatBox } from '../components/StatBox';
import { Topbar } from '../components/Shell';
import type { CorgiState, CertStoreEntry, HealthPayload } from '../types';

type SortDir = 'asc' | 'desc';
type CertSortKey = 'domain' | 'corgi' | 'ca' | 'daysLeft' | 'expires' | 'status';
type CorgiSortKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen';

/** "Apr 30 14:51:20 2027 GMT" → "Apr 30 2027" (handles single-digit day padding) */
function fmtDate(s: string | undefined): string {
  if (!s) return '—';
  const p = s.split(' ').filter(Boolean);
  return p.length >= 4 ? `${p[0]} ${p[1]}, ${p[3]}` : s;
}

export default function Overview(): React.ReactElement {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  const [certEntries, setCertEntries] = useState<CertStoreEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [certSort, setCertSort] = useState<{ key: CertSortKey; dir: SortDir }>({ key: 'daysLeft', dir: 'asc' });
  const [corgiSort, setCorgiSort] = useState<{ key: CorgiSortKey; dir: SortDir }>({ key: 'name', dir: 'asc' });

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

  const sortedCertRows = [...certRows].sort((a, b) => {
    const aDomain = (a.cert.sanNames[0] ?? a.cert.name).toLowerCase();
    const bDomain = (b.cert.sanNames[0] ?? b.cert.name).toLowerCase();
    const aCa = (a.store?.assignment?.ca ?? '').toLowerCase();
    const bCa = (b.store?.assignment?.ca ?? '').toLowerCase();
    const aExpires = a.cert.validTo ? new Date(a.cert.validTo).getTime() : Number.MAX_SAFE_INTEGER;
    const bExpires = b.cert.validTo ? new Date(b.cert.validTo).getTime() : Number.MAX_SAFE_INTEGER;
    const aStatus = a.cert.status.toLowerCase();
    const bStatus = b.cert.status.toLowerCase();

    let cmp = 0;
    switch (certSort.key) {
      case 'domain': cmp = aDomain.localeCompare(bDomain); break;
      case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
      case 'ca': cmp = aCa.localeCompare(bCa); break;
      case 'daysLeft': cmp = a.daysLeft - b.daysLeft; break;
      case 'expires': cmp = aExpires - bExpires; break;
      case 'status': cmp = aStatus.localeCompare(bStatus); break;
    }
    return certSort.dir === 'asc' ? cmp : -cmp;
  });

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
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="th-sort" onClick={() => toggleCertSort('domain')}>Domain / Cert <span>{sortIndicator(certSort.key === 'domain', certSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCertSort('corgi')}>Corgi <span>{sortIndicator(certSort.key === 'corgi', certSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCertSort('ca')}>CA <span>{sortIndicator(certSort.key === 'ca', certSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCertSort('daysLeft')}>Days Left <span>{sortIndicator(certSort.key === 'daysLeft', certSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCertSort('expires')}>Expires <span>{sortIndicator(certSort.key === 'expires', certSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCertSort('status')}>Status <span>{sortIndicator(certSort.key === 'status', certSort.dir)}</span></th>
                </tr>
              </thead>
              <tbody>
                {sortedCertRows.length === 0 && (
                  <tr><td colSpan={6} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No certs found</td></tr>
                )}
                {sortedCertRows.map((row) => {
                  const tone = certTone(row.cert.status, row.daysLeft);
                  const label = tone === 'yellow' ? `Expiring ${row.daysLeft}d` : tone === 'red' ? 'Error' : 'Valid';
                  return (
                    <tr
                      key={`${row.corgi}:${row.cert.name}`}
                      className="clickable"
                      onClick={() => navigate(`/certificates?cert=${encodeURIComponent(row.cert.name)}`)}
                    >
                      <td className="fw-500">{row.cert.sanNames[0] ?? row.cert.name}</td>
                      <td className="text-muted">{row.corgi}</td>
                      <td className="text-muted">{row.store?.assignment?.ca ?? '—'}</td>
                      <td className={tone === 'green' ? 'text-green' : tone === 'yellow' ? 'text-yellow' : 'text-red'}>
                        {row.daysLeft > 0 ? row.daysLeft : '—'}
                      </td>
                      <td className="text-muted">{fmtDate(row.cert.validTo)}</td>
                      <td><StatusBadge label={label} tone={tone} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Corgi fleet table */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Corgi Fleet</span>
            <span className="card-subtitle">{corgis.length} configured</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="th-sort" onClick={() => toggleCorgiSort('name')}>Name <span>{sortIndicator(corgiSort.key === 'name', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('host')}>Host <span>{sortIndicator(corgiSort.key === 'host', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('status')}>Status <span>{sortIndicator(corgiSort.key === 'status', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('certs')}>Certs <span>{sortIndicator(corgiSort.key === 'certs', corgiSort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleCorgiSort('lastSeen')}>Last Seen <span>{sortIndicator(corgiSort.key === 'lastSeen', corgiSort.dir)}</span></th>
                  <th>Services</th>
                </tr>
              </thead>
              <tbody>
                {sortedCorgis.length === 0 && (
                  <tr><td colSpan={6} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No corgis found</td></tr>
                )}
                {sortedCorgis.map((corgi) => {
                  const tone = serviceTone(corgi.status);
                  const statusLabel = corgi.status.charAt(0).toUpperCase() + corgi.status.slice(1);
                  const host = (() => { try { return new URL(corgi.url).hostname; } catch { return corgi.url; } })();
                  return (
                    <tr
                      key={corgi.name}
                      className="clickable"
                      onClick={() => navigate(`/corgis?corgi=${encodeURIComponent(corgi.name)}`)}
                    >
                      <td className="fw-500">{corgi.name}</td>
                      <td className="text-muted mono">{host}</td>
                      <td><StatusBadge label={statusLabel} tone={tone} /></td>
                      <td>{corgi.flock.length}</td>
                      <td className="text-muted">{corgi.lastPolledAt ? new Date(corgi.lastPolledAt).toLocaleTimeString() : '—'}</td>
                      <td>
                        {health?.shepherdApi?.status && (
                          <StatusBadge
                            label={health.shepherdApi.status === 'healthy' ? 'API' : 'API down'}
                            tone={serviceTone(health.shepherdApi.status)}
                          />
                        )}
                      </td>
                    </tr>
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
