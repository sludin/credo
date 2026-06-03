// src/pages/VigilCA.tsx
import React, { useState } from 'react';
import { usePoller } from '../hooks/usePoller';
import { fetchVigilCA, fetchVigilCerts, fetchFlock, fetchCerts } from '../api';
import { StatusBadge, certTone } from '../components/StatusBadge';
import { StatBox } from '../components/StatBox';
import { Topbar } from '../components/Shell';
import type { VigilCAInfo, VigilCertsPayload, CorgiState, CertStoreEntry } from '../types';

type SortDir = 'asc' | 'desc';
type SortKey = 'certName' | 'corgi' | 'domain' | 'daysLeft' | 'status';

function daysUntil(isoDate: string | undefined): number {
  if (!isoDate) return 999;
  return Math.floor((new Date(isoDate).getTime() - Date.now()) / 86_400_000);
}

function pctUsed(from: string, to: string): number {
  const start = new Date(from).getTime();
  const end   = new Date(to).getTime();
  const now   = Date.now();
  if (end <= start) return 100;
  return Math.min(100, Math.round(((now - start) / (end - start)) * 100));
}

export default function VigilCA(): React.ReactElement {
  const [ca, setCA] = useState<VigilCAInfo | null>(null);
  const [vigilStats, setVigilStats] = useState<VigilCertsPayload['stats'] | null>(null);
  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  const [certEntries, setCertEntries] = useState<CertStoreEntry[]>([]);
  const [pemVisible, setPemVisible] = useState(false);
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'daysLeft', dir: 'asc' });

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const [caData, certsData, flockData, storeData] = await Promise.allSettled([
        fetchVigilCA(),
        fetchVigilCerts(),
        fetchFlock(),
        fetchCerts(),
      ]);

      if (caData.status === 'fulfilled') setCA(caData.value.rootCA);
      if (certsData.status === 'fulfilled') setVigilStats(certsData.value.stats);
      if (flockData.status === 'fulfilled') setCorgis(flockData.value.corgis);
      if (storeData.status === 'fulfilled') setCertEntries(storeData.value.entries);

      const firstError = [caData, certsData, flockData, storeData].find((r) => r.status === 'rejected');
      setError(
        firstError?.status === 'rejected'
          ? String((firstError as PromiseRejectedResult).reason)
          : null
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  // Derive vigil-issued certs from certstore assignments
  const vigilFlockCerts = corgis.flatMap((corgi) =>
    corgi.flock
      .filter((cert) => {
        const store = certEntries.find((e) => e.certName === cert.name);
        return store?.assignment?.ca === 'vigil';
      })
      .map((cert) => {
        const daysLeft = cert.validTo ? daysUntil(cert.validTo) : 999;
        return { corgi: corgi.name, cert, daysLeft };
      })
  );

  const sortedVigilFlockCerts = [...vigilFlockCerts].sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'certName': cmp = a.cert.name.localeCompare(b.cert.name); break;
      case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
      case 'domain': cmp = (a.cert.sanNames[0] ?? '').localeCompare(b.cert.sanNames[0] ?? ''); break;
      case 'daysLeft': cmp = a.daysLeft - b.daysLeft; break;
      case 'status': cmp = a.cert.status.localeCompare(b.cert.status); break;
    }
    return sort.dir === 'asc' ? cmp : -cmp;
  });

  const expiringCount = vigilFlockCerts.filter((r) => r.daysLeft <= 30 && r.daysLeft > 0).length;
  const vigilCertCount = certEntries.filter((e) => e.assignment?.ca === 'vigil').length;

  const caDaysLeft = ca ? daysUntil(ca.validTo) : 0;
  const caPct = ca ? pctUsed(ca.validFrom, ca.validTo) : 0;

  function toggleSort(key: SortKey): void {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  function handleCopyPem(): void {
    if (!ca?.certPem) return;
    void navigator.clipboard.writeText(ca.certPem);
    setToast({ msg: 'CA PEM copied to clipboard' });
  }

  function handleDownloadPem(): void {
    if (!ca?.certPem) return;
    const blob = new Blob([ca.certPem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vigil-ca.pem';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <Topbar title="Vigil CA" subtitle="Internal Certificate Authority" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}
        {toast && <div className={`toast${toast.error ? ' toast-error' : ''}`}>{toast.msg}</div>}

        {/* Stats */}
        <div className="stats-row stats-4">
          <StatBox
            value={ca ? caDaysLeft : '—'}
            label="Days remaining (CA)"
            tone={caDaysLeft > 0 && caDaysLeft < 90 ? 'yellow' : 'green'}
          />
          <StatBox value={vigilStats?.total ?? vigilCertCount} label="Issued certs" />
          <StatBox
            value={vigilStats?.active ?? (vigilCertCount - (vigilStats?.revoked ?? 0))}
            label="Active"
            tone="green"
          />
          <StatBox value={expiringCount} label="Expiring ≤30d" tone={expiringCount > 0 ? 'yellow' : 'default'} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          {/* CA Identity */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">CA Identity</span>
              <StatusBadge label="Active" tone="green" />
            </div>
            <div className="card-body">
              {!ca && <p className="text-muted" style={{ fontSize: 12 }}>Loading…</p>}
              {ca && (
                <div>
                  {(
                    [
                      ['Subject', ca.subject, false],
                      ['Serial', ca.serialNumber, true],
                      ['Valid From', ca.validFrom ? ca.validFrom.slice(0, 10) : '—', false],
                      ['Valid To',   ca.validTo   ? ca.validTo.slice(0, 10)   : '—', false],
                      ['SHA-256', ca.fingerprint256, true],
                    ] as [string, string, boolean][]
                  ).map(([label, value, mono]) => (
                    <div className="field-row" key={label}>
                      <span className="field-label">{label}</span>
                      <span className={`field-value${mono ? ' mono' : ''}`}>{value}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Validity + PEM */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="card">
              <div className="card-header"><span className="card-title">Validity</span></div>
              <div className="card-body">
                {!ca && <p className="text-muted" style={{ fontSize: 12 }}>Loading…</p>}
                {ca && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                      <div>
                        <div style={{ fontSize: 24, fontWeight: 700, color: caDaysLeft < 90 ? 'var(--yellow)' : 'var(--green)' }}>
                          {caDaysLeft}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--muted)' }}>days remaining</div>
                      </div>
                      <div style={{ textAlign: 'right', fontSize: 11, color: 'var(--muted)' }}>
                        {caPct}% of lifetime used
                      </div>
                    </div>
                    <div style={{ height: 8, background: 'var(--surface2)', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: `${100 - caPct}%`,
                        background: caDaysLeft < 90 ? 'var(--yellow)' : 'var(--green)',
                        borderRadius: 4,
                      }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--muted)' }}>
                      <span>{ca.validFrom ? ca.validFrom.slice(0, 10) : ''}</span>
                      <span>{ca.validTo ? ca.validTo.slice(0, 10) : ''}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span className="card-title">CA Certificate (PEM)</span>
                <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setPemVisible((v) => !v)}>
                  {pemVisible ? 'Hide' : 'Show'}
                </button>
                <button className="btn btn-ghost btn-sm" onClick={handleCopyPem} disabled={!ca?.certPem}>Copy</button>
                <button className="btn btn-ghost btn-sm" onClick={handleDownloadPem} disabled={!ca?.certPem}>⬇ Download</button>
              </div>
              {pemVisible && (
                <div className="card-body">
                  {ca?.certPem
                    ? <pre className="pem-block">{ca.certPem}</pre>
                    : <p className="text-muted" style={{ fontSize: 12 }}>PEM not available from Vigil /ca endpoint.</p>
                  }
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Issued certs */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Vigil-Issued Certificates</span>
            <span className="card-subtitle">{vigilFlockCerts.length} active in fleet</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="th-sort" onClick={() => toggleSort('certName')}>Cert Name <span>{sortIndicator(sort.key === 'certName', sort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleSort('corgi')}>Corgi <span>{sortIndicator(sort.key === 'corgi', sort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleSort('domain')}>Domain <span>{sortIndicator(sort.key === 'domain', sort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleSort('daysLeft')}>Days Left <span>{sortIndicator(sort.key === 'daysLeft', sort.dir)}</span></th>
                  <th className="th-sort" onClick={() => toggleSort('status')}>Status <span>{sortIndicator(sort.key === 'status', sort.dir)}</span></th>
                </tr>
              </thead>
              <tbody>
                {sortedVigilFlockCerts.length === 0 && (
                  <tr><td colSpan={5} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No Vigil-issued certs found in fleet</td></tr>
                )}
                {sortedVigilFlockCerts.map(({ corgi, cert, daysLeft }) => {
                  const tone = certTone(cert.status, daysLeft);
                  const label = tone === 'yellow' ? `Expiring ${daysLeft}d` : tone === 'red' ? 'Error' : 'Valid';
                  return (
                    <tr key={`${corgi}:${cert.name}`}>
                      <td className="fw-500">{cert.name}</td>
                      <td className="text-muted">{corgi}</td>
                      <td className="text-muted">{cert.sanNames[0] ?? '—'}</td>
                      <td className={tone === 'green' ? 'text-green' : tone === 'yellow' ? 'text-yellow' : 'text-red'}>
                        {daysLeft > 0 && daysLeft < 999 ? daysLeft : '—'}
                      </td>
                      <td><StatusBadge label={label} tone={tone} /></td>
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
