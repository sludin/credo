// src/pages/Certificates.tsx
import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { usePoller } from '../hooks/usePoller';
import { fetchFlock, fetchCerts, fetchCertDetails, fetchLastJob, fetchActiveJob, fetchAssignments, renewCert } from '../api';
import { StatusBadge, certTone } from '../components/StatusBadge';
import { Topbar } from '../components/Shell';
import { usePermission } from '../hooks/usePermission';
import type { CorgiState, CertStoreEntry, FlockCert, CertX509Details, LastRenewalJob, Assignment } from '../types';

/** "Apr 30 14:51:20 2027 GMT" → "Apr 30 2027" (handles single-digit day padding) */
function fmtDate(s: string | undefined): string {
  if (!s) return '—';
  const p = s.split(' ').filter(Boolean);
  return p.length >= 4 ? `${p[0]} ${p[1]}, ${p[3]}` : s;
}

type CertRow = {
  certName: string;
  corgi: string;
  ca: string;
  domain: string;
  sanNames: string[];
  daysLeft: number;
  validTo: string;
  status: FlockCert['status'];
  fingerprint256: string;
};

type SortDir = 'asc' | 'desc';
type CertSortKey = 'domain' | 'corgi' | 'ca' | 'daysLeft' | 'expires' | 'status';


type InspectTab = 'structured' | 'raw' | 'pem';

type SanMismatch = {
  hasMismatch: boolean;
  configuredSans: string[];
  actualSans: string[];
  missing: string[];
  extra: string[];
};

function computeSanMismatch(
  configuredDomain: string | undefined,
  configuredSans: string[] | undefined,
  actualSans: string[],
): SanMismatch {
  const configured = [...new Set([configuredDomain, ...(configuredSans ?? [])].filter(Boolean) as string[])].sort();
  const actual = [...actualSans].sort();
  const configSet = new Set(configured);
  const actualSet = new Set(actual);
  const missing = configured.filter(s => !actualSet.has(s));
  const extra = actual.filter(s => !configSet.has(s));
  return { hasMismatch: missing.length > 0 || extra.length > 0, configuredSans: configured, actualSans: actual, missing, extra };
}

/** Extract DNS SAN hostnames from a subjectAltName string ("DNS:foo.com, URI:..., DNS:bar.com" → ["foo.com","bar.com"]). */
function parseDnsSans(subjectAltName: string | null | undefined): string[] {
  if (!subjectAltName) return [];
  return subjectAltName.split(',').map(s => s.trim()).filter(s => s.startsWith('DNS:')).map(s => s.slice(4));
}

/** Format a hex serial number as colon-separated pairs (openssl style). */
function formatSerial(hex: string): string {
  return hex.replace(/../g, (b, i) => (i === 0 ? b : `:${b}`));
}

function buildRawText(details: CertX509Details): string {
  const lines: string[] = [
    'Certificate:',
    '    Data:',
    '        Version: 3 (0x2)',
    `        Serial Number: ${formatSerial(details.serialNumber)}`,
    '        Issuer:',
    `            ${details.issuer.replace(/\n/g, '\n            ')}`,
    '        Validity',
    `            Not Before: ${details.validFrom}`,
    `            Not After : ${details.validTo}`,
    '        Subject:',
    `            ${details.subject.replace(/\n/g, '\n            ')}`,
  ];

  if (details.subjectAltName) {
    lines.push('        X509v3 extensions:');
    lines.push('            X509v3 Subject Alternative Name:');
    lines.push(`                ${details.subjectAltName}`);
  }

  if (details.ca) {
    lines.push('            X509v3 Basic Constraints: critical');
    lines.push('                CA:TRUE');
  }

  lines.push('');
  lines.push(`    SHA-1  Fingerprint: ${details.fingerprint}`);
  lines.push(`    SHA-256 Fingerprint: ${details.fingerprint256}`);

  return lines.join('\n');
}

/** Format ISO timestamp as "HH:MM:SS" for trace display. */
function fmtTraceTime(iso: string): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

function formatTraceLine(e: LastRenewalJob['trace'][number]): string {
  const parts = [e.step];
  if (e.identifier) parts.push(e.identifier);
  if (e.detail) parts.push(e.detail);
  if (e.status) parts.push(`[${e.status}]`);
  return `[${fmtTraceTime(e.at)}] ${parts.join('  ')}`;
}

const PHASE_LABELS: Record<string, string> = {
  queued: 'Queued',
  validating: 'Validating domains',
  ordering: 'Placing ACME order',
  issuing: 'Issuing certificate',
  installing: 'Installing certificate',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

function ActiveJobSection({ job }: { job: LastRenewalJob }): React.ReactElement {
  const phaseLabel = PHASE_LABELS[job.phase] ?? job.phase;
  const domainCount = job.domains?.length ?? 0;
  const succeededCount = job.domainStatus
    ? Object.values(job.domainStatus).filter(s => s === 'succeeded').length
    : 0;

  return (
    <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border, #333)' }}>
      <div className="field-row">
        <span className="field-label">Renewing</span>
        <span className="field-value" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span
            style={{
              display: 'inline-block',
              width: 8, height: 8, borderRadius: '50%',
              background: 'var(--color-warn, #ff9800)',
              animation: 'pulse 1.2s ease-in-out infinite',
            }}
          />
          <span style={{ fontWeight: 500 }}>{phaseLabel}</span>
        </span>
      </div>
      {job.currentDomain && (
        <div className="field-row">
          <span className="field-label">Domain</span>
          <span className="field-value mono" style={{ fontSize: 12 }}>
            {job.currentDomain}
            {job.domainStatus?.[job.currentDomain] && (
              <span className="text-muted" style={{ marginLeft: 6 }}>
                ({job.domainStatus[job.currentDomain]})
              </span>
            )}
          </span>
        </div>
      )}
      {domainCount > 0 && (
        <div className="field-row">
          <span className="field-label">Progress</span>
          <span className="field-value text-muted" style={{ fontSize: 12 }}>
            {succeededCount} / {domainCount} domains
          </span>
        </div>
      )}
    </div>
  );
}

function LastJobSection({
  job,
  expanded,
  onToggle,
}: {
  job: LastRenewalJob;
  expanded: boolean;
  onToggle: () => void;
}): React.ReactElement {
  const phaseColor =
    job.phase === 'completed' ? 'var(--color-ok, #4caf50)' :
    job.phase === 'failed' ? 'var(--color-error, #f44336)' :
    'var(--color-muted, #888)';

  const jobDate = new Date(job.updatedAt).toLocaleDateString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
  });

  return (
    <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border, #333)' }}>
      <div className="field-row">
        <span className="field-label">Last Job</span>
        <span className="field-value">
          <span style={{ color: phaseColor, fontWeight: 500 }}>{job.phase}</span>
          <span className="text-muted" style={{ marginLeft: 8, fontSize: 11 }}>{jobDate}</span>
        </span>
      </div>
      {job.phase === 'completed' && job.result && (
        <div className="field-row">
          <span className="field-label">Result</span>
          <span className="field-value">
            {job.result.issued ? (job.result.changed ? 'renewed' : 'already up-to-date') : 'not issued'}
          </span>
        </div>
      )}
      {job.error && (
        <div className="field-row" style={{ alignItems: 'flex-start' }}>
          <span className="field-label">Error</span>
          <span className="field-value mono" style={{ color: phaseColor, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {job.error}
          </span>
        </div>
      )}
      {job.trace.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={onToggle}
            style={{ fontSize: 11 }}
          >
            {expanded ? '▲ Hide logs' : `▼ Show logs (${job.trace.length} entries)`}
          </button>
          {expanded && (
            <pre
              className="pem-block"
              style={{ marginTop: 6, fontSize: 11, maxHeight: 320, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
            >
              {job.trace.map(formatTraceLine).join('\n')}
            </pre>
          )}
          {!expanded && job.phase === 'failed' && job.trace.length > 0 && (
            <pre
              className="pem-block"
              style={{ marginTop: 6, fontSize: 11, maxHeight: 120, overflowY: 'auto', opacity: 0.85, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
            >
              {job.trace.slice(-5).map(formatTraceLine).join('\n')}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function Certificates(): React.ReactElement {
  const [searchParams] = useSearchParams();
  const autoSelectCert = searchParams.get('cert');
  const initDoneRef = useRef(false);

  const canRenew = usePermission('cert:renew');

  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  const [certEntries, setCertEntries] = useState<CertStoreEntry[]>([]);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<CertRow | null>(null);
  const [inspectTab, setInspectTab] = useState<InspectTab>('structured');
  const [certDetails, setCertDetails] = useState<CertX509Details | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [lastJob, setLastJob] = useState<LastRenewalJob | null | undefined>(undefined);
  const [logsExpanded, setLogsExpanded] = useState(false);
  const [activeJob, setActiveJob] = useState<LastRenewalJob | null>(null);
  const activeJobRef = useRef<LastRenewalJob | null>(null);
  const activeJobTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sort, setSort] = useState<{ key: CertSortKey; dir: SortDir }>({ key: 'daysLeft', dir: 'asc' });

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const [f, c, a] = await Promise.all([fetchFlock(), fetchCerts(), fetchAssignments()]);
      setCorgis(f.corgis);
      setCertEntries(c.entries);
      setAssignments(a.assignments);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  const rows: CertRow[] = corgis.flatMap((corgi) =>
    corgi.flock.map((cert) => {
      const store = certEntries.find((e) => e.certName === cert.name);
      return {
        certName: cert.name,
        corgi: corgi.name,
        ca: store?.assignment?.ca ?? '—',
        domain: cert.sanNames[0] ?? cert.name,
        sanNames: cert.sanNames,
        daysLeft: Number.isFinite(cert.lifetimeDays)
            ? Math.floor(cert.lifetimeDays)
            : cert.validTo
              ? Math.floor((new Date(cert.validTo).getTime() - Date.now()) / 86400000)
              : -1,
        validTo: cert.validTo ?? '',
        status: cert.status,
        fingerprint256: cert.fingerprint256 ?? '',
      };
    })
  );

  // Pre-select cert from URL param (e.g. navigated from Overview or Corgis)
  useEffect(() => {
    if (!autoSelectCert || initDoneRef.current || rows.length === 0) return;
    const match = rows.find((r) => r.certName === autoSelectCert);
    if (match) {
      setSelected(match);
      initDoneRef.current = true;
    }
  }, [rows, autoSelectCert]);

  const filtered = filter
    ? rows.filter((r) =>
        r.certName.toLowerCase().includes(filter.toLowerCase()) ||
        r.domain.toLowerCase().includes(filter.toLowerCase()) ||
        r.corgi.toLowerCase().includes(filter.toLowerCase())
      )
    : rows;

  const sorted = [...filtered].sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'domain': cmp = a.domain.localeCompare(b.domain); break;
      case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
      case 'ca': cmp = a.ca.localeCompare(b.ca); break;
      case 'daysLeft': cmp = a.daysLeft - b.daysLeft; break;
      case 'expires': cmp = (a.validTo ? new Date(a.validTo).getTime() : Number.MAX_SAFE_INTEGER) - (b.validTo ? new Date(b.validTo).getTime() : Number.MAX_SAFE_INTEGER); break;
      case 'status': cmp = a.status.localeCompare(b.status); break;
    }
    return sort.dir === 'asc' ? cmp : -cmp;
  });

  function toggleSort(key: CertSortKey): void {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  function handleSelectRow(row: CertRow): void {
    if (selected?.certName === row.certName) {
      setSelected(null);
      return;
    }
    setSelected(row);
    setInspectTab('structured');
    setCertDetails(null);
    setLastJob(undefined);
    setLogsExpanded(false);
    setActiveJob(null);
    activeJobRef.current = null;
  }

  useEffect(() => {
    if (selected) {
      void loadDetails(selected.certName);
      void fetchLastJob(selected.certName)
        .then(job => setLastJob(job))
        .catch(() => setLastJob(null));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.certName]);

  // Poll active job while a cert is selected
  useEffect(() => {
    if (activeJobTimerRef.current) {
      clearInterval(activeJobTimerRef.current);
      activeJobTimerRef.current = null;
    }
    if (!selected) return;

    const TERMINAL = ['completed', 'failed', 'cancelled'];
    const certName = selected.certName;

    async function pollActive(): Promise<void> {
      try {
        const job = await fetchActiveJob(certName);
        activeJobRef.current = job;
        setActiveJob(job);
        if (!job || TERMINAL.includes(job.phase)) {
          // Job finished — reload last-job to pick up the new terminal record
          void fetchLastJob(certName)
            .then(j => setLastJob(j))
            .catch(() => {});
          if (activeJobTimerRef.current) {
            clearInterval(activeJobTimerRef.current);
            activeJobTimerRef.current = null;
          }
        }
      } catch { /* ignore */ }
    }

    void pollActive();
    activeJobTimerRef.current = setInterval(() => { void pollActive(); }, 2000);
    return () => {
      if (activeJobTimerRef.current) {
        clearInterval(activeJobTimerRef.current);
        activeJobTimerRef.current = null;
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.certName]);

  async function loadDetails(certName: string): Promise<void> {
    if (certDetails !== null || detailsLoading) return;
    setDetailsLoading(true);
    setToast(null);
    try {
      const d = await fetchCertDetails(certName);
      setCertDetails(d);
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : 'Failed to load cert details', error: true });
    } finally {
      setDetailsLoading(false);
    }
  }

  async function handleRenew(): Promise<void> {
    if (!selected?.corgi) return;
    setRenewing(true);
    setToast(null);
    try {
      await renewCert(selected.certName, selected.corgi);
      setToast({ msg: `Renewal triggered for ${selected.certName}` });
      refresh();
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : 'Failed to trigger renewal', error: true });
    } finally {
      setRenewing(false);
    }
  }

  function handleDownloadPem(): void {
    if (!certDetails?.pem || !selected) return;
    const blob = new Blob([certDetails.pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selected.certName}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleCopyPem(): void {
    if (!certDetails?.pem) return;
    void navigator.clipboard.writeText(certDetails.pem);
    setToast({ msg: 'PEM copied to clipboard' });
  }

  return (
    <>
      <Topbar title="Certificates" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div className="page-content" style={{ flexDirection: 'row', gap: 14, overflow: 'hidden', padding: 0 }}>
        {/* Left: cert table */}
        <div style={{ flex: selected ? '1 1 55%' : '1', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 0 14px 16px' }}>
          {error && <div className="toast toast-error" style={{ marginBottom: 10 }}>{error}</div>}
          {toast && <div className={`toast${toast.error ? ' toast-error' : ''}`}>{toast.msg}</div>}

          <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div className="filter-bar">
              <input
                className="filter-input"
                placeholder="Filter by domain, cert name, or corgi…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            </div>
            <div className="table-wrap" style={{ flex: 1, overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th className="th-sort" onClick={() => toggleSort('domain')}>Domain / Cert <span>{sortIndicator(sort.key === 'domain', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('corgi')}>Corgi <span>{sortIndicator(sort.key === 'corgi', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('ca')}>CA <span>{sortIndicator(sort.key === 'ca', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('daysLeft')}>Days Left <span>{sortIndicator(sort.key === 'daysLeft', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('expires')}>Expires <span>{sortIndicator(sort.key === 'expires', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('status')}>Status <span>{sortIndicator(sort.key === 'status', sort.dir)}</span></th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.length === 0 && (
                    <tr><td colSpan={6} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No certs</td></tr>
                  )}
                  {sorted.map((row) => {
                    const tone = certTone(row.status, row.daysLeft);
                    const label = tone === 'yellow' ? `Expiring ${row.daysLeft}d` : tone === 'red' ? 'Error' : 'Valid';
                    const assignment = assignments.find(a => a.certName === row.certName);
                    // Only compare when FlockCert reports SANs; empty sanNames means
                    // the corgi implementation didn't populate it (e.g. Rust corgi) — not reliable.
                    const mismatch = assignment && row.sanNames.length > 0
                      ? computeSanMismatch(assignment.domain ?? assignment.certName, assignment.sans, row.sanNames)
                      : null;
                    return (
                      <tr
                        key={`${row.corgi}:${row.certName}`}
                        className={`clickable${selected?.certName === row.certName ? ' expanded' : ''}`}
                        onClick={() => handleSelectRow(row)}
                      >
                        <td className="fw-500">
                          {row.domain}
                          {mismatch?.hasMismatch && (
                            <span
                              title="Config mismatch: configured SANs differ from cert SANs"
                              style={{ marginLeft: 6, color: 'var(--color-warn, #ff9800)', fontSize: 12, cursor: 'default' }}
                            >⚠</span>
                          )}
                        </td>
                        <td className="text-muted">{row.corgi}</td>
                        <td className="text-muted">{row.ca}</td>
                        <td className={tone === 'green' ? 'text-green' : tone === 'yellow' ? 'text-yellow' : 'text-red'}>
                          {row.daysLeft > 0 ? row.daysLeft : '—'}
                        </td>
                        <td className="text-muted">{fmtDate(row.validTo)}</td>
                        <td><StatusBadge label={label} tone={tone} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right: inspect panel */}
        {selected && (
          <div style={{ flex: '0 0 42%', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 16px 14px 0' }}>
            <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div className="card-header">
                <span className="card-title" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{selected.domain}</span>
                {canRenew && selected.corgi && (
                  <button
                    className="btn btn-sm"
                    style={{ marginLeft: 'auto', marginRight: 6 }}
                    onClick={() => { void handleRenew(); }}
                    disabled={renewing}
                  >
                    {renewing ? 'Renewing…' : 'Renew'}
                  </button>
                )}
                <button
                  className="btn btn-ghost btn-sm"
                  style={canRenew && selected.corgi ? undefined : { marginLeft: 'auto' }}
                  onClick={() => setSelected(null)}
                >
                  ✕
                </button>
              </div>

              <div className="tab-strip">
                {(['structured', 'raw', 'pem'] as InspectTab[]).map((tab) => (
                  <button
                    key={tab}
                    className={`tab-btn${inspectTab === tab ? ' active' : ''}`}
                    onClick={() => {
                      setInspectTab(tab);
                      if (selected) {
                        void loadDetails(selected.certName);
                      }
                    }}
                  >
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
                  </button>
                ))}
              </div>

              <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
                {inspectTab === 'structured' && (
                  <div>
                    {(
                      [
                        ['Cert Name', selected.certName, false],
                        ['Corgi', selected.corgi, false],
                        ['CA', selected.ca, false],
                        ['Domain', selected.domain, false],
                        ['SANs', selected.sanNames.join(', '), false],
                        ['Days Left', String(selected.daysLeft < 999 ? selected.daysLeft : '—'), false],
                        ['Valid To', selected.validTo || '—', false],
                        ['SHA-256', selected.fingerprint256 || '—', true],
                        ...(certDetails ? [['Issuer', certDetails.issuer, false] as [string, string, boolean]] : []),
                        ...(certDetails?.subjectAltName
                          ? certDetails.subjectAltName
                              .split(',')
                              .map((s) => s.trim())
                              .filter((s) => s.startsWith('URI:'))
                              .map((s) => ['URI', s.slice(4), true] as [string, string, boolean])
                          : []),
                      ] as [string, string, boolean][]
                    ).map(([label, value, mono], i) => (
                      <div className="field-row" key={`${label}-${i}`}>
                        <span className="field-label">{label}</span>
                        <span className={`field-value${mono ? ' mono' : ''}`}>{value}</span>
                      </div>
                    ))}
                    {(() => {
                      const assignment = assignments.find(a => a.certName === selected.certName);
                      if (!assignment) return null;
                      // Use BFF-parsed cert details for SAN comparison — accurate regardless
                      // of SAN ordering in the cert (avoids false positives from Rust corgi).
                      const actualDnsSans = certDetails ? parseDnsSans(certDetails.subjectAltName) : null;
                      const mismatch = actualDnsSans
                        ? computeSanMismatch(assignment.domain ?? assignment.certName, assignment.sans, actualDnsSans)
                        : null;
                      return (
                        <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border, #333)' }}>
                          <div className="field-row" style={{ marginBottom: 4 }}>
                            <span className="field-label" style={{ fontWeight: 600 }}>Config vs. Cert</span>
                            <span className="field-value" style={{ fontSize: 11, color: mismatch ? (mismatch.hasMismatch ? 'var(--color-warn, #ff9800)' : 'var(--color-ok, #4caf50)') : 'var(--color-muted, #888)' }}>
                              {mismatch ? (mismatch.hasMismatch ? '⚠ Mismatch detected' : '✓ Config matches cert') : 'Loading…'}
                            </span>
                          </div>
                          {mismatch?.hasMismatch && (
                            <>
                              {mismatch.missing.length > 0 && (
                                <div className="field-row" style={{ alignItems: 'flex-start' }}>
                                  <span className="field-label">Missing SANs</span>
                                  <span className="field-value mono" style={{ fontSize: 11, color: 'var(--color-warn, #ff9800)', whiteSpace: 'pre-wrap' }}>
                                    {mismatch.missing.join('\n')}
                                  </span>
                                </div>
                              )}
                              {mismatch.extra.length > 0 && (
                                <div className="field-row" style={{ alignItems: 'flex-start' }}>
                                  <span className="field-label">Extra SANs</span>
                                  <span className="field-value mono" style={{ fontSize: 11, color: 'var(--color-muted, #888)', whiteSpace: 'pre-wrap' }}>
                                    {mismatch.extra.join('\n')}
                                  </span>
                                </div>
                              )}
                            </>
                          )}
                          {certDetails && (
                            <div className="field-row">
                              <span className="field-label">Cert Issuer</span>
                              <span className="field-value mono" style={{ fontSize: 11 }}>{certDetails.issuer}</span>
                            </div>
                          )}
                        </div>
                      );
                    })()}
                    {activeJob && (
                      <ActiveJobSection job={activeJob} />
                    )}
                    {!activeJob && lastJob && (
                      <LastJobSection job={lastJob} expanded={logsExpanded} onToggle={() => setLogsExpanded(v => !v)} />
                    )}
                  </div>
                )}

                {inspectTab === 'raw' && (
                  <div>
                    {detailsLoading && <p className="text-muted" style={{ fontSize: 12 }}>Loading…</p>}
                    {certDetails && (
                      <pre className="pem-block" style={{ maxHeight: 'none' }}>
                        {buildRawText(certDetails)}
                      </pre>
                    )}
                    {!certDetails && !detailsLoading && (
                      <p className="text-muted" style={{ fontSize: 12 }}>
                        Certificate file not available from certstore.
                      </p>
                    )}
                  </div>
                )}

                {inspectTab === 'pem' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn-ghost btn-sm" onClick={handleCopyPem} disabled={!certDetails?.pem}>
                        Copy
                      </button>
                      <button className="btn btn-ghost btn-sm" onClick={handleDownloadPem} disabled={!certDetails?.pem}>
                        ⬇ Download
                      </button>
                    </div>
                    {detailsLoading && <p className="text-muted" style={{ fontSize: 12 }}>Loading…</p>}
                    {certDetails?.pem && <pre className="pem-block">{certDetails.pem}</pre>}
                    {!certDetails?.pem && !detailsLoading && (
                      <p className="text-muted" style={{ fontSize: 12 }}>
                        Certificate file not available from certstore.
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
