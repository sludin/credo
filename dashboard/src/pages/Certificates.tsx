// src/pages/Certificates.tsx
import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { usePoller } from '../hooks/usePoller';
import {
  fetchAssignments,
  fetchCerts,
  fetchFlock,
  fetchActiveJobs,
  fetchCertDetails,
  fetchLastJob,
  fetchActiveJob,
  fetchRateLimits,
  fetchShepherdConfigSummary,
  fetchCorgiHooks,
  renewCert,
  createAssignment,
  updateAssignment,
  deleteAssignment,
} from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { Topbar } from '../components/Shell';
import { usePermission } from '../hooks/usePermission';
import type {
  Assignment,
  CertStoreEntry,
  CertX509Details,
  DomainQuotaStatus,
  FlockCert,
  IdentifierSetQuotaStatus,
  LastRenewalJob,
  RateLimitsPayload,
  ShepherdConfigSummary,
} from '../types';

// ── Types ──────────────────────────────────────────────────────────────────

type UnifiedStatus = 'valid' | 'renewing' | 'expiring' | 'diff' | 'none' | 'error';

type UnifiedCertRow = {
  certName: string;
  corgi: string;
  ca: string;
  domain: string;
  assignment: Assignment;
  flockCert: FlockCert | null;
  certEntry: CertStoreEntry | null;
  daysLeft: number | null;
  validTo: string | null;
  status: UnifiedStatus;
  sanNames: string[];
  fingerprint256: string;
};

type PanelMode = 'detail' | 'none-info' | 'edit' | 'new';

type SortDir = 'asc' | 'desc';
type SortKey = 'name' | 'corgi' | 'ca' | 'status' | 'expires';

type InspectTab = 'structured' | 'raw' | 'pem';

type CaInfo = ShepherdConfigSummary['cas'][number];

type FormState = {
  certName: string;
  corgi: string;
  ca: string;
  caTarget: string;
  letsEncryptTarget: string;
  domain: string;
  identityUri: string;
  sans: string;
  days: string;
  renewBeforeDays: string;
  validationType: 'none-01' | 'http-01' | 'dns-01';
  validationProvider: string;
  validationDdnsKey: string;
  hooks: string[];
};

const emptyForm: FormState = {
  certName: '', corgi: '', ca: 'letsencrypt', caTarget: '',
  letsEncryptTarget: '', domain: '', identityUri: '', sans: '',
  days: '90', renewBeforeDays: '30',
  validationType: 'none-01', validationProvider: '', validationDdnsKey: '',
  hooks: [],
};

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtDate(s: string | undefined | null): string {
  if (!s) return '—';
  const p = s.split(' ').filter(Boolean);
  return p.length >= 4 ? `${p[0]} ${p[1]}, ${p[3]}` : s;
}

function parseDnsSans(subjectAltName: string | null | undefined): string[] {
  if (!subjectAltName) return [];
  return subjectAltName.split(',').map(s => s.trim()).filter(s => s.startsWith('DNS:')).map(s => s.slice(4));
}

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

function fmtTraceTime(iso: string): string {
  const d = new Date(iso);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0'))
    .join(':');
}

function formatTraceLine(e: LastRenewalJob['trace'][number]): string {
  const parts = [e.step];
  if (e.identifier) parts.push(e.identifier);
  if (e.detail) parts.push(e.detail);
  if (e.status) parts.push(`[${e.status}]`);
  return `[${fmtTraceTime(e.at)}] ${parts.join('  ')}`;
}

function assignmentToForm(a: Assignment): FormState {
  return {
    certName: a.certName,
    corgi: a.corgi,
    ca: a.ca ?? 'letsencrypt',
    caTarget: a.caTarget ?? '',
    letsEncryptTarget: a.letsEncryptTarget ?? '',
    domain: a.domain ?? '',
    identityUri: a.identityUri ?? '',
    sans: (a.sans ?? []).join('\n'),
    days: String(a.days ?? 90),
    renewBeforeDays: String(a.renewBeforeDays ?? 30),
    validationType: a.validation?.type === 'auto' ? 'none-01' : (a.validation?.type ?? 'none-01'),
    validationProvider: (a.validation?.methods?.['dns-01']?.provider ?? '') as string,
    validationDdnsKey: (a.validation?.methods?.['dns-01']?.providerConfig?.['ddnsKey'] ?? '') as string,
    hooks: a.hooks ?? [],
  };
}

function toAssignmentPayload(form: FormState): Record<string, unknown> {
  const sans = form.sans.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const daysNum = Number(form.days);
  const renewBeforeNum = Number(form.renewBeforeDays);
  const payload: Record<string, unknown> = {
    certName: form.certName.trim(),
    corgi: form.corgi.trim(),
    ca: form.ca.trim(),
    caTarget: form.caTarget.trim() || undefined,
    letsEncryptTarget: form.letsEncryptTarget.trim() || undefined,
    domain: form.domain.trim() || undefined,
    identityUri: form.identityUri.trim() || undefined,
    sans: sans.length > 0 ? sans : undefined,
    days: Number.isFinite(daysNum) && daysNum > 0 ? Math.floor(daysNum) : undefined,
    renewBeforeDays: Number.isFinite(renewBeforeNum) && renewBeforeNum > 0 ? Math.floor(renewBeforeNum) : undefined,
  };
  if (form.validationType !== 'none-01') {
    payload.validation = {
      type: form.validationType,
      methods: form.validationType === 'dns-01'
        ? { 'dns-01': { provider: form.validationProvider.trim() || undefined, providerConfig: form.validationDdnsKey.trim() ? { ddnsKey: form.validationDdnsKey.trim() } : undefined } }
        : undefined,
    };
  }
  if (form.hooks.length > 0) {
    payload.hooks = form.hooks;
  }
  Object.keys(payload).forEach(k => { if (payload[k] === undefined) delete payload[k]; });
  return payload;
}

function deriveStatus(
  assignment: Assignment,
  flockCert: FlockCert | null,
  certEntry: CertStoreEntry | null,
  daysLeft: number | null,
  isRenewing: boolean,
  actualDnsSans: string[] | null,
): UnifiedStatus {
  if (isRenewing) return 'renewing';
  if (!flockCert && !certEntry?.exists) return 'none';
  if (flockCert?.status === 'not-ok') return 'error';
  if (daysLeft !== null && daysLeft < 0) return 'error';
  // SAN mismatch check
  if (actualDnsSans && actualDnsSans.length > 0) {
    const configuredSans = [...new Set([assignment.domain ?? assignment.certName, ...(assignment.sans ?? [])].filter(Boolean) as string[])];
    const configSet = new Set(configuredSans);
    const actualSet = new Set(actualDnsSans);
    const hasMismatch = configuredSans.some(s => !actualSet.has(s)) || actualDnsSans.some(s => !configSet.has(s));
    if (hasMismatch) return 'diff';
  }
  const renewBefore = assignment.renewBeforeDays ?? 30;
  if (daysLeft !== null && daysLeft <= renewBefore) return 'expiring';
  return 'valid';
}

function statusTone(s: UnifiedStatus): 'green' | 'yellow' | 'red' | 'blue' | 'muted' {
  if (s === 'valid') return 'green';
  if (s === 'expiring' || s === 'diff') return 'yellow';
  if (s === 'error') return 'red';
  if (s === 'renewing') return 'blue';
  return 'muted';
}

function statusLabel(s: UnifiedStatus, daysLeft: number | null): string {
  if (s === 'valid') return 'Valid';
  if (s === 'expiring') return daysLeft !== null ? `Expiring ${daysLeft}d` : 'Expiring';
  if (s === 'diff') return 'Diff';
  if (s === 'error') return 'Error';
  if (s === 'renewing') return 'Renewing';
  return 'None';
}

const PHASE_LABELS: Record<string, string> = {
  queued: 'Queued', validating: 'Validating domains', ordering: 'Placing ACME order',
  issuing: 'Issuing certificate', installing: 'Installing certificate',
  completed: 'Completed', failed: 'Failed', cancelled: 'Cancelled',
};

// ── Sub-components ─────────────────────────────────────────────────────────

function RateLimitsSection({ data }: { data: RateLimitsPayload }): React.ReactElement | null {
  const [open, setOpen] = React.useState(false);

  const atRisk = data.domainQuotas.some(q => q.issued7d / q.limit7d >= 0.8)
    || data.identifierSetQuotas.some(q => q.issued7d / q.limit7d >= 0.8);
  const gated = data.domainQuotas.some(q => q.nextSlotAt !== null)
    || data.identifierSetQuotas.some(q => q.nextSlotAt !== null);

  if (data.domainQuotas.length === 0 && data.identifierSetQuotas.length === 0) return null;

  const headerColor = gated ? 'var(--red)' : atRisk ? 'var(--yellow)' : 'var(--green)';
  const headerLabel = gated ? '⛔ Rate limited' : atRisk ? '⚠ Approaching limit' : '✓ Within limits';

  function fmtDate(iso: string): string {
    return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function UsageBar({ issued, limit }: { issued: number; limit: number }): React.ReactElement {
    const pct = Math.min(issued / limit, 1) * 100;
    const color = pct >= 100 ? 'var(--red)' : pct >= 80 ? 'var(--yellow)' : 'var(--green)';
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--border)' }}>
          <div style={{ width: `${pct}%`, height: '100%', borderRadius: 3, background: color }} />
        </div>
        <span style={{ fontSize: 11, color, whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
          {issued} / {limit}
        </span>
      </div>
    );
  }

  return (
    <div className="card" style={{ marginTop: 10, flexShrink: 0 }}>
      <div
        className="card-header"
        style={{ cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setOpen(o => !o)}
      >
        <span className="card-title">Rate Limits</span>
        <span style={{ marginLeft: 8, fontSize: 12, color: headerColor }}>{headerLabel}</span>
        <span style={{ marginLeft: 'auto', color: 'var(--muted)', fontSize: 12 }}>{open ? '▲' : '▼'}</span>
      </div>

      {open && (
        <div style={{ padding: '10px 14px' }}>
          {data.domainQuotas.length > 0 && (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Per Registered Domain (50 / 7 days)
              </div>
              <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ color: 'var(--muted)' }}>
                    <th style={{ textAlign: 'left', padding: '2px 6px 2px 0', fontWeight: 500 }}>Domain</th>
                    <th style={{ textAlign: 'left', padding: '2px 6px', fontWeight: 500 }}>CA</th>
                    <th style={{ padding: '2px 0', fontWeight: 500, width: 160 }}>Usage</th>
                    <th style={{ textAlign: 'right', padding: '2px 0 2px 6px', fontWeight: 500 }}>Next Slot</th>
                  </tr>
                </thead>
                <tbody>
                  {data.domainQuotas.map((q: DomainQuotaStatus) => (
                    <tr key={`${q.registeredDomain}:${q.ca}`}>
                      <td style={{ padding: '3px 6px 3px 0', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{q.registeredDomain}</td>
                      <td style={{ padding: '3px 6px', color: 'var(--muted)' }}>{q.ca}</td>
                      <td style={{ padding: '3px 0' }}><UsageBar issued={q.issued7d} limit={q.limit7d} /></td>
                      <td style={{ textAlign: 'right', padding: '3px 0 3px 6px', color: q.nextSlotAt ? 'var(--red)' : 'var(--muted)', fontSize: 11 }}>
                        {q.nextSlotAt ? fmtDate(q.nextSlotAt) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {data.identifierSetQuotas.length > 0 && (
            <div style={{ marginTop: data.domainQuotas.length > 0 ? 14 : 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Per Cert (5 identical SANs / 7 days)
              </div>
              <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ color: 'var(--muted)' }}>
                    <th style={{ textAlign: 'left', padding: '2px 6px 2px 0', fontWeight: 500 }}>Cert</th>
                    <th style={{ textAlign: 'left', padding: '2px 6px', fontWeight: 500 }}>CA</th>
                    <th style={{ padding: '2px 0', fontWeight: 500, width: 120 }}>Usage</th>
                    <th style={{ textAlign: 'right', padding: '2px 0 2px 6px', fontWeight: 500 }}>Next Slot</th>
                  </tr>
                </thead>
                <tbody>
                  {data.identifierSetQuotas.map((q: IdentifierSetQuotaStatus) => (
                    <tr key={q.certName}>
                      <td style={{ padding: '3px 6px 3px 0', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{q.certName}</td>
                      <td style={{ padding: '3px 6px', color: 'var(--muted)' }}>{q.ca}</td>
                      <td style={{ padding: '3px 0' }}><UsageBar issued={q.issued7d} limit={q.limit7d} /></td>
                      <td style={{ textAlign: 'right', padding: '3px 0 3px 6px', color: q.nextSlotAt ? 'var(--red)' : 'var(--muted)', fontSize: 11 }}>
                        {q.nextSlotAt ? fmtDate(q.nextSlotAt) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ActiveJobSection({ job }: { job: LastRenewalJob }): React.ReactElement {
  const phaseLabel = PHASE_LABELS[job.phase] ?? job.phase;
  const domainCount = job.domains?.length ?? 0;
  const succeededCount = job.domainStatus
    ? Object.values(job.domainStatus).filter(s => s === 'succeeded').length
    : 0;
  return (
    <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
      <div className="field-row">
        <span className="field-label">Renewing</span>
        <span className="field-value" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: 'var(--color-warn, #ff9800)', animation: 'pulse 1.2s ease-in-out infinite' }} />
          <span style={{ fontWeight: 500 }}>{phaseLabel}</span>
        </span>
      </div>
      {job.currentDomain && (
        <div className="field-row">
          <span className="field-label">Domain</span>
          <span className="field-value mono" style={{ fontSize: 12 }}>
            {job.currentDomain}
            {job.domainStatus?.[job.currentDomain] && (
              <span className="text-muted" style={{ marginLeft: 6 }}>({job.domainStatus[job.currentDomain]})</span>
            )}
          </span>
        </div>
      )}
      {domainCount > 0 && (
        <div className="field-row">
          <span className="field-label">Progress</span>
          <span className="field-value text-muted" style={{ fontSize: 12 }}>{succeededCount} / {domainCount} domains</span>
        </div>
      )}
    </div>
  );
}

function LastJobSection({ job, expanded, onToggle }: { job: LastRenewalJob; expanded: boolean; onToggle: () => void }): React.ReactElement {
  const phaseColor = job.phase === 'completed' ? 'var(--green)' : job.phase === 'failed' ? 'var(--red)' : 'var(--muted)';
  const jobDate = new Date(job.updatedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  return (
    <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
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
          <span className="field-value">{job.result.issued ? (job.result.changed ? 'renewed' : 'already up-to-date') : 'not issued'}</span>
        </div>
      )}
      {job.error && (
        <div className="field-row" style={{ alignItems: 'flex-start' }}>
          <span className="field-label">Error</span>
          <span className="field-value mono" style={{ color: phaseColor, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{job.error}</span>
        </div>
      )}
      {job.trace.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <button className="btn btn-ghost btn-sm" onClick={onToggle} style={{ fontSize: 11 }}>
            {expanded ? '▲ Hide logs' : `▼ Show logs (${job.trace.length} entries)`}
          </button>
          {expanded && (
            <pre className="pem-block" style={{ marginTop: 6, fontSize: 11, maxHeight: 320, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {job.trace.map(formatTraceLine).join('\n')}
            </pre>
          )}
          {!expanded && job.phase === 'failed' && job.trace.length > 0 && (
            <pre className="pem-block" style={{ marginTop: 6, fontSize: 11, maxHeight: 120, overflowY: 'auto', opacity: 0.85, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {job.trace.slice(-5).map(formatTraceLine).join('\n')}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default function Certificates(): React.ReactElement {
  const [searchParams] = useSearchParams();
  const autoSelectCert = searchParams.get('cert');
  const initDoneRef = useRef(false);

  const canRenew = usePermission('cert:renew');
  const canCreate = usePermission('assignment:create');
  const canEdit = usePermission('assignment:edit');
  const canDelete = usePermission('assignment:delete');

  // Raw data
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [flockMap, setFlockMap] = useState<Map<string, FlockCert>>(new Map());
  const [certEntryMap, setCertEntryMap] = useState<Map<string, CertStoreEntry>>(new Map());
  const [activeJobNames, setActiveJobNames] = useState<Set<string>>(new Set());
  const [caOptions, setCaOptions] = useState<string[]>(['letsencrypt', 'vigil']);
  const [caMap, setCaMap] = useState<Record<string, CaInfo>>({});
  const [corgiNames, setCorgiNames] = useState<string[]>([]);

  // UI state
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'name', dir: 'asc' });
  const [selectedCertName, setSelectedCertName] = useState<string | null>(null);
  const [panelMode, setPanelMode] = useState<PanelMode>('detail');

  // Detail panel state
  const [inspectTab, setInspectTab] = useState<InspectTab>('structured');
  const [certDetails, setCertDetails] = useState<CertX509Details | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [lastJob, setLastJob] = useState<LastRenewalJob | null | undefined>(undefined);
  const [logsExpanded, setLogsExpanded] = useState(false);
  const [activeJob, setActiveJob] = useState<LastRenewalJob | null>(null);
  const activeJobTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Form state
  const [form, setForm] = useState<FormState>(emptyForm);
  const [editTarget, setEditTarget] = useState<{ certName: string; corgi: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [availableHooks, setAvailableHooks] = useState<string[]>([]);
  const [defaultHooks, setDefaultHooks] = useState<string[]>([]);

  // Rate limits
  const [rateLimits, setRateLimits] = useState<RateLimitsPayload | null>(null);

  // Toast / error
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const [a, f, c, jobs, cfg, rl] = await Promise.all([
        fetchAssignments(),
        fetchFlock(),
        fetchCerts(),
        fetchActiveJobs(),
        fetchShepherdConfigSummary(),
        fetchRateLimits().catch(() => null),
      ]);
      setAssignments(a.assignments);

      // Build flock map: certName → FlockCert (across all corgis)
      const fm = new Map<string, FlockCert>();
      for (const corgi of f.corgis) {
        for (const cert of corgi.flock) {
          fm.set(cert.name, cert);
        }
      }
      setFlockMap(fm);

      // Build cert entry map: certName → CertStoreEntry
      const em = new Map<string, CertStoreEntry>();
      for (const entry of c.entries) {
        em.set(entry.certName, entry);
      }
      setCertEntryMap(em);

      // Active job set
      setActiveJobNames(new Set(jobs.map(j => j.certName)));

      // CA options
      const dynamicCas = cfg.cas.map(ca => ca.name).filter(Boolean);
      setCaOptions(dynamicCas.length > 0 ? dynamicCas : ['letsencrypt', 'vigil']);
      const cm: Record<string, CaInfo> = {};
      for (const ca of cfg.cas) cm[ca.name] = ca;
      setCaMap(cm);

      setCorgiNames([...new Set(a.assignments.map(a => a.corgi))]);
      if (rl) setRateLimits(rl);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  // Build unified rows from assignments
  const rows: UnifiedCertRow[] = assignments.map(assignment => {
    const flockCert = flockMap.get(assignment.certName) ?? null;
    const certEntry = certEntryMap.get(assignment.certName) ?? null;
    const isRenewing = activeJobNames.has(assignment.certName);

    const daysLeft: number | null = flockCert
      ? (Number.isFinite(flockCert.lifetimeDays) ? Math.floor(flockCert.lifetimeDays) : null)
      : null;
    const validTo = flockCert?.validTo ?? null;
    const sanNames = flockCert?.sanNames ?? [];
    const fingerprint256 = flockCert?.fingerprint256 ?? assignment.fingerprint256 ?? '';
    const domain = assignment.domain ?? assignment.certName;

    // Use flock SANs for mismatch check when available
    const actualDnsSans = sanNames.length > 0 ? sanNames : null;
    const status = deriveStatus(assignment, flockCert, certEntry, daysLeft, isRenewing, actualDnsSans);

    return {
      certName: assignment.certName,
      corgi: assignment.corgi,
      ca: assignment.ca ?? '—',
      domain,
      assignment,
      flockCert,
      certEntry,
      daysLeft,
      validTo,
      status,
      sanNames,
      fingerprint256,
    };
  });

  // Pre-select from URL param
  useEffect(() => {
    if (!autoSelectCert || initDoneRef.current || rows.length === 0) return;
    const match = rows.find(r => r.certName === autoSelectCert);
    if (match) {
      setSelectedCertName(match.certName);
      setPanelMode(match.status === 'none' ? 'none-info' : 'detail');
      initDoneRef.current = true;
    }
  }, [rows, autoSelectCert]);

  // Filter + sort
  const filtered = filter
    ? rows.filter(r =>
        r.certName.toLowerCase().includes(filter.toLowerCase()) ||
        r.domain.toLowerCase().includes(filter.toLowerCase()) ||
        r.corgi.toLowerCase().includes(filter.toLowerCase())
      )
    : rows;

  const sorted = [...filtered].sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'name': cmp = a.certName.localeCompare(b.certName); break;
      case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
      case 'ca': cmp = a.ca.localeCompare(b.ca); break;
      case 'status': cmp = a.status.localeCompare(b.status); break;
      case 'expires': cmp = (a.daysLeft ?? Infinity) - (b.daysLeft ?? Infinity); break;
    }
    return sort.dir === 'asc' ? cmp : -cmp;
  });

  function toggleSort(key: SortKey): void {
    setSort(prev => prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' });
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  function handleSelectRow(row: UnifiedCertRow): void {
    if (selectedCertName === row.certName && (panelMode === 'detail' || panelMode === 'none-info')) {
      setSelectedCertName(null);
      return;
    }
    setSelectedCertName(row.certName);
    setPanelMode(row.status === 'none' ? 'none-info' : 'detail');
    setInspectTab('structured');
    setCertDetails(null);
    setLastJob(undefined);
    setLogsExpanded(false);
    setActiveJob(null);
    if (activeJobTimerRef.current) clearInterval(activeJobTimerRef.current);
  }

  function openEdit(row: UnifiedCertRow): void {
    setSelectedCertName(row.certName);
    setForm(assignmentToForm(row.assignment));
    setEditTarget({ certName: row.certName, corgi: row.corgi });
    setPanelMode('edit');
    setToast(null);
  }

  function openNew(): void {
    setSelectedCertName(null);
    setForm({ ...emptyForm, corgi: corgiNames[0] ?? '' });
    setEditTarget(null);
    setPanelMode('new');
    setToast(null);
  }

  function closePanel(): void {
    setSelectedCertName(null);
    setPanelMode('detail');
    if (activeJobTimerRef.current) clearInterval(activeJobTimerRef.current);
  }

  function cancelEdit(): void {
    // Go back to detail/none-info if we were editing an existing cert
    if (editTarget) {
      const row = rows.find(r => r.certName === editTarget.certName);
      if (row) {
        setPanelMode(row.status === 'none' ? 'none-info' : 'detail');
        return;
      }
    }
    closePanel();
  }

  // Load cert details + jobs when selected cert changes
  useEffect(() => {
    if (!selectedCertName || panelMode === 'edit' || panelMode === 'new') return;
    void loadCertDetails(selectedCertName);
    void fetchLastJob(selectedCertName)
      .then(job => setLastJob(job))
      .catch(() => setLastJob(null));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCertName, panelMode]);

  // Poll active job for selected cert
  useEffect(() => {
    if (activeJobTimerRef.current) { clearInterval(activeJobTimerRef.current); activeJobTimerRef.current = null; }
    if (!selectedCertName || panelMode === 'edit' || panelMode === 'new') return;
    const TERMINAL = ['completed', 'failed', 'cancelled'];
    const certName = selectedCertName;
    async function pollActive(): Promise<void> {
      try {
        const job = await fetchActiveJob(certName);
        setActiveJob(job);
        if (!job || TERMINAL.includes(job.phase)) {
          void fetchLastJob(certName).then(j => setLastJob(j)).catch(() => {});
          if (activeJobTimerRef.current) { clearInterval(activeJobTimerRef.current); activeJobTimerRef.current = null; }
        }
      } catch { /* ignore */ }
    }
    void pollActive();
    activeJobTimerRef.current = setInterval(() => { void pollActive(); }, 2000);
    return () => { if (activeJobTimerRef.current) { clearInterval(activeJobTimerRef.current); activeJobTimerRef.current = null; } };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCertName, panelMode]);

  // Fetch available hooks when the selected corgi changes
  useEffect(() => {
    if (!form.corgi) { setAvailableHooks([]); setDefaultHooks([]); return; }
    fetchCorgiHooks(form.corgi).then(r => {
      setAvailableHooks(r.availableHooks);
      setDefaultHooks(r.defaultHooks);
    }).catch(() => {
      setAvailableHooks([]);
      setDefaultHooks([]);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.corgi]);

  async function loadCertDetails(certName: string): Promise<void> {
    setCertDetails(null);
    setDetailsLoading(true);
    try {
      const d = await fetchCertDetails(certName);
      setCertDetails(d);
    } catch {
      // cert may not be in store yet
    } finally {
      setDetailsLoading(false);
    }
  }

  async function handleRenew(): Promise<void> {
    if (!selectedCertName) return;
    const row = rows.find(r => r.certName === selectedCertName);
    if (!row?.corgi) return;
    setRenewing(true);
    setToast(null);
    try {
      await renewCert(selectedCertName, row.corgi);
      setToast({ msg: `Renewal triggered for ${selectedCertName}` });
      refresh();
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : 'Failed to trigger renewal', error: true });
    } finally {
      setRenewing(false);
    }
  }

  function handleSave(): void {
    void (async () => {
      const certName = form.certName.trim();
      const corgi = form.corgi.trim();
      if (!certName || !corgi) {
        setToast({ msg: 'Cert Name and Corgi are required.', error: true });
        return;
      }
      setSaving(true);
      try {
        const payload = toAssignmentPayload(form);
        if (panelMode === 'new') {
          await createAssignment(payload);
          setToast({ msg: `Created ${corgi}/${certName}.` });
        } else {
          const target = editTarget ?? { certName, corgi };
          await updateAssignment(target.certName, payload, target.corgi);
          setToast({ msg: `Saved ${corgi}/${certName}.` });
        }
        setSelectedCertName(certName);
        setPanelMode('detail');
        setEditTarget(null);
        refresh();
      } catch (err) {
        setToast({ msg: err instanceof Error ? err.message : 'Failed to save.', error: true });
      } finally {
        setSaving(false);
      }
    })();
  }

  function handleDelete(): void {
    if (!editTarget) return;
    void (async () => {
      setSaving(true);
      try {
        await deleteAssignment(editTarget.certName, editTarget.corgi);
        setToast({ msg: `Deleted ${editTarget.certName}.` });
        closePanel();
        refresh();
      } catch (err) {
        setToast({ msg: err instanceof Error ? err.message : 'Failed to delete.', error: true });
      } finally {
        setSaving(false);
      }
    })();
  }

  function handleCopyPem(): void {
    if (!certDetails?.pem) return;
    void navigator.clipboard.writeText(certDetails.pem);
    setToast({ msg: 'PEM copied to clipboard' });
  }

  function handleDownloadPem(): void {
    if (!certDetails?.pem || !selectedCertName) return;
    const blob = new Blob([certDetails.pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedCertName}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const selectedRow = selectedCertName ? rows.find(r => r.certName === selectedCertName) ?? null : null;
  const panelOpen = selectedCertName !== null || panelMode === 'new';

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <>
      <Topbar
        title="Certificates"
        secondsAgo={secondsAgo}
        onRefresh={refresh}
        actions={canCreate ? <button className="btn btn-primary btn-sm" onClick={openNew}>+ New</button> : undefined}
      />
      <div className="page-content" style={{ flexDirection: 'row', gap: 14, overflow: 'hidden', padding: 0 }}>

        {/* Left: table */}
        <div style={{ flex: panelOpen ? '1 1 55%' : '1', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 0 14px 16px' }}>
          {error && <div className="toast toast-error" style={{ marginBottom: 10 }}>{error}</div>}
          {toast && !panelOpen && <div className={`toast${toast.error ? ' toast-error' : ''}`}>{toast.msg}</div>}

          <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div className="filter-bar">
              <input
                className="filter-input"
                placeholder="Filter by domain, cert name, or corgi…"
                value={filter}
                onChange={e => setFilter(e.target.value)}
              />
            </div>
            <div className="table-wrap" style={{ flex: 1, overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th className="th-sort" onClick={() => toggleSort('name')}>Name <span>{sortIndicator(sort.key === 'name', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('corgi')}>Corgi <span>{sortIndicator(sort.key === 'corgi', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('ca')}>CA <span>{sortIndicator(sort.key === 'ca', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('status')}>Status <span>{sortIndicator(sort.key === 'status', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('expires')}>Expires <span>{sortIndicator(sort.key === 'expires', sort.dir)}</span></th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.length === 0 && (
                    <tr><td colSpan={5} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No certificates</td></tr>
                  )}
                  {sorted.map(row => (
                    <tr
                      key={`${row.corgi}:${row.certName}`}
                      className={`clickable${selectedCertName === row.certName ? ' expanded' : ''}`}
                      onClick={() => handleSelectRow(row)}
                    >
                      <td className="fw-500">{row.domain}</td>
                      <td className="text-muted">{row.corgi}</td>
                      <td className="text-muted">{row.ca}</td>
                      <td>
                        <StatusBadge
                          label={statusLabel(row.status, row.daysLeft)}
                          tone={statusTone(row.status)}
                          spinning={row.status === 'renewing'}
                        />
                      </td>
                      <td className="text-muted">
                        {row.validTo ? fmtDate(row.validTo) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {rateLimits && <RateLimitsSection data={rateLimits} />}
        </div>

        {/* Right: panel */}
        {panelOpen && (
          <div style={{ flex: '0 0 42%', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 16px 14px 0' }}>
            {toast && panelOpen && <div className={`toast${toast.error ? ' toast-error' : ''}`} style={{ marginBottom: 10 }}>{toast.msg}</div>}
            <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

              {/* ── Detail panel ── */}
              {(panelMode === 'detail' || panelMode === 'none-info') && selectedRow && (
                <>
                  <div className="card-header">
                    <span className="card-title" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{selectedRow.domain}</span>
                    {canEdit && (
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ marginLeft: 'auto' }}
                        onClick={() => openEdit(selectedRow)}
                      >
                        Edit
                      </button>
                    )}
                    {canRenew && selectedRow.corgi && (
                      <button
                        className="btn btn-ghost btn-sm"
                        style={canEdit ? undefined : { marginLeft: 'auto' }}
                        onClick={() => { void handleRenew(); }}
                        disabled={renewing}
                      >
                        {renewing ? 'Renewing…' : 'Renew'}
                      </button>
                    )}
                    <button
                      className="btn btn-ghost btn-sm"
                      style={(!canEdit && !canRenew) ? { marginLeft: 'auto' } : undefined}
                      onClick={closePanel}
                    >
                      ✕
                    </button>
                  </div>

                  {panelMode === 'none-info' ? (
                    // No cert yet — show assignment summary
                    <div style={{ flex: 1, overflowY: 'auto', padding: '16px 14px' }}>
                      <p className="text-muted" style={{ fontSize: 12, marginBottom: 16 }}>No certificate issued yet.</p>
                      <div style={{ paddingTop: 10, borderTop: '1px solid var(--border)' }}>
                        <div className="field-row">
                          <span className="field-label">Corgi</span>
                          <span className="field-value">{selectedRow.corgi}</span>
                        </div>
                        <div className="field-row">
                          <span className="field-label">CA</span>
                          <span className="field-value">{selectedRow.ca}</span>
                        </div>
                        <div className="field-row">
                          <span className="field-label">Validity</span>
                          <span className="field-value">{selectedRow.assignment.days ?? 90}d (renew before {selectedRow.assignment.renewBeforeDays ?? 30}d)</span>
                        </div>
                        {selectedRow.assignment.domain && (
                          <div className="field-row">
                            <span className="field-label">Primary</span>
                            <span className="field-value">{selectedRow.assignment.domain}</span>
                          </div>
                        )}
                        {(selectedRow.assignment.sans ?? []).length > 0 && (
                          <div className="field-row" style={{ alignItems: 'flex-start' }}>
                            <span className="field-label">SANs</span>
                            <span className="field-value">{(selectedRow.assignment.sans ?? []).join(', ')}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    // Cert exists — full detail with tabs
                    <>
                      <div className="tab-strip">
                        {(['structured', 'raw', 'pem'] as InspectTab[]).map(tab => (
                          <button
                            key={tab}
                            className={`tab-btn${inspectTab === tab ? ' active' : ''}`}
                            onClick={() => {
                              setInspectTab(tab);
                              if (selectedCertName) void loadCertDetails(selectedCertName);
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
                                ['Cert Name', selectedRow.certName, false],
                                ['Corgi', selectedRow.corgi, false],
                                ['CA', selectedRow.ca, false],
                                ['Domain', selectedRow.domain, false],
                                ['SANs', selectedRow.sanNames.join(', '), false],
                                ['Days Left', selectedRow.daysLeft !== null ? String(selectedRow.daysLeft) : '—', false],
                                ['Valid To', selectedRow.validTo ? fmtDate(selectedRow.validTo) : '—', false],
                                ['SHA-256', selectedRow.fingerprint256 || '—', true],
                                ...(certDetails ? [['Issuer', certDetails.issuer, false] as [string, string, boolean]] : []),
                                ...(certDetails?.subjectAltName
                                  ? certDetails.subjectAltName.split(',').map(s => s.trim()).filter(s => s.startsWith('URI:')).map(s => ['URI', s.slice(4), true] as [string, string, boolean])
                                  : []),
                              ] as [string, string, boolean][]
                            ).map(([label, value, mono], i) => (
                              <div className="field-row" key={`${label}-${i}`}>
                                <span className="field-label">{label}</span>
                                <span className={`field-value${mono ? ' mono' : ''}`}>{value}</span>
                              </div>
                            ))}

                            {/* Config vs. cert mismatch */}
                            {(() => {
                              const actualDnsSans = certDetails ? parseDnsSans(certDetails.subjectAltName) : null;
                              if (!actualDnsSans) return null;
                              const configured = [...new Set([selectedRow.assignment.domain ?? selectedRow.certName, ...(selectedRow.assignment.sans ?? [])].filter(Boolean) as string[])];
                              const configSet = new Set(configured);
                              const actualSet = new Set(actualDnsSans);
                              const missing = configured.filter(s => !actualSet.has(s));
                              const extra = actualDnsSans.filter(s => !configSet.has(s));
                              const hasMismatch = missing.length > 0 || extra.length > 0;
                              return (
                                <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
                                  <div className="field-row" style={{ marginBottom: 4 }}>
                                    <span className="field-label" style={{ fontWeight: 600 }}>Config vs. Cert</span>
                                    <span className="field-value" style={{ fontSize: 11, color: hasMismatch ? 'var(--yellow)' : 'var(--green)' }}>
                                      {hasMismatch ? '⚠ Mismatch detected' : '✓ Config matches cert'}
                                    </span>
                                  </div>
                                  {hasMismatch && (
                                    <>
                                      {missing.length > 0 && (
                                        <div className="field-row" style={{ alignItems: 'flex-start' }}>
                                          <span className="field-label">Missing SANs</span>
                                          <span className="field-value mono" style={{ fontSize: 11, color: 'var(--yellow)', whiteSpace: 'pre-wrap' }}>{missing.join('\n')}</span>
                                        </div>
                                      )}
                                      {extra.length > 0 && (
                                        <div className="field-row" style={{ alignItems: 'flex-start' }}>
                                          <span className="field-label">Extra SANs</span>
                                          <span className="field-value mono" style={{ fontSize: 11, color: 'var(--muted)', whiteSpace: 'pre-wrap' }}>{extra.join('\n')}</span>
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

                            {activeJob && <ActiveJobSection job={activeJob} />}
                            {!activeJob && lastJob && (
                              <LastJobSection job={lastJob} expanded={logsExpanded} onToggle={() => setLogsExpanded(v => !v)} />
                            )}
                          </div>
                        )}

                        {inspectTab === 'raw' && (
                          <div>
                            {detailsLoading && <p className="text-muted" style={{ fontSize: 12 }}>Loading…</p>}
                            {certDetails && <pre className="pem-block" style={{ maxHeight: 'none' }}>{buildRawText(certDetails)}</pre>}
                            {!certDetails && !detailsLoading && <p className="text-muted" style={{ fontSize: 12 }}>Certificate file not available from certstore.</p>}
                          </div>
                        )}

                        {inspectTab === 'pem' && (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            <div style={{ display: 'flex', gap: 6 }}>
                              <button className="btn btn-ghost btn-sm" onClick={handleCopyPem} disabled={!certDetails?.pem}>Copy</button>
                              <button className="btn btn-ghost btn-sm" onClick={handleDownloadPem} disabled={!certDetails?.pem}>⬇ Download</button>
                            </div>
                            {detailsLoading && <p className="text-muted" style={{ fontSize: 12 }}>Loading…</p>}
                            {certDetails?.pem && <pre className="pem-block">{certDetails.pem}</pre>}
                            {!certDetails?.pem && !detailsLoading && <p className="text-muted" style={{ fontSize: 12 }}>Certificate file not available from certstore.</p>}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </>
              )}

              {/* ── Edit / New form ── */}
              {(panelMode === 'edit' || panelMode === 'new') && (
                <>
                  <div className="card-header" style={{ position: 'sticky', top: 0, zIndex: 1, background: 'var(--surface)' }}>
                    <span className="card-title">{panelMode === 'new' ? 'New Assignment' : `Edit: ${form.certName}`}</span>
                    <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                      <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
                      <button className="btn btn-ghost btn-sm" onClick={cancelEdit} disabled={saving}>Cancel</button>
                    </div>
                  </div>

                  <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
                    {/* Basic */}
                    <div className="form-section">
                      <div className="form-section-label">Basic</div>
                      <div className="form-row">
                        <label className="form-label">Cert Name</label>
                        <input className="form-input" value={form.certName} disabled={panelMode === 'edit'} onChange={e => setForm(f => ({ ...f, certName: e.target.value }))} />
                      </div>
                      <div className="form-row">
                        <label className="form-label">Corgi</label>
                        <select className="form-select" value={form.corgi} onChange={e => setForm(f => ({ ...f, corgi: e.target.value }))}>
                          {corgiNames.map(n => <option key={n} value={n}>{n}</option>)}
                        </select>
                      </div>
                      <div className="form-row">
                        <label className="form-label">CA</label>
                        <select className="form-select" value={form.ca} onChange={e => setForm(f => ({ ...f, ca: e.target.value }))}>
                          {caOptions.map(n => <option key={n} value={n}>{n}</option>)}
                        </select>
                      </div>
                      <div className="form-row">
                        <label className="form-label">Validity (days)</label>
                        <input className="form-input" type="number" value={form.days} onChange={e => setForm(f => ({ ...f, days: e.target.value }))} />
                      </div>
                      <div className="form-row">
                        <label className="form-label">Renew Before (days)</label>
                        <input className="form-input" type="number" value={form.renewBeforeDays} onChange={e => setForm(f => ({ ...f, renewBeforeDays: e.target.value }))} />
                      </div>
                    </div>

                    {/* Post-install hooks */}
                    {availableHooks.length > 0 && (
                      <div className="form-section">
                        <div className="form-section-label">Post-install Hooks</div>
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
                          {form.hooks.length === 0
                            ? `Using corgi defaults: ${defaultHooks.length > 0 ? defaultHooks.join(', ') : '(none)'}`
                            : 'Selected hooks replace corgi defaults for this cert.'}
                        </div>
                        {availableHooks.map(hook => (
                          <div key={hook} className="form-row" style={{ alignItems: 'center', gap: 8 }}>
                            <input
                              type="checkbox"
                              id={`hook-${hook}`}
                              checked={form.hooks.includes(hook)}
                              onChange={e => setForm(f => ({
                                ...f,
                                hooks: e.target.checked
                                  ? [...f.hooks, hook]
                                  : f.hooks.filter(h => h !== hook),
                              }))}
                            />
                            <label htmlFor={`hook-${hook}`} style={{ cursor: 'pointer', fontFamily: 'monospace', fontSize: 13 }}>
                              {hook}{defaultHooks.includes(hook) ? ' (default)' : ''}
                            </label>
                          </div>
                        ))}
                        {form.hooks.length > 0 && (
                          <button
                            type="button"
                            className="btn btn-sm"
                            style={{ marginTop: 6 }}
                            onClick={() => setForm(f => ({ ...f, hooks: [] }))}
                          >
                            Clear (use defaults)
                          </button>
                        )}
                      </div>
                    )}

                    {/* Validation */}
                    <div className="form-section">
                      <div className="form-section-label">Validation</div>
                      <div className="form-row">
                        <label className="form-label">Type</label>
                        <select className="form-select" value={form.validationType} onChange={e => setForm(f => ({ ...f, validationType: e.target.value as FormState['validationType'] }))}>
                          {(() => {
                            const caInfo = caMap[form.ca];
                            const def = caInfo?.defaultValidation;
                            return (
                              <>
                                <option value="none-01">{def && def !== 'none-01' ? `none-01 (CA default: ${def})` : 'none-01'}</option>
                                <option value="http-01">http-01</option>
                                <option value="dns-01">dns-01</option>
                              </>
                            );
                          })()}
                        </select>
                      </div>
                      {form.validationType === 'dns-01' && (
                        <>
                          <div className="form-row">
                            <label className="form-label">Provider</label>
                            <input className="form-input" placeholder="he" value={form.validationProvider} onChange={e => setForm(f => ({ ...f, validationProvider: e.target.value }))} />
                          </div>
                          <div className="form-row">
                            <label className="form-label">DDNS Key (env)</label>
                            <input className="form-input" placeholder="${SHEPHERD_DDNS_KEY}" value={form.validationDdnsKey} onChange={e => setForm(f => ({ ...f, validationDdnsKey: e.target.value }))} />
                          </div>
                        </>
                      )}
                    </div>

                    {/* Domains & SANs */}
                    <div className="form-section">
                      <div className="form-section-label">Domains &amp; SANs</div>
                      <div className="form-row">
                        <label className="form-label">Primary Domain</label>
                        <input className="form-input" value={form.domain} onChange={e => setForm(f => ({ ...f, domain: e.target.value }))} />
                      </div>
                      <div className="form-row">
                        <label className="form-label">Identity URI</label>
                        <input className="form-input" placeholder="vigil://credo/…" value={form.identityUri} onChange={e => setForm(f => ({ ...f, identityUri: e.target.value }))} />
                      </div>
                      <textarea
                        className="form-textarea"
                        placeholder={'Additional SANs, one per line'}
                        value={form.sans}
                        onChange={e => setForm(f => ({ ...f, sans: e.target.value }))}
                        style={{ width: '100%' }}
                      />
                    </div>

                    {/* Danger zone — edit mode only */}
                    {panelMode === 'edit' && canDelete && (
                      <div style={{ paddingTop: 12, borderTop: '1px solid var(--border)', marginTop: 4 }}>
                        <button className="btn btn-danger btn-sm" style={{ width: '100%', justifyContent: 'center' }} disabled={saving} onClick={handleDelete}>
                          Delete Assignment
                        </button>
                      </div>
                    )}
                  </div>
                </>
              )}

            </div>
          </div>
        )}
      </div>
    </>
  );
}
