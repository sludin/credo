// src/components/DnsTxtChecker.tsx
import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  fetchAssignments,
  fetchDnsToolConfig,
  fetchShepherdConfigSummary,
  createDnsJob,
  pollDnsJob,
  updateTxtRecord,
} from '../api';
import type { DnsJobResolverResult } from '../api';
import { Topbar } from './Shell';
import type { Assignment, ShepherdConfigSummary } from '../types';

type CaMap = Record<string, ShepherdConfigSummary['cas'][number]>;
type AssignmentOption = Assignment & { dnsProvider: string };

type ResolverResult = {
  name: string;
  ip: string;
  role: 'authoritative' | 'public';
  txtRecords: string[];
  lastUpdated: Date;
  error?: string;
};

export function DnsTxtChecker(): React.ReactElement {
  const [assignments, setAssignments] = useState<AssignmentOption[]>([]);
  const [selectedCertName, setSelectedCertName] = useState<string>('');
  const [hostname, setHostname] = useState<string>('');
  const [acmePrefix, setAcmePrefix] = useState<boolean>(true);
  const [currentTxtValue, setCurrentTxtValue] = useState<string>('');
  const [newTxtValue, setNewTxtValue] = useState<string>('');
  const [resolverResults, setResolverResults] = useState<Map<string, ResolverResult>>(new Map());
  const [pollingIntervalSeconds, setPollingIntervalSeconds] = useState<number>(5);
  const [isLoaded, setIsLoaded] = useState<boolean>(false);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isUpdating, setIsUpdating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const jobIdRef = useRef<string | null>(null);
  const jobStartedAtRef = useRef<Date | null>(null);
  const pollingIntervalMsRef = useRef<number>(5000);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const effectiveHostname = acmePrefix && hostname ? `_acme-challenge.${hostname}` : hostname;

  useEffect(() => { pollingIntervalMsRef.current = pollingIntervalSeconds * 1000; }, [pollingIntervalSeconds]);

  // Reset on hostname change
  useEffect(() => {
    setIsLoaded(false);
    setIsPolling(false);
    setResolverResults(new Map());
    setCurrentTxtValue('');
    setNewTxtValue('');
    jobIdRef.current = null;
    jobStartedAtRef.current = null;
  }, [effectiveHostname]);

  // Load assignments and DNS config on mount
  useEffect(() => {
    (async () => {
      try {
        const [data, dnsConfig, cfgSummary] = await Promise.all([
          fetchAssignments(),
          fetchDnsToolConfig(),
          fetchShepherdConfigSummary(),
        ]);
        const caMap: CaMap = {};
        for (const ca of cfgSummary.cas) caMap[ca.name] = ca;

        const dns01 = (data.assignments ?? []).flatMap(a => {
          const caInfo = caMap[a.ca ?? ''];
          const effectiveType = a.validation?.type ?? caInfo?.defaultValidation;
          const hasDns01Methods = !!a.validation?.methods?.['dns-01'];
          if (effectiveType !== 'dns-01' && !hasDns01Methods) return [];
          const explicitProvider = a.validation?.methods?.['dns-01']?.provider as string | undefined;
          const provider = explicitProvider ?? caInfo?.validationProviders?.['dns-01'] ?? 'CA default';
          return [{ ...a, dnsProvider: provider }];
        });
        setAssignments(dns01);
        const interval = Math.max(1, dnsConfig.pollingIntervalSeconds ?? 5);
        setPollingIntervalSeconds(interval);
        pollingIntervalMsRef.current = interval * 1000;
        if (dns01.length > 0) {
          setSelectedCertName(dns01[0].certName);
          setHostname(dns01[0].domain ?? dns01[0].certName);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load');
      }
    })();
  }, []);

  // Auto-fill hostname when assignment changes
  useEffect(() => {
    if (!selectedCertName) return;
    const a = assignments.find(a => a.certName === selectedCertName);
    if (a) setHostname(a.domain ?? a.certName);
  }, [selectedCertName, assignments]);

  const applyJobResults = useCallback((results: DnsJobResolverResult[], targetValue: string): void => {
    const newMap = new Map<string, ResolverResult>();
    for (const r of results) {
      newMap.set(r.ip, {
        name: r.name,
        ip: r.ip,
        role: r.role,
        txtRecords: r.txtRecords,
        lastUpdated: new Date(r.queriedAt),
        error: r.error,
      });
    }
    setResolverResults(newMap);

    if (!targetValue) {
      const firstWithValue = results.find(r => !r.error && r.txtRecords.length > 0);
      setCurrentTxtValue(firstWithValue?.txtRecords[0] ?? '');
    }
  }, []);

  const pollJob = useCallback(async (): Promise<void> => {
    const jobId = jobIdRef.current;
    if (!jobId) return;

    if (jobStartedAtRef.current && Date.now() - jobStartedAtRef.current.getTime() > 10 * 60 * 1000) {
      setIsPolling(false);
      return;
    }

    try {
      const response = await pollDnsJob(jobId);
      applyJobResults(response.results, response.targetValue);
      if (response.converged) setIsPolling(false);
    } catch {
      // 429 or transient — keep polling
    }
  }, [applyJobResults]);

  // Single polling interval — starts/stops with isPolling
  useEffect(() => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (!isLoaded || !isPolling) return;
    intervalRef.current = setInterval(() => void pollJob(), pollingIntervalMsRef.current);
    return () => {
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isLoaded, isPolling, pollingIntervalSeconds, pollJob]);

  const handleLoad = async (): Promise<void> => {
    setIsLoading(true);
    setError(null);
    setSuccessMessage(null);
    setIsLoaded(false);
    setResolverResults(new Map());
    jobIdRef.current = null;
    jobStartedAtRef.current = null;

    try {
      const response = await createDnsJob(effectiveHostname, '');
      jobIdRef.current = response.jobId;
      jobStartedAtRef.current = new Date(response.startedAt);
      applyJobResults(response.results, '');
      setIsLoaded(true);
      setIsPolling(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start DNS job');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUpdate = async (): Promise<void> => {
    const assignment = assignments.find(a => a.certName === selectedCertName);
    if (!assignment || !effectiveHostname || !newTxtValue) {
      setError('Select an assignment and enter a value');
      return;
    }
    setIsUpdating(true);
    setError(null);
    setSuccessMessage(null);
    try {
      await updateTxtRecord({ certName: assignment.certName, hostname: effectiveHostname, txtValue: newTxtValue });
      setCurrentTxtValue(newTxtValue);
      setSuccessMessage(`TXT record updated for ${effectiveHostname}`);

      const response = await createDnsJob(effectiveHostname, newTxtValue);
      jobIdRef.current = response.jobId;
      jobStartedAtRef.current = new Date(response.startedAt);
      applyJobResults(response.results, newTxtValue);
      setIsPolling(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update TXT record');
    } finally {
      setIsUpdating(false);
    }
  };

  function resolverStatus(result: ResolverResult): { label: string; cls: string } {
    if (result.error) return { label: '● error', cls: 'text-red' };
    if (result.txtRecords.length === 0) return { label: '● empty', cls: 'text-muted' };
    if (!currentTxtValue) return { label: '● differ', cls: 'text-yellow' };
    const isMatch = result.txtRecords.some(t => t === currentTxtValue);
    return { label: isMatch ? '● match' : '● differ', cls: isMatch ? 'text-green' : 'text-yellow' };
  }

  function resolverRows(label: string, results: ResolverResult[]): React.ReactNode {
    return (
      <>
        <tr>
          <td
            colSpan={4}
            style={{ padding: '6px 10px 4px', background: 'var(--surface2)', borderBottom: '1px solid var(--border)' }}
          >
            <span className="form-section-label" style={{ margin: 0 }}>{label}</span>
          </td>
        </tr>
        {results.length === 0 && (
          <tr>
            <td colSpan={4} className="text-muted" style={{ textAlign: 'center' }}>—</td>
          </tr>
        )}
        {results.map(result => {
          const status = resolverStatus(result);
          return (
            <tr key={result.ip}>
              <td className="fw-500">{result.name}</td>
              <td className="mono text-muted">{result.ip}</td>
              <td>
                <span
                  className={`mono ${status.cls}`}
                  title={result.error ?? result.txtRecords.join(' | ')}
                >
                  {status.label}
                  {!result.error && result.txtRecords.length > 0 && (
                    <span className="text-muted" style={{ marginLeft: 6, fontSize: 11 }}>
                      {result.txtRecords[0].length > 60
                        ? result.txtRecords[0].slice(0, 60) + '…'
                        : result.txtRecords[0]}
                    </span>
                  )}
                  {result.error && (
                    <span className="text-muted" style={{ marginLeft: 6, fontSize: 11 }}>
                      {result.error.length > 60 ? result.error.slice(0, 60) + '…' : result.error}
                    </span>
                  )}
                </span>
              </td>
              <td className="text-muted" style={{ fontSize: 11 }}>
                {result.lastUpdated.toLocaleTimeString()}
              </td>
            </tr>
          );
        })}
      </>
    );
  }

  const allResults = [...resolverResults.values()];
  const authResults = allResults.filter(r => r.role === 'authoritative');
  const pubResults = allResults.filter(r => r.role === 'public');

  return (
    <>
      <Topbar
        title="DNS TXT Checker"
        subtitle="Query and update DNS TXT records"
      />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}
        {successMessage && <div className="toast">{successMessage}</div>}

        {/* Control card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Assignment</span>
          </div>
          <div className="card-body">
            <div className="form-section">
              <div className="form-row">
                <label className="form-label">Assignment</label>
                {assignments.length === 0 ? (
                  <span className="text-muted">No dns-01 assignments configured</span>
                ) : (
                  <select
                    className="form-select"
                    value={selectedCertName}
                    onChange={e => setSelectedCertName(e.target.value)}
                  >
                    {assignments.map(a => (
                      <option key={a.certName} value={a.certName}>
                        {a.certName} ({a.dnsProvider})
                      </option>
                    ))}
                  </select>
                )}
              </div>
              <div className="form-row" style={{ alignItems: 'start' }}>
                <label className="form-label" style={{ paddingTop: 5 }}>Hostname</label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <input
                    type="text"
                    className="form-input"
                    value={hostname}
                    onChange={e => setHostname(e.target.value)}
                    placeholder="example.com"
                  />
                  <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--muted)', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={acmePrefix}
                      onChange={e => setAcmePrefix(e.target.checked)}
                    />
                    Prepend{' '}
                    <code style={{ background: 'var(--surface2)', padding: '1px 5px', borderRadius: 3, fontSize: 11 }}>
                      _acme-challenge.
                    </code>
                    {acmePrefix && hostname && (
                      <span className="text-muted" style={{ fontSize: 11 }}>→ {effectiveHostname}</span>
                    )}
                  </label>
                </div>
              </div>
              <div>
                <button
                  className="btn btn-primary"
                  onClick={() => void handleLoad()}
                  disabled={isLoading || !hostname}
                >
                  {isLoading ? 'Loading…' : 'Load DNS Info'}
                </button>
              </div>
            </div>

            {isLoaded && (
              <div className="form-section">
                <div className="form-row" style={{ alignItems: 'start' }}>
                  <label className="form-label" style={{ paddingTop: 4 }}>Current value</label>
                  <div
                    className="mono"
                    style={{
                      padding: '4px 8px',
                      background: 'var(--surface2)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: 11,
                      wordBreak: 'break-all',
                      minHeight: 28,
                    }}
                  >
                    {currentTxtValue || <span className="text-muted">— no record found —</span>}
                  </div>
                </div>
                <div className="form-row" style={{ alignItems: 'start' }}>
                  <label className="form-label" style={{ paddingTop: 5 }}>New value</label>
                  <textarea
                    className="form-textarea"
                    rows={2}
                    value={newTxtValue}
                    onChange={e => setNewTxtValue(e.target.value)}
                    placeholder="Enter new TXT record value"
                  />
                </div>
                <div>
                  <button
                    className="btn btn-primary"
                    onClick={() => void handleUpdate()}
                    disabled={isUpdating || !newTxtValue}
                  >
                    {isUpdating ? 'Updating…' : 'Update TXT Record'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Resolver monitoring table */}
        {isLoaded && (
          <div className="card">
            <div className="card-header">
              <span className="card-title">Resolver Status</span>
              <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="card-subtitle">
                  {isPolling ? `polling every ${pollingIntervalSeconds}s` : 'paused'}
                </span>
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    if (isPolling) {
                      setIsPolling(false);
                    } else {
                      setIsPolling(true);
                      void pollJob();
                    }
                  }}
                >
                  {isPolling ? '■ Stop' : '▶ Resume'}
                </button>
              </div>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>IP</th>
                    <th>TXT Value</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {resolverRows('Authoritative Nameservers', authResults)}
                  {resolverRows('Public Resolvers', pubResults)}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
