import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { fetchCerts, fetchShepherdCertFull, runMonitorCheck } from '../api';
import { Topbar } from './Shell';
import { StatusBadge } from './StatusBadge';
import { CertDetailPanel, type OutputTab } from './CertDetailPanel';
import { monitorLabel, monitorTone } from '../utils/monitor';
import type { CertStoreEntry, CertChainPayload, MonitorResult, EndpointCheckResult } from '../types';

function EndpointCard({ endpoint }: { endpoint: EndpointCheckResult }): React.ReactElement {
  return (
    <div className="card" style={{ marginBottom: 10 }}>
      <div className="card-header">
        <span className="card-title mono">{endpoint.host}:{endpoint.port}</span>
        <StatusBadge label={monitorLabel(endpoint.status)} tone={monitorTone(endpoint.status)} />
      </div>
      <div className="card-body">
        <div className="field-row">
          <span className="field-label">SNI</span>
          <span className="field-value mono">{endpoint.sni}</span>
        </div>
        {endpoint.resolvedAddr && (
          <div className="field-row">
            <span className="field-label">Resolved</span>
            <span className="field-value mono">{endpoint.resolvedAddr}</span>
          </div>
        )}
        {endpoint.seenFingerprint && (
          <div className="field-row">
            <span className="field-label">Seen Fingerprint</span>
            <span className="field-value mono">{endpoint.seenFingerprint}</span>
          </div>
        )}
        {endpoint.seenCommonName && (
          <div className="field-row">
            <span className="field-label">Seen CN</span>
            <span className="field-value mono">{endpoint.seenCommonName}</span>
          </div>
        )}
        {endpoint.seenSanNames.length > 0 && (
          <div className="field-row">
            <span className="field-label">Seen SANs</span>
            <span className="field-value mono">{endpoint.seenSanNames.join(', ')}</span>
          </div>
        )}
        {endpoint.chainTrusted !== undefined && (
          <div className="field-row">
            <span className="field-label">Chain Trusted</span>
            <span className="field-value">{endpoint.chainTrusted ? 'yes' : 'no'}</span>
          </div>
        )}
        {endpoint.error && (
          <div className="field-row">
            <span className="field-label">Error</span>
            <span className="field-value" style={{ color: 'var(--red)' }}>{endpoint.error}</span>
          </div>
        )}
        {endpoint.matchedArchiveVersion && (
          <div className="toast toast-error" style={{ marginTop: 10 }}>
            This is the version issued {endpoint.matchedArchiveVersion.issuedAt ?? 'unknown'}
            {' '}(ordinal {endpoint.matchedArchiveVersion.ordinal})
            {endpoint.matchedArchiveVersion.currentIssuedAt && (
              <> — superseded by the version issued {endpoint.matchedArchiveVersion.currentIssuedAt}.</>
            )}
            {' '}The reload hook may not have fired.
          </div>
        )}
      </div>
    </div>
  );
}

export function CertMonitorCheck(): React.ReactElement {
  const [searchParams] = useSearchParams();
  const autoRunCert = searchParams.get('cert');

  const [certOptions, setCertOptions] = useState<CertStoreEntry[]>([]);
  const [selectedCertName, setSelectedCertName] = useState(autoRunCert ?? '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [chainData, setChainData] = useState<CertChainPayload | null>(null);
  const [monitorResult, setMonitorResult] = useState<MonitorResult | null>(null);
  const [selectedChainIndex, setSelectedChainIndex] = useState(0);
  const [activeTab, setActiveTab] = useState<OutputTab>('structured');
  const [copied, setCopied] = useState<OutputTab | null>(null);

  const autoRanRef = useRef(false);

  useEffect(() => {
    fetchCerts()
      // The backend only ever returns entries it could successfully read,
      // so every entry here already exists — no `exists` field is sent.
      .then(payload => setCertOptions(payload.entries.filter(e => e.certName)))
      .catch(() => { /* non-fatal */ });
  }, []);

  const handleCopy = (tab: OutputTab): void => {
    setCopied(tab);
    setTimeout(() => setCopied(null), 2000);
  };

  const runCheck = async (certName: string): Promise<void> => {
    if (!certName) return;
    setLoading(true);
    setError(null);
    setSelectedChainIndex(0);
    setActiveTab('structured');
    try {
      const [expected, checked] = await Promise.all([
        fetchShepherdCertFull(certName),
        runMonitorCheck(certName),
      ]);
      setChainData(expected);
      setMonitorResult(checked.monitor);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run monitor check');
    } finally {
      setLoading(false);
    }
  };

  // Auto-run once on mount when landing here via a "Cert Mismatch" click-through.
  useEffect(() => {
    if (autoRunCert && !autoRanRef.current) {
      autoRanRef.current = true;
      void runCheck(autoRunCert);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRunCert]);

  const endpoints = monitorResult?.endpoints ?? [];

  return (
    <>
      <Topbar title="Cert Monitor Check" subtitle="Trigger an on-demand monitor check and compare expected vs. served certs" />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}

        <div className="card">
          <div className="card-header"><span className="card-title">Certificate</span></div>
          <div className="card-body">
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {certOptions.length === 0 ? (
                <span className="text-muted">No certs found in Shepherd cert store</span>
              ) : (
                <select
                  className="form-select"
                  style={{ flex: 1 }}
                  value={selectedCertName}
                  onChange={e => setSelectedCertName(e.target.value)}
                >
                  {!certOptions.some(c => c.certName === selectedCertName) && selectedCertName && (
                    <option value={selectedCertName}>{selectedCertName}</option>
                  )}
                  {certOptions.map(c => (
                    <option key={c.certName} value={c.certName}>{c.certName}</option>
                  ))}
                </select>
              )}
              <button
                className="btn btn-primary"
                onClick={() => void runCheck(selectedCertName)}
                disabled={loading || !selectedCertName}
              >
                {loading ? 'Checking…' : 'Run Check'}
              </button>
            </div>
          </div>
        </div>

        {(chainData || monitorResult) && (
          <div className="split-panel split-50-50">
            <div>
              <div className="card-header" style={{ paddingLeft: 0 }}><span className="card-title">Expected / Installed</span></div>
              {chainData && (
                <CertDetailPanel
                  chainData={chainData}
                  selectedChainIndex={selectedChainIndex}
                  onChainSelect={setSelectedChainIndex}
                  activeTab={activeTab}
                  onTabChange={setActiveTab}
                  copied={copied}
                  onCopy={handleCopy}
                />
              )}
            </div>
            <div>
              <div className="card-header" style={{ paddingLeft: 0 }}><span className="card-title">Observed / Served</span></div>
              {endpoints.length === 0 ? (
                <span className="text-muted">No endpoint data available</span>
              ) : (
                endpoints.map((ep, i) => <EndpointCard key={`${ep.host}:${ep.port}-${i}`} endpoint={ep} />)
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
