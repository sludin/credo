import React, { useState, useEffect } from 'react';
import { fetchCerts, fetchShepherdCertFull, fetchRemoteCert } from '../api';
import { Topbar } from './Shell';
import { CertDetailPanel, type OutputTab } from './CertDetailPanel';
import type { CertStoreEntry, CertChainPayload } from '../types';

type SourceMode = 'shepherd' | 'remote';

function parseRemoteInput(input: string): { host: string; port: number } | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const colonIdx = trimmed.lastIndexOf(':');
  if (colonIdx > 0 && !trimmed.includes('[')) {
    const portStr = trimmed.slice(colonIdx + 1);
    const port = parseInt(portStr, 10);
    if (!isNaN(port) && port > 0 && port <= 65535) {
      return { host: trimmed.slice(0, colonIdx), port };
    }
  }
  return { host: trimmed, port: 443 };
}

export function CertViewer(): React.ReactElement {
  const [mode, setMode] = useState<SourceMode>('shepherd');
  const [shepherdCerts, setShepherdCerts] = useState<CertStoreEntry[]>([]);
  const [selectedCertName, setSelectedCertName] = useState('');
  const [remoteInput, setRemoteInput] = useState('');
  const [remoteInputError, setRemoteInputError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [chainData, setChainData] = useState<CertChainPayload | null>(null);
  const [selectedChainIndex, setSelectedChainIndex] = useState(0);
  const [activeTab, setActiveTab] = useState<OutputTab>('structured');
  const [copied, setCopied] = useState<OutputTab | null>(null);

  useEffect(() => {
    fetchCerts()
      .then(payload => {
        // The backend only ever returns entries it could successfully read
        // (shepherd/src/routes_api.rs::get_certstore uses filter_map), so
        // every entry here already exists — no `exists` field is sent.
        const existing = payload.entries.filter(e => e.certName);
        setShepherdCerts(existing);
        if (existing.length > 0) setSelectedCertName(existing[0].certName);
      })
      .catch(() => { /* non-fatal */ });
  }, []);

  useEffect(() => {
    setChainData(null);
    setError(null);
    setRemoteInputError(null);
    setSelectedChainIndex(0);
    setActiveTab('structured');
    setLoading(false);
  }, [mode]);

  const handleCopy = (tab: OutputTab): void => {
    setCopied(tab);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleLoadShepherd = async (): Promise<void> => {
    if (!selectedCertName) return;
    setLoading(true);
    setError(null);
    setChainData(null);
    setSelectedChainIndex(0);
    try {
      const data = await fetchShepherdCertFull(selectedCertName);
      setChainData(data);
      setActiveTab('structured');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cert');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadRemote = async (): Promise<void> => {
    setRemoteInputError(null);
    const parsed = parseRemoteInput(remoteInput);
    if (!parsed) { setRemoteInputError('Enter a hostname or hostname:port'); return; }

    setLoading(true);
    setError(null);
    setChainData(null);
    setSelectedChainIndex(0);
    try {
      const data = await fetchRemoteCert(parsed.host, parsed.port);
      setChainData(data);
      setActiveTab('structured');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Topbar title="Cert Viewer" subtitle="Inspect X.509 certificates" />
      <div className="page-content">
        {error && <div className="toast toast-error">{error}</div>}

        <div className="card">
          <div className="card-header"><span className="card-title">Source</span></div>
          <div className="card-body">
            <div style={{ display: 'flex', gap: 0, background: 'var(--bg)', borderRadius: 6, padding: 3, width: 'fit-content', marginBottom: 14 }}>
              {(['shepherd', 'remote'] as SourceMode[]).map(m => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  style={{
                    padding: '5px 14px', borderRadius: 4, border: 'none', cursor: 'pointer',
                    background: mode === m ? 'var(--surface2)' : 'transparent',
                    color: mode === m ? 'var(--accent2)' : 'var(--muted)',
                    fontWeight: mode === m ? 600 : 400, fontSize: 12, fontFamily: 'inherit',
                  }}
                >
                  {m === 'shepherd' ? '⬢ Shepherd Cert' : '⚙ Remote Host'}
                </button>
              ))}
            </div>

            {mode === 'shepherd' ? (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {shepherdCerts.length === 0 ? (
                  <span className="text-muted">No certs found in Shepherd cert store</span>
                ) : (
                  <select
                    className="form-select"
                    style={{ flex: 1 }}
                    value={selectedCertName}
                    onChange={e => setSelectedCertName(e.target.value)}
                  >
                    {shepherdCerts.map(c => (
                      <option key={c.certName} value={c.certName}>{c.certName}</option>
                    ))}
                  </select>
                )}
                <button
                  className="btn btn-primary"
                  onClick={() => void handleLoadShepherd()}
                  disabled={loading || !selectedCertName}
                >
                  {loading ? 'Loading…' : 'Load Cert'}
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <div style={{
                    display: 'flex', flex: 1, alignItems: 'center',
                    background: 'var(--surface2)',
                    border: `1px solid ${remoteInputError ? 'var(--red)' : 'var(--border)'}`,
                    borderRadius: 4, overflow: 'hidden',
                  }}>
                    <input
                      type="text"
                      className="form-input"
                      style={{ flex: 1, border: 'none', background: 'transparent' }}
                      placeholder="hostname or hostname:port"
                      value={remoteInput}
                      onChange={e => { setRemoteInput(e.target.value); setRemoteInputError(null); }}
                      onKeyDown={e => { if (e.key === 'Enter') void handleLoadRemote(); }}
                    />
                    <span style={{ padding: '0 8px', color: 'var(--muted)', fontSize: 10, borderLeft: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                      default: 443
                    </span>
                  </div>
                  <button
                    className="btn btn-primary"
                    onClick={() => void handleLoadRemote()}
                    disabled={loading || !remoteInput.trim()}
                  >
                    {loading ? 'Loading…' : 'Load Cert'}
                  </button>
                </div>
                {remoteInputError && <span style={{ fontSize: 11, color: 'var(--red)' }}>{remoteInputError}</span>}
              </div>
            )}
          </div>
        </div>

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
    </>
  );
}
