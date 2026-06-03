import React, { useState, useEffect, useCallback } from 'react';
import { fetchCerts, fetchShepherdCertFull, fetchRemoteCert } from '../api';
import { Topbar } from './Shell';
import type {
  CertStoreEntry,
  ParsedCertFull,
  CertChainPayload,
  CertSection,
  CertField,
} from '../types';

type SourceMode = 'shepherd' | 'remote';
type OutputTab = 'structured' | 'text' | 'pem';

function validityColor(daysLeft: number): string {
  if (daysLeft < 0) return 'var(--red)';
  if (daysLeft < 30) return 'var(--yellow)';
  return 'var(--green)';
}

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

function CopyButton({ text, tab, copied, onCopy }: {
  text: string;
  tab: OutputTab;
  copied: OutputTab | null;
  onCopy: (tab: OutputTab) => void;
}): React.ReactElement {
  return (
    <button
      className="btn btn-ghost btn-sm"
      style={{ marginLeft: 'auto' }}
      onClick={() => {
        navigator.clipboard.writeText(text).then(
          () => onCopy(tab),
          () => { /* clipboard unavailable */ },
        );
      }}
    >
      {copied === tab ? '✓ Copied' : 'Copy'}
    </button>
  );
}

function FieldRow({ field, daysLeft }: { field: CertField; daysLeft: number }): React.ReactElement {
  const isNotAfter = field.label === 'Not After';
  const valueColor = isNotAfter ? validityColor(daysLeft) : undefined;

  return (
    <div className="field-row">
      <span className="field-label">
        {field.label}
        {field.critical && (
          <span style={{
            display: 'inline-block', width: 6, height: 6,
            borderRadius: '50%', background: 'var(--red)',
            verticalAlign: 'middle', marginLeft: 4,
          }} />
        )}
      </span>
      {field.display === 'pills' && Array.isArray(field.value) ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {(field.value as string[]).map(v => (
            <span key={v} style={{
              padding: '1px 8px', background: 'var(--surface2)',
              border: '1px solid var(--border)', borderRadius: 10,
              fontSize: 11, fontFamily: 'var(--font-mono)',
            }}>{v}</span>
          ))}
        </div>
      ) : (
        <span
          className={`field-value${field.display === 'mono' || field.display === 'hex' ? ' mono' : ''}`}
          style={valueColor ? { color: valueColor } : undefined}
        >
          {Array.isArray(field.value) ? (field.value as string[]).join(', ') : field.value as string}
        </span>
      )}
    </div>
  );
}

function SectionView({ sections, daysLeft }: { sections: CertSection[]; daysLeft: number }): React.ReactElement {
  return (
    <>
      {sections.map(section => (
        <div key={section.title} style={{ marginBottom: 14 }}>
          <div className="form-section-label" style={{ marginBottom: 6 }}>{section.title}</div>
          {section.fields.map(field => (
            <FieldRow key={field.label} field={field} daysLeft={daysLeft} />
          ))}
          {section.subsections?.map(sub => (
            <SectionView key={sub.title} sections={[sub]} daysLeft={daysLeft} />
          ))}
        </div>
      ))}
    </>
  );
}

function ChainStrip({ chainData, selectedIndex, onSelect }: {
  chainData: CertChainPayload;
  selectedIndex: number;
  onSelect: (index: number) => void;
}): React.ReactElement {
  const { root, chain } = chainData;
  const displayOrder = [...chain].reverse();

  return (
    <div className="card">
      <div className="card-header"><span className="card-title">Certificate Chain</span></div>
      <div className="card-body" style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', flexWrap: 'nowrap' }}>
        <div style={{
          flexShrink: 0, padding: '6px 10px', borderRadius: 4, textAlign: 'center',
          border: '1px solid var(--border)', opacity: 0.45,
        }}>
          <div style={{ fontSize: 9, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 2 }}>Root</div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)' }}>{root.commonName}</div>
          <div style={{ fontSize: 9, color: 'var(--muted)', marginTop: 2 }}>not received</div>
        </div>

        {displayOrder.map((entry) => {
          const isSelected = entry.index === selectedIndex;
          return (
            <React.Fragment key={entry.index}>
              <div style={{ color: 'var(--border)', fontSize: 18, flexShrink: 0 }}>→</div>
              <button
                type="button"
                onClick={() => onSelect(entry.index)}
                style={{
                  flexShrink: 0, padding: '6px 10px', borderRadius: 4, textAlign: 'center',
                  border: isSelected ? '2px solid var(--accent)' : '1px solid var(--border)',
                  background: isSelected ? 'rgba(99,102,241,0.1)' : 'transparent',
                  cursor: 'pointer',
                }}
              >
                <div style={{ fontSize: 9, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 2 }}>
                  {entry.role}{isSelected ? ' ●' : ''}
                </div>
                <div style={{ fontSize: 11, fontWeight: 600, color: isSelected ? 'var(--accent2)' : 'var(--text)' }}>
                  {entry.commonName}
                </div>
                <div style={{ fontSize: 9, color: 'var(--muted)', marginTop: 2 }}>
                  expires {entry.validTo.slice(0, 12)}
                </div>
              </button>
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

export function CertViewer(): React.ReactElement {
  const [mode, setMode] = useState<SourceMode>('shepherd');
  const [shepherdCerts, setShepherdCerts] = useState<CertStoreEntry[]>([]);
  const [selectedCertName, setSelectedCertName] = useState('');
  const [remoteInput, setRemoteInput] = useState('');
  const [remoteInputError, setRemoteInputError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [certData, setCertData] = useState<ParsedCertFull | null>(null);
  const [chainData, setChainData] = useState<CertChainPayload | null>(null);
  const [selectedChainIndex, setSelectedChainIndex] = useState(0);
  const [activeTab, setActiveTab] = useState<OutputTab>('structured');
  const [copied, setCopied] = useState<OutputTab | null>(null);

  useEffect(() => {
    fetchCerts()
      .then(payload => {
        const existing = payload.entries.filter(e => e.exists);
        setShepherdCerts(existing);
        if (existing.length > 0) setSelectedCertName(existing[0].certName);
      })
      .catch(() => { /* non-fatal */ });
  }, []);

  useEffect(() => {
    setCertData(null);
    setChainData(null);
    setError(null);
    setRemoteInputError(null);
    setSelectedChainIndex(0);
    setActiveTab('structured');
    setLoading(false);
  }, [mode]);

  const handleCopy = useCallback((tab: OutputTab) => {
    setCopied(tab);
    setTimeout(() => setCopied(null), 2000);
  }, []);

  const handleLoadShepherd = async (): Promise<void> => {
    if (!selectedCertName) return;
    setLoading(true);
    setError(null);
    setCertData(null);
    setChainData(null);
    setSelectedChainIndex(0);
    try {
      const data = await fetchShepherdCertFull(selectedCertName);
      setChainData(data);
      setCertData(data.chain[0]?.cert ?? null);
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
    setCertData(null);
    setChainData(null);
    setSelectedChainIndex(0);
    try {
      const data = await fetchRemoteCert(parsed.host, parsed.port);
      setChainData(data);
      setCertData(data.chain[0]?.cert ?? null);
      setActiveTab('structured');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect');
    } finally {
      setLoading(false);
    }
  };

  const handleChainSelect = (index: number): void => {
    setSelectedChainIndex(index);
    const entry = chainData?.chain.find(e => e.index === index);
    if (entry) setCertData(entry.cert);
  };

  const displayed = certData;

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
          <ChainStrip
            chainData={chainData}
            selectedIndex={selectedChainIndex}
            onSelect={handleChainSelect}
          />
        )}

        {displayed && (
          <div className="card">
            <div className="tab-strip">
              {(['structured', 'text', 'pem'] as OutputTab[]).map(tab => (
                <button
                  key={tab}
                  className={`tab-btn${activeTab === tab ? ' active' : ''}`}
                  onClick={() => setActiveTab(tab)}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>

            {activeTab === 'structured' && (
              <div className="card-body">
                <SectionView sections={displayed.sections} daysLeft={displayed.daysLeft} />
              </div>
            )}

            {activeTab === 'text' && (
              <div className="card-body">
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
                  <CopyButton text={displayed.textView} tab="text" copied={copied} onCopy={handleCopy} />
                </div>
                <pre className="pem-block" style={{ maxHeight: 500 }}>{displayed.textView}</pre>
              </div>
            )}

            {activeTab === 'pem' && (
              <div className="card-body">
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
                  <CopyButton text={displayed.pem} tab="pem" copied={copied} onCopy={handleCopy} />
                </div>
                <pre className="pem-block" style={{ maxHeight: 500 }}>{displayed.pem}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
