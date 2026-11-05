import React from 'react';
import type { CertChainPayload, CertSection, CertField } from '../types';

export type OutputTab = 'structured' | 'text' | 'pem';

export function validityColor(daysLeft: number): string {
  if (daysLeft < 0) return 'var(--red)';
  if (daysLeft < 30) return 'var(--yellow)';
  return 'var(--green)';
}

export function CopyButton({ text, tab, copied, onCopy }: {
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

export function ChainStrip({ chainData, selectedIndex, onSelect }: {
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

/// Chain strip + structured/text/pem tabs for whichever chain entry is
/// selected. Shared by CertViewer (ad-hoc inspection) and CertMonitorCheck
/// (expected-vs-observed diagnostic) so both render a cert identically.
export function CertDetailPanel({
  chainData, selectedChainIndex, onChainSelect, activeTab, onTabChange, copied, onCopy,
}: {
  chainData: CertChainPayload;
  selectedChainIndex: number;
  onChainSelect: (index: number) => void;
  activeTab: OutputTab;
  onTabChange: (tab: OutputTab) => void;
  copied: OutputTab | null;
  onCopy: (tab: OutputTab) => void;
}): React.ReactElement {
  const displayed = chainData.chain.find(e => e.index === selectedChainIndex)?.cert
    ?? chainData.chain[0]?.cert
    ?? null;

  return (
    <>
      <ChainStrip chainData={chainData} selectedIndex={selectedChainIndex} onSelect={onChainSelect} />

      {displayed && (
        <div className="card">
          <div className="tab-strip">
            {(['structured', 'text', 'pem'] as OutputTab[]).map(tab => (
              <button
                key={tab}
                className={`tab-btn${activeTab === tab ? ' active' : ''}`}
                onClick={() => onTabChange(tab)}
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
                <CopyButton text={displayed.textView} tab="text" copied={copied} onCopy={onCopy} />
              </div>
              <pre className="pem-block" style={{ maxHeight: 500 }}>{displayed.textView}</pre>
            </div>
          )}

          {activeTab === 'pem' && (
            <div className="card-body">
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
                <CopyButton text={displayed.pem} tab="pem" copied={copied} onCopy={onCopy} />
              </div>
              <pre className="pem-block" style={{ maxHeight: 500 }}>{displayed.pem}</pre>
            </div>
          )}
        </div>
      )}
    </>
  );
}
