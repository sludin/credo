// src/pages/ShepherdCAs.tsx
import React, { useState } from 'react';
import { usePoller } from '../hooks/usePoller';
import { fetchCas, updateCa, deleteCa } from '../api';
import { Topbar } from '../components/Shell';
import { usePermission } from '../hooks/usePermission';
import type { CaDetail } from '../types';

type FormState = {
  name: string;
  protocol: string;
  provider: string;
  directoryUrl: string;
  accountEmail: string;
  accountKeyPath: string;
  days: string;
  renewBeforeDays: string;
  supportedValidations: string[];
  defaultValidation: string;
  validationDns01Provider: string;
  validationDns01DdnsKey: string;
  validationDns01PropagationDelaySeconds: string;
  tlsCertPath: string;
  tlsKeyPath: string;
  tlsCaPath: string;
  insecureSkipVerify: boolean;
};

const VALIDATION_METHODS = ['none-01', 'http-01', 'dns-01'] as const;

const emptyForm: FormState = {
  name: '',
  protocol: 'acme',
  provider: '',
  directoryUrl: '',
  accountEmail: '',
  accountKeyPath: '',
  days: '',
  renewBeforeDays: '',
  supportedValidations: [],
  defaultValidation: '',
  validationDns01Provider: '',
  validationDns01DdnsKey: '',
  validationDns01PropagationDelaySeconds: '',
  tlsCertPath: '',
  tlsKeyPath: '',
  tlsCaPath: '',
  insecureSkipVerify: false,
};

function caToForm(ca: CaDetail): FormState {
  return {
    name: ca.name,
    protocol: ca.protocol ?? 'acme',
    provider: ca.provider ?? '',
    directoryUrl: ca.directoryUrl ?? '',
    accountEmail: ca.accountEmail ?? '',
    accountKeyPath: ca.accountKeyPath ?? '',
    days: ca.days != null ? String(ca.days) : '',
    renewBeforeDays: ca.renewBeforeDays != null ? String(ca.renewBeforeDays) : '',
    supportedValidations: ca.supportedValidations ?? [],
    defaultValidation: ca.defaultValidation ?? '',
    validationDns01Provider: ca.validationDns01Provider ?? '',
    validationDns01DdnsKey: ca.validationDns01DdnsKey ?? '',
    validationDns01PropagationDelaySeconds:
      ca.validationDns01PropagationDelaySeconds != null
        ? String(ca.validationDns01PropagationDelaySeconds)
        : '',
    tlsCertPath: ca.tlsCertPath ?? '',
    tlsKeyPath: ca.tlsKeyPath ?? '',
    tlsCaPath: ca.tlsCaPath ?? '',
    insecureSkipVerify: ca.insecureSkipVerify ?? false,
  };
}

function toCaPayload(form: FormState): Record<string, unknown> {
  const daysNum = form.days.trim() ? Number(form.days) : undefined;
  const renewNum = form.renewBeforeDays.trim() ? Number(form.renewBeforeDays) : undefined;
  const propDelay = form.validationDns01PropagationDelaySeconds.trim()
    ? Number(form.validationDns01PropagationDelaySeconds)
    : undefined;

  const hasDns01 = form.supportedValidations.includes('dns-01');
  const dns01Config =
    hasDns01 && (form.validationDns01Provider.trim() || form.validationDns01DdnsKey.trim() || propDelay !== undefined)
      ? {
          provider: form.validationDns01Provider.trim() || undefined,
          providerConfig: form.validationDns01DdnsKey.trim()
            ? { ddnsKey: form.validationDns01DdnsKey.trim() }
            : undefined,
          propagationDelaySeconds: propDelay,
        }
      : undefined;

  const hasTls = form.tlsCertPath.trim() || form.tlsKeyPath.trim() || form.tlsCaPath.trim();
  const tlsConfig = hasTls
    ? {
        certPath: form.tlsCertPath.trim() || undefined,
        keyPath: form.tlsKeyPath.trim() || undefined,
        caPath: form.tlsCaPath.trim() || undefined,
      }
    : undefined;

  const caConfig: Record<string, unknown> = {
    directoryUrl: form.directoryUrl.trim(),
    accountEmail: form.accountEmail.trim(),
    accountKeyPath: form.accountKeyPath.trim(),
    days: daysNum && Number.isFinite(daysNum) ? Math.floor(daysNum) : undefined,
    renewBeforeDays: renewNum && Number.isFinite(renewNum) ? Math.floor(renewNum) : undefined,
    supportedValidations: form.supportedValidations.length > 0 ? form.supportedValidations : undefined,
    defaultValidation: form.defaultValidation.trim() || undefined,
    validation: dns01Config ? { 'dns-01': dns01Config } : undefined,
    tls: tlsConfig,
    insecureSkipVerify: form.insecureSkipVerify || undefined,
  };

  Object.keys(caConfig).forEach((k) => {
    if (caConfig[k] === undefined) delete caConfig[k];
  });

  return {
    protocol: form.protocol.trim(),
    provider: form.provider.trim() || undefined,
    config: caConfig,
  };
}

export default function ShepherdCAs(): React.ReactElement {
  const [cas, setCas] = useState<CaDetail[]>([]);
  const canManage = usePermission('config:manage');
  const [formMode, setFormMode] = useState<'closed' | 'edit' | 'new'>('closed');
  const [form, setForm] = useState<FormState>(emptyForm);
  const [editName, setEditName] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const payload = await fetchCas();
      setCas(payload.cas);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load CAs');
    }
  });

  function openNew(): void {
    setForm(emptyForm);
    setEditName(null);
    setFormMode('new');
    setToast(null);
  }

  function openEdit(ca: CaDetail): void {
    setForm(caToForm(ca));
    setEditName(ca.name);
    setFormMode('edit');
    setToast(null);
  }

  function closeForm(): void {
    setFormMode('closed');
    setEditName(null);
    setToast(null);
  }

  function toggleValidation(method: string): void {
    setForm((f) => ({
      ...f,
      supportedValidations: f.supportedValidations.includes(method)
        ? f.supportedValidations.filter((m) => m !== method)
        : [...f.supportedValidations, method],
    }));
  }

  function handleSave(): void {
    void (async () => {
      const name = formMode === 'new' ? form.name.trim() : (editName ?? form.name.trim());
      if (!name) {
        setToast({ msg: 'Name is required.', error: true });
        return;
      }
      if (!form.directoryUrl.trim()) {
        setToast({ msg: 'Directory URL is required.', error: true });
        return;
      }
      if (!form.accountEmail.trim()) {
        setToast({ msg: 'Account email is required.', error: true });
        return;
      }
      if (!form.accountKeyPath.trim()) {
        setToast({ msg: 'Account key path is required.', error: true });
        return;
      }

      setSaving(true);
      try {
        await updateCa(name, toCaPayload(form));
        setToast({ msg: `Saved CA '${name}'.` });
        setFormMode('closed');
        setEditName(null);
        refresh();
      } catch (err) {
        setToast({ msg: err instanceof Error ? err.message : 'Failed to save CA.', error: true });
      } finally {
        setSaving(false);
      }
    })();
  }

  function handleDelete(): void {
    void (async () => {
      const name = editName ?? form.name.trim();
      if (!name) return;
      setSaving(true);
      try {
        await deleteCa(name);
        setToast({ msg: `Deleted CA '${name}'.` });
        setFormMode('closed');
        setEditName(null);
        refresh();
      } catch (err) {
        setToast({ msg: err instanceof Error ? err.message : 'Failed to delete CA.', error: true });
      } finally {
        setSaving(false);
      }
    })();
  }

  const hasDns01 = form.supportedValidations.includes('dns-01');

  return (
    <>
      <Topbar title="Certificate Authorities" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div
        className="page-content"
        style={{ flexDirection: 'row', gap: 14, overflow: 'hidden', padding: 0 }}
      >
        {/* Left: CA table */}
        <div
          style={{
            flex: formMode !== 'closed' ? '1 1 55%' : '1',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            padding: '14px 0 14px 16px',
          }}
        >
          {error && <div className="toast toast-error" style={{ marginBottom: 10 }}>{error}</div>}
          {toast && formMode === 'closed' && (
            <div className={`toast${toast.error ? ' toast-error' : ''}`}>{toast.msg}</div>
          )}

          <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div className="filter-bar">
              <span style={{ color: 'var(--muted)', fontSize: 13 }}>{cas.length} CA{cas.length !== 1 ? 's' : ''}</span>
              {canManage && (
                <button className="btn btn-primary btn-sm" onClick={openNew}>+ New</button>
              )}
            </div>
            <div className="table-wrap" style={{ flex: 1, overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Protocol</th>
                    <th>Provider</th>
                    <th>Directory URL</th>
                    <th>Default Validation</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {cas.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>
                        No CAs configured
                      </td>
                    </tr>
                  )}
                  {cas.map((ca) => (
                    <tr key={ca.name}>
                      <td className="fw-500">{ca.name}</td>
                      <td className="text-muted">{ca.protocol}</td>
                      <td className="text-muted">{ca.provider ?? '—'}</td>
                      <td className="text-muted" style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ca.directoryUrl ?? '—'}
                      </td>
                      <td className="text-muted">{ca.defaultValidation ?? '—'}</td>
                      <td>
                        <button className="btn btn-ghost btn-sm" onClick={() => openEdit(ca)}>
                          {canManage ? 'Edit' : 'View'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right: form */}
        {formMode !== 'closed' && (
          <div
            style={{
              flex: '0 0 42%',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
              padding: '14px 16px 14px 0',
            }}
          >
            {toast && (
              <div className={`toast${toast.error ? ' toast-error' : ''}`} style={{ marginBottom: 10 }}>
                {toast.msg}
              </div>
            )}
            <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div
                className="card-header"
                style={{ position: 'sticky', top: 0, zIndex: 1, background: 'var(--surface)' }}
              >
                <span className="card-title">
                  {formMode === 'new' ? 'New CA' : `Edit: ${editName}`}
                </span>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                  {canManage && (
                    <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>
                      {saving ? 'Saving…' : 'Save'}
                    </button>
                  )}
                  <button className="btn btn-ghost btn-sm" onClick={closeForm} disabled={saving}>
                    Cancel
                  </button>
                </div>
              </div>

              <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
                {/* Basic */}
                <div className="form-section">
                  <div className="form-section-label">Basic</div>
                  <div className="form-row">
                    <label className="form-label">Name</label>
                    <input
                      className="form-input"
                      value={form.name}
                      disabled={formMode === 'edit'}
                      onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Protocol</label>
                    <input
                      className="form-input"
                      value={form.protocol}
                      onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Provider</label>
                    <input
                      className="form-input"
                      placeholder="letsencrypt, vigil, …"
                      value={form.provider}
                      onChange={(e) => setForm((f) => ({ ...f, provider: e.target.value }))}
                    />
                  </div>
                </div>

                {/* ACME */}
                <div className="form-section">
                  <div className="form-section-label">ACME</div>
                  <div className="form-row">
                    <label className="form-label">Directory URL</label>
                    <input
                      className="form-input"
                      placeholder="https://acme-v02.api.letsencrypt.org/directory"
                      value={form.directoryUrl}
                      onChange={(e) => setForm((f) => ({ ...f, directoryUrl: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Account Email</label>
                    <input
                      className="form-input"
                      type="email"
                      value={form.accountEmail}
                      onChange={(e) => setForm((f) => ({ ...f, accountEmail: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Account Key Path</label>
                    <input
                      className="form-input"
                      placeholder="/path/to/account-key.pem"
                      value={form.accountKeyPath}
                      onChange={(e) => setForm((f) => ({ ...f, accountKeyPath: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Validity (days)</label>
                    <input
                      className="form-input"
                      type="number"
                      placeholder="90"
                      value={form.days}
                      onChange={(e) => setForm((f) => ({ ...f, days: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Renew Before (days)</label>
                    <input
                      className="form-input"
                      type="number"
                      placeholder="30"
                      value={form.renewBeforeDays}
                      onChange={(e) => setForm((f) => ({ ...f, renewBeforeDays: e.target.value }))}
                    />
                  </div>
                </div>

                {/* Validation */}
                <div className="form-section">
                  <div className="form-section-label">Validation</div>
                  <div className="form-row">
                    <label className="form-label">Supported</label>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                      {VALIDATION_METHODS.map((m) => (
                        <label key={m} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', fontSize: 13 }}>
                          <input
                            type="checkbox"
                            checked={form.supportedValidations.includes(m)}
                            onChange={() => toggleValidation(m)}
                          />
                          {m}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="form-row">
                    <label className="form-label">Default</label>
                    <select
                      className="form-select"
                      value={form.defaultValidation}
                      onChange={(e) => setForm((f) => ({ ...f, defaultValidation: e.target.value }))}
                    >
                      <option value="">— none —</option>
                      {form.supportedValidations.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* DNS-01 */}
                {hasDns01 && (
                  <div className="form-section">
                    <div className="form-section-label">DNS-01 Defaults</div>
                    <div className="form-row">
                      <label className="form-label">Provider</label>
                      <input
                        className="form-input"
                        placeholder="he"
                        value={form.validationDns01Provider}
                        onChange={(e) => setForm((f) => ({ ...f, validationDns01Provider: e.target.value }))}
                      />
                    </div>
                    <div className="form-row">
                      <label className="form-label">DDNS Key</label>
                      <input
                        className="form-input"
                        placeholder="${SHEPHERD_DDNS_KEY}"
                        value={form.validationDns01DdnsKey}
                        onChange={(e) => setForm((f) => ({ ...f, validationDns01DdnsKey: e.target.value }))}
                      />
                    </div>
                    <div className="form-row">
                      <label className="form-label">Propagation Delay (s)</label>
                      <input
                        className="form-input"
                        type="number"
                        value={form.validationDns01PropagationDelaySeconds}
                        onChange={(e) => setForm((f) => ({ ...f, validationDns01PropagationDelaySeconds: e.target.value }))}
                      />
                    </div>
                  </div>
                )}

                {/* TLS */}
                <div className="form-section">
                  <div className="form-section-label">TLS (mTLS to CA)</div>
                  <div className="form-row">
                    <label className="form-label">Cert Path</label>
                    <input
                      className="form-input"
                      placeholder="/path/to/cert.pem"
                      value={form.tlsCertPath}
                      onChange={(e) => setForm((f) => ({ ...f, tlsCertPath: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Key Path</label>
                    <input
                      className="form-input"
                      placeholder="/path/to/key.pem"
                      value={form.tlsKeyPath}
                      onChange={(e) => setForm((f) => ({ ...f, tlsKeyPath: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">CA Path</label>
                    <input
                      className="form-input"
                      placeholder="/path/to/ca.pem"
                      value={form.tlsCaPath}
                      onChange={(e) => setForm((f) => ({ ...f, tlsCaPath: e.target.value }))}
                    />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Skip TLS Verify</label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13 }}>
                      <input
                        type="checkbox"
                        checked={form.insecureSkipVerify}
                        onChange={(e) => setForm((f) => ({ ...f, insecureSkipVerify: e.target.checked }))}
                      />
                      insecureSkipVerify
                    </label>
                  </div>
                </div>

                {/* Delete */}
                {formMode === 'edit' && canManage && (
                  <div style={{ paddingTop: 12, borderTop: '1px solid var(--border)', marginTop: 4 }}>
                    <button
                      className="btn btn-danger btn-sm"
                      style={{ width: '100%', justifyContent: 'center' }}
                      disabled={saving}
                      onClick={handleDelete}
                    >
                      Delete CA
                    </button>
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
