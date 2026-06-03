// src/pages/Assignments.tsx
import React, { useState } from 'react';
import { usePoller } from '../hooks/usePoller';
import {
  createAssignment,
  deleteAssignment,
  fetchAssignments,
  fetchFlock,
  fetchShepherdConfigSummary,
  updateAssignment,
} from '../api';
import { Topbar } from '../components/Shell';
import { StatusBadge } from '../components/StatusBadge';
import { usePermission } from '../hooks/usePermission';
import type { Assignment, CorgiState, ShepherdConfigSummary } from '../types';

type CaInfo = ShepherdConfigSummary['cas'][number];
type CaMap = Record<string, CaInfo>;

type SortDir = 'asc' | 'desc';
type SortKey = 'certName' | 'corgi' | 'ca' | 'validation' | 'renewBeforeDays';

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
};

const emptyForm: FormState = {
  certName: '', corgi: '', ca: 'letsencrypt', caTarget: '',
  letsEncryptTarget: '', domain: '', identityUri: '', sans: '', days: '90', renewBeforeDays: '30',
  validationType: 'none-01', validationProvider: '', validationDdnsKey: '',
};

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
  };
}

function toAssignmentPayload(form: FormState): Record<string, unknown> {
  const sans = form.sans
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
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
        ? {
            'dns-01': {
              provider: form.validationProvider.trim() || undefined,
              providerConfig: form.validationDdnsKey.trim()
                ? { ddnsKey: form.validationDdnsKey.trim() }
                : undefined,
            },
          }
        : undefined,
    };
  }

  Object.keys(payload).forEach((key) => {
    if (payload[key] === undefined) {
      delete payload[key];
    }
  });
  return payload;
}

export default function Assignments(): React.ReactElement {
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const canCreate = usePermission('assignment:create');
  const canEdit = usePermission('assignment:edit');
  const canDelete = usePermission('assignment:delete');

  const [corgis, setCorgis] = useState<CorgiState[]>([]);
  const [caOptions, setCaOptions] = useState<string[]>(['letsencrypt', 'vigil']);
  const [caMap, setCaMap] = useState<CaMap>({});
  const [filter, setFilter] = useState('');
  const [formMode, setFormMode] = useState<'closed' | 'edit' | 'new'>('closed');
  const [form, setForm] = useState<FormState>(emptyForm);
  const [editTarget, setEditTarget] = useState<{ certName: string; corgi: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'certName', dir: 'asc' });

  const { secondsAgo, refresh } = usePoller(async () => {
    try {
      const [a, f, cfg] = await Promise.all([fetchAssignments(), fetchFlock(), fetchShepherdConfigSummary()]);
      setAssignments(a.assignments);
      setCorgis(f.corgis);
      const dynamicCas = cfg.cas
        .map((entry) => entry.name)
        .filter((name) => typeof name === 'string' && name.trim())
        .map((name) => name.trim());
      setCaOptions(dynamicCas.length > 0 ? dynamicCas : ['letsencrypt', 'vigil']);
      const map: CaMap = {};
      for (const ca of cfg.cas) map[ca.name] = ca;
      setCaMap(map);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  });

  const filtered = filter
    ? assignments.filter((a) =>
        a.certName.toLowerCase().includes(filter.toLowerCase()) ||
        a.corgi.toLowerCase().includes(filter.toLowerCase())
      )
    : assignments;

  const sorted = [...filtered].sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'certName': cmp = a.certName.localeCompare(b.certName); break;
      case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
      case 'ca': cmp = (a.ca ?? '').localeCompare(b.ca ?? ''); break;
      case 'validation': cmp = (a.validation?.type ?? 'none-01').localeCompare(b.validation?.type ?? 'none-01'); break;
      case 'renewBeforeDays': cmp = (a.renewBeforeDays ?? 0) - (b.renewBeforeDays ?? 0); break;
    }
    return sort.dir === 'asc' ? cmp : -cmp;
  });

  function toggleSort(key: SortKey): void {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  function sortIndicator(active: boolean, dir: SortDir): string {
    if (!active) return '↕';
    return dir === 'asc' ? '↑' : '↓';
  }

  function openEdit(a: Assignment): void {
    setForm(assignmentToForm(a));
    setEditTarget({ certName: a.certName, corgi: a.corgi });
    setFormMode('edit');
    setToast(null);
  }

  function openNew(): void {
    setForm({ ...emptyForm, corgi: corgis[0]?.name ?? '' });
    setEditTarget(null);
    setFormMode('new');
    setToast(null);
  }

  function closeForm(): void {
    setFormMode('closed');
    setEditTarget(null);
    setToast(null);
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
        if (formMode === 'new') {
          await createAssignment(payload);
          setToast({ msg: `Created assignment ${corgi}/${certName}.` });
        } else {
          const target = editTarget ?? { certName, corgi };
          await updateAssignment(target.certName, payload, target.corgi);
          setToast({ msg: `Saved assignment ${corgi}/${certName}.` });
        }
        setFormMode('closed');
        setEditTarget(null);
        refresh();
      } catch (err) {
        setToast({ msg: err instanceof Error ? err.message : 'Failed to save assignment.', error: true });
      } finally {
        setSaving(false);
      }
    })();
  }

  function handleDelete(certName: string): void {
    void (async () => {
      const corgi = form.corgi.trim();
      setSaving(true);
      try {
        const target = editTarget ?? { certName, corgi };
        await deleteAssignment(target.certName, target.corgi || undefined);
        setToast({ msg: `Deleted assignment ${corgi}/${certName}.` });
        setFormMode('closed');
        setEditTarget(null);
        refresh();
      } catch (err) {
        setToast({ msg: err instanceof Error ? err.message : 'Failed to delete assignment.', error: true });
      } finally {
        setSaving(false);
      }
    })();
  }

  return (
    <>
      <Topbar title="Assignments" secondsAgo={secondsAgo} onRefresh={refresh} />
      <div
        className="page-content"
        style={{ flexDirection: 'row', gap: 14, overflow: 'hidden', padding: 0 }}
      >
        {/* Left: assignment table */}
        <div style={{ flex: formMode !== 'closed' ? '1 1 55%' : '1', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 0 14px 16px' }}>
          {error && <div className="toast toast-error" style={{ marginBottom: 10 }}>{error}</div>}
          {toast && formMode === 'closed' && <div className={`toast${toast.error ? ' toast-error' : ''}`}>{toast.msg}</div>}

          <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div className="filter-bar">
              <input
                className="filter-input"
                placeholder="Filter by cert name or corgi…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              {canCreate && <button className="btn btn-primary btn-sm" onClick={openNew}>+ New</button>}
            </div>
            <div className="table-wrap" style={{ flex: 1, overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th className="th-sort" onClick={() => toggleSort('certName')}>Cert Name <span>{sortIndicator(sort.key === 'certName', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('corgi')}>Corgi <span>{sortIndicator(sort.key === 'corgi', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('ca')}>CA <span>{sortIndicator(sort.key === 'ca', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('validation')}>Validation <span>{sortIndicator(sort.key === 'validation', sort.dir)}</span></th>
                    <th className="th-sort" onClick={() => toggleSort('renewBeforeDays')}>Renew Before <span>{sortIndicator(sort.key === 'renewBeforeDays', sort.dir)}</span></th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.length === 0 && (
                    <tr><td colSpan={6} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>No assignments</td></tr>
                  )}
                  {sorted.map((a) => (
                    <tr key={`${a.corgi}:${a.certName}`}>
                      <td className="fw-500">{a.certName}</td>
                      <td className="text-muted">{a.corgi}</td>
                      <td className="text-muted">{a.ca ?? '—'}</td>
                      <td>
                        {(() => {
                          const caInfo = caMap[a.ca ?? ''];
                          const eff = a.validation?.type ?? caInfo?.defaultValidation ?? 'none-01';
                          const inherited = !a.validation?.type && eff !== 'none-01';
                          return (
                            <StatusBadge
                              label={inherited ? `${eff} (CA)` : eff}
                              tone={eff === 'dns-01' ? 'blue' : 'muted'}
                            />
                          );
                        })()}
                      </td>
                      <td className="text-muted">{a.renewBeforeDays ? `${a.renewBeforeDays}d` : '—'}</td>
                      <td>
                        {canEdit && <button className="btn btn-ghost btn-sm" onClick={() => openEdit(a)}>Edit</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right: edit/new form */}
        {formMode !== 'closed' && (
          <div style={{ flex: '0 0 42%', display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 16px 14px 0' }}>
            {toast && <div className={`toast${toast.error ? ' toast-error' : ''}`} style={{ marginBottom: 10 }}>{toast.msg}</div>}
            <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div className="card-header" style={{ position: 'sticky', top: 0, zIndex: 1, background: 'var(--surface)' }}>
                <span className="card-title">{formMode === 'new' ? 'New Assignment' : `Edit: ${form.certName}`}</span>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                  <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>
                    {saving ? 'Saving...' : 'Save'}
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={closeForm} disabled={saving}>Cancel</button>
                </div>
              </div>

              <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
                {/* Basic */}
                <div className="form-section">
                  <div className="form-section-label">Basic</div>
                  <div className="form-row">
                    <label className="form-label">Cert Name</label>
                    <input className="form-input" value={form.certName} onChange={(e) => setForm((f) => ({ ...f, certName: e.target.value }))} />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Corgi</label>
                    <select className="form-select" value={form.corgi} onChange={(e) => setForm((f) => ({ ...f, corgi: e.target.value }))}>
                      {corgis.map((c) => <option key={c.name} value={c.name}>{c.name}</option>)}
                    </select>
                  </div>
                  <div className="form-row">
                    <label className="form-label">CA</label>
                    <select className="form-select" value={form.ca} onChange={(e) => setForm((f) => ({ ...f, ca: e.target.value }))}>
                      {caOptions.map((caName) => <option key={caName} value={caName}>{caName}</option>)}
                    </select>
                  </div>
                  <div className="form-row">
                    <label className="form-label">Validity (days)</label>
                    <input className="form-input" type="number" value={form.days} onChange={(e) => setForm((f) => ({ ...f, days: e.target.value }))} />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Renew Before (days)</label>
                    <input className="form-input" type="number" value={form.renewBeforeDays} onChange={(e) => setForm((f) => ({ ...f, renewBeforeDays: e.target.value }))} />
                  </div>
                </div>

                {/* Validation */}
                <div className="form-section">
                  <div className="form-section-label">Validation</div>
                  <div className="form-row">
                    <label className="form-label">Type</label>
                    <select className="form-select" value={form.validationType} onChange={(e) => setForm((f) => ({ ...f, validationType: e.target.value as FormState['validationType'] }))}>
                      <option value="none-01">none-01</option>
                      <option value="http-01">http-01</option>
                      <option value="dns-01">dns-01</option>
                    </select>
                  </div>
                  {form.validationType === 'dns-01' && (
                    <>
                      <div className="form-row">
                        <label className="form-label">Provider</label>
                        <input className="form-input" placeholder="he" value={form.validationProvider} onChange={(e) => setForm((f) => ({ ...f, validationProvider: e.target.value }))} />
                      </div>
                      <div className="form-row">
                        <label className="form-label">DDNS Key (env)</label>
                        <input className="form-input" placeholder="${SHEPHERD_DDNS_KEY}" value={form.validationDdnsKey} onChange={(e) => setForm((f) => ({ ...f, validationDdnsKey: e.target.value }))} />
                      </div>
                    </>
                  )}
                </div>

                {/* Domains */}
                <div className="form-section">
                  <div className="form-section-label">Domains & SANs</div>
                  <div className="form-row">
                    <label className="form-label">Primary Domain</label>
                    <input className="form-input" value={form.domain} onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))} />
                  </div>
                  <div className="form-row">
                    <label className="form-label">Identity URI</label>
                    <input
                      className="form-input"
                      placeholder="vigil://credo/dev/service/dashboard"
                      value={form.identityUri}
                      onChange={(e) => setForm((f) => ({ ...f, identityUri: e.target.value }))}
                    />
                  </div>
                  <textarea
                    className="form-textarea"
                    placeholder={"example.com\nwww.example.com"}
                    value={form.sans}
                    onChange={(e) => setForm((f) => ({ ...f, sans: e.target.value }))}
                    style={{ width: '100%' }}
                  />
                </div>

                {/* Delete — edit mode only */}
                {formMode === 'edit' && canDelete && (
                  <div style={{ paddingTop: 12, borderTop: '1px solid var(--border)', marginTop: 4 }}>
                    <button
                      className="btn btn-danger btn-sm"
                      style={{ width: '100%', justifyContent: 'center' }}
                      disabled={saving}
                      onClick={() => handleDelete(form.certName)}
                    >
                      Delete Assignment
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
