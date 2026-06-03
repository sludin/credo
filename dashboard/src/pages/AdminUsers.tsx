import React, { useEffect, useState } from 'react';
import { usePermission } from '../hooks/usePermission';

type UserRow = {
  id: string;
  shepherdAccount: string;
  displayName: string;
  email: string;
  active: boolean;
  createdAt: string;
  passkeyCount: number;
  hasInvite: boolean;
};

export default function AdminUsers(): React.ReactElement {
  const canManage = usePermission('user:manage');
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({ shepherdAccount: '', displayName: '', email: '' });
  const [enrollUrl, setEnrollUrl] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function loadUsers(): Promise<void> {
    try {
      const resp = await fetch('/auth/admin/users', { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json() as { users: UserRow[] };
        setUsers(data.users);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }

  useEffect(() => { void loadUsers(); }, []);

  async function handleCreate(): Promise<void> {
    setCreating(true);
    setError(null);
    try {
      const resp = await fetch('/auth/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(createForm),
      });
      const data = await resp.json() as { enrollUrl?: string; error?: string };
      if (!resp.ok) throw new Error(data.error ?? 'Failed to create user.');
      setEnrollUrl(data.enrollUrl ?? null);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user.');
    } finally {
      setCreating(false);
    }
  }

  async function handleRegenInvite(id: string): Promise<void> {
    try {
      const resp = await fetch(`/auth/admin/users/${id}/invite`, {
        method: 'POST',
        credentials: 'include',
      });
      const data = await resp.json() as { enrollUrl?: string };
      if (data.enrollUrl) setEnrollUrl(data.enrollUrl);
    } catch { /* ignore */ }
  }

  async function handleToggleActive(user: UserRow): Promise<void> {
    try {
      await fetch(`/auth/admin/users/${user.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ active: !user.active }),
      });
      await loadUsers();
    } catch { /* ignore */ }
  }

  if (loading) return <div style={{ padding: 24, color: 'var(--muted)' }}>Loading…</div>;

  return (
    <div style={{ padding: 24 }}>
      <div style={styles.header}>
        <h1 style={styles.heading}>User Management</h1>
        {canManage && (
          <button style={styles.button} onClick={() => { setShowCreate(true); setEnrollUrl(null); }}>
            + Create user
          </button>
        )}
      </div>

      {error && <div style={styles.error}>{error}</div>}

      {enrollUrl && (
        <div style={styles.enrollBanner}>
          <strong>Enrollment URL</strong>
          <code style={styles.enrollUrl}>{enrollUrl}</code>
          <button style={styles.copyBtn} onClick={() => void navigator.clipboard.writeText(enrollUrl)}>
            Copy
          </button>
        </div>
      )}

      {showCreate && canManage && (
        <div style={styles.createForm}>
          <h2 style={styles.sectionTitle}>New user</h2>
          <label style={styles.formLabel}>
            Shepherd account name
            <input
              style={styles.input}
              value={createForm.shepherdAccount}
              onChange={(e) => setCreateForm((f) => ({ ...f, shepherdAccount: e.target.value }))}
              placeholder="alice"
            />
          </label>
          <label style={styles.formLabel}>
            Display name
            <input
              style={styles.input}
              value={createForm.displayName}
              onChange={(e) => setCreateForm((f) => ({ ...f, displayName: e.target.value }))}
              placeholder="Alice Admin"
            />
          </label>
          <label style={styles.formLabel}>
            Email
            <input
              style={styles.input}
              type="email"
              value={createForm.email}
              onChange={(e) => setCreateForm((f) => ({ ...f, email: e.target.value }))}
              placeholder="alice@example.com"
            />
          </label>
          <div style={styles.formActions}>
            <button
              style={{ ...styles.button, ...(creating ? styles.buttonDisabled : {}) }}
              onClick={() => void handleCreate()}
              disabled={creating || !createForm.shepherdAccount || !createForm.displayName || !createForm.email}
            >
              {creating ? 'Creating…' : 'Create & generate invite'}
            </button>
            <button style={styles.cancelBtn} onClick={() => setShowCreate(false)}>Cancel</button>
          </div>
        </div>
      )}

      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>User</th>
            <th style={styles.th}>Shepherd account</th>
            <th style={styles.th}>Passkeys</th>
            <th style={styles.th}>Status</th>
            {canManage && <th style={styles.th}>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td style={styles.td}>
                <div style={{ fontWeight: 500 }}>{u.displayName}</div>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>{u.email}</div>
              </td>
              <td style={styles.td}><code style={styles.mono}>{u.shepherdAccount}</code></td>
              <td style={styles.td}>{u.passkeyCount === 0 ? <span style={{ color: 'var(--muted)' }}>none</span> : u.passkeyCount}</td>
              <td style={styles.td}>
                {u.active
                  ? <span style={styles.badgeGreen}>{u.hasInvite ? 'pending enrollment' : 'active'}</span>
                  : <span style={styles.badgeRed}>inactive</span>
                }
              </td>
              {canManage && (
                <td style={styles.td}>
                  <div style={styles.actions}>
                    <button style={styles.actionBtn} onClick={() => void handleRegenInvite(u.id)}>
                      New invite
                    </button>
                    <button
                      style={{ ...styles.actionBtn, ...(u.active ? styles.deactivateBtn : {}) }}
                      onClick={() => void handleToggleActive(u)}
                    >
                      {u.active ? 'Deactivate' : 'Activate'}
                    </button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 },
  heading: { fontSize: 22, fontWeight: 600, margin: 0, color: 'var(--fg)' },
  button: {
    padding: '8px 16px', background: 'var(--accent, #6366f1)',
    color: '#fff', border: 'none', borderRadius: 6, fontSize: 13,
    fontWeight: 500, cursor: 'pointer',
  },
  buttonDisabled: { opacity: 0.5, cursor: 'not-allowed' },
  cancelBtn: {
    padding: '8px 16px', background: 'transparent',
    border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--muted)', fontSize: 13, cursor: 'pointer',
  },
  error: {
    marginBottom: 16, padding: '10px 14px',
    background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: 6, color: '#f87171', fontSize: 13,
  },
  enrollBanner: {
    marginBottom: 16, padding: '12px 16px',
    background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.3)',
    borderRadius: 6, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
    fontSize: 13,
  },
  enrollUrl: {
    flex: 1, fontFamily: 'monospace', fontSize: 12,
    color: 'var(--fg)', wordBreak: 'break-all',
  },
  copyBtn: {
    padding: '4px 10px', background: 'rgba(34,197,94,0.15)',
    border: '1px solid rgba(34,197,94,0.3)', borderRadius: 4,
    color: '#4ade80', fontSize: 12, cursor: 'pointer',
  },
  createForm: {
    background: 'var(--surface)', border: '1px solid var(--border)',
    borderRadius: 8, padding: '20px 24px', marginBottom: 20,
    display: 'flex', flexDirection: 'column', gap: 12,
  },
  sectionTitle: { margin: 0, fontSize: 15, fontWeight: 600, color: 'var(--fg)' },
  formLabel: { display: 'flex', flexDirection: 'column', gap: 4, fontSize: 13, color: 'var(--muted)' },
  input: {
    marginTop: 4, background: 'var(--surface-2)',
    border: '1px solid var(--border)', borderRadius: 6,
    padding: '8px 12px', color: 'var(--fg)', fontSize: 13,
  },
  formActions: { display: 'flex', gap: 8, marginTop: 4 },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: {
    textAlign: 'left', color: 'var(--muted)', fontWeight: 500,
    padding: '8px 12px', borderBottom: '1px solid var(--border)',
  },
  td: { padding: '10px 12px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle' },
  mono: { fontFamily: 'monospace', fontSize: 12, background: 'var(--surface-2)', padding: '2px 6px', borderRadius: 4 },
  badgeGreen: { fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: 'rgba(34,197,94,0.1)', color: '#4ade80' },
  badgeRed: { fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: 'rgba(239,68,68,0.1)', color: '#f87171' },
  actions: { display: 'flex', gap: 6 },
  actionBtn: {
    padding: '4px 10px', background: 'transparent',
    border: '1px solid var(--border)', borderRadius: 4,
    color: 'var(--muted)', fontSize: 12, cursor: 'pointer',
  },
  deactivateBtn: { borderColor: 'rgba(239,68,68,0.3)', color: '#f87171' },
};
