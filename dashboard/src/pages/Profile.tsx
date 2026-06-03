import React, { useEffect, useState } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import { useAuth } from '../context/AuthContext';

type Passkey = {
  credentialId: string;
  label: string;
  createdAt: string;
  lastUsedAt: string;
};

export default function Profile(): React.ReactElement {
  const { user, refresh } = useAuth();
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [loading, setLoading] = useState(true);
  const [addingPasskey, setAddingPasskey] = useState(false);
  const [newLabel, setNewLabel] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function loadPasskeys(): Promise<void> {
    try {
      const resp = await fetch('/auth/admin/users', { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json() as { users: Array<{ id: string; passkeys: Passkey[] }> };
        const me = data.users.find((u) => u.id === user?.userId);
        if (me) setPasskeys(me.passkeys);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }

  useEffect(() => { void loadPasskeys(); }, []);

  async function handleAddPasskey(): Promise<void> {
    setAddingPasskey(true);
    setError(null);

    try {
      const beginResp = await fetch('/auth/passkeys/begin', {
        method: 'POST',
        credentials: 'include',
      });
      if (!beginResp.ok) throw new Error('Failed to begin passkey registration.');
      const { registrationOptions } = await beginResp.json() as {
        registrationOptions: Parameters<typeof startRegistration>[0]['optionsJSON'];
      };

      const authResponse = await startRegistration({ optionsJSON: registrationOptions });

      const finishResp = await fetch('/auth/passkeys/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ response: authResponse, label: newLabel || undefined }),
      });

      if (!finishResp.ok) {
        const d = await finishResp.json() as { error?: string };
        throw new Error(d.error ?? 'Registration failed.');
      }

      setNewLabel('');
      setSuccess('New passkey registered successfully.');
      await loadPasskeys();
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        setError('Registration was cancelled.');
      } else {
        setError(err instanceof Error ? err.message : 'Registration failed.');
      }
    } finally {
      setAddingPasskey(false);
    }
  }

  async function handleDeletePasskey(credentialId: string): Promise<void> {
    if (!confirm('Remove this passkey? You will need another passkey or an invite link to log in.')) return;
    try {
      await fetch(`/auth/passkeys/${encodeURIComponent(credentialId)}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      await loadPasskeys();
    } catch { /* ignore */ }
  }

  async function handleLogout(): Promise<void> {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    await refresh();
  }

  if (loading) return <div style={{ padding: 24, color: 'var(--muted)' }}>Loading…</div>;

  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>My Profile</h1>

      <section style={styles.section}>
        <h2 style={styles.sectionTitle}>Account</h2>
        <div style={styles.field}><span style={styles.label}>Display name</span><span>{user?.displayName}</span></div>
        <div style={styles.field}><span style={styles.label}>Shepherd account</span><code style={styles.mono}>{user?.shepherdAccount}</code></div>
        <div style={styles.field}><span style={styles.label}>Role</span><span style={styles.roleBadge}>{user?.role}</span></div>
      </section>

      <section style={styles.section}>
        <h2 style={styles.sectionTitle}>Passkeys</h2>

        {error && <div style={styles.error}>{error}</div>}
        {success && <div style={styles.successMsg}>{success}</div>}

        {passkeys.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No passkeys registered.</p>
        ) : (
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Label</th>
                <th style={styles.th}>Added</th>
                <th style={styles.th}>Last used</th>
                <th style={styles.th}></th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((pk) => (
                <tr key={pk.credentialId}>
                  <td style={styles.td}>{pk.label}</td>
                  <td style={styles.td}>{new Date(pk.createdAt).toLocaleDateString()}</td>
                  <td style={styles.td}>{new Date(pk.lastUsedAt).toLocaleDateString()}</td>
                  <td style={styles.td}>
                    <button style={styles.deleteBtn} onClick={() => void handleDeletePasskey(pk.credentialId)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div style={styles.addPasskey}>
          <input
            style={styles.input}
            type="text"
            placeholder="Label for new passkey (e.g. iPhone Face ID)"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
          />
          <button
            style={{ ...styles.button, ...(addingPasskey ? styles.buttonDisabled : {}) }}
            onClick={() => void handleAddPasskey()}
            disabled={addingPasskey}
          >
            {addingPasskey ? 'Waiting…' : 'Add passkey'}
          </button>
        </div>
      </section>

      <section style={styles.section}>
        <button style={styles.logoutBtn} onClick={() => void handleLogout()}>Sign out</button>
      </section>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page: { padding: 24, maxWidth: 640 },
  heading: { fontSize: 22, fontWeight: 600, marginBottom: 24, color: 'var(--fg)' },
  section: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: '20px 24px',
    marginBottom: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  sectionTitle: { margin: 0, fontSize: 15, fontWeight: 600, color: 'var(--fg)' },
  field: { display: 'flex', gap: 16, alignItems: 'center', fontSize: 14 },
  label: { color: 'var(--muted)', width: 160, flexShrink: 0 },
  mono: { fontFamily: 'monospace', fontSize: 13, background: 'var(--surface-2)', padding: '2px 6px', borderRadius: 4 },
  roleBadge: {
    fontSize: 12, fontWeight: 600,
    padding: '2px 10px', borderRadius: 12,
    background: 'rgba(99,102,241,0.15)', color: '#818cf8',
  },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: { textAlign: 'left', color: 'var(--muted)', fontWeight: 500, padding: '6px 8px', borderBottom: '1px solid var(--border)' },
  td: { padding: '8px 8px', borderBottom: '1px solid var(--border)' },
  deleteBtn: {
    background: 'transparent', border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: 4, color: '#f87171', fontSize: 12, padding: '3px 8px', cursor: 'pointer',
  },
  addPasskey: { display: 'flex', gap: 8, alignItems: 'center' },
  input: {
    flex: 1, background: 'var(--surface-2)',
    border: '1px solid var(--border)', borderRadius: 6,
    padding: '8px 12px', color: 'var(--fg)', fontSize: 13,
  },
  button: {
    padding: '8px 16px', background: 'var(--accent, #6366f1)',
    color: '#fff', border: 'none', borderRadius: 6, fontSize: 13,
    fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap',
  },
  buttonDisabled: { opacity: 0.5, cursor: 'not-allowed' },
  error: { padding: '8px 12px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, color: '#f87171', fontSize: 13 },
  successMsg: { padding: '8px 12px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 6, color: '#4ade80', fontSize: 13 },
  logoutBtn: {
    padding: '9px 18px', background: 'transparent',
    border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--muted)', fontSize: 13, cursor: 'pointer',
    alignSelf: 'flex-start',
  },
};
