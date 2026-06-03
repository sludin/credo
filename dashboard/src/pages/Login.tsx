import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  browserSupportsWebAuthn,
  startAuthentication,
} from '@simplewebauthn/browser';
import { useAuth } from '../context/AuthContext';

export default function Login(): React.ReactElement {
  const navigate = useNavigate();
  const location = useLocation();
  const { refresh } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/';

  async function handleSignIn(): Promise<void> {
    if (!browserSupportsWebAuthn()) {
      setError('Your browser does not support passkeys. Please use a modern browser.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const beginResp = await fetch('/auth/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      if (!beginResp.ok) throw new Error('Failed to start authentication.');
      const { options, challengeKey } = await beginResp.json() as {
        options: Parameters<typeof startAuthentication>[0]['optionsJSON'];
        challengeKey: string;
      };

      const authResponse = await startAuthentication({ optionsJSON: options });

      const finishResp = await fetch('/auth/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ challengeKey, response: authResponse }),
      });

      if (!finishResp.ok) {
        const data = await finishResp.json() as { error?: string };
        throw new Error(data.error ?? 'Authentication failed.');
      }

      await refresh();
      navigate(from, { replace: true });
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        setError('Authentication was cancelled or timed out.');
      } else {
        setError(err instanceof Error ? err.message : 'Authentication failed.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.logo}>🔐</div>
        <h1 style={styles.title}>Credo Dashboard</h1>
        <p style={styles.subtitle}>Sign in with your passkey</p>

        {error && (
          <div style={styles.error}>{error}</div>
        )}

        <button
          onClick={() => void handleSignIn()}
          disabled={loading}
          style={{ ...styles.button, ...(loading ? styles.buttonDisabled : {}) }}
        >
          {loading ? 'Waiting for passkey…' : 'Sign in with passkey'}
        </button>

        <p style={styles.hint}>
          No passkey yet? Contact your administrator for an enrollment link.
        </p>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'var(--bg, #0f1117)',
  },
  card: {
    background: 'var(--surface, #1a1d27)',
    border: '1px solid var(--border, #2a2d3a)',
    borderRadius: 12,
    padding: '48px 40px',
    width: '100%',
    maxWidth: 400,
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 16,
  },
  logo: { fontSize: 48, marginBottom: 8 },
  title: { margin: 0, fontSize: 24, fontWeight: 600, color: 'var(--fg, #e2e8f0)' },
  subtitle: { margin: 0, color: 'var(--muted, #64748b)', fontSize: 14 },
  error: {
    width: '100%',
    padding: '10px 14px',
    background: 'rgba(239,68,68,0.1)',
    border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: 6,
    color: '#f87171',
    fontSize: 13,
  },
  button: {
    width: '100%',
    padding: '12px 20px',
    background: 'var(--accent, #6366f1)',
    color: '#fff',
    border: 'none',
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'opacity 0.15s',
  },
  buttonDisabled: { opacity: 0.6, cursor: 'not-allowed' },
  hint: { color: 'var(--muted, #64748b)', fontSize: 12, margin: 0 },
};
