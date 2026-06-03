import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { useAuth } from '../context/AuthContext';

type Step = 'pop' | 'passkey' | 'done';

export default function Enroll(): React.ReactElement {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const { refresh } = useAuth();
  const [step, setStep] = useState<Step>('pop');
  const [popJson, setPopJson] = useState('');
  const [userId, setUserId] = useState<string | null>(null);
  const [registrationOptions, setRegistrationOptions] = useState<unknown>(null);
  const [passkeyLabel, setPasskeyLabel] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const cliCommand = `credo-enroll --cert vigil.pem --key vigil-key.pem --challenge ${token ?? '<token>'}`;

  async function handleVerifyPop(): Promise<void> {
    setLoading(true);
    setError(null);

    let pop: unknown;
    try {
      pop = JSON.parse(popJson);
    } catch {
      setError('Invalid JSON. Please paste the complete output from credo-enroll.');
      setLoading(false);
      return;
    }

    try {
      const resp = await fetch('/auth/enroll/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token, pop }),
      });

      const data = await resp.json() as {
        registrationOptions?: unknown;
        userId?: string;
        error?: string;
        expected?: string;
        got?: string;
        identityUri?: string;
      };
      if (!resp.ok) {
        let msg = data.error ?? 'Verification failed.';
        if (data.expected || data.got || data.identityUri) {
          msg += `\n  identity URI: ${data.identityUri ?? '(unknown)'}`;
          msg += `\n  expected account: ${data.expected ?? '(unknown)'}`;
          msg += `\n  resolved account: ${data.got ?? '(none)'}`;
        }
        throw new Error(msg);
      }

      setUserId(data.userId ?? null);
      setRegistrationOptions(data.registrationOptions ?? null);
      setStep('passkey');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRegisterPasskey(): Promise<void> {
    if (!userId || !registrationOptions) return;
    setLoading(true);
    setError(null);

    try {
      const authResponse = await startRegistration({
        optionsJSON: registrationOptions as Parameters<typeof startRegistration>[0]['optionsJSON'],
      });

      const resp = await fetch('/auth/enroll/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ userId, response: authResponse, label: passkeyLabel || undefined }),
      });

      const data = await resp.json() as { error?: string };
      if (!resp.ok) {
        throw new Error(data.error ?? 'Registration failed.');
      }

      await refresh();
      setStep('done');
      setTimeout(() => navigate('/'), 2000);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        setError('Registration was cancelled. Please try again.');
      } else {
        setError(err instanceof Error ? err.message : 'Registration failed.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>Enroll Your Passkey</h1>

        <div style={styles.stepper}>
          {(['pop', 'passkey', 'done'] as Step[]).map((s, i) => (
            <React.Fragment key={s}>
              <div style={{ ...styles.stepDot, ...(step === s ? styles.stepDotActive : step > s ? styles.stepDotDone : {}) }}>
                {i + 1}
              </div>
              {i < 2 && <div style={styles.stepLine} />}
            </React.Fragment>
          ))}
        </div>

        {error && <div style={styles.error}>{error}</div>}

        {step === 'pop' && (
          <div style={styles.section}>
            <p style={styles.desc}>
              First, prove your identity using your Vigil certificate. Run this command on your computer:
            </p>
            <pre style={styles.code}>{cliCommand}</pre>
            <p style={styles.desc}>
              Paste the JSON output below:
            </p>
            <textarea
              style={styles.textarea}
              placeholder='{ "cert": "...", "signature": "...", ... }'
              value={popJson}
              onChange={(e) => setPopJson(e.target.value)}
              rows={6}
            />
            <button
              style={{ ...styles.button, ...(loading || !popJson.trim() ? styles.buttonDisabled : {}) }}
              onClick={() => void handleVerifyPop()}
              disabled={loading || !popJson.trim()}
            >
              {loading ? 'Verifying…' : 'Verify Identity'}
            </button>
          </div>
        )}

        {step === 'passkey' && (
          <div style={styles.section}>
            <p style={styles.desc}>
              Identity verified! Now register your passkey. You can use Touch ID, Face ID, or a hardware key.
            </p>
            <input
              style={styles.input}
              type="text"
              placeholder="Label this device (e.g. MacBook Touch ID)"
              value={passkeyLabel}
              onChange={(e) => setPasskeyLabel(e.target.value)}
            />
            <button
              style={{ ...styles.button, ...(loading ? styles.buttonDisabled : {}) }}
              onClick={() => void handleRegisterPasskey()}
              disabled={loading}
            >
              {loading ? 'Waiting for passkey…' : 'Register Passkey'}
            </button>
          </div>
        )}

        {step === 'done' && (
          <div style={styles.section}>
            <div style={{ fontSize: 48, textAlign: 'center' }}>✅</div>
            <p style={{ ...styles.desc, textAlign: 'center' }}>
              Passkey registered! Redirecting to dashboard…
            </p>
          </div>
        )}
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
    padding: 24,
  },
  card: {
    background: 'var(--surface, #1a1d27)',
    border: '1px solid var(--border, #2a2d3a)',
    borderRadius: 12,
    padding: '40px 36px',
    width: '100%',
    maxWidth: 520,
    display: 'flex',
    flexDirection: 'column',
    gap: 20,
  },
  title: { margin: 0, fontSize: 22, fontWeight: 600, color: 'var(--fg, #e2e8f0)' },
  stepper: { display: 'flex', alignItems: 'center', gap: 0 },
  stepDot: {
    width: 28, height: 28, borderRadius: '50%',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: 12, fontWeight: 600, flexShrink: 0,
    background: 'var(--surface-2, #2a2d3a)', color: 'var(--muted, #64748b)',
  },
  stepDotActive: { background: 'var(--accent, #6366f1)', color: '#fff' },
  stepDotDone: { background: '#22c55e', color: '#fff' },
  stepLine: { flex: 1, height: 2, background: 'var(--border, #2a2d3a)' },
  section: { display: 'flex', flexDirection: 'column', gap: 12 },
  desc: { margin: 0, color: 'var(--muted, #94a3b8)', fontSize: 14, lineHeight: 1.6 },
  code: {
    background: 'var(--surface-2, #0d0f18)',
    border: '1px solid var(--border, #2a2d3a)',
    borderRadius: 6,
    padding: '10px 14px',
    fontSize: 12,
    fontFamily: 'monospace',
    color: 'var(--fg, #e2e8f0)',
    overflowX: 'auto',
    wordBreak: 'break-all',
    whiteSpace: 'pre-wrap',
    margin: 0,
  },
  textarea: {
    width: '100%',
    background: 'var(--surface-2, #0d0f18)',
    border: '1px solid var(--border, #2a2d3a)',
    borderRadius: 6,
    padding: '10px 14px',
    color: 'var(--fg, #e2e8f0)',
    fontSize: 12,
    fontFamily: 'monospace',
    resize: 'vertical',
    boxSizing: 'border-box',
  },
  input: {
    width: '100%',
    background: 'var(--surface-2, #0d0f18)',
    border: '1px solid var(--border, #2a2d3a)',
    borderRadius: 6,
    padding: '10px 14px',
    color: 'var(--fg, #e2e8f0)',
    fontSize: 14,
    boxSizing: 'border-box',
  },
  error: {
    padding: '10px 14px',
    background: 'rgba(239,68,68,0.1)',
    border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: 6,
    color: '#f87171',
    fontSize: 13,
    whiteSpace: 'pre-line' as const,
  },
  button: {
    padding: '11px 20px',
    background: 'var(--accent, #6366f1)',
    color: '#fff',
    border: 'none',
    borderRadius: 8,
    fontSize: 14,
    fontWeight: 500,
    cursor: 'pointer',
    alignSelf: 'flex-start',
  },
  buttonDisabled: { opacity: 0.5, cursor: 'not-allowed' },
};
