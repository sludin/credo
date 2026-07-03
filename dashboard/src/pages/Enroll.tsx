import React, { useState, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { useAuth } from '../context/AuthContext';
import { buildBrowserPop, extractIdentityUri } from '../utils/pop-browser';

type Step = 'pop' | 'passkey' | 'done';
const STEP_ORDER: Step[] = ['pop', 'passkey', 'done'];
const stepIdx = (s: Step) => STEP_ORDER.indexOf(s);

export default function Enroll(): React.ReactElement {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const { refresh } = useAuth();

  const [step, setStep] = useState<Step>('pop');
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem]   = useState('');
  const [identityUri, setIdentityUri] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [registrationOptions, setRegistrationOptions] = useState<unknown>(null);
  const [passkeyLabel, setPasskeyLabel] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const certRef = useRef<HTMLInputElement>(null);
  const keyRef  = useRef<HTMLInputElement>(null);

  const readFile = useCallback((file: File): Promise<string> =>
    new Promise((res, rej) => {
      const r = new FileReader();
      r.onload  = () => res(r.result as string);
      r.onerror = () => rej(new Error(`Failed to read ${file.name}`));
      r.readAsText(file);
    }), []);

  const handleCertFile = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const pem = await readFile(file);
      setCertPem(pem);
      setIdentityUri(extractIdentityUri(pem));
      setError(null);
    } catch {
      setError('Could not read certificate file.');
    }
  }, [readFile]);

  const handleKeyFile = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setKeyPem(await readFile(file));
      setError(null);
    } catch {
      setError('Could not read key file.');
    }
  }, [readFile]);

  async function handleVerifyPop(): Promise<void> {
    if (!token || !certPem || !keyPem) return;
    setLoading(true);
    setError(null);
    try {
      const pop = await buildBrowserPop(certPem, keyPem, token);

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
      if (!resp.ok) throw new Error(data.error ?? 'Registration failed.');

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

  const canVerify = !!certPem && !!keyPem && !!identityUri && !loading;

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>Enroll Your Passkey</h1>

        <div style={styles.stepper}>
          {(['pop', 'passkey', 'done'] as Step[]).map((s, i) => (
            <React.Fragment key={s}>
              <div style={{ ...styles.stepDot, ...(step === s ? styles.stepDotActive : stepIdx(step) > stepIdx(s) ? styles.stepDotDone : {}) }}>
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
              Prove your identity by selecting your Vigil certificate and private key.
              Signing happens locally — your private key never leaves this browser.
            </p>

            <div style={styles.fileRow}>
              <label style={styles.fileLabel}>
                <span style={styles.fileLabelText}>Certificate (.pem)</span>
                <button style={{ ...styles.fileButton, ...(certPem ? styles.fileButtonDone : {}) }}
                  onClick={() => certRef.current?.click()} type="button">
                  {certPem ? '✓ Loaded' : 'Choose file…'}
                </button>
                <input ref={certRef} type="file" accept=".pem,.crt,.cer" style={styles.hiddenInput}
                  onChange={(e) => void handleCertFile(e)} />
              </label>

              <label style={styles.fileLabel}>
                <span style={styles.fileLabelText}>Private key (.pem)</span>
                <button style={{ ...styles.fileButton, ...(keyPem ? styles.fileButtonDone : {}) }}
                  onClick={() => keyRef.current?.click()} type="button">
                  {keyPem ? '✓ Loaded' : 'Choose file…'}
                </button>
                <input ref={keyRef} type="file" accept=".pem,.key" style={styles.hiddenInput}
                  onChange={(e) => void handleKeyFile(e)} />
              </label>
            </div>

            {certPem && !identityUri && (
              <div style={styles.warn}>
                No vigil:// URI found in this certificate's Subject Alternative Names.
                Make sure you selected your Vigil identity certificate.
              </div>
            )}

            {identityUri && (
              <div style={styles.identity}>
                <span style={styles.identityLabel}>Identity detected</span>
                <code style={styles.identityUri}>{identityUri}</code>
              </div>
            )}

            <button
              style={{ ...styles.button, ...(!canVerify ? styles.buttonDisabled : {}) }}
              onClick={() => void handleVerifyPop()}
              disabled={!canVerify}
            >
              {loading ? 'Signing…' : 'Sign & Verify Identity'}
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
  title:   { margin: 0, fontSize: 22, fontWeight: 600, color: 'var(--fg, #e2e8f0)' },
  stepper: { display: 'flex', alignItems: 'center', gap: 0 },
  stepDot: {
    width: 28, height: 28, borderRadius: '50%',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: 12, fontWeight: 600, flexShrink: 0,
    background: 'var(--surface-2, #2a2d3a)', color: 'var(--muted, #64748b)',
  },
  stepDotActive: { background: 'var(--accent, #6366f1)', color: '#fff' },
  stepDotDone:   { background: '#22c55e', color: '#fff' },
  stepLine:      { flex: 1, height: 2, background: 'var(--border, #2a2d3a)' },
  section:       { display: 'flex', flexDirection: 'column', gap: 12 },
  desc:          { margin: 0, color: 'var(--muted, #94a3b8)', fontSize: 14, lineHeight: 1.6 },
  fileRow:       { display: 'flex', flexDirection: 'column', gap: 8 },
  fileLabel:     { display: 'flex', alignItems: 'center', gap: 10 },
  fileLabelText: { color: 'var(--muted, #94a3b8)', fontSize: 13, width: 160, flexShrink: 0 },
  hiddenInput:   { display: 'none' },
  fileButton: {
    padding: '7px 14px',
    background: 'var(--surface-2, #2a2d3a)',
    border: '1px solid var(--border, #3a3d4a)',
    borderRadius: 6,
    color: 'var(--fg, #e2e8f0)',
    fontSize: 13,
    cursor: 'pointer',
  },
  fileButtonDone: {
    borderColor: '#22c55e',
    color: '#22c55e',
  },
  identity: {
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
    padding: '10px 14px',
    background: 'rgba(99,102,241,0.08)',
    border: '1px solid rgba(99,102,241,0.25)',
    borderRadius: 6,
  },
  identityLabel: { fontSize: 11, color: 'var(--accent, #6366f1)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' },
  identityUri:   { fontSize: 12, color: 'var(--fg, #e2e8f0)', fontFamily: 'monospace', wordBreak: 'break-all' },
  warn: {
    padding: '10px 14px',
    background: 'rgba(234,179,8,0.1)',
    border: '1px solid rgba(234,179,8,0.3)',
    borderRadius: 6,
    color: '#fbbf24',
    fontSize: 13,
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
