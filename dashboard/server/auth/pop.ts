import { X509Certificate, createVerify } from 'crypto';
import fs from 'fs';
import type { DashboardConfig } from '../config';

export type PopToken = {
  cert: string;           // PEM
  signature: string;      // base64url
  challenge: string;      // hex — must match the stored invite token
  identityUri: string;    // vigil:// URI from the cert's SAN
  issuedAt: string;       // ISO timestamp
};

const POP_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes

function extractIdentityUri(pem: string): string | null {
  try {
    const x509 = new X509Certificate(pem);
    const san = x509.subjectAltName ?? '';
    const uriEntry = san
      .split(',')
      .map((s) => s.trim())
      .find((s) => s.startsWith('URI:vigil://'));
    return uriEntry ? uriEntry.slice(4).trim() : null;
  } catch {
    return null;
  }
}

function parseCertsFromBundle(bundlePem: string): X509Certificate[] {
  const certs: X509Certificate[] = [];
  for (const block of bundlePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []) {
    try { certs.push(new X509Certificate(block)); } catch { /* skip malformed */ }
  }
  return certs;
}

function buildSignedMessage(challenge: string, identityUri: string, issuedAt: string): Buffer {
  return Buffer.concat([
    Buffer.from(challenge, 'hex'),
    Buffer.from(identityUri),
    Buffer.from(issuedAt),
  ]);
}

export function verifyPopToken(
  token: PopToken,
  expectedChallenge: string,
  config: DashboardConfig
): { ok: true; identityUri: string } | { ok: false; error: string } {
  // 1. Replay protection: issuedAt must be within the last 5 minutes.
  const issuedAtMs = new Date(token.issuedAt).getTime();
  if (isNaN(issuedAtMs) || Date.now() - issuedAtMs > POP_MAX_AGE_MS) {
    return { ok: false, error: 'PoP token has expired (issuedAt too old).' };
  }

  // 2. Challenge must match the raw invite token.
  if (token.challenge !== expectedChallenge) {
    return { ok: false, error: 'PoP token challenge does not match.' };
  }

  // 3. Cert must parse.
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(token.cert);
  } catch {
    return { ok: false, error: 'Could not parse certificate PEM.' };
  }

  // 4. Verify cert against Vigil CA trust chain.
  if (config.mtls.caPath) {
    try {
      const caPem = fs.readFileSync(config.mtls.caPath, 'utf8');
      const caCerts = parseCertsFromBundle(caPem);
      if (caCerts.length === 0) {
        return { ok: false, error: 'CA bundle contains no valid certificates.' };
      }
      // Try each cert in the bundle — the user cert may be signed by an intermediate, not the root.
      const signedByBundle = caCerts.some((ca) => { try { return x509.verify(ca.publicKey); } catch { return false; } });
      if (!signedByBundle) {
        return { ok: false, error: 'Certificate was not signed by the configured Vigil CA.' };
      }
    } catch (err) {
      return { ok: false, error: `CA verification error: ${String(err)}` };
    }
  }

  // 5. Extract identity URI from cert SAN and compare to token's claimed identityUri.
  const certIdentityUri = extractIdentityUri(token.cert);
  if (!certIdentityUri) {
    return { ok: false, error: 'Certificate has no vigil:// URI in Subject Alternative Names.' };
  }
  if (certIdentityUri !== token.identityUri) {
    return { ok: false, error: 'PoP token identityUri does not match certificate SAN.' };
  }

  // 6. Verify signature over SHA256(challenge || identityUri || issuedAt).
  const message = buildSignedMessage(token.challenge, token.identityUri, token.issuedAt);
  try {
    const verify = createVerify('SHA256');
    verify.update(message);
    const sigBuf = Buffer.from(token.signature, 'base64url');
    const valid = verify.verify(x509.publicKey, sigBuf);
    if (!valid) {
      return { ok: false, error: 'Signature verification failed.' };
    }
  } catch (err) {
    return { ok: false, error: `Signature error: ${String(err)}` };
  }

  return { ok: true, identityUri: certIdentityUri };
}

// Resolves the shepherd account name from a vigil:// identity URI by querying Shepherd.
export async function resolveShepherdAccount(
  identityUri: string,
  shepherdApi: import('axios').AxiosInstance
): Promise<string | null> {
  try {
    const resp = await shepherdApi.get<{
      accounts: Array<{ name: string; identities?: string[] }>;
    }>('/accounts');
    const account = resp.data.accounts.find(
      (a) => Array.isArray(a.identities) && a.identities.includes(identityUri)
    );
    return account?.name ?? null;
  } catch {
    return null;
  }
}
