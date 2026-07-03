import 'reflect-metadata';
import * as x509lib from '@peculiar/x509';

export interface BrowserPop {
  cert: string;        // full PEM (may be chain)
  signature: string;   // base64url, DER-encoded ECDSA
  challenge: string;   // hex enrollment token
  identityUri: string; // vigil:// URI from cert SAN
  issuedAt: string;    // ISO timestamp
}

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const arr = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return buf;
}

function toBase64Url(buf: Uint8Array): string {
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function extractLeafCert(pem: string): string {
  const match = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  return match ? match[0] : pem;
}

export function extractIdentityUri(certPem: string): string | null {
  try {
    const cert = new x509lib.X509Certificate(extractLeafCert(certPem));
    const san = cert.getExtension<x509lib.SubjectAlternativeNameExtension>(
      x509lib.SubjectAlternativeNameExtension,
    );
    if (!san) return null;
    const uri = san.names.items.find(
      n => n.type === 'url' && String(n.value).startsWith('vigil://'),
    );
    return uri ? String(uri.value) : null;
  } catch {
    return null;
  }
}

// WebCrypto ECDSA produces IEEE P1363 (raw r||s). Node.js createVerify expects DER.
function p1363ToDer(p1363: Uint8Array): Uint8Array {
  const half = p1363.length >> 1;

  const encodeInt = (buf: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    buf = buf.slice(i);
    if (buf[0] & 0x80) { const p = new Uint8Array(buf.length + 1); p.set(buf, 1); buf = p; }
    return buf;
  };

  const r = encodeInt(p1363.slice(0, half));
  const s = encodeInt(p1363.slice(half));
  const body = new Uint8Array(4 + r.length + s.length);
  let o = 0;
  body[o++] = 0x02; body[o++] = r.length; body.set(r, o); o += r.length;
  body[o++] = 0x02; body[o++] = s.length; body.set(s, o);
  const der = new Uint8Array(2 + body.length);
  der[0] = 0x30; der[1] = body.length; der.set(body, 2);
  return der;
}

async function importPrivateKey(keyPem: string): Promise<CryptoKey> {
  const der = pemToDer(keyPem);
  for (const namedCurve of ['P-256', 'P-384'] as const) {
    try {
      return await crypto.subtle.importKey(
        'pkcs8', der, { name: 'ECDSA', namedCurve }, false, ['sign'],
      );
    } catch { /* try next curve */ }
  }
  throw new Error(
    'Could not import private key. The key must be a PKCS#8 EC key (P-256 or P-384).\n' +
    'If your key starts with "-----BEGIN EC PRIVATE KEY-----", convert it first:\n' +
    '  openssl pkcs8 -topk8 -nocrypt -in your.key -out pkcs8.key',
  );
}

export async function buildBrowserPop(
  certPem: string,
  keyPem: string,
  challenge: string,
): Promise<BrowserPop> {
  const identityUri = extractIdentityUri(certPem);
  if (!identityUri) {
    throw new Error('Certificate has no vigil:// URI in Subject Alternative Names.');
  }

  const issuedAt = new Date().toISOString();

  // message = hex_decode(challenge) || utf8(identityUri) || utf8(issuedAt)
  const challengeBytes = Uint8Array.from(
    (challenge.match(/.{2}/g) ?? []).map(h => parseInt(h, 16)),
  );
  const enc = new TextEncoder();
  const parts = [challengeBytes, enc.encode(identityUri), enc.encode(issuedAt)];
  const totalLen = parts.reduce((n, p) => n + p.length, 0);
  const messageBuf = new ArrayBuffer(totalLen);
  const message = new Uint8Array(messageBuf);
  let off = 0;
  for (const p of parts) { message.set(p, off); off += p.length; }

  const key = await importPrivateKey(keyPem);
  const p1363 = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, messageBuf),
  );

  return { cert: certPem, signature: toBase64Url(p1363ToDer(p1363)), challenge, identityUri, issuedAt };
}
