import 'reflect-metadata';
import { describe, it, expect, beforeAll } from 'vitest';
import crypto, { webcrypto } from 'crypto';
import * as x509 from '@peculiar/x509';
import { verifyPopToken, type PopToken } from './pop';
import type { DashboardConfig } from '../config';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' };

function minimalConfig(): DashboardConfig {
  // caPath deliberately unset — this branch predates the separate fix that
  // makes CA verification mandatory; that's not what this test covers.
  return { mtls: {} } as unknown as DashboardConfig;
}

async function buildLeaf(identityUri: string) {
  const keys = await webcrypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=enrollment-leaf',
    notBefore: new Date('2020-01-01'),
    notAfter: new Date('2035-01-01'),
    signingAlgorithm: ECDSA_SHA256,
    keys,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'url', value: identityUri }])],
  });
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
  return { certPem: cert.toString('pem'), privateKey };
}

function signToken(
  certPem: string,
  privateKey: import('crypto').KeyObject,
  challenge: string,
  identityUri: string,
  issuedAt: string
): PopToken {
  const message = Buffer.concat([
    Buffer.from(challenge, 'hex'),
    Buffer.from(identityUri),
    Buffer.from(issuedAt),
  ]);
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  const signature = sign.sign(privateKey).toString('base64url');
  return { cert: certPem, signature, challenge, identityUri, issuedAt };
}

describe('verifyPopToken single-use replay protection', () => {
  let certPem: string;
  let privateKey: import('crypto').KeyObject;
  const identityUri = 'vigil://credo/test-enrollment-identity';

  beforeAll(async () => {
    const leaf = await buildLeaf(identityUri);
    certPem = leaf.certPem;
    privateKey = leaf.privateKey;
  });

  function freshToken(challenge = 'aabbccdd'): PopToken {
    const issuedAt = new Date().toISOString();
    return signToken(certPem, privateKey, challenge, identityUri, issuedAt);
  }

  it('accepts a token the first time', () => {
    const token = freshToken();
    const result = verifyPopToken(token, 'aabbccdd', minimalConfig());
    expect(result).toEqual({ ok: true, identityUri });
  });

  /// Regression test for a Medium finding: a captured, still-fresh PoP token
  /// could be replayed against verifyPopToken's success path any number of
  /// times within its 5-minute validity window (e.g. re-run against
  /// /enroll/verify to keep minting fresh Shepherd token pairs).
  it('rejects an exact replay of the same signed token', () => {
    const token = freshToken();
    const first = verifyPopToken(token, 'aabbccdd', minimalConfig());
    expect(first.ok).toBe(true);

    const second = verifyPopToken(token, 'aabbccdd', minimalConfig());
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.error).toMatch(/already been used/);
    }
  });

  it('accepts a fresh token for a different challenge after a prior one was consumed', () => {
    const first = freshToken('aaaaaaaa');
    expect(verifyPopToken(first, 'aaaaaaaa', minimalConfig()).ok).toBe(true);

    // A genuinely new signing operation (new issuedAt -> new signature) for a
    // different enrollment attempt must not be blocked by the earlier one.
    const second = freshToken('bbbbbbbb');
    expect(verifyPopToken(second, 'bbbbbbbb', minimalConfig()).ok).toBe(true);
  });
});
