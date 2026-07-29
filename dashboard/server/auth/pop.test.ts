import 'reflect-metadata';
import { describe, it, expect, beforeAll } from 'vitest';
import crypto, { webcrypto } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as x509 from '@peculiar/x509';
import { verifyPopToken, type PopToken } from './pop';
import type { DashboardConfig } from '../config';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' };

function minimalConfig(caPath?: string): DashboardConfig {
  return {
    mtls: { caPath },
  } as unknown as DashboardConfig;
}

async function buildCa() {
  const keys = await webcrypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test Vigil Root CA',
    notBefore: new Date('2020-01-01'),
    notAfter: new Date('2035-01-01'),
    signingAlgorithm: ECDSA_SHA256,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true
      ),
    ],
  });
  return { keys, cert };
}

async function buildLeaf(
  issuerCert: x509.X509Certificate,
  issuerSigningKey: CryptoKey,
  identityUri: string
) {
  const keys = await webcrypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=enrollment-leaf',
    issuer: issuerCert.subject,
    notBefore: new Date('2020-01-01'),
    notAfter: new Date('2035-01-01'),
    signingAlgorithm: ECDSA_SHA256,
    publicKey: keys.publicKey,
    signingKey: issuerSigningKey,
    extensions: [
      new x509.SubjectAlternativeNameExtension([{ type: 'url', value: identityUri }]),
    ],
  });
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });
  return { cert, privateKey };
}

function signToken(
  leafCertPem: string,
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
  return { cert: leafCertPem, signature, challenge, identityUri, issuedAt };
}

describe('verifyPopToken CA verification', () => {
  let caCert: x509.X509Certificate;
  let leafCertPem: string;
  let leafPrivateKey: import('crypto').KeyObject;
  let identityUri: string;
  let caPath: string;
  let otherCaPath: string;

  beforeAll(async () => {
    const ca = await buildCa();
    caCert = ca.cert;
    identityUri = 'vigil://credo/test-enrollment-identity';
    const leaf = await buildLeaf(ca.cert, ca.keys.privateKey, identityUri);
    leafCertPem = leaf.cert.toString('pem');
    leafPrivateKey = leaf.privateKey;

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pop-test-'));
    caPath = path.join(dir, 'ca.pem');
    fs.writeFileSync(caPath, caCert.toString('pem'));

    // A second, unrelated CA — used to prove verification actually checks
    // *which* CA signed the cert, not just that some CA is configured.
    const otherCa = await buildCa();
    otherCaPath = path.join(dir, 'other-ca.pem');
    fs.writeFileSync(otherCaPath, otherCa.cert.toString('pem'));
  });

  function freshToken(): PopToken {
    const issuedAt = new Date().toISOString();
    const challenge = 'aabbccdd';
    return signToken(leafCertPem, leafPrivateKey, challenge, identityUri, issuedAt);
  }

  it('rejects a validly-signed token when mtls.caPath is not configured, instead of skipping CA verification', () => {
    // Regression test: this used to silently skip CA verification and fall
    // through to identity/signature checks, which only prove possession of
    // *some* private key — not that Vigil ever issued the certificate.
    const result = verifyPopToken(freshToken(), 'aabbccdd', minimalConfig(undefined));
    expect(result.ok).toBe(false);
  });

  it('accepts a token whose cert chains to the configured CA', () => {
    const result = verifyPopToken(freshToken(), 'aabbccdd', minimalConfig(caPath));
    expect(result).toEqual({ ok: true, identityUri });
  });

  it('rejects a token whose cert does not chain to the configured CA', () => {
    const result = verifyPopToken(freshToken(), 'aabbccdd', minimalConfig(otherCaPath));
    expect(result.ok).toBe(false);
  });
});

describe('verifyPopToken single-use replay protection', () => {
  let leafCertPem: string;
  let leafPrivateKey: import('crypto').KeyObject;
  let caPath: string;
  const identityUri = 'vigil://credo/test-enrollment-identity-replay';

  beforeAll(async () => {
    // CA verification is mandatory now (see the suite above), so these
    // replay tests need a properly-signed leaf chaining to a configured CA
    // to reach the single-use check at all, not a bare self-signed cert.
    const ca = await buildCa();
    const leaf = await buildLeaf(ca.cert, ca.keys.privateKey, identityUri);
    leafCertPem = leaf.cert.toString('pem');
    leafPrivateKey = leaf.privateKey;

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pop-replay-test-'));
    caPath = path.join(dir, 'ca.pem');
    fs.writeFileSync(caPath, ca.cert.toString('pem'));
  });

  function freshToken(challenge = 'aabbccdd'): PopToken {
    const issuedAt = new Date().toISOString();
    return signToken(leafCertPem, leafPrivateKey, challenge, identityUri, issuedAt);
  }

  it('accepts a token the first time', () => {
    const token = freshToken();
    const result = verifyPopToken(token, 'aabbccdd', minimalConfig(caPath));
    expect(result).toEqual({ ok: true, identityUri });
  });

  // Regression test for a Medium finding: a captured, still-fresh PoP token
  // could be replayed against verifyPopToken's success path any number of
  // times within its 5-minute validity window (e.g. re-run against
  // /enroll/verify to keep minting fresh Shepherd token pairs).
  it('rejects an exact replay of the same signed token', () => {
    const token = freshToken();
    const first = verifyPopToken(token, 'aabbccdd', minimalConfig(caPath));
    expect(first.ok).toBe(true);

    const second = verifyPopToken(token, 'aabbccdd', minimalConfig(caPath));
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.error).toMatch(/already been used/);
    }
  });

  it('accepts a fresh token for a different challenge after a prior one was consumed', () => {
    const first = freshToken('aaaaaaaa');
    expect(verifyPopToken(first, 'aaaaaaaa', minimalConfig(caPath)).ok).toBe(true);

    // A genuinely new signing operation (new issuedAt -> new signature) for a
    // different enrollment attempt must not be blocked by the earlier one.
    const second = freshToken('bbbbbbbb');
    expect(verifyPopToken(second, 'bbbbbbbb', minimalConfig(caPath)).ok).toBe(true);
  });
});
