import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto, { webcrypto } from 'crypto';
import fs from 'fs';
import https from 'https';
import net from 'net';
import os from 'os';
import path from 'path';
import tls from 'tls';
import * as x509 from '@peculiar/x509';
import { reloadTlsSecureContext, type SecureContextHolder } from './tls-reload';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' };

async function selfSignedLeaf(cn: string): Promise<{ certPem: string; keyPem: string }> {
  const keys = await webcrypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${cn}`,
    notBefore: new Date('2020-01-01'),
    notAfter: new Date('2035-01-01'),
    signingAlgorithm: ECDSA_SHA256,
    keys,
  });
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const keyPem = crypto
    .createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' })
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
  return { certPem: cert.toString('pem'), keyPem };
}

function tempFiles(): { dir: string; certPath: string; keyPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-reload-test-'));
  return { dir, certPath: path.join(dir, 'cert.pem'), keyPath: path.join(dir, 'key.pem') };
}

describe('reloadTlsSecureContext', () => {
  it('reads the cert/key from disk and calls setSecureContext with their contents', async () => {
    const { certPath, keyPath } = tempFiles();
    const { certPem, keyPem } = await selfSignedLeaf('unit-test');
    fs.writeFileSync(certPath, certPem);
    fs.writeFileSync(keyPath, keyPem);

    const setSecureContext = vi.fn();
    const server: SecureContextHolder = { setSecureContext };

    reloadTlsSecureContext(server, certPath, keyPath);

    expect(setSecureContext).toHaveBeenCalledTimes(1);
    const arg = setSecureContext.mock.calls[0][0];
    expect(Buffer.from(arg.cert).toString()).toBe(certPem);
    expect(Buffer.from(arg.key).toString()).toBe(keyPem);
  });

  it('throws and never calls setSecureContext when the cert file is missing', () => {
    const { certPath, keyPath } = tempFiles();
    fs.writeFileSync(keyPath, 'irrelevant');
    const setSecureContext = vi.fn();
    const server: SecureContextHolder = { setSecureContext };

    expect(() => reloadTlsSecureContext(server, certPath, keyPath)).toThrow();
    expect(setSecureContext).not.toHaveBeenCalled();
  });

  it('hot-swaps a real https.Server with zero downtime — no restart, no dropped listener', async () => {
    const { certPath: certA, keyPath: keyA } = tempFiles();
    const before = await selfSignedLeaf('before-reload');
    fs.writeFileSync(certA, before.certPem);
    fs.writeFileSync(keyA, before.keyPem);

    const { certPath: certB, keyPath: keyB } = tempFiles();
    const after = await selfSignedLeaf('after-reload');
    fs.writeFileSync(certB, after.certPem);
    fs.writeFileSync(keyB, after.keyPem);

    const server = https.createServer({ cert: before.certPem, key: before.keyPem });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;

    const fingerprintOf = () =>
      new Promise<string>((resolve, reject) => {
        const socket = tls.connect({ port, host: '127.0.0.1', rejectUnauthorized: false }, () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          resolve(cert.fingerprint256);
        });
        socket.on('error', reject);
      });

    const fingerprintBefore = await fingerprintOf();

    reloadTlsSecureContext(server, certB, keyB);

    const fingerprintAfter = await fingerprintOf();

    expect(fingerprintAfter).not.toBe(fingerprintBefore);
    // Same server instance, same port, never closed/relistened — this is the
    // whole point: zero-downtime reload, unlike the Rust services' rebind.
    expect(server.listening).toBe(true);

    server.close();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });
});
