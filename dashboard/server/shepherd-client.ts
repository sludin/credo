import fs from 'fs';
import https from 'https';
import { X509Certificate } from 'crypto';
import axios, { AxiosInstance } from 'axios';
import type { DashboardConfig } from './config';

type ClientGroup = {
  api: AxiosInstance;
  /** SHA-256 fingerprint of the dashboard mTLS service cert (lowercase hex, no colons). */
  certFingerprint: string;
  certPath: string;
  /** vigil:// URI SANs extracted from the dashboard service cert (may be empty). */
  certIdentityUris: string[];
};

function extractIdentityUris(certPem: Buffer): string[] {
  try {
    const san = new X509Certificate(certPem).subjectAltName ?? '';
    return san.split(',').map((s) => s.trim()).filter((s) => s.startsWith('URI:')).map((s) => s.slice(4).trim());
  } catch {
    return [];
  }
}

export function createShepherdClients(config: DashboardConfig): ClientGroup {
  const certPem = fs.readFileSync(config.mtls.certPath);
  const certFingerprint = new X509Certificate(certPem).fingerprint256.replace(/:/g, '').toLowerCase();
  const certIdentityUris = extractIdentityUris(certPem);

  const agent = new https.Agent({
    cert: certPem,
    key: fs.readFileSync(config.mtls.keyPath),
    ca: config.mtls.caPath ? fs.readFileSync(config.mtls.caPath) : undefined,
    rejectUnauthorized: config.mtls.rejectUnauthorized,
    keepAlive: true,
  });

  const common = {
    httpsAgent: agent,
    timeout: config.requestTimeoutSeconds * 1000,
  };

  const api = axios.create({
    ...common,
    baseURL: config.shepherdApiUrl,
  });

  return { api, certFingerprint, certPath: config.mtls.certPath, certIdentityUris };
}
