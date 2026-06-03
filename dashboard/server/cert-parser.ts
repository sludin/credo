// dashboard/server/cert-parser.ts
// Full X.509 certificate parser using @peculiar/x509

import * as x509 from '@peculiar/x509';
import { webcrypto as crypto } from 'crypto';
interface CertField {
  label: string;
  value: string | string[];
  display?: 'mono' | 'hex' | 'pills' | 'text';
  critical?: boolean;
}

interface CertSection {
  title: string;
  fields: CertField[];
  subsections?: CertSection[];
}

interface ParsedCertFull {
  pem: string;
  textView: string;
  daysLeft: number;
  sections: CertSection[];
}

// Set up the Node.js WebCrypto provider so @peculiar/x509 can do async ops if needed
x509.cryptoProvider.set(crypto as unknown as Crypto);

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Convert plain hex string to colon-separated lowercase hex */
function hexColon(hex: string): string {
  const lower = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
  // Ensure even length
  const padded = lower.length % 2 === 0 ? lower : '0' + lower;
  return padded.match(/.{2}/g)!.join(':');
}

/** Convert ArrayBuffer to colon-separated lowercase hex */
function bufHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':');
}

/** Map WebCrypto algorithm to openssl-style name */
function sigAlgName(alg: { name: string; hash?: { name: string } }): string {
  if (alg.name === 'ECDSA') {
    const hash = alg.hash?.name ?? 'SHA-256';
    const bits = hash.replace('SHA-', '');
    return `ecdsa-with-SHA${bits}`;
  }
  if (alg.name === 'RSASSA-PKCS1-v1_5') {
    const hash = alg.hash?.name ?? 'SHA-256';
    const bits = hash.replace('SHA-', '');
    return `sha${bits}WithRSAEncryption`;
  }
  if (alg.name === 'RSA-PSS') {
    return 'rsassaPss';
  }
  if (alg.name === 'Ed25519') {
    return 'ED25519';
  }
  return alg.name;
}

const EKU_NAMES: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
};

const EXT_OID_TITLES: Record<string, string> = {
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '1.3.6.1.4.1.11129.2.4.2': 'CT Precertificate SCTs',
};

// OIDs handled by explicit sections (skip in fallback loop)
const HANDLED_OIDS = new Set([
  '2.5.29.17', // SAN
  '2.5.29.15', // Key Usage
  '2.5.29.37', // EKU
  '2.5.29.19', // Basic Constraints
  '2.5.29.14', // SKI
  '2.5.29.35', // AKI
]);

const KU_FLAG_NAMES: Array<[x509.KeyUsageFlags, string]> = [
  [x509.KeyUsageFlags.digitalSignature, 'digitalSignature'],
  [x509.KeyUsageFlags.nonRepudiation,   'nonRepudiation'],
  [x509.KeyUsageFlags.keyEncipherment,  'keyEncipherment'],
  [x509.KeyUsageFlags.dataEncipherment, 'dataEncipherment'],
  [x509.KeyUsageFlags.keyAgreement,     'keyAgreement'],
  [x509.KeyUsageFlags.keyCertSign,      'keyCertSign'],
  [x509.KeyUsageFlags.cRLSign,          'cRLSign'],
  [x509.KeyUsageFlags.encipherOnly,     'encipherOnly'],
  [x509.KeyUsageFlags.decipherOnly,     'decipherOnly'],
];

// ── Public Key Description (using Node.js built-in) ──────────────────────────

function pkDescription(pem: string): string {
  // Use a dynamic import-style workaround — we use require-style since we're in Node
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodeCrypto = require('crypto') as typeof import('crypto');
  const nodeCert = new nodeCrypto.X509Certificate(pem);
  const pkType = nodeCert.publicKey.asymmetricKeyType ?? 'unknown';
  const pkDetails = (nodeCert.publicKey.asymmetricKeyDetails as Record<string, unknown>) ?? {};

  if (pkType === 'ec') {
    const curve = (pkDetails.namedCurve as string | undefined) ?? 'unknown';
    return `id-ecPublicKey — curve: ${curve}`;
  }
  if (pkType === 'rsa' || pkType === 'rsa-pss') {
    const bits = (pkDetails.modulusLength as number | undefined) ?? 0;
    return `rsaEncryption — ${bits} bit`;
  }
  if (pkType === 'ed25519') {
    return 'ED25519';
  }
  return pkType;
}

// ── buildTextView ─────────────────────────────────────────────────────────────

function buildTextView(cert: x509.X509Certificate, pem: string): string {
  const lines: string[] = [];
  const algName = sigAlgName(cert.signatureAlgorithm as unknown as { name: string; hash?: { name: string } });
  const serialHex = hexColon(cert.serialNumber);

  lines.push('Certificate:');
  lines.push('    Data:');
  lines.push('        Version: 3 (0x2)');
  lines.push('        Serial Number:');
  lines.push(`            ${serialHex}`);
  lines.push(`        Signature Algorithm: ${algName}`);
  lines.push(`        Issuer: ${cert.issuer}`);
  lines.push('        Validity');
  lines.push(`            Not Before: ${cert.notBefore.toUTCString()}`);
  lines.push(`            Not After : ${cert.notAfter.toUTCString()}`);
  lines.push(`        Subject: ${cert.subject}`);
  lines.push('        Subject Public Key Info:');
  lines.push(`            ${pkDescription(pem)}`);
  lines.push('        X509v3 extensions:');

  const extensions = cert.extensions;
  for (const ext of extensions) {
    const critStr = ext.critical ? ' critical' : '';
    const oid = ext.type;

    if (oid === '2.5.29.17') {
      // SAN
      const san = cert.getExtension<x509.SubjectAlternativeNameExtension>(x509.SubjectAlternativeNameExtension);
      if (san) {
        lines.push(`            X509v3 Subject Alternative Name:${critStr}`);
        const names = san.names.items.map(n => `${n.type.toUpperCase()}:${n.value}`).join(', ');
        lines.push(`                ${names}`);
      }
    } else if (oid === '2.5.29.15') {
      // Key Usage
      const ku = cert.getExtension<x509.KeyUsagesExtension>(x509.KeyUsagesExtension);
      if (ku) {
        lines.push(`            X509v3 Key Usage:${critStr}`);
        const flags = KU_FLAG_NAMES.filter(([f]) => ku.usages & f).map(([, n]) => n);
        lines.push(`                ${flags.join(', ')}`);
      }
    } else if (oid === '2.5.29.37') {
      // EKU
      const eku = cert.getExtension<x509.ExtendedKeyUsageExtension>(x509.ExtendedKeyUsageExtension);
      if (eku) {
        lines.push(`            X509v3 Extended Key Usage:${critStr}`);
        const names = eku.usages.map((u) => EKU_NAMES[String(u)] ?? String(u)).join(', ');
        lines.push(`                ${names}`);
      }
    } else if (oid === '2.5.29.19') {
      // Basic Constraints
      const bc = cert.getExtension<x509.BasicConstraintsExtension>(x509.BasicConstraintsExtension);
      if (bc) {
        lines.push(`            X509v3 Basic Constraints:${critStr}`);
        const caStr = bc.ca ? 'CA:TRUE' : 'CA:FALSE';
        const pathStr = bc.pathLength !== undefined ? `, pathlen:${bc.pathLength}` : '';
        lines.push(`                ${caStr}${pathStr}`);
      }
    } else if (oid === '2.5.29.14') {
      // SKI
      const ski = cert.getExtension<x509.SubjectKeyIdentifierExtension>(x509.SubjectKeyIdentifierExtension);
      if (ski) {
        lines.push(`            X509v3 Subject Key Identifier:${critStr}`);
        lines.push(`                ${hexColon(ski.keyId).toUpperCase()}`);
      }
    } else if (oid === '2.5.29.35') {
      // AKI
      const aki = cert.getExtension<x509.AuthorityKeyIdentifierExtension>(x509.AuthorityKeyIdentifierExtension);
      if (aki) {
        lines.push(`            X509v3 Authority Key Identifier:${critStr}`);
        const keyId = (aki as unknown as { keyId?: string }).keyId;
        if (keyId) {
          lines.push(`                ${hexColon(keyId).toUpperCase()}`);
        }
      }
    } else {
      // Unknown extension — show hex
      const title = EXT_OID_TITLES[oid] ?? `Extension (${oid})`;
      lines.push(`            ${title}:${critStr}`);
      lines.push(`                ${bufHex(ext.value)}`);
    }
  }

  lines.push(`    Signature Algorithm: ${algName}`);
  lines.push('    Signature Value:');
  lines.push(`        ${bufHex(cert.signature)}`);

  return lines.join('\n');
}

// ── parseCertFull ─────────────────────────────────────────────────────────────

export function parseCertFull(pem: string): ParsedCertFull {
  const cert = new x509.X509Certificate(pem);

  // daysLeft
  const now = Date.now();
  const notAfterMs = cert.notAfter.getTime();
  const daysLeft = Math.floor((notAfterMs - now) / (1000 * 60 * 60 * 24));

  const sections: CertSection[] = [];

  // ── Identity ──────────────────────────────────────────────────────────────
  const serialHex = hexColon(cert.serialNumber);
  sections.push({
    title: 'Identity',
    fields: [
      { label: 'Subject', value: cert.subject, display: 'mono' },
      { label: 'Issuer', value: cert.issuer, display: 'mono' },
      { label: 'Serial Number', value: serialHex, display: 'hex' },
    ],
  });

  // ── Validity ──────────────────────────────────────────────────────────────
  const notAfterStr = `${cert.notAfter.toUTCString()} (${daysLeft} days remaining)`;
  sections.push({
    title: 'Validity',
    fields: [
      { label: 'Not Before', value: cert.notBefore.toUTCString(), display: 'mono' },
      { label: 'Not After', value: notAfterStr, display: 'mono' },
    ],
  });

  // ── Public Key ────────────────────────────────────────────────────────────
  const pkAlg = pkDescription(pem);
  const sigAlg = sigAlgName(cert.signatureAlgorithm as unknown as { name: string; hash?: { name: string } });
  sections.push({
    title: 'Public Key',
    fields: [
      { label: 'Algorithm', value: pkAlg, display: 'mono' },
      { label: 'Signature Alg', value: sigAlg, display: 'mono' },
    ],
  });

  // ── Extensions ────────────────────────────────────────────────────────────

  // SAN
  const san = cert.getExtension<x509.SubjectAlternativeNameExtension>(x509.SubjectAlternativeNameExtension);
  if (san) {
    const names = san.names.items.map(n => n.value);
    sections.push({
      title: 'Subject Alt Names',
      fields: [
        { label: 'Names', value: names, display: 'pills', critical: san.critical },
      ],
    });
  }

  // Key Usage
  const ku = cert.getExtension<x509.KeyUsagesExtension>(x509.KeyUsagesExtension);
  if (ku) {
    const flags = KU_FLAG_NAMES.filter(([f]) => ku.usages & f).map(([, n]) => n);
    sections.push({
      title: 'Key Usage',
      fields: [
        { label: 'Usages', value: flags.join(', '), display: 'text', critical: ku.critical },
      ],
    });
  }

  // EKU
  const eku = cert.getExtension<x509.ExtendedKeyUsageExtension>(x509.ExtendedKeyUsageExtension);
  if (eku) {
    const names = eku.usages.map((u) => EKU_NAMES[String(u)] ?? String(u));
    sections.push({
      title: 'Extended Key Usage',
      fields: [
        { label: 'Usages', value: names.join(', '), display: 'text' },
      ],
    });
  }

  // Basic Constraints
  const bc = cert.getExtension<x509.BasicConstraintsExtension>(x509.BasicConstraintsExtension);
  if (bc) {
    const bcFields: CertField[] = [
      { label: 'CA', value: bc.ca ? 'TRUE' : 'FALSE', display: 'mono', critical: bc.critical },
    ];
    if (bc.pathLength !== undefined) {
      bcFields.push({ label: 'Path Length', value: String(bc.pathLength), display: 'mono' });
    }
    sections.push({ title: 'Basic Constraints', fields: bcFields });
  }

  // Key Identifiers
  const skiExt = cert.getExtension<x509.SubjectKeyIdentifierExtension>(x509.SubjectKeyIdentifierExtension);
  const akiExt = cert.getExtension<x509.AuthorityKeyIdentifierExtension>(x509.AuthorityKeyIdentifierExtension);
  const kidFields: CertField[] = [];
  if (skiExt) {
    kidFields.push({ label: 'Subject Key ID', value: hexColon(skiExt.keyId), display: 'hex' });
  }
  if (akiExt) {
    const keyId = (akiExt as unknown as { keyId?: string }).keyId;
    if (keyId) {
      kidFields.push({ label: 'Authority Key ID', value: hexColon(keyId), display: 'hex' });
    }
  }
  if (kidFields.length > 0) {
    sections.push({ title: 'Key Identifiers', fields: kidFields });
  }

  // Fallback: all other extensions not handled above
  for (const ext of cert.extensions) {
    if (HANDLED_OIDS.has(ext.type)) continue;
    const title = EXT_OID_TITLES[ext.type] ?? `Extension (${ext.type})`;
    sections.push({
      title,
      fields: [
        { label: 'Value', value: bufHex(ext.value), display: 'hex', critical: ext.critical },
      ],
    });
  }

  // ── Signature ──────────────────────────────────────────────────────────────
  sections.push({
    title: 'Signature',
    fields: [
      { label: 'Algorithm', value: sigAlg, display: 'mono' },
      { label: 'Value', value: bufHex(cert.signature), display: 'hex' },
    ],
  });

  // ── textView ───────────────────────────────────────────────────────────────
  const textView = buildTextView(cert, pem);

  return { pem, textView, daysLeft, sections };
}

// ── pemFromDer ────────────────────────────────────────────────────────────────

export function pemFromDer(derBuffer: Buffer): string {
  const b64 = derBuffer.toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;
}

// ── extractCNFromSubject ──────────────────────────────────────────────────────

export function extractCNFromSubject(rfcName: string): string {
  const m = rfcName.match(/(?:^|,)\s*CN=([^,]+)/);
  return m ? m[1].trim() : rfcName;
}

// ── splitPemChain ─────────────────────────────────────────────────────────────

export function splitPemChain(pem: string): string[] {
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
}
