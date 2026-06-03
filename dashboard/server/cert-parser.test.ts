import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { join, dirname } from 'path';
import { parseCertFull } from './cert-parser';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_PEM = readFileSync(
  join(__dirname, 'tests/fixtures/test-cert.pem'),
  'utf-8',
);

describe('parseCertFull', () => {
  it('returns pem unchanged', () => {
    const result = parseCertFull(TEST_PEM);
    expect(result.pem).toBe(TEST_PEM);
  });

  it('textView starts with Certificate: header', () => {
    const { textView } = parseCertFull(TEST_PEM);
    expect(textView).toMatch(/^Certificate:/m);
    expect(textView).toContain('Signature Algorithm');
    expect(textView).toContain('Subject:');
    expect(textView).toContain('Not Before');
  });

  it('Identity section contains Subject, Issuer, Serial Number', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const identity = sections.find(s => s.title === 'Identity');
    expect(identity).toBeDefined();
    const labels = identity!.fields.map(f => f.label);
    expect(labels).toContain('Subject');
    expect(labels).toContain('Issuer');
    expect(labels).toContain('Serial Number');
  });

  it('Serial Number uses colon-separated lowercase hex', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const identity = sections.find(s => s.title === 'Identity')!;
    const serial = identity.fields.find(f => f.label === 'Serial Number')!;
    expect(typeof serial.value).toBe('string');
    expect(serial.value as string).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2})*$/);
  });

  it('Validity section has Not Before and Not After', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const validity = sections.find(s => s.title === 'Validity');
    expect(validity).toBeDefined();
    const labels = validity!.fields.map(f => f.label);
    expect(labels).toContain('Not Before');
    expect(labels).toContain('Not After');
  });

  it('daysLeft is a positive number for non-expired cert', () => {
    const { daysLeft } = parseCertFull(TEST_PEM);
    expect(daysLeft).toBeGreaterThan(0);
  });

  it('Subject Alt Names section has pills display', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const san = sections.find(s => s.title === 'Subject Alt Names');
    expect(san).toBeDefined();
    const field = san!.fields.find(f => f.label === 'Names')!;
    expect(field.display).toBe('pills');
    expect(Array.isArray(field.value)).toBe(true);
    expect(field.value as string[]).toContain('test.example.com');
  });

  it('Key Usage section is marked critical', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const ku = sections.find(s => s.title === 'Key Usage');
    expect(ku).toBeDefined();
    expect(ku!.fields[0].critical).toBe(true);
  });

  it('Basic Constraints section is marked critical and CA:FALSE', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const bc = sections.find(s => s.title === 'Basic Constraints');
    expect(bc).toBeDefined();
    const caField = bc!.fields.find(f => f.label === 'CA')!;
    expect(caField.value).toBe('FALSE');
    expect(caField.critical).toBe(true);
  });

  it('Signature section is present', () => {
    const { sections } = parseCertFull(TEST_PEM);
    const sig = sections.find(s => s.title === 'Signature');
    expect(sig).toBeDefined();
    const labels = sig!.fields.map(f => f.label);
    expect(labels).toContain('Algorithm');
    expect(labels).toContain('Value');
  });
});
