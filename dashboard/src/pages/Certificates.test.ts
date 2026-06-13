import { describe, it, expect } from 'vitest';
import { deriveStatus, statusTone, statusLabel } from './Certificates.testable';
import type { Assignment, FlockCert, CertStoreEntry } from '../types';

const base: Assignment = {
  certName: 'example.com', corgi: 'node1', ca: 'letsencrypt',
  domain: 'example.com', renewBeforeDays: 30,
};

const okFlock: FlockCert = {
  name: 'example.com', lifetimeDays: 60, status: 'ok',
  sanNames: ['example.com'], fingerprint256: 'abc',
};

const existsEntry = { exists: true } as CertStoreEntry;
const noEntry = { exists: false } as CertStoreEntry;

describe('deriveStatus', () => {
  it('returns renewing when active job exists', () => {
    expect(deriveStatus(base, null, null, null, true, null, false)).toBe('renewing');
  });

  it('returns invalid when no cert and no entry', () => {
    expect(deriveStatus(base, null, noEntry, null, false, null, false)).toBe('invalid');
  });

  it('returns invalid when cert is expired (daysLeft < 0)', () => {
    expect(deriveStatus(base, okFlock, existsEntry, -1, false, ['example.com'], false)).toBe('invalid');
  });

  it('returns invalid when flock status is not-ok', () => {
    const bad: FlockCert = { ...okFlock, status: 'not-ok' };
    expect(deriveStatus(base, bad, existsEntry, 60, false, ['example.com'], false)).toBe('invalid');
  });

  it('returns error when SAN mismatch', () => {
    expect(deriveStatus(base, okFlock, existsEntry, 60, false, ['other.com'], false)).toBe('error');
  });

  it('returns error when last renewal failed and cert is still valid', () => {
    expect(deriveStatus(base, okFlock, existsEntry, 60, false, ['example.com'], true)).toBe('error');
  });

  it('returns valid when cert is within renewBefore window but not expired', () => {
    expect(deriveStatus(base, okFlock, existsEntry, 20, false, ['example.com'], false)).toBe('valid');
  });

  it('returns valid when cert is healthy', () => {
    expect(deriveStatus(base, okFlock, existsEntry, 60, false, ['example.com'], false)).toBe('valid');
  });
});

describe('statusTone', () => {
  it('valid → green',    () => expect(statusTone('valid')).toBe('green'));
  it('renewing → blue',  () => expect(statusTone('renewing')).toBe('blue'));
  it('error → yellow',   () => expect(statusTone('error')).toBe('yellow'));
  it('invalid → red',    () => expect(statusTone('invalid')).toBe('red'));
});

describe('statusLabel', () => {
  it('valid → Valid',       () => expect(statusLabel('valid', null)).toBe('Valid'));
  it('renewing → Renewing', () => expect(statusLabel('renewing', null)).toBe('Renewing'));
  it('error → Error',       () => expect(statusLabel('error', null)).toBe('Error'));
  it('invalid → Invalid',   () => expect(statusLabel('invalid', null)).toBe('Invalid'));
});
