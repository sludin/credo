import { describe, it, expect } from 'vitest';
import { monitorTone, monitorLabel, monitorToForm, monitorFromForm } from './monitor';

describe('monitorTone', () => {
  it('maps statuses to badge tones', () => {
    expect(monitorTone('ok')).toBe('green');
    expect(monitorTone('cert-mismatch')).toBe('red');
    expect(monitorTone('unreachable')).toBe('yellow');
    expect(monitorTone('unmonitored')).toBe('muted');
    expect(monitorTone('pending')).toBe('muted');
  });
});

describe('monitorLabel', () => {
  it('maps statuses to human labels', () => {
    expect(monitorLabel('ok')).toBe('OK');
    expect(monitorLabel('cert-mismatch')).toBe('Cert Mismatch');
    expect(monitorLabel('unreachable')).toBe('Unreachable');
    expect(monitorLabel('unmonitored')).toBe('Unmonitored');
    expect(monitorLabel('pending')).toBe('Pending');
  });
});

describe('monitorFromForm', () => {
  it('returns undefined when host is blank (unmonitored)', () => {
    expect(monitorFromForm('', '443', 'https')).toBeUndefined();
    expect(monitorFromForm('   ', '443', 'https')).toBeUndefined();
  });

  it('builds an endpoint with explicit values', () => {
    expect(monitorFromForm('api.example.com', '8443', 'tls')).toEqual({
      host: 'api.example.com',
      port: 8443,
      protocol: 'tls',
    });
  });

  it('trims host and defaults a blank or invalid port to 443', () => {
    expect(monitorFromForm(' api.example.com ', '', 'https')).toEqual({
      host: 'api.example.com',
      port: 443,
      protocol: 'https',
    });
    expect(monitorFromForm('api.example.com', 'nope', 'https')?.port).toBe(443);
  });
});

describe('monitorToForm', () => {
  it('returns empty-host defaults when unset', () => {
    expect(monitorToForm(undefined)).toEqual({ host: '', port: '443', protocol: 'https' });
  });

  it('stringifies an existing endpoint', () => {
    expect(monitorToForm({ host: 'db.internal', port: 5432, protocol: 'tls' })).toEqual({
      host: 'db.internal',
      port: '5432',
      protocol: 'tls',
    });
  });
});
