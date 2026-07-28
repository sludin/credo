import { describe, it, expect } from 'vitest';
import { isBlockedSsrfTarget } from './ssrf-guard';

describe('isBlockedSsrfTarget', () => {
  it('blocks IPv4 loopback', () => {
    expect(isBlockedSsrfTarget('127.0.0.1')).toBe(true);
    expect(isBlockedSsrfTarget('127.1.2.3')).toBe(true);
  });

  /// Regression test for a Medium (pre-existing) finding: /api/cert-remote
  /// performed tls.connect to a fully user-supplied host/port with no
  /// destination restriction, letting an authenticated (even readonly) user
  /// probe internal-only addresses including the cloud-metadata service.
  it('blocks the cloud-metadata / link-local range', () => {
    expect(isBlockedSsrfTarget('169.254.169.254')).toBe(true);
    expect(isBlockedSsrfTarget('169.254.0.1')).toBe(true);
  });

  it('blocks "this network" / unspecified addresses', () => {
    expect(isBlockedSsrfTarget('0.0.0.0')).toBe(true);
  });

  it('blocks IPv6 loopback and link-local', () => {
    expect(isBlockedSsrfTarget('::1')).toBe(true);
    expect(isBlockedSsrfTarget('::')).toBe(true);
    expect(isBlockedSsrfTarget('fe80::1')).toBe(true);
    expect(isBlockedSsrfTarget('fe80::1%eth0')).toBe(true);
  });

  it('blocks an IPv4-mapped IPv6 loopback/link-local address', () => {
    expect(isBlockedSsrfTarget('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedSsrfTarget('::ffff:169.254.169.254')).toBe(true);
  });

  it('allows RFC1918 private addresses (this dashboard\'s normal fleet targets)', () => {
    expect(isBlockedSsrfTarget('10.0.0.5')).toBe(false);
    expect(isBlockedSsrfTarget('172.16.0.1')).toBe(false);
    expect(isBlockedSsrfTarget('192.168.1.1')).toBe(false);
  });

  it('allows ordinary public addresses', () => {
    expect(isBlockedSsrfTarget('93.184.216.34')).toBe(false);
    expect(isBlockedSsrfTarget('2606:2800:220:1:248:1893:25c8:1946')).toBe(false);
  });
});
