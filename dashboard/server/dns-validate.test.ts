import { describe, it, expect } from 'vitest';
import { isValidHostname } from './dns-validate';

describe('isValidHostname', () => {
  it('accepts ordinary hostnames', () => {
    expect(isValidHostname('example.com')).toBe(true);
    expect(isValidHostname('www.example.com')).toBe(true);
    expect(isValidHostname('a-b-c.example.com')).toBe(true);
    expect(isValidHostname('example.com.')).toBe(true); // trailing dot (FQDN)
  });

  it('rejects empty and oversized input', () => {
    expect(isValidHostname('')).toBe(false);
    expect(isValidHostname('a'.repeat(254))).toBe(false);
  });

  /// Regression test for a Medium finding: /api/dns/jobs forwarded an
  /// unvalidated hostname as a positional `dig` argument. `dig` treats a
  /// leading `@`, `+`, or `-` as a directive/flag rather than a query name
  /// regardless of argv position, letting an authenticated user redirect
  /// the query to an arbitrary nameserver or toggle dig options.
  it('rejects values that dig would interpret as directives or flags', () => {
    expect(isValidHostname('@10.0.0.5')).toBe(false);
    expect(isValidHostname('@ns.attacker.example')).toBe(false);
    expect(isValidHostname('+trace')).toBe(false);
    expect(isValidHostname('-x')).toBe(false);
    expect(isValidHostname('--help')).toBe(false);
  });

  it('rejects other shapes that are not valid hostnames', () => {
    expect(isValidHostname('exa mple.com')).toBe(false);
    expect(isValidHostname('example..com')).toBe(false);
    expect(isValidHostname('-example.com')).toBe(false);
    expect(isValidHostname('example-.com')).toBe(false);
    expect(isValidHostname('exam;ple.com')).toBe(false);
  });
});
