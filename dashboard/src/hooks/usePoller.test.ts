import { describe, it, expect } from 'vitest';
import { resolvePollIntervalMs } from './usePoller';

describe('resolvePollIntervalMs', () => {
  it('converts a valid pollIntervalSeconds to milliseconds', () => {
    expect(resolvePollIntervalMs({ pollIntervalSeconds: 60 })).toBe(60_000);
  });

  it('falls back to 30s when the field is missing', () => {
    expect(resolvePollIntervalMs({})).toBe(30_000);
  });

  it('falls back to 30s for malformed payloads', () => {
    expect(resolvePollIntervalMs(null)).toBe(30_000);
    expect(resolvePollIntervalMs(undefined)).toBe(30_000);
    expect(resolvePollIntervalMs({ pollIntervalSeconds: 'fast' })).toBe(30_000);
    expect(resolvePollIntervalMs({ pollIntervalSeconds: 0 })).toBe(30_000);
    expect(resolvePollIntervalMs({ pollIntervalSeconds: -5 })).toBe(30_000);
  });
});
