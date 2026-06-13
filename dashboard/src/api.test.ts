import { describe, it, expect } from 'vitest';

describe('api module exports', () => {
  it('exports fetchLastTerminalJobsPerCert', async () => {
    const api = await import('./api');
    expect(typeof api.fetchLastTerminalJobsPerCert).toBe('function');
  });
});
