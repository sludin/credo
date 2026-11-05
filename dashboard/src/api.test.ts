import { describe, it, expect } from 'vitest';

describe('api module exports', () => {
  it('exports fetchLastTerminalJobsPerCert', async () => {
    const api = await import('./api');
    expect(typeof api.fetchLastTerminalJobsPerCert).toBe('function');
  });

  it('exports fetchLogsHistorical and openLogsStream', async () => {
    const api = await import('./api');
    expect(typeof api.fetchLogsHistorical).toBe('function');
    expect(typeof api.openLogsStream).toBe('function');
  });

  it('exports runMonitorCheck', async () => {
    const api = await import('./api');
    expect(typeof api.runMonitorCheck).toBe('function');
  });
});
