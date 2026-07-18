import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { loadConfig } from './config';

function writeTempConfig(extra: Record<string, unknown> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-config-test-'));
  const configPath = path.join(dir, 'dashboard.config.json');
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      shepherdApiUrl: 'https://shepherd.example.com:7011',
      tls: { certPath: '/tmp/tls.pem', keyPath: '/tmp/tls.key' },
      mtls: { certPath: '/tmp/mtls.pem', keyPath: '/tmp/mtls.key' },
      auth: {
        sessionSecret: 'a-sufficiently-long-random-session-secret-value',
        rpId: 'dashboard.example.com',
      },
      ...extra,
    })
  );
  return configPath;
}

describe('pollIntervalSeconds', () => {
  afterEach(() => {
    delete process.env.DASHBOARD_CONFIG_PATH;
    delete process.env.DASHBOARD_POLL_INTERVAL_SECONDS;
  });

  it('defaults to 30 seconds', () => {
    process.env.DASHBOARD_CONFIG_PATH = writeTempConfig();
    const config = loadConfig({ skipTlsCheck: true });
    expect(config.pollIntervalSeconds).toBe(30);
  });

  it('honors an explicit config value', () => {
    process.env.DASHBOARD_CONFIG_PATH = writeTempConfig({ pollIntervalSeconds: 60 });
    const config = loadConfig({ skipTlsCheck: true });
    expect(config.pollIntervalSeconds).toBe(60);
  });

  it('honors the environment override', () => {
    process.env.DASHBOARD_CONFIG_PATH = writeTempConfig({ pollIntervalSeconds: 60 });
    process.env.DASHBOARD_POLL_INTERVAL_SECONDS = '90';
    const config = loadConfig({ skipTlsCheck: true });
    expect(config.pollIntervalSeconds).toBe(90);
  });
});
