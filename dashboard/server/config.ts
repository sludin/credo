import fs from 'fs';
import path from 'path';
import { deepInterpolate, buildLookup, resolveIncludes } from './config-utils';

export type DashboardAuthConfig = {
  usersPath: string;
  sessionSecret: string;
  sessionDurationHours: number;
  enrollmentTokenTTLHours: number;
  rpId: string;
  rpName: string;
  origin: string;
  identityEnvironment: string;
  roleRefreshIntervalSeconds: number;
  roleStaleTimeoutSeconds: number;
  sessionsDir: string;
};

export type DashboardConfig = {
  port: number;
  bind: string;
  shepherdApiUrl: string;
  caPath?: string;
  tls: {
    certPath: string;
    keyPath: string;
  };
  mtls: {
    certPath: string;
    keyPath: string;
    caPath?: string;
    rejectUnauthorized: boolean;
  };
  requestTimeoutSeconds: number;
  dnsPollingIntervalSeconds: number;
  dnsJobTimeoutSeconds: number;
  dnsPublicResolvers: Array<{ name: string; ip: string }>;
  auth: DashboardAuthConfig;
  configPath: string;
};

type RawDashboardConfig = {
  vars?: Record<string, unknown>;
  port?: unknown;
  bind?: unknown;
  baseDir?: unknown;
  shepherdApiUrl?: unknown;
  caPath?: unknown;
  tls?: {
    certPath?: unknown;
    keyPath?: unknown;
  };
  mtls?: {
    certPath?: unknown;
    keyPath?: unknown;
    caPath?: unknown;
    rejectUnauthorized?: unknown;
  };
  // New seconds field; legacy ms field accepted for backward compat
  requestTimeoutSeconds?: unknown;
  requestTimeoutMs?: unknown;
  dnsPollingIntervalSeconds?: unknown;
  dnsJobTimeoutSeconds?: unknown;
  dnsPublicResolvers?: unknown;
  auth?: {
    usersPath?: unknown;
    sessionSecret?: unknown;
    sessionDurationHours?: unknown;
    enrollmentTokenTTLHours?: unknown;
    rpId?: unknown;
    rpName?: unknown;
    origin?: unknown;
    identityEnvironment?: unknown;
    // New seconds fields; legacy ms fields accepted for backward compat
    roleRefreshIntervalSeconds?: unknown;
    roleRefreshIntervalMs?: unknown;
    roleStaleTimeoutSeconds?: unknown;
    roleStaleTimeoutMs?: unknown;
    sessionsDir?: unknown;
  };
};

function intFromEnv(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function boolFromEnv(value: string | undefined, fallback: boolean): boolean {
  if (!value) {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return fallback;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function optionalString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

export function loadConfig(options?: { skipTlsCheck?: boolean }): DashboardConfig {
  const configPath = process.env.DASHBOARD_CONFIG_PATH || path.resolve(process.cwd(), 'dashboard.config.json');
  if (!fs.existsSync(configPath)) {
    throw new Error(`Dashboard config not found at ${configPath}. Copy dashboard.config.example.json to dashboard.config.json.`);
  }

  const parsed = resolveIncludes(JSON.parse(fs.readFileSync(configPath, 'utf8')) as Record<string, unknown>, configPath);
  const raw = deepInterpolate(parsed, buildLookup(parsed, 'dashboard'), 'dashboard') as RawDashboardConfig;
  const configDir = path.dirname(path.resolve(configPath));
  // baseDir overrides config-file directory for relative path resolution
  const baseDir = typeof raw.baseDir === 'string' && raw.baseDir.trim()
    ? path.resolve(configDir, raw.baseDir.trim())
    : configDir;
  const port = intFromEnv(process.env.PORT, typeof raw.port === 'number' ? raw.port : 7030);
  const bind = process.env.BIND || optionalString(raw.bind) || '127.0.0.1';
  const shepherdApiUrl = process.env.SHEPHERD_API_URL || requiredString(raw.shepherdApiUrl, 'shepherdApiUrl');
  const caPath = process.env.DASHBOARD_CA_PATH || optionalString(raw.caPath);
  const tlsCertPath = process.env.DASHBOARD_TLS_CERT_PATH || requiredString(raw.tls?.certPath, 'tls.certPath');
  const tlsKeyPath = process.env.DASHBOARD_TLS_KEY_PATH || requiredString(raw.tls?.keyPath, 'tls.keyPath');
  const mtlsCertPath = process.env.DASHBOARD_MTLS_CERT_PATH || requiredString(raw.mtls?.certPath, 'mtls.certPath');
  const mtlsKeyPath = process.env.DASHBOARD_MTLS_KEY_PATH || requiredString(raw.mtls?.keyPath, 'mtls.keyPath');
  const mtlsCaPath = process.env.DASHBOARD_MTLS_CA_PATH || optionalString(raw.mtls?.caPath) || caPath;
  const rejectUnauthorized = boolFromEnv(
    process.env.DASHBOARD_MTLS_REJECT_UNAUTHORIZED,
    typeof raw.mtls?.rejectUnauthorized === 'boolean' ? raw.mtls.rejectUnauthorized : true
  );
  // Accept new requestTimeoutSeconds or legacy requestTimeoutMs (divide by 1000)
  const requestTimeoutSeconds = intFromEnv(
    process.env.DASHBOARD_REQUEST_TIMEOUT_SECONDS,
    typeof raw.requestTimeoutSeconds === 'number' && raw.requestTimeoutSeconds > 0
      ? raw.requestTimeoutSeconds
      : typeof raw.requestTimeoutMs === 'number' && raw.requestTimeoutMs > 0
        ? Math.round(raw.requestTimeoutMs / 1000)
        : 15
  );
  const dnsPollingIntervalSeconds = intFromEnv(
    process.env.DASHBOARD_DNS_POLLING_INTERVAL_SECONDS,
    typeof raw.dnsPollingIntervalSeconds === 'number' && raw.dnsPollingIntervalSeconds > 0 ? raw.dnsPollingIntervalSeconds : 5
  );
  const dnsJobTimeoutSeconds = intFromEnv(
    process.env.DASHBOARD_DNS_JOB_TIMEOUT_SECONDS,
    typeof raw.dnsJobTimeoutSeconds === 'number' && raw.dnsJobTimeoutSeconds > 0
      ? raw.dnsJobTimeoutSeconds
      : 600
  );
  const dnsPublicResolvers: Array<{ name: string; ip: string }> = (() => {
    if (!Array.isArray(raw.dnsPublicResolvers)) return [];
    return raw.dnsPublicResolvers
      .filter((e): e is { name: string; ip: string } =>
        typeof (e as Record<string, unknown>)?.name === 'string' &&
        typeof (e as Record<string, unknown>)?.ip === 'string'
      )
      .map(e => ({ name: e.name.trim(), ip: e.ip.trim() }))
      .filter(e => e.name && e.ip);
  })();

  if (!options?.skipTlsCheck) {
    for (const tlsPath of [tlsCertPath, tlsKeyPath, mtlsCertPath, mtlsKeyPath, mtlsCaPath]) {
      if (!tlsPath) {
        continue;
      }
      if (!fs.existsSync(tlsPath)) {
        throw new Error(`TLS file not found: ${tlsPath}`);
      }
    }
  }

  const rawAuth = raw.auth ?? {};

  const authUsersPath = path.resolve(
    baseDir,
    optionalString(rawAuth.usersPath) ?? 'dashboard.users.json'
  );
  const authSessionSecret = requiredString(rawAuth.sessionSecret, 'auth.sessionSecret');
  const KNOWN_PLACEHOLDER_SECRETS = [
    'replace-with-a-long-random-secret',
    'change-me',
    'changeme',
    'secret',
    'your-secret-here',
    'your_secret_here',
  ];
  if (
    KNOWN_PLACEHOLDER_SECRETS.includes(authSessionSecret.toLowerCase()) ||
    authSessionSecret.length < 32
  ) {
    throw new Error(
      'auth.sessionSecret is insecure: must be a random string of at least 32 characters and not a placeholder value. ' +
      'Generate one with: openssl rand -base64 32'
    );
  }
  const authSessionDurationHours = typeof rawAuth.sessionDurationHours === 'number' && rawAuth.sessionDurationHours > 0
    ? rawAuth.sessionDurationHours : 24;
  const authEnrollmentTokenTTLHours = typeof rawAuth.enrollmentTokenTTLHours === 'number' && rawAuth.enrollmentTokenTTLHours > 0
    ? rawAuth.enrollmentTokenTTLHours : 24;
  const authRpId = requiredString(rawAuth.rpId, 'auth.rpId');
  const authRpName = optionalString(rawAuth.rpName) ?? 'Credo Dashboard';
  const authOrigin = optionalString(rawAuth.origin) ?? `https://${authRpId}`;
  const authIdentityEnvironment = optionalString(rawAuth.identityEnvironment) ?? 'prod';
  // Accept new *Seconds fields or legacy *Ms fields (divide by 1000)
  const authRoleRefreshIntervalSeconds =
    typeof rawAuth.roleRefreshIntervalSeconds === 'number' && rawAuth.roleRefreshIntervalSeconds > 0
      ? rawAuth.roleRefreshIntervalSeconds
      : typeof rawAuth.roleRefreshIntervalMs === 'number' && rawAuth.roleRefreshIntervalMs > 0
        ? Math.round(rawAuth.roleRefreshIntervalMs / 1000)
        : 300;
  const authRoleStaleTimeoutSeconds =
    typeof rawAuth.roleStaleTimeoutSeconds === 'number' && rawAuth.roleStaleTimeoutSeconds > 0
      ? rawAuth.roleStaleTimeoutSeconds
      : typeof rawAuth.roleStaleTimeoutMs === 'number' && rawAuth.roleStaleTimeoutMs > 0
        ? Math.round(rawAuth.roleStaleTimeoutMs / 1000)
        : 1800;
  const authSessionsDir = path.resolve(
    baseDir,
    optionalString(rawAuth.sessionsDir) ?? 'sessions'
  );

  return {
    port,
    bind,
    shepherdApiUrl,
    caPath,
    tls: {
      certPath: tlsCertPath,
      keyPath: tlsKeyPath,
    },
    mtls: {
      certPath: mtlsCertPath,
      keyPath: mtlsKeyPath,
      caPath: mtlsCaPath,
      rejectUnauthorized,
    },
    requestTimeoutSeconds,
    dnsPollingIntervalSeconds,
    dnsJobTimeoutSeconds,
    dnsPublicResolvers,
    auth: {
      usersPath: authUsersPath,
      sessionSecret: authSessionSecret,
      sessionDurationHours: authSessionDurationHours,
      enrollmentTokenTTLHours: authEnrollmentTokenTTLHours,
      rpId: authRpId,
      rpName: authRpName,
      origin: authOrigin,
      identityEnvironment: authIdentityEnvironment,
      roleRefreshIntervalSeconds: authRoleRefreshIntervalSeconds,
      roleStaleTimeoutSeconds: authRoleStaleTimeoutSeconds,
      sessionsDir: authSessionsDir,
    },
    configPath,
  };
}
