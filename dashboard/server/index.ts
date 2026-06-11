import 'reflect-metadata'; // must remain first — required by @peculiar/x509 (tsyringe)
import fs from 'fs';
import https from 'https';
import path from 'path';
import dns from 'dns';
import tls from 'tls';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { AsyncLocalStorage } from 'async_hooks';
import express, { NextFunction, Request, Response } from 'express';
import { isAxiosError } from 'axios';
import { loadConfig } from './config';
import { createShepherdClients } from './shepherd-client';
import { parseCertFull, pemFromDer, extractCNFromSubject, splitPemChain } from './cert-parser';
import { createSessionMiddleware } from './auth/session';
import { initUsersStore, loadUsers, saveUsers, findUserById } from './auth/users';
import { requireAuth, makeRoleRefresh } from './auth/middleware';
import { createAuthRouter } from './routes-auth';

type Assignment = {
  corgi: string;
  certName: string;
  ca?: string;
  caTarget?: string;
  letsEncryptTarget?: string;
  domain?: string;
  renewBeforeDays?: number;
  days?: number;
  sans?: string[];
  validation?: {
    type?: 'auto' | 'none-01' | 'http-01' | 'dns-01';
    provider?: string;
    providerConfig?: Record<string, unknown>;
  };
  fingerprint256?: string;
};

type DnsJobResolverResult = {
  name: string;
  ip: string;
  role: 'authoritative' | 'public';
  txtRecords: string[];
  queriedAt: string;
  error?: string;
};

type DnsJobRecord = {
  id: string;
  startedAt: Date;
  hostname: string;
  targetValue: string;
  lastQueriedAt: Date | null;
  lastResults: DnsJobResolverResult[];
  authNameservers: Array<{ name: string; ip: string }>;
  converged: boolean;
};

const dnsJobs = new Map<string, DnsJobRecord>();

function buildJobResponse(job: DnsJobRecord): Record<string, unknown> {
  return {
    jobId: job.id,
    hostname: job.hostname,
    targetValue: job.targetValue,
    results: job.lastResults,
    converged: job.converged,
    startedAt: job.startedAt.toISOString(),
    elapsedMs: Date.now() - job.startedAt.getTime(),
  };
}

type RouteHandler = (req: Request, res: Response, next: NextFunction) => Promise<void> | void;

type NormalizedError = {
  statusCode: number;
  clientMessage: string;
  logMessage: string;
};

function asyncHandler(handler: RouteHandler): RouteHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function normalizeError(error: unknown): NormalizedError {
  if (isAxiosError(error)) {
    const statusCode = typeof error.response?.status === 'number' ? error.response.status : 502;
    const upstreamUrl = error.config?.url || 'unknown-url';
    const upstreamCode = error.code || 'UPSTREAM_ERROR';
    const upstreamBody =
      typeof error.response?.data === 'object' && error.response?.data && 'error' in error.response.data
        ? String((error.response.data as { error?: unknown }).error)
        : error.message;

    return {
      statusCode,
      clientMessage: upstreamBody && upstreamBody !== error.message
        ? `Upstream request failed (${upstreamCode}): ${upstreamBody}`
        : `Upstream request failed (${upstreamCode}).`,
      logMessage: `upstream failure status=${statusCode} code=${upstreamCode} url=${upstreamUrl} message=${upstreamBody}`,
    };
  }

  if (error instanceof Error) {
    return {
      statusCode: 500,
      clientMessage: error.message,
      logMessage: error.stack || error.message,
    };
  }

  return {
    statusCode: 500,
    clientMessage: 'Unexpected server error.',
    logMessage: 'unexpected non-error thrown value',
  };
}

async function resolveAuthNameservers(
  hostname: string,
): Promise<Array<{ name: string; ip: string }>> {
  const resolver = new dns.Resolver();
  const resolveNs = promisify(resolver.resolveNs.bind(resolver));
  const resolveA = promisify(dns.resolve4);
  const resolveAAAA = promisify(dns.resolve6);

  let nsLookupHostname = hostname;
  let nsRecords: string[] = [];
  while (nsLookupHostname.includes('.')) {
    try {
      nsRecords = (await resolveNs(nsLookupHostname)) as string[];
      if (nsRecords.length > 0) break;
    } catch { /* walk up */ }
    const dotIdx = nsLookupHostname.indexOf('.');
    nsLookupHostname = nsLookupHostname.slice(dotIdx + 1);
  }

  const nameservers: Array<{ name: string; ip: string }> = [];
  for (const ns of nsRecords.slice(0, 5)) {
    try {
      const aRecords = (await resolveA(ns)) as string[];
      if (aRecords.length > 0) { nameservers.push({ name: ns, ip: aRecords[0] }); continue; }
      const aaaaRecords = (await resolveAAAA(ns)) as string[];
      if (aaaaRecords.length > 0) nameservers.push({ name: ns, ip: aaaaRecords[0] });
    } catch { /* skip unresolvable NS */ }
  }
  return nameservers;
}

async function runJobDnsQueries(
  hostname: string,
  authNameservers: Array<{ name: string; ip: string }>,
  publicResolvers: Array<{ name: string; ip: string }>,
): Promise<DnsJobResolverResult[]> {
  const queriedAt = new Date().toISOString();

  const execFileAsync = promisify(execFile);

  const queryOne = async (
    entry: { name: string; ip: string },
    role: 'authoritative' | 'public',
  ): Promise<DnsJobResolverResult> => {
    const digArgs = [`@${entry.ip}`, 'TXT', hostname, '+short', '+time=5', '+tries=1'];
    process.stdout.write(`[dns/job] query hostname=${hostname} resolver=${entry.name} ip=${entry.ip} role=${role} cmd="dig ${digArgs.join(' ')}"\n`);
    let stdout = '';
    try {
      const result = await execFileAsync('dig', digArgs, { timeout: 7000 });
      stdout = result.stdout;
      process.stdout.write(`[dns/job] raw hostname=${hostname} resolver=${entry.name} stdout=${JSON.stringify(stdout)}\n`);
    } catch (err) {
      // dig exits non-zero on timeout (code 9) but may still have output
      stdout = (err as { stdout?: string }).stdout ?? '';
      const code = (err as { code?: unknown }).code;
      if (!stdout) {
        const error = err instanceof Error ? err.message : 'TXT lookup failed';
        process.stdout.write(`[dns/job] error hostname=${hostname} resolver=${entry.name} ip=${entry.ip} code=${code} error=${error}\n`);
        return { name: entry.name, ip: entry.ip, role, txtRecords: [], queriedAt, error };
      }
      process.stdout.write(`[dns/job] raw (non-zero exit code=${code}) hostname=${hostname} resolver=${entry.name} stdout=${JSON.stringify(stdout)}\n`);
    }

    // dig +short TXT output: one line per record, strings double-quoted.
    // Multi-string records appear as: "part1" "part2" — join them.
    const txtRecords = stdout.trim().split('\n')
      .map(line => line.trim())
      .filter(line => line.startsWith('"'))
      .map(line => {
        const parts = line.match(/"([^"\\]|\\.)*"/g) ?? [];
        return parts.map(p => p.slice(1, -1)).join('');
      });

    process.stdout.write(`[dns/job] result hostname=${hostname} resolver=${entry.name} ip=${entry.ip} records=${JSON.stringify(txtRecords)}\n`);
    return { name: entry.name, ip: entry.ip, role, txtRecords, queriedAt };
  };

  const authResults = await Promise.all(authNameservers.map(ns => queryOne(ns, 'authoritative')));
  const pubResults = await Promise.all(publicResolvers.map(ns => queryOne(ns, 'public')));
  return [...authResults, ...pubResults];
}

// Per-request Bearer token storage — avoids shared-header race conditions.
const shepherdTokenStorage = new AsyncLocalStorage<string>();

async function getValidShepherdToken(
  userId: string,
  shepherdApi: ReturnType<typeof createShepherdClients>['api'],
): Promise<string | null> {
  const { users } = loadUsers();
  const user = findUserById(users, userId);
  if (!user?.shepherdAccessToken || !user.shepherdRefreshToken) return null;

  // If the access token JWT is still fresh (expires > 5 min from now), use it.
  // We don't parse the JWT here — instead we use shepherdTokenExpiresAt which
  // tracks the *refresh token* expiry. For the access token, we track a separate
  // access token expiry by decoding the exp claim.
  try {
    const [, bodyB64] = user.shepherdAccessToken.split('.');
    const claims = JSON.parse(Buffer.from(bodyB64, 'base64url').toString()) as { exp: number };
    const expiresInMs = claims.exp * 1000 - Date.now();
    if (expiresInMs > 5 * 60 * 1000) {
      return user.shepherdAccessToken;
    }
  } catch {
    // Fall through to refresh
  }

  // Access token expired or unparseable — try refresh.
  try {
    const resp = await shepherdApi.post<{
      accessToken: string;
      refreshToken: string;
      expiresAt: string;
    }>('/auth/refresh', { refreshToken: user.shepherdRefreshToken });

    const { users: freshUsers } = loadUsers();
    const idx = freshUsers.findIndex((u) => u.id === userId);
    if (idx !== -1) {
      freshUsers[idx] = {
        ...freshUsers[idx],
        shepherdAccessToken: resp.data.accessToken,
        shepherdRefreshToken: resp.data.refreshToken,
        shepherdTokenExpiresAt: resp.data.expiresAt,
      };
      saveUsers({ users: freshUsers });
    }
    return resp.data.accessToken;
  } catch (err) {
    // If Shepherd rejected the refresh token (e.g. after a restart), clear the
    // stale tokens so subsequent requests don't keep hammering /auth/refresh.
    const status = (err as { response?: { status?: number } }).response?.status;
    if (status === 401) {
      const { users: freshUsers } = loadUsers();
      const idx = freshUsers.findIndex((u) => u.id === userId);
      if (idx !== -1) {
        const { shepherdAccessToken: _a, shepherdRefreshToken: _r, shepherdTokenExpiresAt: _e, ...rest } = freshUsers[idx];
        freshUsers[idx] = rest as typeof freshUsers[number];
        saveUsers({ users: freshUsers });
      }
    }
    return null;
  }
}

async function main(): Promise<void> {
  const config = loadConfig();
  const clients = createShepherdClients(config);

  initUsersStore(config.auth.usersPath);

  // Attach the Bearer JWT to every outbound Shepherd API call using the token
  // stored in AsyncLocalStorage for the current request context.
  clients.api.interceptors.request.use((axiosConfig) => {
    const token = shepherdTokenStorage.getStore();
    if (token) {
      axiosConfig.headers = axiosConfig.headers ?? {};
      axiosConfig.headers['Authorization'] = `Bearer ${token}`;
    }
    return axiosConfig;
  });

  const app = express();
  app.use(express.json());
  app.use(createSessionMiddleware(config.auth));

  const serviceCert = { certPath: clients.certPath, certFingerprint: clients.certFingerprint };

  // Public auth routes (login, enroll) — no authentication required.
  app.use('/auth', createAuthRouter(config, clients.api, serviceCert));

  // All /api/* routes require a valid session.
  app.use('/api', requireAuth);
  app.use('/api', makeRoleRefresh(config, clients.api, serviceCert));

  // Resolve and attach the Bearer JWT for all Shepherd API calls.
  // Uses AsyncLocalStorage so each request has its own token context —
  // no shared-state race condition between concurrent users.
  app.use('/api', asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const user = req.session.user;
    if (!user) { next(); return; }
    const token = await getValidShepherdToken(user.userId, clients.api);
    if (token) {
      shepherdTokenStorage.run(token, next);
    } else {
      res.status(401).json({ error: 'Session credentials have expired. Please sign in again.' });
    }
  }));

  app.get('/api/health', asyncHandler(async (_req: Request, res: Response) => {
    const [apiHealth] = await Promise.allSettled([
      clients.api.get('/health'),
    ]);

    res.json({
      dashboard: { status: 'healthy' },
      shepherdApi: apiHealth.status === 'fulfilled' ? apiHealth.value.data : { status: 'unreachable' },
      shepherdCorgi: { status: 'api-only' },
    });
  }));

  app.get('/api/flock', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/flock');
    res.json(response.data);
  }));

  app.get('/api/certs', asyncHandler(async (_req: Request, res: Response) => {
    const [storeRes, assignRes] = await Promise.all([
      clients.api.get('/admin/certstore'),
      clients.api.get('/admin/assignments'),
    ]);

    const assignMap = new Map<string, { corgi: string; ca: string; domain?: string }>();
    const rawAssignments: Array<{ certName?: string; corgi?: string; ca?: string; domain?: string }> =
      Array.isArray(assignRes.data?.assignments) ? assignRes.data.assignments : [];
    for (const a of rawAssignments) {
      if (a.certName) {
        assignMap.set(a.certName, { corgi: a.corgi ?? '', ca: a.ca ?? '', domain: a.domain });
      }
    }

    const rawEntries: Array<{ name?: string; [k: string]: unknown }> =
      Array.isArray(storeRes.data?.entries) ? storeRes.data.entries : [];

    const entries = rawEntries.map((e) => {
      const certName = (e.name as string) ?? '';
      const assignment = assignMap.get(certName);
      return { ...e, certName, ...(assignment ? { assignment } : {}) };
    });

    res.json({ certStoreDir: storeRes.data?.certStoreDir, entries });
  }));

  app.get('/api/cert-remote', asyncHandler(async (req: Request, res: Response) => {
    const hostParam = typeof req.query.host === 'string' ? req.query.host.trim() : '';
    const portParam = typeof req.query.port === 'string' ? parseInt(req.query.port, 10) : 443;
    if (!hostParam) { res.status(400).json({ error: 'host query parameter required' }); return; }
    const port = isNaN(portParam) || portParam < 1 || portParam > 65535 ? 443 : portParam;

    const pems = await new Promise<string[]>((resolve, reject) => {
      const socket = tls.connect(
        { host: hostParam, port, servername: hostParam, rejectUnauthorized: false, timeout: 10000 },
        () => {
          const peer = socket.getPeerCertificate(true);
          socket.destroy();
          const collected: string[] = [];
          const seen = new Set<string>();
          let cur: tls.DetailedPeerCertificate | null = peer;
          while (cur && !seen.has(cur.fingerprint256)) {
            seen.add(cur.fingerprint256);
            collected.push(pemFromDer(Buffer.from(cur.raw)));
            const issuer: tls.DetailedPeerCertificate | null = cur.issuerCertificate ?? null;
            if (!issuer || issuer.fingerprint256 === cur.fingerprint256) break;
            cur = issuer;
          }
          resolve(collected);
        },
      );
      socket.on('error', reject);
      socket.setTimeout(10000, () => {
        socket.destroy();
        reject(new Error(`Timed out connecting to ${hostParam}:${port}`));
      });
    });

    if (pems.length === 0) { res.status(502).json({ error: 'No certificate received from server' }); return; }

    const { X509Certificate: NodeX509 } = await import('crypto');
    const lastCert = new NodeX509(pems[pems.length - 1]);
    const lastIsSelfSigned = pems.length > 1 && lastCert.subject === lastCert.issuer;
    const chainPems = lastIsSelfSigned ? pems.slice(0, -1) : pems;
    const rootCN = extractCNFromSubject(lastIsSelfSigned ? lastCert.subject : lastCert.issuer);

    const chain = chainPems.map((pem, index) => {
      const nodeCert = new NodeX509(pem);
      return {
        index,
        role: (index === 0 ? 'leaf' : 'intermediate') as 'leaf' | 'intermediate',
        commonName: extractCNFromSubject(nodeCert.subject),
        validTo: nodeCert.validTo,
        cert: parseCertFull(pem),
      };
    });

    res.json({ host: hostParam, port, chain, root: { role: 'root', commonName: rootCN, received: false } });
  }));

  app.get('/api/certs/:certName', asyncHandler(async (req: Request, res: Response) => {
    const response = await clients.api.get(`/admin/certstore/${encodeURIComponent(req.params.certName)}`);
    res.json(response.data);
  }));

  app.post('/api/certs/:certName/renew', asyncHandler(async (req: Request, res: Response) => {
    const certName = req.params.certName;
    const corgiName = typeof req.body?.corgiName === 'string' ? req.body.corgiName.trim() : '';
    if (!corgiName) {
      res.status(400).json({ error: 'corgiName is required' });
      return;
    }

    const response = await clients.api.post(
      `/admin/provision/${encodeURIComponent(certName)}`,
      { expectedCorgi: corgiName }
    );
    res.json(response.data);
  }));

  app.get('/api/assignments', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/admin/assignments');
    const assignments = Array.isArray(response.data?.assignments) ? response.data.assignments as Assignment[] : [];
    const grouped = new Map<string, Assignment[]>();
    for (const assignment of assignments) {
      const corgi = typeof assignment.corgi === 'string' ? assignment.corgi : '';
      if (!grouped.has(corgi)) {
        grouped.set(corgi, []);
      }
      grouped.get(corgi)!.push(assignment);
    }
    const assignmentsByCorgi = Array.from(grouped.entries()).map(([corgi, entries]) => ({ corgi, assignments: entries }));
    res.json({ assignments, byCorgi: assignmentsByCorgi });
  }));

  app.post('/api/admin/reload-assignments', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.post('/admin/reload-assignments');
    res.json(response.data);
  }));

  app.get('/api/vigil/ca', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/admin/vigil/ca');
    res.json(response.data);
  }));

  app.get('/api/vigil/certs', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/admin/vigil/status');
    const stats = (response.data as { certificates?: unknown })?.certificates ?? { total: 0, active: 0, revoked: 0 };
    res.json({ certificates: [], stats });
  }));

  app.get('/api/certs/:certName/pem', asyncHandler(async (req: Request, res: Response) => {
    const response = await clients.api.get(
      `/admin/certstore/${encodeURIComponent(req.params.certName)}/pem`,
      { responseType: 'text' }
    );
    res.type('text/plain').send(response.data);
  }));

  app.get('/api/certs/:certName/last-job', asyncHandler(async (req: Request, res: Response) => {
    try {
      const response = await clients.api.get(
        `/admin/renewal-jobs/last/${encodeURIComponent(req.params.certName)}`
      );
      res.json(response.data);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status === 404) { res.json({ job: null }); return; }
      throw err;
    }
  }));

  app.get('/api/certs/:certName/active-job', asyncHandler(async (req: Request, res: Response) => {
    const response = await clients.api.get(
      `/admin/renewal-jobs?domain=${encodeURIComponent(req.params.certName)}&active=true`
    );
    const jobs = (response.data as { jobs?: unknown[] })?.jobs ?? [];
    const job = jobs.length > 0 ? jobs[0] : null;
    res.json({ job });
  }));

  app.get('/api/certs/:certName/details', asyncHandler(async (req: Request, res: Response) => {
    const pemResponse = await clients.api.get(
      `/admin/certstore/${encodeURIComponent(req.params.certName)}/pem`,
      { responseType: 'text' }
    );
    const pem = pemResponse.data as string;
    const { X509Certificate } = await import('crypto');
    const cert = new X509Certificate(pem);
    res.json({
      pem,
      subject: cert.subject,
      issuer: cert.issuer,
      subjectAltName: cert.subjectAltName ?? null,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      serialNumber: cert.serialNumber,
      fingerprint: cert.fingerprint,
      fingerprint256: cert.fingerprint256,
      ca: cert.ca,
    });
  }));

  app.get('/api/certs/:certName/full', asyncHandler(async (req: Request, res: Response) => {
    const fullchainResponse = await clients.api.get(
      `/admin/certstore/${encodeURIComponent(req.params.certName)}/fullchain`,
      { responseType: 'text' },
    );
    const pems = splitPemChain(fullchainResponse.data as string);
    if (pems.length === 0) { res.status(502).json({ error: 'No certificate found in PEM' }); return; }

    const { X509Certificate: NodeX509 } = await import('crypto');

    // Try to append root CA from Shepherd's clientCa
    try {
      const caResponse = await clients.api.get('/admin/ca', { responseType: 'text' });
      const rootPems = splitPemChain(caResponse.data as string);
      if (rootPems.length > 0) {
        const lastInChain = new NodeX509(pems[pems.length - 1]);
        for (const rootPem of rootPems) {
          const rootCert = new NodeX509(rootPem);
          if (rootCert.subject === lastInChain.issuer) {
            pems.push(rootPem);
            break;
          }
        }
      }
    } catch (err: unknown) {
      const status = isAxiosError(err) ? err.response?.status : undefined;
      if (status !== 404) throw err;
      // 404 = clientCa not configured; proceed without root
    }

    const lastCert = new NodeX509(pems[pems.length - 1]);
    const lastIsSelfSigned = pems.length > 1 && lastCert.subject === lastCert.issuer;
    const chainPems = lastIsSelfSigned ? pems.slice(0, -1) : pems;
    const rootCN = extractCNFromSubject(lastIsSelfSigned ? lastCert.subject : lastCert.issuer);

    const chain = chainPems.map((pem, index) => {
      const nodeCert = new NodeX509(pem);
      return {
        index,
        role: (index === 0 ? 'leaf' : 'intermediate') as 'leaf' | 'intermediate',
        commonName: extractCNFromSubject(nodeCert.subject),
        validTo: nodeCert.validTo,
        cert: parseCertFull(pem),
      };
    });
    res.json({ host: req.params.certName, port: 0, chain, root: { role: 'root', commonName: rootCN, received: false } });
  }));

  app.get('/api/admin/config-summary', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/admin/config-summary');
    res.json(response.data);
  }));

  app.post('/api/assignments', asyncHandler(async (req: Request, res: Response) => {
    const response = await clients.api.post('/admin/assignments', req.body ?? {});
    res.status(201).json(response.data);
  }));

  app.put('/api/assignments/:certName', asyncHandler(async (req: Request, res: Response) => {
    const response = await clients.api.put(
      `/admin/assignments/${encodeURIComponent(req.params.certName)}`,
      req.body ?? {}
    );
    res.json(response.data);
  }));

  app.delete('/api/assignments/:certName', asyncHandler(async (req: Request, res: Response) => {
    const body = req.body && typeof req.body === 'object' ? req.body : undefined;
    await clients.api.request({
      method: 'DELETE',
      url: `/admin/assignments/${encodeURIComponent(req.params.certName)}`,
      data: body,
    });
    res.status(204).end();
  }));

  // ── CA config ──────────────────────────────────────────────────────────────
  app.get('/api/admin/cas', asyncHandler(async (_req: Request, res: Response) => {
    const response = await clients.api.get('/admin/cas');
    res.json(response.data);
  }));

  app.put('/api/admin/cas/:caName', asyncHandler(async (req: Request, res: Response) => {
    const response = await clients.api.put(
      `/admin/cas/${encodeURIComponent(req.params.caName)}`,
      req.body ?? {}
    );
    res.status(response.status).json(response.data);
  }));

  app.delete('/api/admin/cas/:caName', asyncHandler(async (req: Request, res: Response) => {
    await clients.api.request({
      method: 'DELETE',
      url: `/admin/cas/${encodeURIComponent(req.params.caName)}`,
    });
    res.status(204).end();
  }));

  // ── DNS Jobs ───────────────────────────────────────────────────────────────
  app.post('/api/dns/jobs', asyncHandler(async (req: Request, res: Response) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const hostname = typeof body.hostname === 'string' ? body.hostname.trim() : '';
    const targetValue = typeof body.targetValue === 'string' ? body.targetValue : '';
    if (!hostname) {
      res.status(400).json({ error: 'hostname required' });
      return;
    }

    const cutoff = Date.now() - config.dnsJobTimeoutSeconds * 2 * 1000;
    for (const [id, job] of dnsJobs) {
      if (job.startedAt.getTime() < cutoff) dnsJobs.delete(id);
    }

    const authNameservers = await resolveAuthNameservers(hostname);
    if (authNameservers.length === 0) {
      res.status(400).json({ error: 'Could not resolve authoritative nameservers for hostname' });
      return;
    }

    const results = await runJobDnsQueries(hostname, authNameservers, config.dnsPublicResolvers);
    const converged = targetValue !== '' &&
      results.every(r => !r.error && r.txtRecords.some(t => t === targetValue));

    const { randomUUID } = await import('crypto');
    const id = randomUUID();
    const job: DnsJobRecord = {
      id,
      startedAt: new Date(),
      hostname,
      targetValue,
      lastQueriedAt: new Date(),
      lastResults: results,
      authNameservers,
      converged,
    };
    dnsJobs.set(id, job);
    res.status(201).json(buildJobResponse(job));
  }));

  app.get('/api/dns/jobs/:id', asyncHandler(async (req: Request, res: Response) => {
    const job = dnsJobs.get(req.params.id);
    if (!job) {
      res.status(404).json({ error: 'Job not found' });
      return;
    }

    const rateLimitMs = config.dnsPollingIntervalSeconds * 1000;
    if (job.lastQueriedAt && Date.now() - job.lastQueriedAt.getTime() < rateLimitMs) {
      res.status(429).json({ error: 'Too many requests; wait for next polling interval' });
      return;
    }

    const results = await runJobDnsQueries(job.hostname, job.authNameservers, config.dnsPublicResolvers);
    const converged = job.targetValue !== '' &&
      results.every(r => !r.error && r.txtRecords.some(t => t === job.targetValue));

    job.lastQueriedAt = new Date();
    job.lastResults = results;
    job.converged = converged;
    res.json(buildJobResponse(job));
  }));

  // ── DNS Tools ──────────────────────────────────────────────────────────────
  app.get('/api/dns/config', (_req: Request, res: Response) => {
    res.json({
      pollingIntervalSeconds: config.dnsPollingIntervalSeconds,
      publicResolvers: config.dnsPublicResolvers,
    });
  });

  app.get('/api/dns/authoritative-ns', asyncHandler(async (req: Request, res: Response) => {
    const hostname = req.query.hostname;
    if (typeof hostname !== 'string' || !hostname.trim()) {
      res.status(400).json({ error: 'hostname query parameter required' });
      return;
    }

    try {
      const resolver = new dns.Resolver();
      const resolveA = promisify(dns.resolve4);
      const resolveAAAA = promisify(dns.resolve6);

      // NS records live at zone apexes — strip any leading label that isn't part of the registered domain.
      // In practice, the caller may pass _acme-challenge.<domain>; we walk up until resolveNs succeeds.
      const resolveNs = promisify(resolver.resolveNs.bind(resolver));
      let nsLookupHostname = hostname;
      let nsRecords: string[] = [];
      while (nsLookupHostname.includes('.')) {
        try {
          nsRecords = (await resolveNs(nsLookupHostname)) as string[];
          if (nsRecords.length > 0) break;
        } catch {
          // ENODATA / ENOTFOUND — try parent label
        }
        const dotIdx = nsLookupHostname.indexOf('.');
        nsLookupHostname = nsLookupHostname.slice(dotIdx + 1);
      }

      const nameservers: Array<{ name: string; ip: string }> = [];
      for (const ns of nsRecords.slice(0, 5)) {
        try {
          // Try to resolve NS to A record first
          const aRecords = (await resolveA(ns)) as string[];
          if (aRecords.length > 0) {
            nameservers.push({ name: ns, ip: aRecords[0] });
            continue;
          }

          // Fall back to AAAA record
          const aaaaRecords = (await resolveAAAA(ns)) as string[];
          if (aaaaRecords.length > 0) {
            nameservers.push({ name: ns, ip: aaaaRecords[0] });
          }
        } catch {
          // Skip NS records that can't be resolved
        }
      }

      if (nameservers.length === 0) {
        res.status(400).json({ error: 'Could not resolve any nameservers for hostname' });
        return;
      }

      res.json({ hostname, nameservers });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'DNS lookup failed';
      res.status(400).json({ error: msg });
    }
  }));

  app.get('/api/dns/txt', asyncHandler(async (req: Request, res: Response) => {
    const hostname = req.query.hostname;
    const nameserver = req.query.nameserver;

    if (typeof hostname !== 'string' || !hostname.trim()) {
      res.status(400).json({ error: 'hostname query parameter required' });
      return;
    }
    if (typeof nameserver !== 'string' || !nameserver.trim()) {
      res.status(400).json({ error: 'nameserver query parameter required' });
      return;
    }

    process.stdout.write(`[dns/txt] query hostname=${hostname} ns=${nameserver}\n`);
    try {
      const resolver = new dns.Resolver();
      resolver.setServers([nameserver]);
      const resolveTxt = promisify(resolver.resolveTxt.bind(resolver));

      const txtRecords = (await resolveTxt(hostname)) as string[][];
      const txtValues = txtRecords.map(parts => parts.join(''));

      process.stdout.write(
        `[dns/txt] result hostname=${hostname} ns=${nameserver} records=${JSON.stringify(txtValues)}\n`
      );
      res.json({
        hostname,
        resolver: nameserver,
        txtRecords: txtValues,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'TXT lookup failed';
      process.stdout.write(
        `[dns/txt] error hostname=${hostname} ns=${nameserver} error=${msg}\n`
      );
      res.json({
        hostname,
        resolver: nameserver,
        txtRecords: [],
        error: msg,
      });
    }
  }));

  app.post('/api/dns/txt', asyncHandler(async (req: Request, res: Response) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const certName = body.certName ? String(body.certName) : undefined;
    const hostname = body.hostname ? String(body.hostname) : undefined;
    const txtValue = body.txtValue ? String(body.txtValue) : undefined;

    if (!hostname || !txtValue) {
      res.status(400).json({ error: 'hostname and txtValue required' });
      return;
    }

    if (!certName) {
      res.status(400).json({ error: 'certName required for DNS update' });
      return;
    }

    try {
      // Call Shepherd API to perform DNS update via configured provider
      const response = await clients.api.post('/admin/dns/txt', {
        certName,
        recordName: hostname,
        txtValue,
      });
      res.json(response.data);
    } catch (error) {
      if (isAxiosError(error)) {
        const statusCode = error.response?.status || 502;
        const errorMsg = error.response?.data?.error || error.message;
        res.status(statusCode).json({ error: errorMsg });
      } else {
        throw error;
      }
    }
  }));

  app.use((error: unknown, req: Request, res: Response, _next: NextFunction) => {
    const normalized = normalizeError(error);
    process.stderr.write(
      `[dashboard] request error ${req.method} ${req.path}: ${normalized.logMessage}\n`
    );

    if (res.headersSent) {
      return;
    }

    res.status(normalized.statusCode).json({
      error: normalized.clientMessage,
      path: req.path,
      statusCode: normalized.statusCode,
    });
  });

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
      root: process.cwd(),
    });
    app.use(vite.middlewares);
  } else {
    const clientRoot = path.resolve(process.cwd(), 'dist/client');
    app.use(express.static(clientRoot));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(clientRoot, 'index.html'));
    });
  }

  const tlsOptions: https.ServerOptions = {
    cert: fs.readFileSync(config.tls.certPath),
    key: fs.readFileSync(config.tls.keyPath),
  };
  const server = https.createServer(tlsOptions, app);
  server.on('tlsClientError', (err) => {
    process.stderr.write(`[dashboard] TLS client error: ${err.message}\n`);
  });
  server.listen(config.port, config.bind, () => {
    process.stdout.write(
      `[dashboard] listening on https://${config.bind}:${config.port} using shepherd API ${config.shepherdApiUrl}\n`
    );
    const identityUrisLine = clients.certIdentityUris.length > 0
      ? ` | identity URIs: ${clients.certIdentityUris.join(', ')}`
      : ' | identity URIs: (none — cert has no URI SANs)';
    process.stdout.write(
      `[dashboard] service cert: ${clients.certPath} | fingerprint256: ${clients.certFingerprint}${identityUrisLine}\n`
    );
  });

  const bannerPath = path.resolve(process.cwd(), 'dashboard.config.example.json');
  if (!fs.existsSync(path.resolve(process.cwd(), 'dashboard.config.json')) && fs.existsSync(bannerPath)) {
    process.stdout.write('[dashboard] copy dashboard.config.example.json to dashboard.config.json before first real run.\n');
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  process.stderr.write(`[dashboard] startup error: ${message}\n`);
  process.exit(1);
});
