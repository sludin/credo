import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import express, { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { createAuthRouter } from './routes-auth';
import { initUsersStore } from './auth/users';
import type { DashboardConfig } from './config';
import type { SessionUser } from './auth/session';

const openServers: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (openServers.length > 0) {
    await openServers.pop()!();
  }
});

function testConfig(): DashboardConfig {
  return {
    auth: {
      usersPath: '/nonexistent/dashboard.users.json',
      sessionSecret: 'x'.repeat(32),
      sessionDurationHours: 24,
      enrollmentTokenTTLHours: 24,
      rpId: 'test.local',
      rpName: 'Test',
      origin: 'https://test.local',
      identityEnvironment: 'test',
      // Force staleness immediately so every request triggers a refresh
      // against the mocked shepherd /accounts endpoint.
      roleRefreshIntervalSeconds: 0,
      roleStaleTimeoutSeconds: 300,
      sessionsDir: '/nonexistent/sessions',
    },
  } as unknown as DashboardConfig;
}

/** Injects a fake `req.session` (no real express-session/cookies involved)
 * with an already-stale `roleVerifiedAt`, so makeRoleRefresh always attempts
 * a refresh against the mocked shepherd `/accounts` endpoint. */
function fakeSession(user: SessionUser) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    (req as unknown as { session: unknown }).session = {
      user: { ...user },
      destroy: (cb: (err?: unknown) => void) => cb(),
    };
    next();
  };
}

async function startServers(
  sessionUser: SessionUser,
  shepherdAccounts: Array<{ name: string; role: string; active: boolean }>
) {
  const mockShepherd = express();
  mockShepherd.get('/accounts', (_req, res) => {
    res.json({ accounts: shepherdAccounts });
  });
  const upstream = http.createServer(mockShepherd);
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;
  const shepherdApi = axios.create({ baseURL: `http://127.0.0.1:${upstreamPort}` });

  initUsersStore('/nonexistent/dashboard.users.json');

  const app = express();
  app.use(express.json());
  app.use(fakeSession(sessionUser));
  app.use(
    '/auth',
    createAuthRouter(testConfig(), shepherdApi, {
      certPath: '/dev/null',
      certFingerprint: 'test-fingerprint',
    })
  );
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await new Promise((r) => server.close(r));
    await new Promise((r) => upstream.close(r));
  };
  openServers.push(close);

  return { base: `http://127.0.0.1:${port}`, close };
}

function adminSessionUser(): SessionUser {
  return {
    userId: 'usr_test',
    shepherdAccount: 'alice',
    identityUri: 'vigil://credo/user/alice',
    displayName: 'Alice',
    role: 'admin',
    // Long in the past — always stale given roleRefreshIntervalSeconds: 0.
    roleVerifiedAt: 0,
  };
}

describe('/auth/admin/* role revalidation', () => {
  // Regression test for a High finding: /auth/admin/* routes never got
  // makeRoleRefresh applied (unlike /api/*), so a cached admin session kept
  // full admin-panel access — including after Shepherd deactivated the
  // account — for the life of the session cookie.
  it('rejects a cached admin session once Shepherd reports the account deactivated', async () => {
    const servers = await startServers(adminSessionUser(), [
      { name: 'alice', role: 'admin', active: false },
    ]);

    const resp = await axios.get(`${servers.base}/auth/admin/users`, {
      validateStatus: () => true,
    });

    expect(resp.status).toBe(401);
    await servers.close();
  });

  it('rejects a cached admin session once Shepherd reports the account demoted', async () => {
    const servers = await startServers(adminSessionUser(), [
      { name: 'alice', role: 'operator', active: true },
    ]);

    // admin-only route; a demoted-to-operator session must be refused here
    // even though the cached session role was still 'admin'.
    const resp = await axios.post(
      `${servers.base}/auth/admin/users`,
      { shepherdAccount: 'bob', displayName: 'Bob', email: 'bob@example.test' },
      { validateStatus: () => true }
    );

    expect(resp.status).toBe(403);
    await servers.close();
  });

  it('still allows access when Shepherd confirms the cached role is current', async () => {
    const servers = await startServers(adminSessionUser(), [
      { name: 'alice', role: 'admin', active: true },
    ]);

    const resp = await axios.get(`${servers.base}/auth/admin/users`, {
      validateStatus: () => true,
    });

    expect(resp.status).toBe(200);
    expect(resp.data.users).toEqual([]);
    await servers.close();
  });
});
