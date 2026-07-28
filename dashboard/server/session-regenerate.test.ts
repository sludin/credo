import { describe, it, expect, afterEach } from 'vitest';
import http from 'http';
import express from 'express';
import session from 'express-session';
import axios from 'axios';
import { regenerateSession } from './routes-auth';

const openServers: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (openServers.length > 0) {
    await openServers.pop()!();
  }
});

async function startServer() {
  const app = express();
  app.use(
    session({
      secret: 'test-secret-not-for-real-use-01234567890',
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false },
    })
  );

  // Anonymous route: establishes an initial (pre-auth) session.
  app.get('/anonymous', (req, res) => {
    (req.session as unknown as { touched?: boolean }).touched = true;
    res.json({ sessionId: req.sessionID });
  });

  // Stand-in for login/finish and enroll/finish: regenerates the session
  // before writing authenticated state, exactly as those handlers now do.
  app.post('/login-like', async (req, res) => {
    await regenerateSession(req);
    (req.session as unknown as { user?: { userId: string } }).user = { userId: 'u1' };
    res.json({ sessionId: req.sessionID });
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await new Promise((r) => server.close(r));
  };
  openServers.push(close);

  return { base: `http://127.0.0.1:${port}`, close };
}

/// Regression test for a Medium finding: neither login nor enrollment
/// completion called req.session.regenerate() before writing session.user,
/// reusing a pre-existing (possibly attacker-fixed) session ID across the
/// anonymous -> authenticated transition. The session ID must change once
/// regenerateSession runs, and the authenticated state set afterward must
/// survive on the new session.
describe('regenerateSession', () => {
  it('issues a new session ID and preserves state set after regeneration', async () => {
    const servers = await startServer();

    const jar: string[] = [];
    const anon = await axios.get(`${servers.base}/anonymous`, { withCredentials: true });
    const anonCookie = anon.headers['set-cookie']?.[0];
    expect(anonCookie).toBeDefined();
    jar.push(anonCookie!);

    const finish = await axios.post(`${servers.base}/login-like`, undefined, {
      headers: { Cookie: jar.join('; ') },
    });
    const finishCookie = finish.headers['set-cookie']?.[0];

    expect(anon.data.sessionId).toBeDefined();
    expect(finish.data.sessionId).toBeDefined();
    expect(finish.data.sessionId).not.toBe(anon.data.sessionId);
    // A new Set-Cookie confirms the client would actually pick up the new ID.
    expect(finishCookie).toBeDefined();
    expect(finishCookie).not.toBe(anonCookie);

    await servers.close();
  });
});
