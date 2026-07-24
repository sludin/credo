import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import express from 'express';
import axios, { isAxiosError } from 'axios';
import { LoggingHandle } from './logging';
import { createLogsRouter } from './routes-logs';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-routes-logs-test-'));
}

// Safety net: every server pair startServers opens gets closed here even
// when an assertion throws mid-test, so a failing expect can't leak
// ephemeral-port listeners into the rest of the vitest worker's life.
// (close() is idempotent, so tests that reach their own close() are fine.)
const openServers: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (openServers.length > 0) {
    await openServers.pop()!();
  }
});

/**
 * Boots a bare Express app with the logs router mounted at /api/logs (no
 * session/auth stack - the router itself is auth-agnostic by design) and a
 * mock shepherd standing in for /admin/logs. The error middleware is a
 * minimal stand-in for the real BFF's app-level handler, matching it on
 * the one dimension these tests assert (a defined upstream status is
 * preserved, e.g. 404 stays 404) - not a faithful mirror of its full body
 * shape or its 502 no-response fallback.
 */
async function startServers(handle: LoggingHandle, mockShepherd: express.Express) {
  const upstream = http.createServer(mockShepherd);
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;

  const shepherdApi = axios.create({ baseURL: `http://127.0.0.1:${upstreamPort}` });
  const app = express();
  app.use('/api/logs', createLogsRouter({ handle, shepherdApi }));
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = isAxiosError(err) && typeof err.response?.status === 'number' ? err.response.status : 500;
    res.status(status).json({ error: 'proxied failure' });
  });
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

describe('GET /api/logs', () => {
  describe('source=dashboard', () => {
    it('serves filtered lines from the local log files', async () => {
      const dir = tmpDir();
      fs.writeFileSync(
        path.join(dir, 'dashboard.log'),
        '2024-01-15T10:00:00Z INFO D > 200 GET /api/flock h ip alice 1.00\n' +
          '2024-01-15T10:00:01Z INFO D > 500 GET /api/certs h ip bob 2.00\n',
      );
      const handle = LoggingHandle.init(
        { enabled: true, dir, rotateOn: { sizeMb: 100, keepFiles: 12 }, alsoStdout: false },
        'dashboard',
      );
      const servers = await startServers(handle, express());

      const all = await axios.get(`${servers.base}/api/logs?source=dashboard`);
      expect(all.data).toHaveLength(2);
      const filtered = await axios.get(`${servers.base}/api/logs?source=dashboard&q=flock`);
      expect(filtered.data).toEqual([
        '2024-01-15T10:00:00Z INFO D > 200 GET /api/flock h ip alice 1.00',
      ]);

      await servers.close();
    });

    it('returns 400 when file logging is not enabled', async () => {
      const servers = await startServers(LoggingHandle.disabled(), express());
      const resp = await axios.get(`${servers.base}/api/logs?source=dashboard`, { validateStatus: () => true });
      expect(resp.status).toBe(400);
      expect(resp.data.error).toContain('not enabled');
      await servers.close();
    });

    it('defaults source to dashboard when omitted', async () => {
      const servers = await startServers(LoggingHandle.disabled(), express());
      const resp = await axios.get(`${servers.base}/api/logs`, { validateStatus: () => true });
      expect(resp.status).toBe(400); // reached the dashboard branch, which rejects (disabled)
      await servers.close();
    });
  });

  describe('proxied sources', () => {
    it('maps source to target and forwards the filter params to shepherd', async () => {
      const mock = express();
      let seenQuery: Record<string, unknown> = {};
      mock.get('/admin/logs', (req, res) => {
        seenQuery = req.query;
        res.json(['upstream line 1', 'upstream line 2']);
      });
      const servers = await startServers(LoggingHandle.disabled(), mock);

      const resp = await axios.get(
        `${servers.base}/api/logs?source=corgi:web-1&last=5m&level=error&q=tls&limit=100`,
      );
      expect(resp.data).toEqual(['upstream line 1', 'upstream line 2']);
      expect(seenQuery).toEqual({ target: 'corgi:web-1', last: '5m', level: 'error', q: 'tls', limit: '100' });

      await servers.close();
    });

    it('propagates upstream error statuses through the error middleware', async () => {
      const mock = express();
      mock.get('/admin/logs', (_req, res) => {
        res.status(404).json({ error: "Corgi 'nope' not found" });
      });
      const servers = await startServers(LoggingHandle.disabled(), mock);

      const resp = await axios.get(`${servers.base}/api/logs?source=corgi:nope`, { validateStatus: () => true });
      expect(resp.status).toBe(404);

      await servers.close();
    });
  });

  it('rejects an unknown source with 400', async () => {
    const servers = await startServers(LoggingHandle.disabled(), express());
    const resp = await axios.get(`${servers.base}/api/logs?source=bogus`, { validateStatus: () => true });
    expect(resp.status).toBe(400);
    expect(resp.data.error).toContain('unknown source');
    await servers.close();
  });
});

/**
 * Minimal SSE reader: collects raw bytes from an open HTTP response until
 * `count` data events have arrived (ignoring comment/keep-alive frames),
 * then destroys the connection and returns the parsed event payloads.
 */
function readSseEvents(url: string, count: number, onOpen?: () => void): Promise<Array<{ line: string; source: string }>> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`unexpected status ${res.statusCode}`));
        return;
      }
      onOpen?.();
      let buf = '';
      const events: Array<{ line: string; source: string }> = [];
      res.on('data', (chunk: Buffer) => {
        buf += chunk.toString('utf8');
        let idx: number;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (frame.startsWith('data: ')) {
            events.push(JSON.parse(frame.slice('data: '.length)));
            if (events.length >= count) {
              req.destroy();
              resolve(events);
              return;
            }
          }
        }
      });
      res.on('error', () => resolve(events));
    });
    req.on('error', reject);
  });
}

describe('GET /api/logs/stream', () => {
  it('replays the historical backlog then continues with live lines, in the shared SSE shape', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'dashboard.log'), '2024-01-15T10:00:00Z INFO historical line\n');
    const handle = LoggingHandle.init(
      { enabled: true, dir, rotateOn: { sizeMb: 100, keepFiles: 12 }, alsoStdout: false },
      'dashboard',
    );
    const servers = await startServers(handle, express());

    const events = await readSseEvents(
      `${servers.base}/api/logs/stream?source=dashboard`,
      2,
      // Fires once the response is open - the live write must land after
      // the subscription exists, proving replay-then-continue end to end.
      () => setTimeout(() => handle.write('2024-01-15T10:00:01Z INFO live line'), 20),
    );

    expect(events).toEqual([
      { line: '2024-01-15T10:00:00Z INFO historical line', source: 'dashboard' },
      { line: '2024-01-15T10:00:01Z INFO live line', source: 'dashboard' },
    ]);

    await servers.close();
  });

  it('applies the level filter to live lines, not just the backlog', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'dashboard.log'), '2024-01-15T10:00:00Z ERROR old failure\n');
    const handle = LoggingHandle.init(
      { enabled: true, dir, rotateOn: { sizeMb: 100, keepFiles: 12 }, alsoStdout: false },
      'dashboard',
    );
    const servers = await startServers(handle, express());

    const events = await readSseEvents(
      `${servers.base}/api/logs/stream?source=dashboard&level=error`,
      2,
      () =>
        setTimeout(() => {
          handle.write('2024-01-15T10:00:01Z INFO filtered out');
          handle.write('2024-01-15T10:00:02Z ERROR new failure');
        }, 20),
    );

    expect(events.map((e) => e.line)).toEqual([
      '2024-01-15T10:00:00Z ERROR old failure',
      '2024-01-15T10:00:02Z ERROR new failure',
    ]);

    await servers.close();
  });

  it('returns 400 for source=dashboard when file logging is not enabled', async () => {
    const servers = await startServers(LoggingHandle.disabled(), express());
    const resp = await axios.get(`${servers.base}/api/logs/stream?source=dashboard`, { validateStatus: () => true });
    expect(resp.status).toBe(400);
    await servers.close();
  });

  it('pipes a proxied stream through verbatim and forwards follow=true', async () => {
    const mock = express();
    let seenQuery: Record<string, unknown> = {};
    mock.get('/admin/logs', (req, res) => {
      seenQuery = req.query;
      res.setHeader('Content-Type', 'text/event-stream');
      res.write('data: {"line":"upstream live","source":"vigil"}\n\n');
      res.end();
    });
    const servers = await startServers(LoggingHandle.disabled(), mock);

    const events = await readSseEvents(`${servers.base}/api/logs/stream?source=vigil&last=5m`, 1);
    expect(events).toEqual([{ line: 'upstream live', source: 'vigil' }]);
    expect(seenQuery).toEqual({ target: 'vigil', last: '5m', follow: 'true' });

    await servers.close();
  });

  it('ends the client connection when the upstream dies mid-stream', async () => {
    const mock = express();
    mock.get('/admin/logs', (_req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.write('data: {"line":"first","source":"vigil"}\n\n');
      // Abrupt socket destruction, not a clean res.end() - simulates the
      // proxied service (or shepherd) restarting mid-tail. pipe() alone
      // does NOT propagate this to the client response, which would hang
      // open forever with no close event (this test times out pre-fix).
      setTimeout(() => {
        res.socket?.destroy();
      }, 20);
    });
    const servers = await startServers(LoggingHandle.disabled(), mock);

    await new Promise<void>((resolve, reject) => {
      const streamReq = http.get(`${servers.base}/api/logs/stream?source=vigil`, (res) => {
        res.on('data', () => {});
        res.on('end', () => resolve());
        res.on('close', () => resolve());
        res.on('error', () => resolve());
      });
      streamReq.on('error', reject);
    });

    await servers.close();
  });

  it('aborts the upstream request when the client disconnects', async () => {
    const mock = express();
    let upstreamClosed = false;
    mock.get('/admin/logs', (req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.write('data: {"line":"first","source":"vigil"}\n\n');
      // Hold the connection open; only the client abort should end it.
      req.on('close', () => {
        upstreamClosed = true;
      });
    });
    const servers = await startServers(LoggingHandle.disabled(), mock);

    // readSseEvents destroys the client connection after the first event.
    await readSseEvents(`${servers.base}/api/logs/stream?source=vigil`, 1);
    await vi.waitFor(() => {
      expect(upstreamClosed).toBe(true);
    });

    await servers.close();
  });
});
