# Dashboard BFF Logging Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the dashboard BFF the same "rotating log file + in-memory live-tail broadcast" foundation the three Rust services already have, so a later slice can add `GET /api/logs`/`GET /api/logs/stream` and let `source=dashboard` serve the BFF's own logs the same way `target=shepherd` serves Shepherd's. This is Phase 4 of `docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`, split the same way Phase 0/0b (rotation + broadcast) was split from Phase 1 (the query endpoint) on the Rust side — this slice is the Node-side foundation only, not the query routes.

**Architecture:** `credo-lib`'s `LoggingHandle` (`credo-lib/src/log.rs`, `rotating_log.rs`) can't be shared with Node, so this plan hand-rolls a TypeScript equivalent with the same invariant: one `write()` call is the *only* place that both appends to the rotating file and broadcasts to live-tail subscribers, so the two can never drift out of sync by construction (same reasoning as credo-lib's `RotatingFileWriter`, which wraps one `Write` impl for the same purpose). A new `LoggingHandle` class in `dashboard/server/logging.ts` owns the file + rotation + an `EventEmitter`-based broadcast; a `createRequestLogMiddleware` factory in the same file produces an Express middleware that logs one line per inbound request in the field order `credo`'s `RequestLogEntry` uses (`<code> <dir> <status> <method> <path> <host> <peer_ip> <identity> <ms>`, service code `"D"` for dashboard), so a later slice's historical/live-tail query logic can filter dashboard lines with the same timestamp-prefix and level-token conventions the Rust `log_query` module already uses (`credo-lib/src/log_query/filter.rs`'s `line_timestamp`/`line_level_rank`: first whitespace token is an RFC 3339 timestamp, one later token is `ERROR`/`WARN`/`INFO`/`DEBUG`). Unlike the Rust services, the BFF uses synchronous `fs.appendFileSync`/`fs.renameSync` rather than an async writer — at the BFF's request volume this is simpler and avoids stream-lifecycle bugs (no open file descriptor to manage across a rotation rename), at the cost of a blocking syscall per line, which is an acceptable, deliberate tradeoff for an admin-facing BFF (not a documented invariant to preserve — a future slice could swap this for async I/O without changing the public `LoggingHandle` interface).

**Tech Stack:** TypeScript/Node (`fs`, `path`, `events.EventEmitter` — all built-in, no new npm dependency), Express (existing dependency), Vitest (existing test runner).

## Global Constraints

- Touches `dashboard/server/` only: `logging.ts` (new), `logging.test.ts` (new), `config.ts`, `config.test.ts`, `index.ts`, and `dashboard/docs/config.md`.
- No new npm dependencies. The original design sketch mentioned `rotating-file-stream`; this plan deliberately hand-rolls rotation instead (mirroring the Rust side's own deviation from its original `file-rotate` dependency plan, recorded in `docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`'s Phase 0 notes) — a hand-rolled size-rotate-and-prune is simple enough here too, and avoids depending on a third-party rotation library's exact semantics.
- `npm run typecheck` and `npm test` (run from `dashboard/`) must both pass cleanly — this is what the repo's pre-commit hook runs for any `dashboard/` file change (see root `CLAUDE.md`).
- No placeholder/TODO code. Every function must be fully implemented and covered by a test in the same task.
- Follow existing `dashboard/server` conventions exactly: `config.ts`'s `optionalString`/`intFromEnv`/`boolFromEnv` helpers and its pattern of resolving on-disk paths against `baseDir` (see `authUsersPath`/`authSessionsDir`); `index.ts`'s `main()` structure and Express middleware ordering.
- This plan does not add `GET /api/logs` or `GET /api/logs/stream` — those routes, and the query/filter logic they need (historical + live tail), are a separate, later plan. This slice only makes the BFF *capable* of producing a queryable log file and broadcast stream; nothing consumes them yet.

---

### Task 1: `LoggingHandle` — rotating file writer + live-tail broadcast

**Files:**
- Create: `dashboard/server/logging.ts`
- Create: `dashboard/server/logging.test.ts`

**Interfaces:**
- Produces (used by Task 2 and by the later query-routes plan): `RotationConfig { sizeMb: number; keepFiles: number }`, `LoggingConfig { enabled: boolean; dir: string; rotateOn: RotationConfig; alsoStdout: boolean }`, `DEFAULT_LOGGING_CONFIG: LoggingConfig`, `class LoggingHandle` with `static disabled(): LoggingHandle`, `static init(config: LoggingConfig, basename: string): LoggingHandle`, `write(line: string): void`, `subscribe(onLine: (line: string) => void): () => void`, `isEnabled(): boolean`, `logDir(): string`, `logBasename(): string`.

- [ ] **Step 1: Write the failing tests**

Create `dashboard/server/logging.test.ts`:

```typescript
import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LoggingHandle, type LoggingConfig } from './logging';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-logging-test-'));
}

function enabledConfig(dir: string, overrides: Partial<LoggingConfig> = {}): LoggingConfig {
  return {
    enabled: true,
    dir,
    rotateOn: { sizeMb: 100, keepFiles: 12 },
    alsoStdout: true,
    ...overrides,
  };
}

describe('LoggingHandle.disabled', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('writes only to stdout and creates no file or directory', () => {
    const dir = path.join(os.tmpdir(), `dashboard-logging-unused-${Date.now()}`);
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const handle = LoggingHandle.disabled();

    handle.write('hello');

    expect(stdoutSpy).toHaveBeenCalledWith('hello\n');
    expect(fs.existsSync(dir)).toBe(false);
  });

  it('isEnabled reports false', () => {
    expect(LoggingHandle.disabled().isEnabled()).toBe(false);
  });
});

describe('LoggingHandle.init (enabled)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('appends written lines to <basename>.log', () => {
    const dir = tmpDir();
    const handle = LoggingHandle.init(enabledConfig(dir), 'dashboard');

    handle.write('line one');
    handle.write('line two');

    const content = fs.readFileSync(path.join(dir, 'dashboard.log'), 'utf8');
    expect(content).toBe('line one\nline two\n');
  });

  it('suppresses stdout when alsoStdout is false', () => {
    const dir = tmpDir();
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const handle = LoggingHandle.init(enabledConfig(dir, { alsoStdout: false }), 'dashboard');

    handle.write('quiet line');

    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it('also writes to stdout when alsoStdout is true', () => {
    const dir = tmpDir();
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const handle = LoggingHandle.init(enabledConfig(dir, { alsoStdout: true }), 'dashboard');

    handle.write('loud line');

    expect(stdoutSpy).toHaveBeenCalledWith('loud line\n');
  });

  it('delivers lines to subscribers, and unsubscribe stops delivery', () => {
    const dir = tmpDir();
    const handle = LoggingHandle.init(enabledConfig(dir), 'dashboard');
    const received: string[] = [];
    const unsubscribe = handle.subscribe((line) => received.push(line));

    handle.write('first');
    unsubscribe();
    handle.write('second');

    expect(received).toEqual(['first']);
  });

  it('isEnabled reports true and logDir/logBasename report the configured values', () => {
    const dir = tmpDir();
    const handle = LoggingHandle.init(enabledConfig(dir), 'dashboard');

    expect(handle.isEnabled()).toBe(true);
    expect(handle.logDir()).toBe(dir);
    expect(handle.logBasename()).toBe('dashboard');
  });
});

describe('LoggingHandle rotation', () => {
  it('moves the current file to <basename>.1.log and starts a fresh current file once the size threshold is crossed', () => {
    const dir = tmpDir();
    // sizeMb is a plain multiplier on 1024*1024; a tiny fraction keeps the
    // test fast without needing megabytes of real writes.
    const handle = LoggingHandle.init(enabledConfig(dir, { rotateOn: { sizeMb: 0.001, keepFiles: 12 } }), 'dashboard');
    const line = 'x'.repeat(100);

    // 0.001 MB = ~1048 bytes; each line + newline is 101 bytes, so the
    // 11th write (1111 bytes) is the first to cross the threshold -
    // writing exactly 11 lines means rotation fires on the final write,
    // leaving the fresh current file empty for the assertion below.
    for (let i = 0; i < 11; i++) {
      handle.write(line);
    }

    expect(fs.existsSync(path.join(dir, 'dashboard.1.log'))).toBe(true);
    // The rotated-away file was closed at a consistent line boundary - no
    // partial/truncated last line.
    const rotated = fs.readFileSync(path.join(dir, 'dashboard.1.log'), 'utf8');
    expect(rotated.length % 101).toBe(0);

    // Writes after rotation land in a fresh current file.
    handle.write('after rotation');
    const current = fs.readFileSync(path.join(dir, 'dashboard.log'), 'utf8');
    expect(current).toBe('after rotation\n');
  });

  it('prunes rotated files beyond keepFiles', () => {
    const dir = tmpDir();
    const handle = LoggingHandle.init(enabledConfig(dir, { rotateOn: { sizeMb: 0.001, keepFiles: 2 } }), 'dashboard');
    const line = 'x'.repeat(100);

    // Cross the threshold three separate times (three rotations), each
    // preceded by enough lines to exceed ~1048 bytes.
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 15; i++) {
        handle.write(line);
      }
    }

    expect(fs.existsSync(path.join(dir, 'dashboard.1.log'))).toBe(true);
    expect(fs.existsSync(path.join(dir, 'dashboard.2.log'))).toBe(true);
    expect(fs.existsSync(path.join(dir, 'dashboard.3.log'))).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run server/logging.test.ts`
Expected: FAIL — `Cannot find module './logging'` (the module doesn't exist yet).

- [ ] **Step 3: Implement `dashboard/server/logging.ts`**

```typescript
import fs from 'fs';
import path from 'path';
import { EventEmitter } from 'events';

export type RotationConfig = {
  sizeMb: number;
  keepFiles: number;
};

export type LoggingConfig = {
  enabled: boolean;
  dir: string;
  rotateOn: RotationConfig;
  alsoStdout: boolean;
};

export const DEFAULT_LOGGING_CONFIG: LoggingConfig = {
  enabled: false,
  dir: 'logs',
  rotateOn: { sizeMb: 100, keepFiles: 12 },
  alsoStdout: true,
};

/**
 * Node-side mirror of credo-lib's LoggingHandle: a rotating log file plus an
 * in-memory broadcast for live tail. write() is the only place that both
 * appends to the file and notifies subscribers, so the two can never drift
 * out of sync - the same invariant credo-lib's RotatingFileWriter enforces
 * by wrapping a single Write impl.
 */
export class LoggingHandle {
  private currentSize: number;

  private constructor(
    private readonly config: LoggingConfig,
    private readonly basename: string,
    private readonly emitter: EventEmitter,
    currentSize: number,
  ) {
    this.currentSize = currentSize;
  }

  /** File logging and live tail both off - write() falls through to stdout only. */
  static disabled(): LoggingHandle {
    return new LoggingHandle({ ...DEFAULT_LOGGING_CONFIG, enabled: false }, 'dashboard', new EventEmitter(), 0);
  }

  static init(config: LoggingConfig, basename: string): LoggingHandle {
    if (!config.enabled) {
      return new LoggingHandle(config, basename, new EventEmitter(), 0);
    }
    fs.mkdirSync(config.dir, { recursive: true });
    const emitter = new EventEmitter();
    // Unbounded: each open live-tail SSE connection (added by a later slice)
    // adds one listener, and Node's default cap of 10 would otherwise warn.
    emitter.setMaxListeners(0);
    const filePath = path.join(config.dir, `${basename}.log`);
    const currentSize = fs.existsSync(filePath) ? fs.statSync(filePath).size : 0;
    return new LoggingHandle(config, basename, emitter, currentSize);
  }

  private filePath(): string {
    return path.join(this.config.dir, `${this.basename}.log`);
  }

  /**
   * Appends one line, feeding both the rotating file and every live-tail
   * subscriber from this single call. When disabled, writes go to stdout
   * only - unchanged from the BFF's prior behavior of unstructured
   * process.stdout.write calls.
   */
  write(line: string): void {
    if (!this.config.enabled) {
      process.stdout.write(line + '\n');
      return;
    }
    fs.appendFileSync(this.filePath(), line + '\n');
    this.currentSize += Buffer.byteLength(line, 'utf8') + 1;
    if (this.config.alsoStdout) {
      process.stdout.write(line + '\n');
    }
    this.emitter.emit('line', line);
    if (this.currentSize >= this.config.rotateOn.sizeMb * 1024 * 1024) {
      this.rotate();
    }
  }

  private rotate(): void {
    const dir = this.config.dir;
    const keepFiles = this.config.rotateOn.keepFiles;
    for (let n = keepFiles - 1; n >= 1; n--) {
      const src = path.join(dir, `${this.basename}.${n}.log`);
      if (!fs.existsSync(src)) continue;
      if (n + 1 > keepFiles) {
        fs.unlinkSync(src);
      } else {
        fs.renameSync(src, path.join(dir, `${this.basename}.${n + 1}.log`));
      }
    }
    fs.renameSync(this.filePath(), path.join(dir, `${this.basename}.1.log`));
    this.currentSize = 0;
  }

  /** Subscribes to live lines as they're written. Returns an unsubscribe function. */
  subscribe(onLine: (line: string) => void): () => void {
    this.emitter.on('line', onLine);
    return () => {
      this.emitter.off('line', onLine);
    };
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  logDir(): string {
    return this.config.dir;
  }

  logBasename(): string {
    return this.basename;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd dashboard && npx vitest run server/logging.test.ts`
Expected: all 9 tests pass.

- [ ] **Step 5: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add dashboard/server/logging.ts dashboard/server/logging.test.ts
git commit -m "$(cat <<'EOF'
feat(dashboard): add LoggingHandle, a Node mirror of credo-lib's rotating file + live-tail broadcast

The BFF needs the same on-demand log retrieval capability the Rust
services already have (credo-lib's LoggingHandle), but Node can't
share that Rust code. write() is the single choke point that both
appends to the rotating file and notifies live-tail subscribers, so
the two can never drift - same invariant, hand-rolled for TypeScript.

Rotation and appends are synchronous (fs.appendFileSync/renameSync)
rather than using an async writer - simpler than managing an open file
descriptor across a rotation rename, and acceptable at the BFF's
request volume. No new npm dependency: a hand-rolled rotate-and-prune
is simple enough here, mirroring the Rust side's own choice to drop
the file-rotate crate for the same reason.

Nothing calls this yet - a later plan adds the /api/logs query routes
that use it.
EOF
)"
```

---

### Task 2: Request-log middleware, config wiring, and startup wiring

**Files:**
- Modify: `dashboard/server/logging.ts`
- Modify: `dashboard/server/logging.test.ts`
- Modify: `dashboard/server/config.ts`
- Modify: `dashboard/server/config.test.ts`
- Modify: `dashboard/server/index.ts`
- Modify: `dashboard/docs/config.md`

**Interfaces:**
- Consumes (from Task 1): `LoggingHandle`, `LoggingConfig`.
- Produces: `createRequestLogMiddleware(handle: LoggingHandle): (req, res, next) => void`; `DashboardConfig.logging: LoggingConfig`.

- [ ] **Step 1: Write the failing tests**

Append to `dashboard/server/logging.test.ts` (add the import at the top alongside the existing ones, then add this new `describe` block at the end of the file):

Add to the existing import line:
```typescript
import { LoggingHandle, createRequestLogMiddleware, type LoggingConfig } from './logging';
```
(replacing the current `import { LoggingHandle, type LoggingConfig } from './logging';`)

Append this block at the end of the file:

```typescript
describe('createRequestLogMiddleware', () => {
  it('logs one line on response finish, in the credo field order, with the "D" service code', () => {
    const handle = LoggingHandle.disabled();
    const writeSpy = vi.spyOn(handle, 'write');
    const middleware = createRequestLogMiddleware(handle);

    const res = new EventEmitter() as EventEmitter & { statusCode: number };
    res.statusCode = 200;
    const req = {
      method: 'GET',
      path: '/api/flock',
      hostname: 'dashboard.example.com',
      ip: '10.0.0.5',
      session: { user: { userId: 'alice' } },
    };
    const next = vi.fn();

    middleware(req as never, res as never, next);
    expect(next).toHaveBeenCalledOnce();

    res.emit('finish');

    expect(writeSpy).toHaveBeenCalledOnce();
    const line = writeSpy.mock.calls[0][0];
    const fields = line.split(' ');
    // <timestamp> INFO D > 200 GET /api/flock dashboard.example.com 10.0.0.5 alice <ms>
    expect(fields).toHaveLength(11);
    expect(() => new Date(fields[0]).toISOString()).not.toThrow();
    expect(fields.slice(1)).toEqual(
      expect.arrayContaining(['INFO', 'D', '>', '200', 'GET', '/api/flock', 'dashboard.example.com', '10.0.0.5', 'alice']),
    );
    expect(Number(fields[10])).toBeGreaterThanOrEqual(0);
  });

  it("uses '-' for identity when there is no session user", () => {
    const handle = LoggingHandle.disabled();
    const writeSpy = vi.spyOn(handle, 'write');
    const middleware = createRequestLogMiddleware(handle);

    const res = new EventEmitter() as EventEmitter & { statusCode: number };
    res.statusCode = 401;
    const req = { method: 'GET', path: '/api/certs', hostname: 'dashboard.example.com', ip: '10.0.0.6', session: {} };
    const next = vi.fn();

    middleware(req as never, res as never, next);
    res.emit('finish');

    const line = writeSpy.mock.calls[0][0];
    expect(line).toContain(' - '); // identity field
  });
});
```

Add `EventEmitter` to the top-level imports of `logging.test.ts` (it's used both by the implementation and now by these tests):
```typescript
import { EventEmitter } from 'events';
```

Append to `dashboard/server/config.test.ts` (new `describe` block at the end of the file):

```typescript
describe('logging', () => {
  afterEach(() => {
    delete process.env.DASHBOARD_CONFIG_PATH;
  });

  it('defaults to disabled with standard rotation settings', () => {
    process.env.DASHBOARD_CONFIG_PATH = writeTempConfig();
    const config = loadConfig({ skipTlsCheck: true });
    expect(config.logging.enabled).toBe(false);
    expect(config.logging.rotateOn).toEqual({ sizeMb: 100, keepFiles: 12 });
    expect(config.logging.alsoStdout).toBe(true);
  });

  it('honors explicit logging config values', () => {
    process.env.DASHBOARD_CONFIG_PATH = writeTempConfig({
      logging: { enabled: true, dir: 'custom-logs', rotateOn: { sizeMb: 50, keepFiles: 5 }, alsoStdout: false },
    });
    const config = loadConfig({ skipTlsCheck: true });
    expect(config.logging.enabled).toBe(true);
    expect(config.logging.dir.endsWith('custom-logs')).toBe(true);
    expect(config.logging.rotateOn).toEqual({ sizeMb: 50, keepFiles: 5 });
    expect(config.logging.alsoStdout).toBe(false);
  });

  it('resolves logging.dir relative to baseDir', () => {
    process.env.DASHBOARD_CONFIG_PATH = writeTempConfig({ logging: { enabled: true, dir: 'my-logs' } });
    const config = loadConfig({ skipTlsCheck: true });
    const configDir = path.dirname(config.configPath);
    expect(config.logging.dir).toBe(path.join(configDir, 'my-logs'));
  });
});
```

(`path` is already imported at the top of `config.test.ts` per its existing `writeTempConfig` helper — no new import needed there.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run server/logging.test.ts server/config.test.ts`
Expected: FAIL — `createRequestLogMiddleware` is not exported from `./logging`; `config.logging` is `undefined` (property doesn't exist on `DashboardConfig` yet).

- [ ] **Step 3: Implement**

Append to `dashboard/server/logging.ts` (add the import at the top, then the new function at the end of the file):

Add to the top imports:
```typescript
import type { NextFunction, Request, Response } from 'express';
```

Append at the end of the file:

```typescript
/**
 * Express middleware that logs one line per inbound request, in the same
 * field order as credo's RequestLogEntry (code, direction, status, method,
 * path, host, peer_ip, identity, duration_ms) - service code "D" for
 * dashboard, direction always ">" (the BFF only logs its own inbound
 * requests here, not its outbound calls to Shepherd). Logging on the
 * 'finish' event (not before calling next()) matches how the Rust services
 * log after next.run(req).await completes, so status and duration are
 * accurate.
 */
export function createRequestLogMiddleware(handle: LoggingHandle) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const start = Date.now();
    res.on('finish', () => {
      const durationMs = Date.now() - start;
      const identity = req.session?.user?.userId ?? '-';
      const host = req.hostname || '-';
      const peerIp = req.ip || '-';
      const line = [
        new Date().toISOString(),
        'INFO',
        'D',
        '>',
        String(res.statusCode),
        req.method,
        req.path,
        host,
        peerIp,
        identity,
        durationMs.toFixed(2),
      ].join(' ');
      handle.write(line);
    });
    next();
  };
}
```

In `dashboard/server/config.ts`, add a `logging` field to `RawDashboardConfig`. Change:

```typescript
  dnsPublicResolvers?: unknown;
  auth?: {
```

to:

```typescript
  dnsPublicResolvers?: unknown;
  logging?: {
    enabled?: unknown;
    dir?: unknown;
    rotateOn?: {
      sizeMb?: unknown;
      keepFiles?: unknown;
    };
    alsoStdout?: unknown;
  };
  auth?: {
```

Add a `logging` field to the `DashboardConfig` type. Change:

```typescript
  dnsPublicResolvers: Array<{ name: string; ip: string }>;
  auth: DashboardAuthConfig;
```

to:

```typescript
  dnsPublicResolvers: Array<{ name: string; ip: string }>;
  logging: {
    enabled: boolean;
    dir: string;
    rotateOn: { sizeMb: number; keepFiles: number };
    alsoStdout: boolean;
  };
  auth: DashboardAuthConfig;
```

Parse the new block. Change:

```typescript
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
```

to:

```typescript
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

  // Opt-in rotating log file + live tail for GET /api/logs (a later plan
  // adds the routes); omit entirely for stdout-only (current behavior).
  const rawLogging = raw.logging ?? {};
  const loggingEnabled = typeof rawLogging.enabled === 'boolean' ? rawLogging.enabled : false;
  const loggingDir = path.resolve(baseDir, optionalString(rawLogging.dir) ?? 'logs');
  const loggingSizeMb =
    typeof rawLogging.rotateOn?.sizeMb === 'number' && rawLogging.rotateOn.sizeMb > 0
      ? rawLogging.rotateOn.sizeMb
      : 100;
  const loggingKeepFiles =
    typeof rawLogging.rotateOn?.keepFiles === 'number' && rawLogging.rotateOn.keepFiles > 0
      ? Math.floor(rawLogging.rotateOn.keepFiles)
      : 12;
  const loggingAlsoStdout = typeof rawLogging.alsoStdout === 'boolean' ? rawLogging.alsoStdout : true;

  if (!options?.skipTlsCheck) {
```

Add the parsed values to the returned object. Change:

```typescript
    dnsPublicResolvers,
    auth: {
```

to:

```typescript
    dnsPublicResolvers,
    logging: {
      enabled: loggingEnabled,
      dir: loggingDir,
      rotateOn: { sizeMb: loggingSizeMb, keepFiles: loggingKeepFiles },
      alsoStdout: loggingAlsoStdout,
    },
    auth: {
```

In `dashboard/server/index.ts`, add the import. Change:

```typescript
import { requireAuth, makeRoleRefresh } from './auth/middleware';
import { createAuthRouter } from './routes-auth';
```

to:

```typescript
import { requireAuth, makeRoleRefresh } from './auth/middleware';
import { createAuthRouter } from './routes-auth';
import { LoggingHandle, createRequestLogMiddleware } from './logging';
```

Create the handle and apply the middleware. Change:

```typescript
  const config = loadConfig();
  const clients = createShepherdClients(config);

  initUsersStore(config.auth.usersPath);
```

to:

```typescript
  const config = loadConfig();
  const clients = createShepherdClients(config);
  const loggingHandle = LoggingHandle.init(config.logging, 'dashboard');

  initUsersStore(config.auth.usersPath);
```

Apply the middleware early, right after body parsing and before the session middleware (so it covers every route, including `/auth`, while still logging status/duration via `res.on('finish')` regardless of when `req.session.user` gets populated later in the pipeline). Change:

```typescript
  const app = express();
  app.use(express.json());
  app.use(createSessionMiddleware(config.auth));
```

to:

```typescript
  const app = express();
  app.use(express.json());
  app.use(createRequestLogMiddleware(loggingHandle));
  app.use(createSessionMiddleware(config.auth));
```

In `dashboard/docs/config.md`, add a new `## Logging` section. Insert it after the `## DNS Checker` section and before `## Auth`. Change:

```markdown
| `dnsPublicResolvers` | array | `[]` | — | Public DNS resolvers to query in addition to authoritative nameservers. Each entry: `{ "name": "Google", "ip": "8.8.8.8" }` |

## Auth
```

to:

```markdown
| `dnsPublicResolvers` | array | `[]` | — | Public DNS resolvers to query in addition to authoritative nameservers. Each entry: `{ "name": "Google", "ip": "8.8.8.8" }` |

## Logging

Opt-in rotating log file + live tail, backing `GET /api/logs` (see a later plan for the routes themselves). Omit entirely for stdout-only (current behavior). Requires a BFF restart to pick up changes.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logging.enabled` | bool | `false` | Enable file logging + live tail |
| `logging.dir` | string | `"logs"` | Directory for the rotating log file, resolved relative to `baseDir` |
| `logging.rotateOn.sizeMb` | number | `100` | Rotate when the current log file reaches this size |
| `logging.rotateOn.keepFiles` | number | `12` | Number of rotated backups to retain |
| `logging.alsoStdout` | bool | `true` | Also write log lines to stdout when file logging is enabled (stdout-only always happens when `enabled` is `false`, regardless of this field) |

## Auth
```

Add the `logging` block to the example config JSON near the end of the same file. Change:

```json
  "dnsPublicResolvers": [
    { "name": "Google",     "ip": "8.8.8.8" },
    { "name": "Cloudflare", "ip": "1.1.1.1" }
  ],

  "auth": {
```

to:

```json
  "dnsPublicResolvers": [
    { "name": "Google",     "ip": "8.8.8.8" },
    { "name": "Cloudflare", "ip": "1.1.1.1" }
  ],

  "logging": {
    "enabled": false,
    "dir": "logs",
    "rotateOn": { "sizeMb": 100, "keepFiles": 12 },
    "alsoStdout": true
  },

  "auth": {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd dashboard && npx vitest run server/logging.test.ts server/config.test.ts`
Expected: all tests pass (11 in `logging.test.ts`, plus the 3 new ones in `config.test.ts` alongside the existing ones).

- [ ] **Step 5: Full test suite and typecheck**

Run: `cd dashboard && npm test && npm run typecheck`
Expected: all tests pass, no type errors.

- [ ] **Step 6: Commit**

```bash
git add dashboard/server/logging.ts dashboard/server/logging.test.ts dashboard/server/config.ts dashboard/server/config.test.ts dashboard/server/index.ts dashboard/docs/config.md
git commit -m "$(cat <<'EOF'
feat(dashboard): wire config-driven logging and a request-log middleware

Every inbound BFF request now gets a structured one-line log entry
(service code "D", credo's field order) through LoggingHandle.write,
so file logging, rotation, and live tail all come for free once a
later plan adds the /api/logs query routes. logging.* config mirrors
the shape already used by shepherd/corgi/vigil's logging block, with
the same "omit entirely for unchanged stdout-only behavior" default.

The middleware is applied right after body parsing, ahead of session
middleware, so every route is covered - it logs on the response
'finish' event, so status and duration are accurate regardless of
where in the pipeline req.session.user gets populated.
EOF
)"
```

---

## Verification (whole plan)

1. `cd dashboard && npm test && npm run typecheck` — must be clean.
2. Manual smoke test: set `logging.enabled: true` in a local `dashboard.config.json`, start the BFF (`npm run dev`), make a few requests through the browser or `curl`, confirm `logs/dashboard.log` is created and contains one line per request in the documented field order, and that setting `alsoStdout: false` suppresses console output while the file still fills in.
3. Confirm no files outside `dashboard/server/` and `dashboard/docs/config.md` changed: `git diff --stat <plan-start-commit>..HEAD`.
