import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { EventEmitter } from 'events';
import { LoggingHandle, createRequestLogMiddleware, type LoggingConfig } from './logging';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-logging-test-'));
}

function enabledConfig(dir: string, overrides: Partial<LoggingConfig> = {}): LoggingConfig {
  return {
    enabled: true,
    dir,
    rotateOn: { sizeMb: 100, keepFiles: 12 },
    // Default off so tests that don't spy on stdout stay silent; the two
    // stdout-behavior tests pass explicit overrides.
    alsoStdout: false,
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
    // alsoStdout: false keeps the bulk writes out of the test output.
    const handle = LoggingHandle.init(
      enabledConfig(dir, { rotateOn: { sizeMb: 0.001, keepFiles: 12 }, alsoStdout: false }),
      'dashboard',
    );
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
    const handle = LoggingHandle.init(
      enabledConfig(dir, { rotateOn: { sizeMb: 0.001, keepFiles: 2 }, alsoStdout: false }),
      'dashboard',
    );
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
    // Exact positional match, not arrayContaining: the /api/logs query
    // slice will parse these lines with credo-lib's conventions (leading
    // timestamp token, standalone level token), so field ORDER is the
    // contract, not just field presence.
    expect(fields.slice(1, 10)).toEqual([
      'INFO',
      'D',
      '>',
      '200',
      'GET',
      '/api/flock',
      'dashboard.example.com',
      '10.0.0.5',
      'alice',
    ]);
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
