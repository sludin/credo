import fs from 'fs';
import path from 'path';
import { EventEmitter } from 'events';
import type { NextFunction, Request, Response } from 'express';

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
    // Shift .1 -> .2 -> ... up to .keepFiles; starting at keepFiles - 1
    // means the oldest backup (.keepFiles) is simply overwritten by the
    // rename from .keepFiles-1, which is what prunes history to keepFiles.
    for (let n = keepFiles - 1; n >= 1; n--) {
      const src = path.join(dir, `${this.basename}.${n}.log`);
      if (!fs.existsSync(src)) continue;
      fs.renameSync(src, path.join(dir, `${this.basename}.${n + 1}.log`));
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
