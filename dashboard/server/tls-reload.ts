import fs from 'fs';
import type { SecureContextOptions } from 'tls';

/**
 * Narrow interface so this is testable without a real https.Server.
 * `https.Server` satisfies this via its inherited `tls.Server#setSecureContext`.
 */
export interface SecureContextHolder {
  setSecureContext(context: SecureContextOptions): void;
}

/**
 * Re-reads the cert/key from disk and swaps them into an already-listening
 * server via Node's native setSecureContext — zero downtime, no listener
 * rebind, no dropped connections. This is what a SIGHUP handler should call
 * once a renewed cert has landed on disk.
 */
export function reloadTlsSecureContext(server: SecureContextHolder, certPath: string, keyPath: string): void {
  const cert = fs.readFileSync(certPath);
  const key = fs.readFileSync(keyPath);
  server.setSecureContext({ cert, key });
}
