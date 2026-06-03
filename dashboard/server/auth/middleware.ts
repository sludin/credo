import type { Request, Response, NextFunction } from 'express';
import type { SessionUser } from './session';
import type { DashboardConfig } from '../config';
import type { AxiosInstance } from 'axios';

type Role = 'admin' | 'operator' | 'readonly';
const ROLE_ORDER: Role[] = ['readonly', 'operator', 'admin'];

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.user) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  next();
}

export function requireRole(minRole: Role) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.session.user;
    if (!user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (ROLE_ORDER.indexOf(user.role) < ROLE_ORDER.indexOf(minRole)) {
      res.status(403).json({ error: 'Insufficient permissions.' });
      return;
    }
    next();
  };
}

// Re-validates the session user's role from Shepherd if the cached role is stale.
export function makeRoleRefresh(
  config: DashboardConfig,
  shepherdApi: AxiosInstance,
  serviceCert: { certPath: string; certFingerprint: string }
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const user = req.session.user;
    if (!user) {
      next();
      return;
    }

    const staleMs = config.auth.roleRefreshIntervalSeconds * 1000;
    const timeoutMs = config.auth.roleStaleTimeoutSeconds * 1000;
    const ageMs = Date.now() - user.roleVerifiedAt;

    if (ageMs < staleMs) {
      next();
      return;
    }

    try {
      const resp = await shepherdApi.get<{ accounts: Array<{ name: string; role: Role; active: boolean }> }>('/accounts');
      const account = resp.data.accounts.find((a) => a.name === user.shepherdAccount);
      if (!account) {
        req.session.destroy(() => {});
        res.status(401).json({
          error: `[Layer 2 — proxied user identity] Shepherd account '${user.shepherdAccount}' no longer exists. ` +
            `Remove the session and re-enroll, or add the account back to shepherd.accounts.json.`,
        });
        return;
      }
      if (!account.active) {
        req.session.destroy(() => {});
        res.status(401).json({
          error: `[Layer 2 — proxied user identity] Shepherd account '${user.shepherdAccount}' has been deactivated.`,
        });
        return;
      }
      user.role = account.role;
      user.roleVerifiedAt = Date.now();
      next();
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (ageMs > timeoutMs) {
        req.session.destroy(() => {});
        const base = 'Role refresh failed and cached role has expired — session terminated.';
        const detail = (status === 401 || status === 403)
          ? ` [Layer 1 — dashboard service cert] Shepherd rejected the dashboard mTLS cert (HTTP ${status}). ` +
            `Cert: ${serviceCert.certPath} | fingerprint256: ${serviceCert.certFingerprint}`
          : ` Shepherd unreachable: ${err instanceof Error ? err.message : String(err)}`;
        res.status(401).json({ error: base + detail });
        return;
      }
      // Shepherd temporarily unreachable — use cached role within timeout window.
      next();
    }
  };
}

export function getSessionUser(req: Request): SessionUser | undefined {
  return req.session.user;
}
