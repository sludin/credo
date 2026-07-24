import express, { NextFunction, Request, Response, Router } from 'express';
import type { AxiosInstance } from 'axios';
import { LoggingHandle } from './logging';
import { readHistoricalLines, type LogQueryParams } from './log-query';

type LogsRouterDeps = {
  handle: LoggingHandle;
  shepherdApi: AxiosInstance;
};

function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };
}

function queryString(req: Request, key: string): string | undefined {
  const v = req.query[key];
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/** The filter params shared by both routes, straight off the query string. */
function filterParams(req: Request): LogQueryParams {
  const limitRaw = queryString(req, 'limit');
  const limit = limitRaw !== undefined ? Number(limitRaw) : undefined;
  return {
    since: queryString(req, 'since'),
    until: queryString(req, 'until'),
    last: queryString(req, 'last'),
    level: queryString(req, 'level'),
    q: queryString(req, 'q'),
    limit: limit !== undefined && Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : undefined,
  };
}

/** The same params as an object to forward on a proxied shepherd request. */
function forwardParams(params: LogQueryParams): Record<string, string> {
  const out: Record<string, string> = {};
  if (params.since !== undefined) out.since = params.since;
  if (params.until !== undefined) out.until = params.until;
  if (params.last !== undefined) out.last = params.last;
  if (params.level !== undefined) out.level = params.level;
  if (params.q !== undefined) out.q = params.q;
  if (params.limit !== undefined) out.limit = String(params.limit);
  return out;
}

/**
 * source=dashboard (default) is served locally; shepherd/vigil/corgi:<name>
 * map 1:1 onto shepherd's /admin/logs target param (shepherd proxies
 * onward to vigil/corgi itself). Anything else -> null.
 */
function resolveSource(req: Request): { kind: 'dashboard' } | { kind: 'proxy'; target: string } | null {
  const source = queryString(req, 'source') ?? 'dashboard';
  if (source === 'dashboard') return { kind: 'dashboard' };
  // Bare "corgi:" (empty name) intentionally passes through as-is:
  // shepherd owns corgi-name validation and 404s unknown (including
  // empty) names, so validating here would just duplicate its rules.
  if (source === 'shepherd' || source === 'vigil' || source.startsWith('corgi:')) {
    return { kind: 'proxy', target: source };
  }
  return null;
}

/**
 * GET /        - historical JSON (array of raw log lines)
 * GET /stream  - live tail as SSE (added in the next task)
 *
 * Auth-agnostic by design: mounted under /api in index.ts, so the existing
 * session/role/token middlewares run first; shepherd additionally enforces
 * Readonly+ on its end for proxied sources.
 */
export function createLogsRouter(deps: LogsRouterDeps): Router {
  const router = express.Router();

  router.get(
    '/',
    asyncHandler(async (req: Request, res: Response) => {
      const source = resolveSource(req);
      if (source === null) {
        res.status(400).json({ error: `unknown source '${String(req.query.source)}'` });
        return;
      }
      const params = filterParams(req);

      if (source.kind === 'dashboard') {
        const dir = deps.handle.logDir();
        const basename = deps.handle.logBasename();
        if (!deps.handle.isEnabled()) {
          res.status(400).json({ error: 'file logging is not enabled' });
          return;
        }
        res.json(readHistoricalLines(dir, basename, params, new Date()));
        return;
      }

      const response = await deps.shepherdApi.get('/admin/logs', {
        params: { target: source.target, ...forwardParams(params) },
      });
      res.json(response.data);
    }),
  );

  return router;
}
