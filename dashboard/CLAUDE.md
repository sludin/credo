# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Role

The dashboard is a React+Vite SPA backed by an Express BFF (backend-for-frontend) server. The BFF proxies requests to Shepherd and Vigil using mTLS client certificates, so the browser never handles raw TLS credentials. In production, the BFF also serves the compiled frontend bundle.

## Architecture

```
Browser → BFF (Express, server/) → Shepherd dashboard port (7443, mTLS) → Vigil (3555, mTLS)
```

The BFF holds one set of mTLS client credentials (for Shepherd). All Vigil calls are proxied through Shepherd — the dashboard never contacts Vigil directly.

## Key Files

| Path | Purpose |
|------|---------|
| `server/index.ts` | BFF entry point: Express routes, HTTPS proxy calls to Shepherd/Vigil, DNS-TXT watcher jobs |
| `server/config.ts` | Config loading for BFF (TLS cert paths, Shepherd/Vigil URLs) |
| `server/shepherd-client.ts` | Typed mTLS HTTPS client for Shepherd dashboard API |
| `server/cert-parser.ts` | Parse X.509 certs (DER/PEM) using `@peculiar/x509`; extract CN, chain, SANs |
| `src/App.tsx` | React Router setup; all page routes |
| `src/pages/` | Page-level components (Overview, Corgis, Assignments, Certificates, VigilCA, Tools) |
| `src/components/` | Shared components (CertViewer, DnsTxtChecker, Shell, StatBox, StatusBadge) |
| `src/api.ts` | Frontend API client (calls BFF endpoints) |
| `src/types.ts` | Shared TypeScript types for frontend |

## Development

```bash
cd dashboard
npm run dev         # tsx server/index.ts — BFF only, Vite proxy handles frontend HMR
npm run build       # vite build + tsc for server
./dashboard server start   # start BFF server in the foreground (production, serves built SPA)
npm test            # vitest run
npm run typecheck   # type-check both tsconfigs (client + server)
./dashboard --help  # CLI help
```

There are two `tsconfig` files:
- `tsconfig.json` — frontend (Vite/React)
- `tsconfig.server.json` — BFF server (Node.js)

## CLI

`server/cli.ts` provides user management commands for the dashboard's passkey auth system.

```bash
./dashboard server start                                                       # start the server in the foreground
./dashboard user create --account <name> --email <e> --name <display>          # create user + enrollment link
./dashboard user list                                                          # list all dashboard users
./dashboard user reset --account <name>                                        # revoke passkeys, generate new enrollment link
```

## Certificate Parsing

`server/cert-parser.ts` uses `@peculiar/x509` (which requires `reflect-metadata` to be imported first — it's at the top of `server/index.ts`). The parser handles full chain extraction, self-signed root detection, and DER↔PEM conversion. The `CertViewer` component renders parsed chain data in the UI.

## DNS TXT Watcher

The BFF maintains in-memory DNS polling jobs (see `server/index.ts`). When a job is created, it polls both authoritative and public resolvers at intervals and stores results in memory. These jobs are ephemeral — they exist only for the lifetime of the BFF process.

## Config

Dashboard BFF loads `dashboard.config.json` (path configurable via `DASHBOARD_CONFIG_PATH`). See `dashboard.config.example.json` for the format. Key fields: Shepherd URL + mTLS cert/key, Vigil URL + mTLS cert/key, listen port.
