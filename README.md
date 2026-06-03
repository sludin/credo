# credo

`credo` is a hub-and-spoke TLS certificate management project.

- `shepherd` is the central coordinator.
- `corgi` is the distributed node running near services that consume certs.
- `vigil` is the certificate authority service.

Current repository status: early scaffold with working HTTP services and placeholder certificate-management logic.

## Background

Credo started as an effort to monitor the health of my certificates on my various nodes. I wanted a single pane of glass
that showed me everything at once. The auto-renew aspects of certbot and Caddy are great, but they did not
provide the vivilbilty and alerting that I wanted. So I wrote a script (later agent) to monitor my certs and provide
regular updates. Then I left my job at Google and had time on my hands, and Credo came from that. Is it needed? - probably
not. Is it useful for me? - definitley. Is it over engineered? - oh yeah. Is is under engineered for an enterprise system? - very likely.

A secondary goal was to do as much with agentic coding as I could as a learning exercise, so this is a product of me and my junior 
coders Claude and Codex - whoever wasn't on a token time out. 

## Goals

- Keep certificate state visible across machines.
- Centralize renewal orchestration while still allowing local actions.
- Support ACME challenge workflows (`DNS-01` and `HTTP-01`).
- Use mTLS between coordinator and nodes.

## Architecture

### Control Plane Model

The system operates via a pull-based reconciliation model:

1. **Shepherd** (coordinator) maintains desired certificate assignments and state.
2. **Corgi** (agent) periodically pulls assignment updates from Shepherd and reconciles them locally.
3. **Vigil** (CA) speaks ACME protocol and signs certificate requests.

When certificates need renewal, Shepherd orchestrates issuance through whichever CA provider is configured for each assignment (Let's Encrypt, Vigil, or other ACME-compatible providers).

### Shepherd (Hub)

Responsibilities:

- Manage desired certificate assignments for the fleet.
- Poll Corgi instances for certificate status.
- Orchestrate renewals via configured Certificate Authority providers.
- Host a dashboard API for administrative operations.
- Serve assignment updates to Corgi agents.

Shepherd listens on two separate ports:

- **Agent port** (`corgiInboundPort`, default `7000`): Assignment and renewal endpoints for Corgi agents.
- **Dashboard port** (`dashboardPort`, default `7443`): Admin/dashboard endpoints with optional mTLS gate.

Current endpoints:

- Agent API (`/agents/*`): Assignment retrieval, renewal requests
- Dashboard (`GET /flock`, `GET /flock/:corgiName`, `POST /admin/*`): Fleet overview and administrative operations
- `GET /health` on both listeners

### Vigil (Certificate Authority)

Responsibilities:

- Generate and manage root CA keypair.
- Sign Certificate Signing Requests (CSRs).
- Speak ACME protocol for compatibility with orchestration tools.
- Provide CLI for manual CA operations.

Vigil endpoints:

- mTLS-protected CSR signing and certificate management APIs
- ACME-compatible endpoints (`/acme/directory`, `/acme/nonce`, `/acme/new-account`, etc.)
- CLI commands for root CA creation, signing, revocation, and status

Default port:

- `3555` (override with `PORT`).

Root CA behavior:

- On startup, Vigil ensures a root CA key/cert pair exists.
- If missing, it generates a new self-signed root certificate.
- If both files exist, it loads and reuses them.
- If only one file exists, startup fails to avoid an inconsistent CA state.

Default root CA file locations:

- `certs/root-ca.key.pem`
- `certs/root-ca.cert.pem`

SAN Handling:

- Vigil always includes the certificate Common Name (CN) as a Subject Alternative Name (SAN).
- Additional SANs can be specified when issuing certificates.

### Corgi (Node)

Responsibilities:

- Pull assignment updates from Shepherd's agent API on a configurable interval.
- Reconcile local certificate state with desired assignments.
- Generate CSRs and request certificate issuance.
- Install certificates and restart dependent services.
- Fail gracefully when Shepherd is unavailable (use cached assignments).

Current endpoints:

- `GET /health` -> service status payload
- `GET /agents/:corgiId/assignments` (Shepherd's agent API)
- `POST /agents/:corgiId/renew/:certName` (Shepherd's agent API)
- `GET /.well-known/acme-challenge/:token` -> HTTP-01 challenge response

Corgi connects to Shepherd's agent port (default `7000`) for pulling assignment updates and posting renewal requests.

Default port:

- `3001` (mTLS control API, override with `PORT`).

## Repository Layout

```text
credo/
	README.md
	SPEC
	shepherd/
		package.json
		tsconfig.json
		src/
			index.ts
	corgi/
		package.json
		tsconfig.json
		corgi.config.example.json
		src/
			index.ts
	vigil/
		package.json
		tsconfig.json
		src/
			index.ts
			ca.ts
```

## Requirements

- Node.js 18+
- npm 9+ (or compatible)

## Quick Start

Run Shepherd in one terminal:

```bash
cd shepherd
npm install
npm run dev
```

Run Corgi in another terminal:

```bash
cd corgi
npm install
cp corgi.config.example.json corgi.config.json
npm run dev
```

Run Vigil in a third terminal:

```bash
cd vigil
npm install
npm run dev
```

Health checks:

```bash
curl http://localhost:3000/health
curl http://localhost:3001/health
curl http://localhost:3002/health
```

## Build and Run

Both packages expose the same script names:

- `npm run dev` -> run with `ts-node`.
- `npm run build` -> compile TypeScript to `dist`.
- `npm start` -> run compiled output from `dist/index.js`.
- `npm run watch` -> TypeScript watch mode.

Production-style local run example:

```bash
cd shepherd && npm run build && npm start
# in a second shell
cd corgi && npm run build && npm start
```

## Corgi Config Example

`corgi/corgi.config.example.json` includes:

- Node identity (`nodeId`)
- Shepherd URL (`shepherdUrl`)
- TLS cert/key paths for node identity
- Local flock certificate definitions
- HTTP challenge port
- Service restart commands

This file is a template and should be copied to a local runtime config file before use.

## Deploy Over SSH

Copy `examples/.deploy.json.example` to `.deploy.json` at the repo root and fill in your hosts. Then from the repo root:

```bash
npm run deploy -- corgi home        # deploy one corgi by name
npm run deploy -- shepherd          # deploy shepherd
npm run deploy -- all               # deploy everything
npm run deploy:dry-run -- shepherd  # preview without transferring
npm run rollback -- shepherd        # roll back to previous release
```

The deploy CLI builds TypeScript locally, assembles a clean staging directory, and rsyncs only declared files to the remote host. SSH key auth and `~/.ssh/config` are used automatically.

## Current Implementation Scope

Implemented:

- TypeScript project wiring for all services
- Express servers and JSON middleware
- Basic health/status endpoints
- Self-signed root CA bootstrap in Vigil

Planned:

- Persistent registry and node enrollment
- ACME integration and challenge execution
- Certificate expiry monitoring/renewal thresholds
- mTLS trust bootstrap and rotation
- Safe reload hooks and restart command execution

## Terminology

- `flock`: all certificates managed by the system.
- `shepherd`: central coordination service.
- `corgi`: distributed local management agent.

## License

MIT
