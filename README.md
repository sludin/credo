# credo

`credo` is a hub-and-spoke TLS certificate management system written in Rust. It provides centralized certificate orchestration and lifecycle management across multiple machines using a pull-based reconciliation model.

## Background

Credo started as an effort to monitor the health of my certificates on my various nodes. I wanted a single pane of glass that showed me everything at once. The auto-renew aspects of certbot and Caddy are great, but they did not provide the visibility and alerting that I wanted. So I wrote a script (later an agent) to monitor my certs and provide regular updates. Then I left my job at Google and had time on my hands, and Credo came from that. Is it needed? — probably not. Is it useful for me? — definitely. Is it over engineered? — oh yeah. Is it under engineered for an enterprise system? — very likely.

A secondary goal was to do as much with agentic coding as I could as a learning exercise, so this is a product of me and my junior coders Claude and Codex — whoever wasn't on a token time out.

## Goals

- Keep certificate state visible across machines.
- Centralize renewal orchestration while still allowing local actions.
- Support ACME challenge workflows (`DNS-01` and `HTTP-01`).
- Use mTLS between coordinator and nodes.
- Private keys never leave the node where they were generated.

## Services

| Package | Role |
|---------|------|
| `shepherd` | Central coordinator (control plane). Holds assignments, drives ACME issuance, stores cert material. |
| `corgi` | Distributed agent on each managed node. Pulls assignments from Shepherd, installs certs, runs service hooks. |
| `vigil` | Private ACME-compatible certificate authority. |
| `dashboard` | React+Vite management UI with an Express BFF. |
| `ceremony` | Offline PKI ceremony scripts for root/intermediate CA generation (run once, air-gapped). |
| `credo-lib` | Shared Rust library used by all Rust services. |

## Architecture

The system operates on a **pull-based reconciliation model**. Shepherd never pushes config or cert material to Corgi — Corgi always pulls. When Shepherd is unavailable, Corgi continues operating from its local assignment cache.

1. **Shepherd** holds `ManagedAssignment` records (which cert, which Corgi, which CA). It drives ACME issuance and stores cert material in a certstore (`archive/` + `live/` layout).
2. **Corgi** periodically pulls assignment updates. When the local cert fingerprint differs from Shepherd's, Corgi fetches updated cert material, installs it atomically, and runs configured service hooks. Private keys are generated on Corgi and **never sent to Shepherd**.
3. **Vigil** is the private CA. Shepherd talks to Vigil as an ACME client over mTLS.

All inter-service communication uses mTLS with URI-SAN-only identity matching.

## Setup

**Requirements:** Rust toolchain (stable) via [rustup](https://rustup.rs); Node.js 18+ and npm 9+ for the dashboard.

Setup has four steps: configure the deployment targets, prepare the remote host, build and deploy the service binaries, then run the bootstrap wizard (which handles PKI ceremony, TLS certificates, and initial service configuration).

```bash
git clone <repo-url> credo && cd credo

./scripts/install init      # generate .install.json (interactive — hosts, paths, services)
./scripts/install setup     # prepare remote host: directories, users, systemd units
./scripts/install           # build and deploy service binaries
./scripts/bootstrap         # PKI ceremony, TLS certificates, initial service configuration
```

See [docs/bootstrap-guide.md](docs/bootstrap-guide.md) for the full walkthrough and [docs/examples/](docs/examples/) for config file skeletons.

## Documentation

See [docs/README.md](docs/README.md) for the full documentation index, including:

- Architecture and security design
- Full bootstrap guide (manual and scripted)
- Configuration reference and example configs
- API reference for all services
- Operator hardening checklist
- Troubleshooting guide

## License

MIT
