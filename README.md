# credo

`credo` is a hub-and-spoke TLS certificate management system written in Rust.

- **shepherd** is the central coordinator (control plane).
- **corgi** is the distributed agent running on each managed node.
- **vigil** is the private ACME-compatible certificate authority.
- **dashboard** is the React+Vite management UI with an Express BFF.
- **ceremony** contains offline shell scripts for the initial PKI ceremony.

## Background

Credo started as an effort to monitor the health of my certificates on my various nodes. I wanted a single pane of glass that showed me everything at once. The auto-renew aspects of certbot and Caddy are great, but they did not provide the visibility and alerting that I wanted. So I wrote a script (later an agent) to monitor my certs and provide regular updates. Then I left my job at Google and had time on my hands, and Credo came from that. Is it needed? — probably not. Is it useful for me? — definitely. Is it over engineered? — oh yeah. Is it under engineered for an enterprise system? — very likely.

A secondary goal was to do as much with agentic coding as I could as a learning exercise, so this is a product of me and my junior coders Claude and Codex — whoever wasn't on a token time out.

## Goals

- Keep certificate state visible across machines.
- Centralize renewal orchestration while still allowing local actions.
- Support ACME challenge workflows (`DNS-01` and `HTTP-01`).
- Use mTLS between coordinator and nodes.
- Private keys never leave the node where they were generated.

## Architecture

### Control Plane Model

The system operates via a pull-based reconciliation model:

1. **Shepherd** holds `ManagedAssignment` records (which cert, which corgi, which CA). It runs ACME issuance and stores cert material in a certstore (`archive/` + `live/` layout mirroring certbot).
2. **Corgi** periodically pulls assignment updates from Shepherd. When the local fingerprint differs from Shepherd's, Corgi fetches updated cert material, installs it atomically, and runs configured service hooks. Private keys are generated on Corgi and **never sent to Shepherd**.
3. **Vigil** is an ACME-compatible private CA. Shepherd talks to Vigil as an ACME client over mTLS.

Shepherd never pushes config or cert material to Corgi. Corgi always pulls. When Shepherd is unavailable, Corgi continues operating from its local assignment cache.

### Ports

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Shepherd | 7010 | mTLS | Agent port — Corgi pulls assignments and delivers CSRs here |
| Shepherd | 7011 | HTTPS | Dashboard port — JWT Bearer or mTLS client cert auth |
| Corgi | 7001 | mTLS | Corgi control API |
| Corgi | 8080 | HTTP | HTTP-01 ACME challenge listener |
| Vigil | 7020 | mTLS | ACME and admin endpoints |
| Dashboard | 7030 | HTTPS | React SPA + Express BFF |

### mTLS and Authentication

mTLS is used on all inter-service paths. Authentication uses URI-SAN-only matching — no fingerprint or fleet-wide fallbacks.

**Agent port (7010):** Corgi client cert URI SAN must match an entry in `shepherd.corgis.json`.

**Dashboard port (7011):** JWT Bearer token (ES256, 1h expiry) checked first; falls back to mTLS cert URI SAN lookup in `shepherd.accounts.json`. Account must have `active: true`. Three roles: `readonly < operator < admin`.

## Repository Layout

```text
credo/
├── Cargo.toml           # workspace root
├── credo-lib/           # shared Rust library (auth, tls, archive, types, …)
├── shepherd/            # central coordinator
├── corgi/               # distributed node agent
├── vigil/               # private ACME-compatible CA
├── credo-test/          # integration test harness
├── dashboard/           # React+Vite SPA + Express BFF (TypeScript/npm)
├── ceremony/            # offline PKI ceremony scripts (run once, air-gapped)
├── wizard/              # interactive bootstrap wizard
├── tools/               # gen-fixtures and other dev tools
└── docs/                # architecture, bootstrap guide, config reference, ADRs
```

## Requirements

### Rust services (shepherd, corgi, vigil, credo-lib)

- Rust toolchain (stable) — install via [rustup](https://rustup.rs)

### Dashboard (TypeScript/npm)

- Node.js 18+
- npm 9+ (or compatible)

## Building

```bash
# Build all Rust workspace members
cargo build

# Optimized release build
cargo build --release

# Run all workspace tests
cargo test

# Test a single package
cargo test -p shepherd
```

## Running Services

Each compiled binary uses a `group command` structure:

```bash
./target/debug/shepherd server start
./target/debug/corgi server start
./target/debug/vigil server start
```

Or run without a pre-built binary:

```bash
cargo run --bin shepherd -- server start
cargo run --bin corgi -- server start
cargo run --bin vigil -- server start
```

Run `<binary> --help` for command groups, `<binary> <group> --help` for commands within a group.

### Dashboard

```bash
cd dashboard
npm install
npm run dev        # Vite dev server + BFF
npm run build      # compile for production
npm test           # vitest run
```

## Configuration

Each service loads a JSON config file from its working directory (or from the path set by an environment variable):

| Service | Default config | Env override |
|---------|---------------|--------------|
| Shepherd | `shepherd.config.json` | `SHEPHERD_CONFIG_PATH` |
| Shepherd assignments | `shepherd.assignments.json` | `SHEPHERD_ASSIGNMENTS_CONFIG_PATH` |
| Shepherd corgi inventory | `shepherd.corgis.json` | set in `shepherd.config.json` → `corgisConfigPath` |
| Corgi | `corgi.config.json` | `CORGI_CONFIG_PATH` |
| Vigil | `vigil.config.json` | `VIGIL_CONFIG_PATH` |

Config files use camelCase JSON and support `$VAR` interpolation, a `vars` block, and `includes` arrays for splitting secrets from non-secrets. Several config files are hot-reloaded based on mtime changes with no service restart required. See `docs/config-overview.md` for the full reference.

## Bootstrap

Before services can communicate, a PKI trust chain must exist and each service must have a valid TLS certificate signed by that chain. Bootstrap runs once in six phases.

**TL;DR — use the wizard for single-machine or simple topologies:**

```bash
cd wizard
./bootstrap-wizard
```

For multi-machine topologies or precise control, follow the manual bootstrap guide in `docs/bootstrap-guide.md`.

### PKI Ceremony (Phase 1, required for all paths)

Run on an air-gapped machine:

```bash
cd ceremony
cp ca-vars.env.example ca-vars.env   # edit with your CA details
./scripts/generate-openssl-cnf.sh --env-file ca-vars.env
./scripts/bootstrap-roots.sh         # root CA key + self-signed cert
./scripts/issue-intermediary.sh      # ECDSA intermediate CA
```

Build and distribute the CA trust bundle:

```bash
cat ca/root-ecdsa/certs/root-ecdsa.cert.pem \
    ca/int-ecdsa/certs/int-ecdsa.cert.pem \
    > ca/credo-catrust.pem
```

`credo-catrust.pem` goes to every machine. The root CA key stays offline.

## Certificate Lifecycle

1. An operator adds a `ManagedAssignment` to `shepherd.assignments.json` (hot-reloaded; no restart).
2. Corgi's sync loop detects a fingerprint mismatch or missing cert and sends a CSR to Shepherd.
3. Shepherd drives ACME issuance against the configured CA (Vigil, Let's Encrypt, or any ACME-compatible CA), storing the result in its certstore.
4. On the next sync, Corgi fetches the cert material, verifies it against the local private key, installs it atomically, and runs configured service hooks.

## Terminology

- **flock** — the full set of certificates managed by the system.
- **shepherd** — central coordination service.
- **corgi** — distributed local management agent.
- **vigil** — private certificate authority.
- **ceremony** — offline PKI ceremony for generating the root and intermediate CA.

## License

MIT
