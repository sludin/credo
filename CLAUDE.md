# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`credo` is a hub-and-spoke TLS certificate management system. The main services (`shepherd`, `corgi`, `vigil`, `credo-lib`) are a Rust Cargo workspace. `dashboard` remains TypeScript/npm. `ceremony` is shell scripts.

| Package | Role | Default Port |
|---------|------|-------------|
| `shepherd` | Central coordinator (control plane) | Agent: 7010, Dashboard: 7011 |
| `corgi` | Distributed agent on each managed node | mTLS API: 7001, HTTP-01: 8080 |
| `vigil` | Private certificate authority (ACME-compatible) | 7020 |
| `ceremony` | Offline PKI ceremony scripts (root/intermediate CA generation) | — |
| `dashboard` | React+Vite frontend + Express BFF for Shepherd | 7030 |
| `credo-lib` | Shared Rust library used by all Rust services | — |

## Architecture

**Pull-based reconciliation:** Corgi periodically pulls desired assignment state from Shepherd. Shepherd never pushes to Corgi. When Shepherd is unavailable, Corgi continues operating from its local assignment cache.

**Certificate flow:**
1. Shepherd holds `ManagedAssignment` records (which cert, which corgi, which CA).
2. Shepherd runs its own ACME issuance and stores cert material in a certstore (`archive/` + `live/` layout mirroring certbot).
3. Corgi pulls assignments; if local fingerprint differs from Shepherd's `fingerprint256`, Corgi fetches updated cert material from Shepherd.
4. Corgi installs certs locally and runs configured service hooks.

**mTLS everywhere:** All inter-service communication uses mutual TLS. Shepherd's agent port validates Corgi client certificates. Vigil validates admin/shepherd client certs via user registry.

**Authentication model (Shepherd):** Two separate auth chains, both URI-SAN-only (no fingerprint or fleet fallbacks):

- **Agent port (7010, mTLS):** Corgi client cert URI SAN must match an entry in the corgis config. No match → 401.
- **Dashboard port (7011):** JWT Bearer token (ES256, 1h, issued by Shepherd) checked first; falls back to mTLS cert URI SAN lookup in `shepherd.accounts.json`. Account must have `active: true`.

## Common Commands

Rust services (shepherd, corgi, vigil, credo-lib) use Cargo:

```bash
cargo build                        # build all workspace members
cargo build --release              # optimized release build
cargo test                         # run all workspace tests
cargo test -p shepherd             # test a single package
cargo run --bin shepherd -- server start  # run without a pre-built binary
```

Each compiled service binary also accepts a `group command` structure:

```bash
./target/debug/shepherd server start     # start Shepherd
./target/debug/corgi server start        # start Corgi
./target/debug/vigil server start        # start Vigil
```

Run `<binary> --help` for groups, `<binary> <group> --help` for commands in a group.

Dashboard (TypeScript/npm) is developed from its own directory:

```bash
cd dashboard && npm run dev        # Vite dev server + BFF
cd dashboard && npm run build      # compile for production
cd dashboard && npm test           # vitest run
```

## Shared Library (`credo-lib/`)

`credo-lib` is the shared Rust crate used by all three Rust services. It exports: logging (`log`), config utilities (`config`), archive helpers (`archive`), file-policy enforcement (`file_policy`), TLS helpers (`tls`), auth primitives (`auth`), and shared types (`types`, `error`). Cargo resolves the build order automatically.

## Request Log Format

All services emit structured one-line request logs:
```
<code> <dir> <status> <method> <path> <host> <peer_ip> <uri_name> <ms>
```
Service codes: `S` = Shepherd API server, `C` = Shepherd corgi-facing server (also used by Corgi for its own logs), `F` = outbound client call, `V` = Vigil server. Direction `>` = serving inbound, `<` = making outbound call.

## Config Files

Each service loads a JSON config file (default location in its CWD):

| Service | Default config | Env override |
|---------|---------------|--------------|
| Shepherd | `shepherd.config.json` | `SHEPHERD_CONFIG_PATH` |
| Shepherd assignments | `shepherd.assignments.json` | `SHEPHERD_ASSIGNMENTS_CONFIG_PATH` |
| Shepherd corgi inventory | `shepherd.corgis.json` | set in `shepherd.config.json` → `corgisConfigPath` |
| Corgi | `corgi.config.json` | `CORGI_CONFIG_PATH` |
| Vigil | `vigil.config.json` | `VIGIL_CONFIG_PATH` |

No example config files are committed for the Rust services. See each service's `docs/config.md` for field reference.

## Agent skills

### Issue tracker

Issues live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Multi-context monorepo — one `CONTEXT.md` per package, `CONTEXT-MAP.md` at root, `docs/adr/` for system-wide decisions. See `docs/agents/domain.md`.
