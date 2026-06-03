# Documentation Plan

**Date:** 2026-06-03

## Stability Assessment

The codebase is ready for thorough documentation. Key evidence:

- The TypeScript → Rust migration is functionally **complete**. Shepherd, Corgi, and Vigil all have full Rust source trees; TypeScript versions are in `/deprecated/`.
- Only **2 TODOs** in the entire codebase — both in Vigil's ACME state (`vigil/src/acme.rs:9`, `vigil/src/state.rs:25`), both known planned limitations (in-memory ACME state, SQLite persistence planned).
- The config audit (`.scratch/config-audit/`) is a completed analysis, not unresolved work.
- The pull-based reconciliation architecture is stable.

**Known limitations to note in docs:**
- Vigil's ACME state is in-memory only; a restart loses orders/authzs.
- No `.example.json` config files exist for the Rust services (Shepherd, Corgi, Vigil).
- Dashboard is intentionally still TypeScript.

## What to Document

### 1. Config Reference + Example Files (highest priority)

Each Rust service has a `config.rs` as the authoritative schema. No operator-facing reference exists yet.

Deliverables:
- `shepherd/docs/config.md` — all fields, types, defaults, security notes
- `corgi/docs/config.md`
- `vigil/docs/config.md`
- Example `.json` files for each service derived from `config.rs` defaults

### 2. Operator Hardening Guide

The config audit already identified the critical settings operators must change from defaults. Needs reformatting into a deployment checklist:

- `auth.identityOnly: true` on Shepherd (fingerprint/fleet fallbacks)
- `auth.sessionSecret` replacement on Dashboard
- `issuancePolicy.allowedDnsSuffixes` on Vigil (empty = no enforcement)
- `alerts[].secure: true` on Shepherd SMTP
- Interface binding (`bind` defaults to `0.0.0.0` on most services)

Deliverable: `docs/operator-hardening.md`

### 3. API Endpoint Reference

Routes are stable but undocumented. Source files:
- Shepherd agent-facing: `shepherd/src/routes_corgi.rs`
- Shepherd dashboard-facing: `shepherd/src/routes_api.rs`
- Corgi control API + HTTP-01: `corgi/src/routes.rs`
- Vigil ACME + admin: `vigil/src/routes.rs`

Deliverables:
- `shepherd/docs/api.md`
- `corgi/docs/api.md`
- `vigil/docs/api.md`

### 4. Architecture Narrative

`CLAUDE.md` covers the architecture concisely. A fuller narrative for new operators:

- Certificate lifecycle: Shepherd issues → Corgi pulls → hooks run
- mTLS bootstrap flow: ceremony → vigil → shepherd → corgi
- RBAC identity resolution order and strict mode
- Failure modes and offline behavior

Deliverable: `docs/architecture.md`

## Recommended Order

1. Config reference + example files — most immediately useful for operators
2. Hardening guide — reformats completed audit work, low effort
3. API endpoint reference — routes are stable, mechanical to document
4. Architecture narrative — expands on existing CLAUDE.md content
