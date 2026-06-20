# Credo Improvement Roadmap

**Date:** 2026-06-15

This document captures the full improvement roadmap for credo, including the decisions made about how to implement each item. It is intended as a working document — add comments, check off completed items, and revise as priorities change.

**Tracking:** the actionable, checkbox-style version of this roadmap lives in [`docs/roadmap/`](roadmap/) — one file per tier. Tick items off there as work completes; this file remains the narrative description of the decisions behind each item.

---

## Tier Structure

Each tier is a shippable milestone. A deployment at the end of any tier is production-worthy for its target audience. Tiers complete in order; work within a tier may proceed in parallel.

| Tier | Target audience | Gate condition |
|------|----------------|----------------|
| **Tier 1** | Any operator, any skill level | Setup completes in under 15 minutes; nothing is silently insecure out of the box |
| **Tier 2** | Small org / internal IT | Key material never persists to disk in plaintext; cert events are attributable; system survives a Shepherd restart |
| **Tier 3** | Enterprise / compliance-required | CA key never touches disk in plaintext; every security-relevant event is attributed and queryable; security team can evaluate against SOC 2 / ISO 27001 / HIPAA |

---

## Tier 1 — Any Operator, Any Skill Level

### [Setup] Restructure install / ceremony / wizard

**Decision:** Everything stays in bash. No new Rust CLI for setup. The operator flow is:

1. `git pull && cargo build`
2. `scripts/install init` — optional, interactively generates `.install.json`. See below.
3. `scripts/install` — copies built binaries to local target dir (`$TARGET_DIR`), creates service users/groups, optionally generates systemd unit files. Uses `sudo` only for the specific commands that require it (see below) — not as a blanket wrapper around the whole script.
4. `scripts/ceremony/*` — run manually, as separate standalone scripts (no orchestrator script). Recommended to run on an air-gapped machine and copy the output to `$TARGET_DIR/ca`, leaving the root key offline.
5. `scripts/bootstrap` — interactive wizard that configures and bootstraps all services.

**Directory changes:**

- `ceremony/scripts/` → `scripts/ceremony/` (scripts move; `ceremony/ca/` stays as operator data)
- `scripts/deploy` → `scripts/install` (rename; all existing functionality preserved)
- `.deploy.json` → `.install.json`
- `.deploy-local.json` → `.install-local.json`
- `.deploy-remote.json` → `.install-remote.json`

**`scripts/install init` (new subcommand)**

Interactive setup that generates `.install.json` for the operator's machine. Asks:
- Target directory (default: `/var/apps/credo`)
- Which services to install (shepherd, vigil, corgi; dashboard optional)
- Rust target (auto-detected from `rustup` or `uname -m`, offered as default)
- Whether to create service users/groups and generate systemd unit files

**User and group model**

Each service gets its own dedicated system user **and** its own dedicated group — `vigil:vigil`, `shepherd:shepherd`, `corgi:corgi` (the standard `useradd -r -U <name>` pattern). No shared `credo` group across services for internal secrets: this keeps blast radius isolated — a corgi compromise grants no group access to vigil's CA key or shepherd's JWT signing key.

Each service's own private key material stays owned by that service's own user, mode `600`, no group access (e.g., vigil's CA key is `vigil:vigil`, `600` — only the vigil process ever reads it).

**`credo-cert` group and cert store access:**

Corgi's cert store (`$TARGET_DIR/corgi/certs/`, standard `live/<certname>/` layout) is owned `corgi:credo-cert`, mode `2750` (setgid). Every consumer that needs to read cert or key material corgi manages — Shepherd, Vigil (for their own TLS identity certs on a single-host deployment), Caddy, nginx — reads directly from this store via the `credo-cert` group. There is no separate "delivery" copy step; the cert store IS the delivery point. In Tier 2, this path becomes the tmpfs mount.

Mechanism — **setgid cert store**, not group membership on corgi itself:
- `scripts/install` creates `$TARGET_DIR/corgi/certs/` owned `corgi:credo-cert`, mode `2750` (the leading `2` is the setgid bit).
- Corgi owns the directory, so it can write into it regardless of its own group membership.
- Because of the setgid bit, any file corgi creates inside that directory **automatically inherits the `credo-cert` group** — the kernel handles this at file-creation time. Corgi never needs to be a member of `credo-cert` itself, and there's no separate `chgrp` call that could be forgotten.
- `scripts/install` adds the `shepherd` and `vigil` system users to `credo-cert`. The operator adds external service users (`caddy`, `www-data`) to `credo-cert` as needed. Files are mode `640`.

**Systemd unit file generation (new)**

When requested (via `scripts/install init` or `--systemd` flag), generate `/etc/systemd/system/credo-<service>.service` files after copying binaries. Services are NOT started automatically — operator runs `systemctl enable --now credo-vigil` etc. after the wizard completes.

**Minimal sudo footprint:** binaries are staged and copied in a directory the current user owns (no `sudo` for `cp`). `sudo` is used only for: `groupadd`/`useradd`, `chmod`/`chown` to hand ownership to the service user (chmod happens *before* chown, while the current user still owns the file, so the chmod itself doesn't need `sudo`), writing unit files to `/etc/systemd/system/`, and `systemctl daemon-reload`.

Unit file template per service:
```ini
[Unit]
Description=credo <service>
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<service>
Group=<service>
WorkingDirectory=$TARGET_DIR/<service>
ExecStart=$TARGET_DIR/<service>/<service> server start
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=<service>
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$TARGET_DIR/<service>
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

No `ExecStop` line — systemd's default `KillSignal=SIGTERM` is sufficient; the credo binaries don't have a `server stop` subcommand. Shepherd and Vigil units include `SupplementaryGroups=credo-cert` so they can read the TLS identity certs corgi manages for them. Corgi's unit does **not** — it owns the cert store directory and never needs group membership to write into it.

**`scripts/bootstrap` (new)**

Interactive bash script run from the git source directory after install. Phases:

- **Phase 0:** Read `.install.json` to determine `$TARGET_DIR`. Prompt if not found.
- **Phase 1 — Ceremony:** Ask whether ceremony has been run.
  - If no: collect ceremony variables (see table below), call `scripts/ceremony/generate-openssl-cnf.sh` + `bootstrap-roots.sh` + `issue-intermediary.sh` with `--ca-dir $TARGET_DIR/ca`
  - If yes: prompt for path to existing CA output (default: `$TARGET_DIR/ca`)
- **Phase 2 — Service config:** Collect per-service values, generate `vigil.config.json`, `shepherd.config.json`, `corgi.config.json` under `$TARGET_DIR/<service>/`. Paths to CA artifacts are derived from `$TARGET_DIR/ca` automatically.
- **Phase 3 — Bootstrap:** Run bootstrap sequence (current phases 2–6).
- **Phase 4 — Verify:** Hit health endpoints, report pass/fail.

**Ceremony variables `scripts/bootstrap` collects:**

| Question | Variable | Default |
|---|---|---|
| Organization name | `ORG` | *(required)* |
| Country code | `COUNTRY` | `US` |
| Root CA common name | `ROOT_ECDSA_CN` | `{ORG} Root X1` |
| Intermediate CA common name | `INT_ECDSA_CN` | `E1` |
| PKI base URL | `PKI_BASE_URL` | `http://pki.example.com` |
| Root cert validity (days) | `ROOT_DAYS` | `3650` (10 yr) |
| Intermediate cert validity (days) | `INT_DAYS` | `730` (2 yr) |
| Root CA passphrase | *(secure prompt)* | *(required)* |

CRL validity days use ceremony script defaults silently (`ROOT_CRL_DAYS=90`, `INT_CRL_DAYS=7`).

**No logic is duplicated between bootstrap and ceremony scripts.** Bootstrap collects inputs and orchestrates; ceremony scripts perform CA operations.

---

### [Security] Vigil deny-all default

`issuancePolicy.allowedDnsSuffixes: []` currently means "issue for any domain." Flip the semantic: empty list = deny-all; explicit `"*"` = unrestricted. A misconfigured first deployment should fail loudly.

---

### [Security] Dashboard session secret startup assertion

Shepherd/Dashboard must refuse to start if the session secret matches the example value or falls below a minimum entropy threshold. Currently the doc describes the problem; the code does not enforce it.

---

### [Docs] "What you get out of the box" security narrative

Short honest document: what credo protects by default, what requires operator action, what it will never protect (hardware key binding, network isolation). Replaces the current "operator's responsibility" footnotes scattered across docs.

---

## Tier 2 — Small Org / Internal IT

### [Security] Encrypted key store + tmpfs key delivery in Corgi

Corgi writes private keys to a `tmpfs`/`ramfs` mount so they never persist to disk in plaintext and disappear on reboot. The source of truth is an **encrypted key store** on disk: key material is wrapped with a key-encryption-key (KEK) before being written. On startup, Corgi automatically decrypts and populates tmpfs — no human intervention.

KEK source is pluggable:
- TPM-sealed secret (where hardware is available)
- Env var injected by init system or secrets manager (Vault Agent, systemd `CredentialStore`, AWS Secrets Manager)
- Passphrase file at mode `0400` owned by root (weakest, still better than plaintext)

Apps like Caddy and nginx see no change — they still read a file path. Protects against cold-storage theft and disk imaging; does NOT protect against a live root attacker with memory access.

This KEK abstraction becomes the foundation for the Vault Agent integration in Tier 3.

---

### [Security] Structured audit log

Dedicated audit log (separate from request logs) covering every security-relevant event: cert issued, cert installed, account added/removed, auth failure with presented identity, assignment changed, config reloaded. Each entry is structured JSON with timestamp, actor identity URI, and outcome. Rotates; forwardable to SIEM.

---

### [Security] `insecureSkipVerify` moved to environment variable

Remove from config JSON entirely. Replace with `CREDO_INSECURE_SKIP_VERIFY=1` env var. Eliminates "copied from staging to prod" failure mode. Makes auditing 50 nodes a process environment grep rather than reading 50 JSON files.

---

### [Security] Config and key file permission enforcement at startup

Each service checks that its config file and all referenced key files have appropriate modes at startup. Wrong permissions → logged warning + refusal to start (in strict mode, configurable).

---

### [Security] `operator` role — implement or remove

`operator` currently does exactly what `readonly` does. Either define meaningful write permissions (candidate: trigger manual renewals, view full cert material, manage assignments) or remove the role. A vestigial role in a security-sensitive system is an audit liability.

---

### [Infra] SQLite as the unified state store

Move all mutable state to SQLite in a single coherent design. Scope:
- **Shepherd:** assignments, corgis inventory, accounts, CA configs, renewal jobs, refresh tokens
- **Vigil:** ACME state (orders, authorizations, challenges), issued cert log
- **Corgi:** assignment cache, local cert state

Flat JSON config files become the **seed/import format** — operators can still write a `shepherd.corgis.json` and import it, but live state lives in the database. Benefits: atomic changes, change history with timestamps, audit queries, versioned schema migrations.

---

### [Docs] Revocation workflow runbook

Step-by-step "a Corgi node is compromised right now" runbook: which commands to run, in what order, how long until all components stop trusting the revoked identity, and what happens to the certs that node was managing.

---

### [Docs] Update operator hardening doc

Incorporate tmpfs delivery, encrypted key store setup, permission enforcement, and `insecureSkipVerify` env-var change.

---

## Tier 3 — Enterprise / Compliance-Required

### [Security] HSM integration for Vigil CA key (PKCS#11)

Design already written in `docs/hsm-integration-plan.md`. Implementation: `SigningBackend` trait in Vigil, `PemFileBackend` preserving current behavior, `Pkcs11Backend` using SoftHSM2 as reference implementation (`cryptoki` crate). P-256 and P-384 required; RSA optional.

Trait abstraction means swapping SoftHSM2 for real hardware is a config change, not a code change. `signingBackend` defaults to `"pem"` — no behavior change for existing deployments.

Estimated effort: ~6 days.

---

### [Security] Hardware HSM upgrade path

Once PKCS#11 abstraction exists, document upgrade to real hardware: Nitrokey HSM 2, YubiHSM 2, network HSMs (Thales, Entrust). No code changes required — deliverable is config examples, token setup procedures, and operational runbook per device class.

---

### [Security] Vault integration guide

Two integration points to design and document:

1. **Vault as KEK source for Corgi's encrypted key store** — Vault Agent sidecar delivers the KEK at startup, keeps it rotated. Extends the Tier 2 KEK abstraction without code changes to Corgi.

2. **Vault PKI secrets engine as optional Vigil signing backend** — Vigil submits CSR to Vault; Vault returns signed cert; CA private key never touches the Vigil host. Full implementation deferred; deliverable is a design doc and integration guide.

---

### [Security] Supply chain hygiene

`cargo audit` in CI with failure on high-severity advisories. `Cargo.lock` committed and reviewed in PRs. Supply chain section in security doc covering dependency pinning rationale.

---

### [Infra] GitOps-style state management

With SQLite as state store (Tier 2), add approval and attribution layer: import git-tracked YAML/JSON into the database with diff preview and approver attribution before changes go live. Change log queryable by actor and timestamp.

---

### [Infra] SIEM integration

Document the Tier 2 audit log schema. Provide example forwarder configs for Splunk, Elastic/OpenSearch, Datadog, and syslog.

---

### [Docs] Compliance control mapping

Structured document mapping credo controls to:
- SOC 2 Type II Trust Service Criteria
- ISO 27001 Annex A controls
- HIPAA Security Rule safeguards

For each control: what credo provides natively, what requires operator configuration, what requires compensating controls elsewhere.

---

### [Docs] "Getting credo enterprise-ready" guide

Practical guide for a security or platform team: what to configure before go-live, what to integrate with (IdP, SIEM, secrets manager, HSM), what to document for auditors, which credo tier maps to which compliance posture.

---

### [Docs] Fresh security audit

Comprehensive dated security audit after Tier 1 and Tier 2 work is complete. Formal review covering threat model, cryptographic choices, auth model, key lifecycle, trust boundaries, and residual risks with explicit severity ratings. Supersedes `docs/security-critique.md`.

---

## Relationship to Existing Docs

| Existing document | Status after roadmap |
|---|---|
| `docs/hsm-integration-plan.md` | Implemented in Tier 3; superseded by implementation |
| `docs/security-critique.md` | Superseded by Tier 3 fresh security audit |
| `docs/security.md` | Updated incrementally as each tier completes |
| `docs/operator-hardening.md` | Updated at Tier 2 completion |
| `docs/bootstrap-guide.md` | Superseded by Tier 1 `scripts/install` + `scripts/bootstrap` |
| `docs/rust-audit.md` | Ongoing; items complete as refactoring continues |
