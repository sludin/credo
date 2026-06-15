# Credo Improvement Roadmap

**Date:** 2026-06-15  
**Status:** Approved

---

## Overview

This document defines the improvement roadmap for credo, organized into three tiers. Each tier is a shippable milestone — a deployment at the end of any tier is production-worthy for its target audience.

Tiers must generally complete in order. A Tier 3 compliance narrative that points to open Tier 1 security gaps is worse than no narrative. Work within a tier may proceed in parallel.

Each item carries a theme tag: **[Setup]**, **[Security]**, **[Docs]**, **[Infra]**.

---

## Tier Structure

| Tier | Target audience | Gate condition |
|------|----------------|----------------|
| **Tier 1** | Any operator, any skill level | Setup completes in under 15 minutes; nothing is silently insecure out of the box |
| **Tier 2** | Small org / internal IT | Key material never persists to disk in plaintext; cert events are attributable; system survives a Shepherd restart without disruption |
| **Tier 3** | Enterprise / compliance-required | CA key never touches disk in plaintext; every security-relevant event is attributed and queryable; a security team can evaluate credo against SOC 2, ISO 27001, or HIPAA and get clear answers |

---

## Tier 1 — Any Operator, Any Skill Level

### [Setup] Collapse the bootstrap sequence

The current 6-phase, multi-machine bootstrap has too many "go to this machine, run this, come back" coordination steps. Goal: a single `credo init` command that scaffolds all config files with safe defaults, runs the PKI ceremony in-process for single-machine deployments, and produces a running system. Multi-machine topology becomes an explicit flag, not the assumed path. Time-to-running system: under 15 minutes.

### [Setup] Config scaffolding with required-vs-optional clarity

Too many JSON files with undocumented required fields. `credo init` should generate starter configs where optional fields are visually distinct (grouped, commented, or separated). The minimum viable config for each service should be 5–10 fields, not 30.

### [Setup] Single-binary CA option (`credo ca init`)

The PKI ceremony is the biggest single coordination cost. Provide a `credo ca init` subcommand that runs the ceremony in-process — no shell scripts, no OpenSSL dependency — for non-air-gap deployments. The offline ceremony remains available for operators who need it, but is no longer the only path.

### [Security] Vigil deny-all default

`issuancePolicy.allowedDnsSuffixes: []` currently means "issue for any domain." Flip the semantic: an empty list means deny-all; an explicit `"*"` opts into unrestricted issuance. A misconfigured first deployment should fail loudly, not silently sign anything. Secure-by-default means the safe configuration requires no action; the unsafe configuration requires explicit action.

### [Security] Dashboard session secret startup assertion

A placeholder session secret allows session forgery. Shepherd/Dashboard must refuse to start if the session secret matches the example value or falls below a minimum entropy threshold. The current state — where the doc describes the problem and the code does not enforce it — is a gap that will never close on its own.

### [Docs] "What you get out of the box" security narrative

A short, honest document covering: what credo protects by default, what requires explicit operator configuration, and what it will never protect (hardware key binding, network-level isolation). Replaces the current "operator's responsibility" footnotes scattered across multiple docs. Written for an operator evaluating whether credo is appropriate for their environment before installing it.

---

## Tier 2 — Small Org / Internal IT

### [Security] Encrypted key store + tmpfs delivery in Corgi

Corgi writes private keys to a memory-backed filesystem mount (`tmpfs`/`ramfs`) so keys are never on persistent disk in plaintext and disappear on reboot. The source of truth is an **encrypted key store** on disk: raw key material is wrapped with a key-encryption-key (KEK) before being written to persistent storage.

On startup, Corgi automatically decrypts the store and populates tmpfs — no human intervention. The KEK source is pluggable:
- TPM-sealed secret (where hardware is available)
- Env var injected by the init system or a secrets manager (Vault Agent, systemd `CredentialStore`, AWS Secrets Manager)
- A local passphrase file at mode `0400` owned by root (weakest option, still better than plaintext)

Apps like Caddy and nginx see no change — they still read a file path. The design clearly documents what this protects against (cold-storage theft, disk imaging) and what it does not (live root attacker with memory access).

This KEK abstraction also becomes the foundation for the Vault Agent integration in Tier 3.

### [Security] Structured audit log

A dedicated audit log, separate from request logs, covering every security-relevant event: cert issued, cert installed, account added/removed, auth failure (with presented identity), assignment changed, config reloaded. Each entry is structured (JSON), carries a timestamp, actor identity URI, and outcome. The log rotates and can be forwarded to a SIEM. This closes the single largest compliance gap identified in `docs/security-critique.md`.

### [Security] `insecureSkipVerify` moved to environment variable

Remove `insecureSkipVerify` from config JSON entirely. Replace with an environment variable (`CREDO_INSECURE_SKIP_VERIFY=1`) that requires a conscious, per-process decision at startup. Eliminates the "copied from staging to prod" failure mode. Makes auditing 50 nodes a grep of process environments rather than manual inspection of 50 JSON files.

### [Security] Config and key file permission enforcement at startup

Each service checks that its config file and all referenced key files have appropriate modes at startup. Wrong permissions result in a logged warning and refusal to start (in strict mode, configurable). Closes the gap where `vigil.config.json` at `0644` is currently accepted without complaint.

### [Security] `operator` role — implement or remove

Current state: `operator` does exactly what `readonly` does. Either define meaningful write permissions for `operator` (candidate: trigger manual renewals, view full cert material, manage assignments) or remove the role entirely. A vestigial role in a security-sensitive system is an audit liability: auditors will ask what it can do, and "nothing" is the wrong answer.

### [Infra] SQLite as the unified state store

Rather than piecemeal persistence, move all mutable state to SQLite in a single coherent design. Scope:
- **Shepherd:** assignments, corgis inventory, accounts, CA configs, renewal jobs, refresh tokens
- **Vigil:** ACME state (orders, authorizations, challenges), issued cert log
- **Corgi:** assignment cache, local cert state

Flat JSON config files become the **seed/import format** — operators can still write a `shepherd.corgis.json` and import it, but the live state is in the database. Benefits: atomic changes (no partial writes), change history with timestamps, audit queries ("show me all certs issued in the last 30 days"), schema migrations are versioned. This directly addresses the "flat ACL files invisible to change management" gap from `docs/security-critique.md`.

### [Docs] Revocation workflow runbook

A step-by-step "a Corgi node is compromised right now" runbook: which commands to run, in what order, how long until all components stop trusting the revoked identity, and what happens to the certs that node was managing. This is the scenario that keeps operators up at night and currently has no documented answer in credo.

### [Docs] Update operator hardening doc

Incorporate tmpfs delivery, encrypted key store setup, permission enforcement, and `insecureSkipVerify` env-var change. The current `docs/operator-hardening.md` is good but will be stale after Tier 2 work completes.

---

## Tier 3 — Enterprise / Compliance-Required

### [Security] HSM integration for Vigil CA key (PKCS#11)

The design is already written in `docs/hsm-integration-plan.md`. This is the implementation: a `SigningBackend` trait in Vigil, a `PemFileBackend` preserving current behavior, and a `Pkcs11Backend` using SoftHSM2 as the reference implementation. The `cryptoki` crate provides the PKCS#11 binding. P-256 and P-384 key types are required; RSA follows if needed.

The trait abstraction means swapping SoftHSM2 for real hardware is a config change, not a code change. `signingBackend` defaults to `"pem"` — no change in behavior for existing deployments.

Estimated effort: ~6 days (per existing plan).

### [Security] Hardware HSM upgrade path

Once the PKCS#11 abstraction exists, document the upgrade path to real hardware: Nitrokey HSM 2, YubiHSM 2, and network HSMs (Thales, Entrust). No code changes required after the abstraction layer — the deliverable is config examples, token setup procedures, and an operational runbook for each device class.

### [Security] Vault integration guide

Two integration points to design and document:

1. **Vault as KEK source for Corgi's encrypted key store** — Vault Agent runs as a sidecar on each Corgi node, delivers the KEK at startup, and keeps it rotated. Keys populate tmpfs automatically. This extends the Tier 2 KEK abstraction without code changes to Corgi.

2. **Vault PKI secrets engine as an optional Vigil signing backend** — Vigil submits a CSR to Vault; Vault returns the signed cert; the CA private key never touches the Vigil host. This is the strongest available protection for the CA key short of a hardware HSM, for orgs already running Vault. Full implementation is deferred; the deliverable is a design doc and integration guide.

### [Security] Supply chain hygiene

`cargo audit` added to CI with failure on high-severity advisories. Lock file policy: `Cargo.lock` committed, reviewed in PRs, updated deliberately. A supply chain section added to the security doc covering dependency pinning rationale and what a compromised crate dependency means for a system managing TLS infrastructure.

### [Infra] GitOps-style state management

With SQLite as the state store (Tier 2), this tier adds an approval and attribution layer: import git-tracked YAML/JSON into the database with diff preview and approver attribution before changes go live. Changes to accounts, CA configs, and corgis inventory are reviewed before application; the change log is queryable by actor and timestamp. Closes the "ACL changes are invisible to change management" gap.

### [Infra] SIEM integration

Document the Tier 2 audit log schema and provide example forwarder configs for common SIEM targets: Splunk, Elastic/OpenSearch, Datadog, and syslog. The structured audit log is the foundation; this tier makes it pluggable into existing enterprise security infrastructure.

### [Docs] Compliance control mapping

A structured document mapping credo's controls to:
- SOC 2 Type II Trust Service Criteria
- ISO 27001 Annex A controls
- HIPAA Security Rule safeguards (Administrative, Physical, Technical)

For each control: what credo provides natively, what requires operator configuration, and what requires compensating controls elsewhere in the operator's environment. This is the artifact a security team uses during a vendor assessment or internal audit.

### [Docs] "Getting credo enterprise-ready" guide

A practical guide for a security or platform team evaluating credo: what to configure before go-live, what to integrate with (IdP, SIEM, secrets manager, HSM), what to document for auditors, and which credo tier maps to which compliance posture. Written for the security team lead evaluating adoption, not the operator doing installation.

### [Docs] Fresh security audit

A comprehensive, dated security audit of credo after Tier 1 and Tier 2 work is complete. This is not an incremental update to `docs/security-critique.md` — it is a formal review of the then-current system covering: threat model, cryptographic choices, auth model, key lifecycle, trust boundaries, and residual risks with explicit severity ratings. It supersedes `security-critique.md` as the primary security reference document.

---

## Relationship to Existing Docs

| Existing document | Status after roadmap |
|---|---|
| `docs/hsm-integration-plan.md` | Implemented in Tier 3; superseded by implementation |
| `docs/security-critique.md` | Superseded by Tier 3 fresh security audit |
| `docs/security.md` | Updated incrementally as each tier completes |
| `docs/operator-hardening.md` | Updated at Tier 2 completion |
| `docs/bootstrap-guide.md` | Superseded by Tier 1 `credo init` flow |
| `docs/rust-audit.md` | Ongoing; items complete as refactoring continues |
