# Tier 2 — Small Org / Internal IT

**Gate condition:** key material never persists to disk in plaintext; cert events are attributable;
system survives a Shepherd restart without disruption.

Depends on Tier 1 being complete (in particular, the `credo-cert` group / setgid delivery directory
mechanism from [[tier-1.md]], which this tier's tmpfs delivery item builds on).

---

## [Security] Encrypted key store + tmpfs key delivery in Corgi

User-driven correction from the original design: tmpfs alone is insufficient because keys can't be
regenerated on reboot without human intervention — there must be an encrypted store backing it.

- [ ] Corgi writes private keys to a `tmpfs`/`ramfs` mount so they never persist to disk in
  plaintext and disappear on reboot.
- [ ] Source of truth is an **encrypted key store** on disk: key material is wrapped with a
  key-encryption-key (KEK) before being written.
- [ ] On startup, Corgi automatically decrypts the store and populates tmpfs — **no human
  intervention required**.
- [ ] KEK source is pluggable (design for at least these three, even if only one ships first):
  - TPM-sealed secret (where hardware is available)
  - Env var injected by init system or secrets manager (Vault Agent, systemd `CredentialStore`,
    AWS Secrets Manager) — this is the extension point [[tier-3.md]]'s Vault Agent integration
    plugs into without further Corgi code changes
  - Passphrase file, mode `0400`, root-owned (weakest option, still strictly better than plaintext)
- [ ] Apps like Caddy and nginx see no behavior change — they still read a file path. Delivery to
  those external services uses the `credo-cert` group + setgid directory mechanism from Tier 1.
- [ ] Document explicitly what this protects against (cold-storage theft, disk imaging) and what it
  does **not** (a live root attacker with memory access) — this honesty matters for the Tier 3
  compliance mapping later.

---

## [Security] Structured audit log

- [ ] Add a dedicated audit log, separate from the existing one-line request logs described in
  `CLAUDE.md`. Covers every security-relevant event: cert issued, cert installed, account
  added/removed, auth failure (with presented identity), assignment changed, config reloaded.
- [ ] Each entry is structured JSON: timestamp, actor identity URI, outcome.
- [ ] Log rotates and is forwardable to a SIEM (sets up [[tier-3.md]]'s SIEM integration item).
- [ ] This closes the single largest compliance gap called out in `docs/security-critique.md`.

---

## [Security] `insecureSkipVerify` moved to environment variable

- [ ] Remove `insecureSkipVerify` from config JSON entirely (currently `cas[].insecureSkipVerify`
  and `corgis[].insecureSkipVerify` per `docs/security.md`).
- [ ] Replace with an environment variable, e.g. `CREDO_INSECURE_SKIP_VERIFY=1`, requiring a
  conscious per-process decision at startup.
- [ ] Eliminates the "copied from staging to prod" failure mode — auditing 50 nodes becomes a
  process-environment grep instead of reading 50 JSON files.

---

## [Security] Config and key file permission enforcement at startup

- [ ] Each service checks its own config file and all referenced key files for correct mode at
  startup.
- [ ] Wrong permissions → logged warning, and refusal to start in strict mode (configurable).
- [ ] Closes the gap noted in `docs/security.md` Known Weaknesses #6 — currently `vigil.config.json`
  at `0644` is accepted without complaint.

---

## [Security] `operator` role — implement or remove

- [ ] Decide: either give `operator` meaningful write permissions distinct from `readonly`
  (candidate scope: trigger manual renewals, view full cert material, manage assignments), or
  remove the role entirely.
- [ ] Currently (`docs/security.md` RBAC table) `operator` does exactly what `readonly` does — a
  vestigial role in a security-sensitive system is an audit liability ("what can this role do?" /
  "nothing" is the wrong answer in a compliance review).

---

## [Infra] SQLite as the unified state store

User-driven correction from the original design: don't do this piecemeal (e.g. just Vigil ACME
state) — unify all mutable state into one coherent SQLite design across all three services.

- [ ] **Shepherd**: assignments, corgis inventory, accounts, CA configs, renewal jobs, refresh
  tokens.
- [ ] **Vigil**: ACME state (orders, authorizations, challenges — currently in-memory only per
  `docs/security.md` Known Weaknesses #8, lost on restart), issued cert log.
- [ ] **Corgi**: assignment cache, local cert state.
- [ ] Flat JSON config files become the **seed/import format** — operators can still write
  `shepherd.corgis.json` and import it, but live state lives in the database.
- [ ] Benefits to capture in the design: atomic changes (no partial writes), change history with
  timestamps, audit queries ("certs issued in the last 30 days"), versioned schema migrations.
- [ ] Directly addresses the "flat ACL files invisible to change management" gap from
  `docs/security-critique.md`, and is the foundation [[tier-3.md]]'s GitOps approval/attribution
  layer is built on top of.

---

## [Docs] Revocation workflow runbook

- [ ] Write the step-by-step "a Corgi node is compromised right now" runbook: which commands to
  run, in what order, how long until all components stop trusting the revoked identity, and what
  happens to the certs that node was managing. No documented answer exists today.

---

## [Docs] Update operator hardening doc

- [ ] Incorporate tmpfs delivery + encrypted key store setup, permission enforcement, and the
  `insecureSkipVerify` env-var change into `docs/operator-hardening.md` (will be stale once the
  above ships).

---

## Relationship to existing docs touched by this tier

| Existing document | Status after Tier 2 |
|---|---|
| `docs/security-critique.md` | Largest gaps (audit log, flat ACL files) addressed; not yet superseded — that happens in Tier 3 |
| `docs/security.md` | Known Weaknesses #1 (unencrypted keys), #4 (`insecureSkipVerify`), #6 (no permission enforcement), #8 (in-memory ACME state) all addressed; update the table |
| `docs/operator-hardening.md` | Updated per the item above |
