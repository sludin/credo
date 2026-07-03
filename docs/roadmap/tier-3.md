# Tier 3 — Enterprise / Compliance-Required

**Gate condition:** CA key never touches disk in plaintext; every security-relevant event is
attributed and queryable; a security team can evaluate credo against SOC 2, ISO 27001, or HIPAA and
get clear answers.

Depends on Tier 1 and Tier 2 being complete — a compliance narrative that points to open Tier 1
security gaps is worse than no narrative.

---

## [Security] HSM integration for Vigil CA key (PKCS#11)

Design already written in full: `docs/hsm-integration-plan.md`. This item is the implementation.

- [ ] Add `SigningBackend` trait in `vigil/src/ca.rs`:
  ```rust
  pub trait SigningBackend: Send + Sync {
      fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
      fn sig_alg_oid(&self) -> &'static str;
      fn sig_alg_identifier_der(&self) -> Vec<u8>;
  }
  ```
- [ ] Implement `PemFileBackend` wrapping the current `CaSigningKey` logic — non-breaking, keeps
  existing behavior as default.
- [ ] Implement `Pkcs11Backend` using the `cryptoki` crate, with SoftHSM2 as the reference
  implementation (`/usr/lib/softhsm/libsofthsm2.so`). Connect to token slot, authenticate with PIN,
  locate key by `CKA_LABEL`, perform `C_Sign`. P-256 and P-384 required (`CKM_ECDSA` with
  SHA-256/SHA-384); RSA optional/follow-on.
- [ ] Move `AppState`'s key handling from per-request disk read to
  `Arc<dyn SigningBackend>` initialized once at startup.
- [ ] Update the 3 call sites: `vigil/src/ca.rs` `sign_csr` (~line 471), `vigil/src/pki_wire.rs`
  OCSP signing (~line 175), `vigil/src/pki_wire.rs` CRL signing (~line 243). Each becomes
  `state.signing_backend.sign(&tbs)?`.
- [ ] Add config (`vigil/src/config.rs`):
  ```json
  "signingBackend": "pem",
  "pkcs11": {
    "libraryPath": "/usr/lib/softhsm/libsofthsm2.so",
    "tokenLabel": "vigil-ca",
    "pin": "${VIGIL_HSM_PIN}",
    "keyLabel": "int-ecdsa"
  }
  ```
  `signingBackend` defaults to `"pem"` — zero behavior change for existing deployments.
- [ ] Add `cryptoki` crate dependency (SoftHSM2 itself is an operator-installed system package, not
  a Rust dependency — `apt install softhsm2` / `brew install softhsm`).
- [ ] Update docs: `docs/security.md` (replace "unencrypted PEM file" language, describe both
  backends, explain hardware upgrade path), `docs/operator-hardening.md` (SoftHSM2 setup
  procedure: install, initialize token, import/generate key, configure Vigil),
  `docs/security-critique.md` (mark HSM showstopper item addressed).
- [ ] Note what does **not** change: ceremony scripts still generate PEM keys — operators use
  `softhsm2-util --import` after the ceremony; root CA offline storage is unchanged; Shepherd and
  Corgi are unaffected, change is entirely within Vigil.
- [ ] Effort estimate (from the existing plan): trait + `PemFileBackend` 1 day, `Pkcs11Backend`
  2–3 days, `AppState`/call-site updates 0.5 days, config/startup wiring 0.5 days, integration
  testing with SoftHSM2 1 day, docs 0.5 days. **Total ~6 days.**

---

## [Security] Hardware HSM upgrade path

- [ ] Once the PKCS#11 abstraction above exists, document the upgrade to real hardware: Nitrokey
  HSM 2, YubiHSM 2, network HSMs (Thales, Entrust). No code changes required — deliverable is
  config examples, token setup procedures, and an operational runbook per device class.

---

## [Security] Vault integration guide

Two integration points, both design+guide only (no full implementation) unless an org actively
needs it:

- [ ] **Vault Agent as KEK source for Corgi's encrypted key store** (extends [[tier-2.md]]'s KEK
  abstraction with zero Corgi code changes — Vault Agent sidecar delivers the KEK at startup, keeps
  it rotated, keys populate tmpfs automatically as before).
- [ ] **Vault PKI secrets engine as an optional Vigil signing backend** — Vigil submits a CSR to
  Vault, Vault returns the signed cert, CA private key never touches the Vigil host. Strongest
  available protection for the CA key short of a hardware HSM, for orgs already running Vault.
  Costs called out in `docs/hsm-integration-plan.md`: Vault becomes a hard runtime dependency
  (Vigil can't sign if Vault is unreachable), higher operational complexity, requires reworking
  cert construction around CSR-in/cert-out, ~3–4× the effort of the PKCS#11 path. Implement as a
  second `SigningBackend` once the trait exists.

---

## [Security] Supply chain hygiene

- [ ] Add `cargo audit` to CI, fail build on high-severity advisories.
- [ ] `Cargo.lock` committed and reviewed in PRs as policy.
- [ ] Add a supply-chain section to `docs/security.md` covering dependency pinning rationale and
  what a compromised crate dependency means for a system managing TLS infrastructure.

---

## [Infra] GitOps-style state management

- [ ] Built on top of [[tier-2.md]]'s SQLite state store: add an approval/attribution layer —
  import git-tracked YAML/JSON into the database with diff preview and approver attribution before
  changes go live.
- [ ] Changes to accounts, CA configs, and corgis inventory are reviewed before application.
- [ ] Change log queryable by actor and timestamp.
- [ ] Closes the "ACL changes are invisible to change management" gap from
  `docs/security-critique.md`.

---

## [Infra] SIEM integration

- [ ] Document the Tier 2 structured audit log schema.
- [ ] Provide example forwarder configs: Splunk, Elastic/OpenSearch, Datadog, syslog.

---

## [Docs] Compliance control mapping

- [ ] Map credo's controls to:
  - SOC 2 Type II Trust Service Criteria
  - ISO 27001 Annex A controls
  - HIPAA Security Rule safeguards (Administrative, Physical, Technical)
- [ ] For each control: what credo provides natively, what requires operator configuration, what
  requires compensating controls elsewhere in the operator's environment.
- [ ] This is the artifact a security team uses during a vendor assessment or internal audit.

---

## [Docs] "Getting credo enterprise-ready" guide

- [ ] Practical guide for a security/platform team evaluating credo: what to configure before
  go-live, what to integrate with (IdP, SIEM, secrets manager, HSM), what to document for auditors,
  which credo tier maps to which compliance posture. Written for the team lead evaluating adoption,
  not the operator doing installation.

---

## [Docs] Fresh security audit

- [ ] Comprehensive, dated security audit of credo after Tier 1 and Tier 2 are complete. Not an
  incremental update — a formal review covering threat model, cryptographic choices, auth model,
  key lifecycle, trust boundaries, residual risks with explicit severity ratings.
- [ ] Supersedes `docs/security-critique.md` as the primary security reference document.

---

## Relationship to existing docs touched by this tier

| Existing document | Status after Tier 3 |
|---|---|
| `docs/hsm-integration-plan.md` | Implemented; superseded by the implementation itself |
| `docs/security-critique.md` | Superseded entirely by the fresh security audit |
| `docs/security.md` | Updated for HSM backend, supply chain section |
| `docs/archive/rust-audit.md` | Ongoing; items complete as refactoring continues alongside this tier |
