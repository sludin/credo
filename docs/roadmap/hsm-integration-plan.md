# Software HSM Integration Plan

This document covers the plan for adding software HSM support for Vigil's intermediate CA private key, addressing the key-on-disk concern identified in [security-critique.md](security-critique.md).

---

## What a Software HSM Provides

A software HSM (the reference implementation is [SoftHSM2](https://www.opendnssec.org/softhsm/), from the OpenDNSSEC project) changes the key storage model in the following ways:

**Real gains:**
- The private key is no longer a plaintext PEM file — it lives in an AES-256 encrypted token database
- All signing operations go through the PKCS#11 interface; the raw key bytes are never returned to the application
- Satisfies "PKCS#11 key storage" checklist items for SOC 2, HIPAA, ISO 27001, and most PCI-DSS assessments
- Establishes the right operational pattern — the PKCS#11 interface is identical to what a hardware HSM exposes, so this work doubles as the hardware migration path: swap the library path and the token, keep everything else

**What it does NOT provide:**
- Hardware-bound protection: a root attacker can still copy the SoftHSM2 token database and the PIN, or dump process memory during a signing operation
- FIPS 140-2 Level 3 validation (required for FedRAMP High, root CAs in public WebPKI)
- Tamper evidence

**Honest framing:** Software HSM clears the audit objection for roughly 80% of enterprise deployments — SOC 2, HIPAA, ISO 27001, most PCI-DSS. It won't satisfy FedRAMP High or payment-network root CA requirements. For an internal infrastructure PKI, it is a credible and defensible control.

---

## Alternative: HashiCorp Vault PKI

For organizations that already run Vault, a stronger option exists: use Vault's PKI secrets engine as a signing oracle. Vigil submits a CSR to Vault; Vault returns the signed cert. The CA private key lives entirely outside Vigil's process and host.

**Gains over SoftHSM2:**
- CA private key is not on the Vigil host at all
- Vault provides built-in audit logging of every signing operation — every cert issuance is attributed and timestamped
- Vault has a hardware HSM backend, providing a further upgrade path
- Centralized key management across the organization

**Costs:**
- Vault becomes a hard runtime dependency — Vigil cannot sign certs if Vault is unreachable
- Significantly higher operational complexity
- Requires reworking cert construction around Vault's CSR-in / cert-out model
- Estimated effort: 3–4× more than the PKCS#11 path

The plan below implements SoftHSM2/PKCS#11. The Vault path is the right answer for organizations already running Vault and should be implemented as a second backend once the abstraction layer exists.

---

## Current Code Surface

Vigil's CA key usage is small and well-isolated. There is no abstraction layer today — the code is tightly coupled to concrete Rust types:

**`vigil/src/ca.rs`**
- `CaSigningKey` enum (lines 185–189): 3 variants — `EcdsaP256`, `EcdsaP384`, `Rsa`
- `impl CaSigningKey` (lines 191–229): `sign()`, `sig_alg_oid()`, `sig_alg_identifier_der()` methods
- `load_signing_key()` (lines 232–256): loads key from PEM file, returns `CaSigningKey`

**`vigil/src/pki_wire.rs`**
- OCSP response signing (lines 175–177, 207)
- CRL signing (lines 243–245, 274)

**Key call pattern at all 3 sites:**
```rust
let key_pem = std::fs::read_to_string(&config.ca_ecdsa_intermediate_key_path)?;
let signing_key = load_signing_key(&key_pem)?;
let sig_bytes = signing_key.sign(&tbs)?;
```

The key is loaded fresh from disk on every signing operation. `AppState` stores only the config path, not the key itself.

**Total lines touching key material: ~65, across 2 files.**

---

## Implementation Plan

### Step 1 — Add a `SigningBackend` trait

In `vigil/src/ca.rs`, replace the `CaSigningKey` enum with a trait:

```rust
pub trait SigningBackend: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn sig_alg_oid(&self) -> &'static str;
    fn sig_alg_identifier_der(&self) -> Vec<u8>;
}
```

Implement `PemFileBackend` that wraps the existing `CaSigningKey` logic — this keeps the current behavior as the default and makes the refactor non-breaking.

### Step 2 — Implement `Pkcs11Backend`

Add a `Pkcs11Backend` struct using the [`cryptoki`](https://crates.io/crates/cryptoki) crate (the most actively maintained Rust PKCS#11 binding):

- Connect to the PKCS#11 library (SoftHSM2: `/usr/lib/softhsm/libsofthsm2.so`)
- Open the named token slot, authenticate with PIN
- Locate the key by label (`CKA_LABEL`)
- Perform `C_Sign` for each signing request

Support P-256 and P-384 key types (PKCS#11 mechanisms `CKM_ECDSA` with SHA-256/SHA-384). RSA support can follow if needed.

### Step 3 — Store backend in `AppState`

Change `AppState` to hold `Arc<dyn SigningBackend>` initialized once at startup rather than loading the key per-request. This also eliminates the per-request disk read.

### Step 4 — Update call sites (3 locations)

- `vigil/src/ca.rs:471–476` (`sign_csr`)
- `vigil/src/pki_wire.rs:175–177` (OCSP)
- `vigil/src/pki_wire.rs:243–245` (CRL)

Each becomes: `state.signing_backend.sign(&tbs)?`

### Step 5 — Update config

Add to `vigil/src/config.rs`:

```json
"signingBackend": "pem",
"pkcs11": {
  "libraryPath": "/usr/lib/softhsm/libsofthsm2.so",
  "tokenLabel": "vigil-ca",
  "pin": "${VIGIL_HSM_PIN}",
  "keyLabel": "int-ecdsa"
}
```

`signingBackend` defaults to `"pem"` — no change in behavior for existing deployments.

### Step 6 — Update documentation

- `docs/security.md`: replace "unencrypted PEM file" language; describe both backends; explain the hardware upgrade path
- `docs/operator-hardening.md`: add SoftHSM2 setup procedure (install, initialize token, import or generate key, configure Vigil)
- `docs/security-critique.md`: update the HSM showstopper item to reflect that the gap is addressed

---

## What This Does Not Change

- The ceremony scripts (`ceremony/`) still generate PEM keys — operators use `softhsm2-util --import` to load the key into SoftHSM2 after the ceremony
- The root CA key management (offline storage) is unchanged
- All other services (Shepherd, Corgi) are unaffected — this change is entirely within Vigil

---

## Effort Estimate

| Task | Estimate |
|------|----------|
| Trait abstraction + PemFileBackend | 1 day |
| Pkcs11Backend (P-256, P-384) | 2–3 days |
| AppState + call site updates | 0.5 days |
| Config + startup wiring | 0.5 days |
| Integration testing with SoftHSM2 | 1 day |
| Documentation updates | 0.5 days |
| **Total** | **~6 days** |

---

## Dependencies to Add

| Crate | Purpose |
|-------|---------|
| `cryptoki` | Rust PKCS#11 binding (replaces unmaintained `pkcs11` crate) |

SoftHSM2 is an operator-installed system package (`apt install softhsm2` / `brew install softhsm`), not a Rust dependency.
