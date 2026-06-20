# Security Critique

A CISO-perspective review of `docs/security.md`. What holds up, what doesn't, and what would block enterprise adoption.

---

## What Works Well

**The honesty.** The threat model explicitly lists what credo does NOT protect against. Most vendor security docs don't do this. An honest "out of scope" section builds trust and makes the document actually useful for a risk assessment.

**mTLS with URI SAN-only identity.** No fingerprint fallbacks, no fleet-account escape hatches. The auth model is simple and strict. Simple auth is hard to misconfigure. This is the right call.

**Constant-time comparisons throughout.** Using `subtle::ConstantTimeEq` and the XOR-fold pattern shows real security awareness, not cargo-culted token comparison.

**Bootstrap fingerprint pinning before secret exchange.** Establishing trust before transmitting the secret is the correct sequence. A lot of home-grown enrollment systems get this backwards.

**Private keys never touch disk during bootstrap.** Good hygiene. The ephemeral window is well-contained.

**Private keys never leave their origin node.** Corgi generates its own private key, sends only the CSR to Shepherd, and receives only the signed cert back. Shepherd's certstore holds certs and chains — not keys. This is the correct PKI model and it significantly limits the blast radius of a Shepherd compromise. The security document should say this explicitly and prominently — it's a meaningful architectural property that a security reviewer needs to know.

**The PoP token mechanism.** Signing a challenge with your private key to obtain a JWT — rather than exchanging a shared secret — is a solid design for service identity credential exchange.

---

## Showstoppers for Enterprise Adoption

### 1. No HSM/KMS support, and the CA intermediate key is on disk

The Vigil intermediate CA private key is an unencrypted PEM file on the Vigil host. For any organization with a PKI security policy — SOC 2, PCI-DSS, anything with the word "HSM" in it — this is a hard stop. The intermediate CA can sign certificates for any identity in your namespace. It is the most sensitive key in the system and it sits next to the application binary.

"Use encrypted filesystem" is not an equivalent control to an HSM. An HSM means the key cannot be exfiltrated even with root access to the host. A LUKS-encrypted volume means the key is decrypted into memory at boot and accessible to any root process from that point forward.

---

## Significant Concerns

### 2. No audit log

This document has no mention of an audit trail. Who issued which certificate, when, authorized by which account? Who added or removed an account? Which Corgi fetched a cert and when? For any compliance framework — SOC 2, PCI-DSS, HIPAA, ISO 27001 — these events need to be in an immutable log that feeds a SIEM. Structured request logs exist, but a request log is not an audit log.

### 3. No revocation workflow described

The document mentions that Vigil has CRL and OCSP endpoints, but doesn't describe what "revoke a node" looks like operationally. If a Corgi host is compromised right now: what is the sequence of steps to invalidate its identity? How long until all components stop trusting it? What happens to the certs it was managing? This is the scenario that keeps CISOs up at night, and the answer should be in the security document.

### 4. The `operator` role does nothing

"All readonly operations (no additional write permissions currently assigned)" is a flag. Enterprises run access reviews. An auditor will ask what `operator` can do that `readonly` cannot. "Nothing" is the wrong answer. Either implement it or remove it — a vestigial role in a security-sensitive system is an audit liability.

### 5. `insecureSkipVerify` belongs in an environment variable, not a config file

Dev-mode flags in JSON config files get checked into source control, copied from staging to production, and inherited by new deployments. The only safe place for this flag is as an environment variable that requires an operator to consciously set it in the shell. Burying it in a config file that "should never have this in prod" is exactly how it ends up in prod. Auditing 50 nodes means grepping 50 `corgi.config.json` files manually.

### 6. Vigil ships open by default

`issuancePolicy.allowedDnsSuffixes: []` means Vigil will issue certs for any domain. The correct default for a CA is deny-all. A misconfigured first deployment produces a CA that signs whatever a client asks for, with no restriction. Secure-by-default means the safe configuration requires no action; the unsafe configuration requires explicit action.

### 7. The access control lists are flat JSON files with no change detection

`shepherd.accounts.json` and `shepherd.corgis.json` are the access control lists for the entire system. There is no versioning, no diff history, no approval workflow, and no detection of unauthorized modification. In an enterprise, changes to ACLs need to be audited, attributed to an approver, and ideally sourced from an IdP or secrets manager. Flat files on disk that get hot-reloaded are operationally convenient but invisible to any change management process.

### 8. The Dashboard session secret placeholder does not prevent startup

The document acknowledges that a deployment copying the example config verbatim runs with a publicly known session secret because there is no startup assertion. This should be a hard failure, not a deployment checklist item. The document describing the problem and the code not enforcing it is a gap — the document will be read once; the missing check will be missing forever.

---

## Smaller Issues

**TLS configuration is implicit.** "rustls defaults apply" is probably fine in practice, but enterprise security policies require explicit statements. An auditor cannot sign off on "the library picks it." Document what rustls actually negotiates.

**No mention of SIEM integration or alertable events.** What does a failed Corgi auth look like in a log aggregator? Is there a rate of failed auths that should trigger an alert? These are operational security questions that belong in the security document.

**No supply chain discussion.** Credo imports dozens of Rust crates. For a system that manages TLS infrastructure, a supply-chain compromise would be catastrophic. Dependency pinning, `cargo audit` in CI, and crate provenance aren't mentioned.

---

## Bottom Line

One thing would actually block a deployment in a security-conscious enterprise:

**No HSM support for the CA key.** This is a hard requirement for any organization with a PKI policy. An unencrypted intermediate CA key in a flat PEM file does not satisfy it.

Everything else is a significant concern but negotiable with compensating controls and engineering effort. Notably, the architecture gets the most important thing right: private keys are generated on the Corgi node and never leave it. Shepherd is a cert broker, not a key escrow. That's the correct design, and it means a Shepherd compromise is a disruption to cert distribution, not a full key compromise. That distinction matters enormously for blast radius assessment.
