# What You Get Out of the Box

This document describes credo's security posture as shipped — what is enforced automatically, what requires explicit operator action, and what credo will never protect regardless of configuration. It is written for an operator evaluating credo before installing it.

---

## Enforced by default — no action required

**Mutual TLS everywhere.** All inter-service communication (Corgi ↔ Shepherd, Shepherd/Corgi ↔ Vigil) uses mTLS. A missing or unrecognized client certificate fails the TLS handshake, not just the HTTP layer. There is no way to reach internal APIs over plaintext or with a one-sided TLS connection.

**URI-SAN-only identity matching.** Shepherd and Vigil match client identities exclusively against URI SANs in the presented certificate. There are no fingerprint fallbacks, no fleet-wide bypass modes, and no anonymous-admin escape hatches.

**Private keys never leave their origin node.** Corgi generates private keys locally and returns only the CSR. Shepherd never receives, stores, or transmits private key material. A Shepherd compromise exposes cert chain data (not sensitive) but not private keys.

**DNS issuance disabled until explicitly configured.** Vigil's `issuancePolicy.allowedDnsSuffixes` defaults to `[]`, which means DNS certificate issuance is denied for all names. You must explicitly list allowed suffixes, or set `["*"]` to permit any name. An unconfigured Vigil cannot be silently induced to issue certificates by a misconfigured ACME client.

**Session secrets validated at startup.** The Dashboard BFF refuses to start if `auth.sessionSecret` matches a known placeholder value or is shorter than 32 characters. A deployment with a weak session secret fails loudly at boot, not silently at runtime.

**Bootstrap secrets are ephemeral.** Vigil's bootstrap secret (256-bit, OS CSPRNG) is printed to stdout once and cleared from memory after first use. Subsequent calls to `/bootstrap` return 404. Corgi's enrollment token behaves the same way. There is no persistent "setup password" left on disk.

**Fingerprint pinning prevents bootstrap MITM.** Shepherd's enrollment command pins to the Corgi bootstrap server's TLS certificate fingerprint before exchanging the enrollment token. An attacker on the network path cannot intercept the token without the operator noticing the fingerprint mismatch.

**Timing-safe secret comparison.** All bootstrap secret and token comparisons use constant-time algorithms. Timing attacks against the bootstrap flow are not viable.

---

## Requires explicit operator action

**Bind addresses.** Most services default to `127.0.0.1`. If Corgi and Shepherd run on separate machines, you must bind Shepherd's agent port to the interface Corgis reach. Do not bind to `0.0.0.0` without network-level controls.

**Issuance policy scope.** `allowedDnsSuffixes: []` denies all DNS issuance — but you must still set `allowedIdentityUriPrefixes` to restrict which identity URIs Vigil will sign. An empty prefix list permits any URI SAN. Scope your identity namespace explicitly.

**File permissions.** Credo does not verify config file permissions at startup. Set `0600` on files that contain credentials: `shepherd.config.json` (SMTP password), `vigil.config.json` (CA key path), `dashboard.config.json` (session secret). The `operator-hardening.md` checklist covers every file that requires restricted permissions.

**SMTP transport security.** Alert delivery over email defaults to `secure: false` (no STARTTLS). Set `alerts[].secure: true` for any production alert destination that supports TLS.

**Corgi key file mode.** `filePolicy.keyMode` defaults to `0640`. Set it to `0600` unless you have an explicit reason for group read access.

**Session secret generation.** The Dashboard BFF enforces a minimum 32-character length and rejects known placeholder values, but it does not verify randomness. Generate the secret with `openssl rand -base64 32` or equivalent — do not invent a string yourself.

---

## What credo will never protect

**Encryption at rest.** Private keys are stored as unencrypted PKCS#8 PEM files. Credo has no HSM, TPM, or KMS integration. If encryption at rest is required, use an encrypted filesystem or volume encryption at the infrastructure level.

**Hardware key binding.** There is no mechanism to bind private key material to a hardware security module or trusted execution environment. Key material is accessible to any process running as the service user.

**Network-level isolation.** Credo enforces mTLS between its own services, but it cannot enforce firewall rules, network segmentation, or host-level isolation. Restricting which machines can reach which ports is the operator's responsibility.

**CA/B Forum compliance.** The ceremony scripts produce a functional internal PKI, but the resulting CA is not a publicly trusted root and does not follow CA/B Forum guidelines. Credo is designed for internal deployments only. It should not be used as a public-facing CA.

**Shepherd high availability.** Corgis tolerate Shepherd outages (fail-stale assignment cache) but cannot renew expiring certificates while Shepherd is down. Shepherd availability depends on standard host-level redundancy; credo provides no clustering or failover.

---

## Where to go next

- **`docs/operator-hardening.md`** — deployment checklist; every security-relevant default with the recommended production value
- **`docs/roadmap/security.md`** — security design and threat model; cryptographic choices, auth flow details, known weaknesses
- **`docs/architecture.md`** — system overview; pull-based reconciliation, port assignments, service roles
