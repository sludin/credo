# Credo Security Design

This document explains the security model behind credo: what it is designed to protect against, how each authentication mechanism works, what cryptographic choices were made, and where known weaknesses exist.

For the deployment checklist (file modes, bind addresses, session secrets), see [operator-hardening.md](operator-hardening.md). For the overall architecture, see [architecture.md](architecture.md).

---

## Threat Model

### What credo protects against

- **Unauthorized certificate issuance.** Vigil only issues certificates to authenticated identities. ACME clients must own a registered account key. Admin endpoints require mTLS with a registered identity URI.
- **Unauthorized certificate distribution.** Shepherd only returns cert material (including private keys) to the Corgi node that owns the assignment. A Corgi authenticated as node A cannot fetch node B's keys.
- **Unauthorized control-plane access.** Shepherd's agent port requires mTLS with a recognized identity URI. Shepherd's admin port requires a valid JWT or mTLS cert registered in accounts. Corgi's control API requires mTLS.
- **MITM during node enrollment.** The Corgi bootstrap server prints its TLS fingerprint to stdout. Shepherd's enroll command pins to that fingerprint before exchanging the enrollment token, preventing an attacker from intercepting the exchange.
- **Timing attacks on bootstrap secrets.** All secret and token comparisons use constant-time algorithms.

### What credo does NOT protect against (operator's responsibility)

- **Key encryption at rest.** Private keys are stored as unencrypted PEM files. Filesystem-level encryption or an HSM must be provided by the operator if encryption at rest is required.
- **Config file confidentiality.** Credo does not check config file permissions at startup. The operator must restrict configs containing credentials to mode `0600`.
- **Network-level isolation.** Credo binds to `0.0.0.0` by default for most services. Firewall rules or specific bind addresses must be configured by the operator (see [operator-hardening.md](operator-hardening.md)).
- **CA/B Forum compliance.** The ceremony scripts produce a functional internal PKI but do not follow CA/B Forum guidelines. Credo is designed for internal deployments only.

---

## Authentication Model

### Vigil (port 7020)

| Route group | Auth mechanism |
|-------------|---------------|
| `GET/POST /acme/*` | ACME JWS (RFC 8555) — client authenticates via ACME account key |
| `POST /bootstrap` | 256-bit random secret, single-use |
| All other routes | mTLS client certificate — URI SAN matched against `rbacIdentities[]` in `vigil.config.json` |

The URI SAN in the client certificate must match a configured identity. There are no fingerprint fallbacks. An unrecognized SAN returns 401 with a diagnostic listing the presented SANs.

### Shepherd — Agent Port (7010)

This port is reached only by Corgi agents. mTLS is required; a missing client certificate fails the TLS handshake, not the HTTP layer.

**Identity resolution:**
1. Extract URI SANs from the client certificate.
2. Find a Corgi entry in `shepherd.corgis.json` whose `identityUri` matches one of the presented SANs.
3. Inject the matched `CorgiNodeConfig` into the request. No match → 401.

There are no fallback paths. Each request is also scope-checked: a Corgi authenticated as node A that requests data for node B receives 403.

### Shepherd — Dashboard/Admin Port (7011)

This port is reached by the Dashboard BFF, CLI tools, and direct API clients. Two auth paths are tried in order:

**Path 1 — JWT Bearer token:**
```
Authorization: Bearer <token>
```
Shepherd verifies the ES256 JWT signature against its signing key, checks expiry and `aud: ["shepherd"]`, and extracts `sub` (identity URI) and `role` from claims. If valid, the request proceeds immediately without consulting the accounts file.

**Path 2 — mTLS client certificate:**
If no JWT is present, the client certificate URI SAN is looked up in `shepherd.accounts.json`. The account must exist and have `active: true`. The account's stored `role` is used for RBAC.

**Obtaining a JWT — Proof of Possession (PoP):**

The Dashboard BFF calls `POST /token` with a PoP payload:
```json
{
  "pop": {
    "cert":        "<PEM cert>",
    "identityUri": "<URI SAN from cert>",
    "issuedAt":    "<RFC3339 timestamp>",
    "challenge":   "<server-provided or self-generated nonce>",
    "signature":   "<base64 ECDSA signature over the above fields>"
  }
}
```
Shepherd verifies the CA chain and the ECDSA signature, and checks that `issuedAt` is within the last 5 minutes. On success it issues a short-lived JWT and a refresh token.

**RBAC roles:**

| Role | Rank | Capabilities |
|------|------|-------------|
| `readonly` | 0 | Read all state (assignments, certstore, accounts, renewal jobs) |
| `operator` | 1 | All readonly operations (no additional write permissions currently assigned) |
| `admin` | 2 | All read operations + write operations (create/update/delete accounts, trigger renewals, provision certs) |

### Corgi — Control API (port 7001)

**Default mode — mTLS:**
The URI SAN from the client certificate is resolved against `rbacIdentities[]` in `corgi.config.json` to determine a role. Read routes (health, flock status) require `readonly`; write routes (cert install, CSR submission) require `admin`.

**Optional mode — proxy-headers:**
When `auth.mode = "proxy-headers"` is configured, Corgi reads the client certificate from an HTTP header forwarded by an upstream proxy. The security of this mode depends entirely on the proxy correctly enforcing mTLS and sanitizing headers. A misconfigured proxy allows any caller to forge an identity. This mode is intended for deployments where Corgi runs behind a reverse proxy that terminates mTLS.

**HTTP-01 challenge server (port 8080):**
The challenge listener serves `/.well-known/acme-challenge/<token>` with no authentication. Challenge tokens are public by ACME design (RFC 8555); there is no secret to protect here.

---

## Key Storage and Cryptographic Choices

### Algorithms in use

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Node identity certs | ECDSA P-256 | Corgi, Shepherd, Vigil service certs |
| Vigil CA intermediate | ECDSA P-384 | Default in ceremony scripts; P-256 or RSA also supported |
| Vigil cert signing | Matches CA key type | P-256 → SHA-256, P-384 → SHA-384, RSA → SHA-256 |
| JWT signing | ES256 (ECDSA P-256) | Key auto-generated at first start, mode `0600` |
| TLS transport | rustls defaults | TLS 1.2+; ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM |
| Certificate fingerprints | SHA-256 | Used for fingerprint comparison and Corgi bootstrap pinning |
| Bootstrap secrets | OS CSPRNG | Vigil: 256-bit hex; Corgi: ~285-bit alphanumeric (48 chars) |

TLS cipher suites and version bounds are not explicitly configured in credo — rustls library defaults apply. Rustls does not support SSL/TLS < 1.2, RC4, 3DES, or export-grade ciphers.

### Key storage model

All operational private keys are stored on disk as **unencrypted PKCS#8 PEM files**. No HSM, TPM, or KMS integration is provided. This is a deliberate trade-off: complexity of key encryption at rest is pushed to the operator's infrastructure (encrypted filesystems, volume encryption, restricted access control).

Recommended permissions: key files at mode `0600`, owned by the service process user.

**Keys that live on disk:**
- Corgi's own mTLS identity key (`corgi.config.json → tls.keyPath`)
- Each managed cert's private key (in Corgi's cert store, mode configurable via `filePolicy.keyMode`)
- Shepherd's JWT signing key (`shepherd.config.json → auth.jwtSigningKeyPath`, auto-created at `0600`)
- Vigil's intermediate CA key (`vigil.config.json → caEcdsaIntermediateKeyPath`, must be `0600`)

**Keys that never touch disk:**
- Vigil's bootstrap secret (held in memory, cleared after first use)
- Corgi's bootstrap token (held in memory, never persisted)
- Vigil's ephemeral bootstrap TLS key and cert (held in memory)

### Private key distribution

Private keys are generated on the Corgi node and never leave it. The provisioning flow is:

1. Shepherd calls `POST /flock/{name}/csr` on Corgi. Corgi generates an ECDSA private key locally and returns only the CSR PEM. The key is written to `entry.key_path` at mode `0600` on the Corgi host.
2. Shepherd submits the CSR to the CA (Vigil or an external ACME provider). The CA signs it and returns the cert. No private key is involved.
3. Shepherd stores the cert, chain, and fullchain in its certstore. No `privkey.pem` is written because Shepherd never had one.
4. Shepherd calls `POST /flock/{name}/install` on Corgi with just the cert material. Corgi installs the cert alongside the key already on disk.

When Corgi's sync loop calls `GET /agents/{nodeId}/certs/{certName}`, the `keyPem` field in Shepherd's response is `None` — the file does not exist in Shepherd's certstore.

**Implication:** A Shepherd compromise exposes cert and chain material (not sensitive) but not private keys. The blast radius is disruption to cert distribution, not key compromise. Shepherd's certstore should still be restricted to mode `0700` to limit exposure of cert metadata and timing information.

---

## Bootstrap Security Properties

The bootstrap flow has several non-obvious security properties that are worth making explicit.

**Vigil bootstrap secret:**
- 256 bits of entropy from `OsRng` (OS CSPRNG via the `rand` crate)
- Printed to stdout once at startup; never written to a file, never emitted to structured logs
- Compared using `subtle::ConstantTimeEq::ct_eq()` — immune to timing attacks
- One-shot: the secret is set to `None` in memory immediately after the first successful use; subsequent calls to `/bootstrap` return 404

**Corgi bootstrap token:**
- ~285 bits of entropy (48 alphanumeric characters sampled from `rand::thread_rng()`)
- Printed to stdout once at startup; never persisted
- Compared via constant-time byte XOR fold: `bytes.iter().zip(expected).fold(0u8, |acc, (a,b)| acc | (a^b)) == 0`
- No rate limiting is applied to the bootstrap endpoint; rely on the short window and out-of-band fingerprint verification to mitigate brute force

**Fingerprint pinning prevents MITM:**
The Corgi bootstrap server generates an ephemeral self-signed cert and prints its SHA-256 fingerprint. Shepherd's enrollment command accepts `--fingerprint` and pins to that value during the TLS handshake. An attacker who intercepts the network path cannot present a different cert without the operator noticing the fingerprint mismatch. The token is never exchanged unless the fingerprint matches.

**No insecure-skip-verify during bootstrap:**
Unlike operational connections (which have a config-level `insecureSkipVerify` escape hatch for dev use), the bootstrap server fingerprint verification cannot be disabled. Bootstrap is the one moment where trust is being established from scratch — weakening it would undermine the entire chain.

**Bootstrap cert lifetime:**
Both Vigil's and Shepherd's bootstrap certs are valid for 1 day. They are issued from the intermediate CA during Phase 2 and Phase 3 of the bootstrap flow and are replaced by production-lifetime certs when the first Corgi sync cycle completes (Phase 6).

---

## Known Weaknesses

| # | Weakness | Severity | Mitigation |
|---|----------|----------|------------|
| 1 | Private keys stored unencrypted on disk | **High** | Use encrypted filesystem or volume encryption. Set key file mode to `0600` with service-user ownership. No HSM support. |
| 2 | Shepherd certstore is a high-value target for cert material | **Medium** | Shepherd holds certs and chains but not private keys (keys never leave their origin Corgi node). A Shepherd compromise disrupts cert distribution but does not expose private keys. Restrict certstore directory permissions (`0700`). |
| 3 | Simple service hooks execute via `sh -c` | **Medium** | Hook commands come entirely from operator-controlled `corgi.config.json`, not from network input. Risk exists only if the config file is writable by an untrusted party. Prefer parameterized hooks (`spawn_no_shell` + regex-validated args) for any hook that includes dynamic values. |
| 4 | `insecureSkipVerify` escape hatch in config | **Medium** | Default `false`. Available per-CA (`cas[].insecureSkipVerify`) and per-Corgi node (`corgis[].insecureSkipVerify`) for lab environments. Enabling it allows MITM on outbound Shepherd connections. Never enable in production. |
| 5 | Corgi `proxy-headers` auth mode | **Medium** | Auth strength depends on the upstream proxy. A misconfigured or compromised proxy allows identity forgery. Only use in environments where the proxy is trusted and correctly configured. |
| 6 | Config files containing credentials have no permission enforcement | **Low** | Credo does not validate file modes at startup. Operator must set `0600` on `shepherd.config.json` (SMTP password), `vigil.config.json` (CA key path), and `dashboard.config.json` (session secret). |
| 7 | SMTP alert password stored in config as plaintext | **Low** | Use `${VAR}` placeholder syntax to load the password from an environment variable rather than embedding it in the JSON file. |
| 8 | Vigil ACME state in-memory only | **Info** | Vigil restart loses pending ACME orders and authorizations. Shepherd retries automatically on the next poll cycle. No issued-cert data is lost. SQLite persistence is a planned improvement. |
| 9 | No Shepherd HA/failover | **Info** | Corgis tolerate Shepherd outages via fail-stale assignment cache, but cannot renew expiring certs while Shepherd is down. Plan for Shepherd availability with standard host-level redundancy. |

---

## Secure Configuration Summary

The following settings have security implications beyond the defaults. Each is covered in detail in [operator-hardening.md](operator-hardening.md).

| Service | Setting | Default | Production requirement |
|---------|---------|---------|------------------------|
| All | `bind` | `0.0.0.0` | Restrict to specific interface |
| Vigil | `issuancePolicy.allowedDnsSuffixes` | `[]` (deny-all) | Set to your domain(s), or `["*"]` to allow any |
| Vigil | `issuancePolicy.allowedIdentityUriPrefixes` | `[]` (no restriction) | Set to your identity namespace |
| Vigil | intermediate CA key path | relative to CWD | Use absolute path, mode `0600` |
| Shepherd | `auth.jwtSigningKeyPath` | `./shepherd.jwt.key.pem` | Use absolute path |
| Shepherd | `alerts[].secure` | `false` | Set `true` for SMTP over TLS |
| Dashboard | `auth.sessionSecret` | *(enforced at startup — placeholder or short value refuses to start)* | Generate with `openssl rand -base64 32` |
| Corgi | `filePolicy.keyMode` | `0640` | Set `0600` |
