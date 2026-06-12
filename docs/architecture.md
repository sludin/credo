# Credo Architecture

This document describes how credo works at a conceptual level — the certificate lifecycle, how trust is established, how identities are resolved, and how the system behaves when things go wrong. For step-by-step operator instructions, see [bootstrap-guide.md](bootstrap-guide.md). For configuration field references, see the per-service `docs/config.md` files.

---

## System Topology

Credo is a hub-and-spoke certificate management system. Shepherd is the single control plane; Corgi agents run on every managed node and are the only component that requires a routable network path to Shepherd.

```
                      ┌──────────────────────────────────┐
                      │  Machine A (vigil + corgi-A)     │
                      │                                  │
                      │  vigil    ── private CA (7020)   │
                      │  corgi-A  ── manages vigil cert  │
                      └────────────────┬─────────────────┘
                                       │ mTLS (7020)
                      ┌────────────────▼─────────────────┐
                      │  Machine B (shepherd + corgi-B)  │
                      │                                  │
                      │  shepherd ── control plane       │
                      │  corgi-B  ── manages shepherd    │
                      └───────┬────────────────┬─────────┘
                              │ mTLS (7010)    │ HTTPS (7011)
               ┌──────────────▼──┐         ┌──▼──────────────┐
               │ corgi-C         │   ...   │ dashboard BFF   │
               │ managed node    │         │ (7030)          │
               └─────────────────┘         └─────────────────┘
```

**Component roles:**

- **Shepherd** — holds assignment records (which cert goes where), drives ACME issuance against a CA, distributes non-private cert material to Corgi agents on demand. Tracks renewal job state and rate limits issuance against a rolling 7-day ledger.
- **Corgi** — runs on every managed node. Periodically pulls its assignments from Shepherd, compares certificate fingerprints, generates keys and CSRs locally, fetches updated cert material when needed, installs certs atomically, and runs service hooks. Private keys are generated on Corgi and never sent to Shepherd.
- **Vigil** — ACME-compatible private CA. Signs certs for all services and end-entity certificates when configured. Shepherd talks to Vigil as an ACME client over mTLS.
- **Ceremony scripts** — offline shell scripts for generating the root CA and intermediate CA. Run once, air-gapped.
- **Dashboard** — React+Vite SPA served by an Express BFF. Provides a UI for managing assignments, accounts, and viewing cert status. Talks only to Shepherd's dashboard API port (7011) via mTLS + JWT Bearer token.

---

## Certificate Lifecycle

### 1. Assignment Creation

An operator adds a `ManagedAssignment` record to `shepherd.assignments.json`, specifying the certificate name (`certName`), target Corgi node, domains, SANs, and which CA to use. Shepherd hot-reloads this file on every poll cycle when its mtime changes — no restart required.

### 2. Corgi Pulls and Detects the Gap

Corgi runs its own sync loop (default every 60s), independent of Shepherd. Each tick:

1. `GET /agents/{nodeId}/assignments` from Shepherd.
2. Write the response to the assignments cache file (for fail-stale behavior on Shepherd outage).
3. Merge dynamic assignments from Shepherd with static `flock` entries from the local config.
4. For each assignment, read the local cert fingerprint. Compare against `fingerprint256` from Shepherd (normalizing format — colons stripped, lowercase). Needs-install is true when:
   - No local cert exists (regardless of whether Shepherd has a fingerprint).
   - Local cert exists but has no Shepherd fingerprint and expires within 30 days.
   - Fingerprints differ.

### 3. Key and CSR Generation

When a cert needs to be installed and no archived private key exists yet, Corgi:

1. Generates an ECDSA private key locally — **the private key never leaves the node**.
2. Builds a CSR with the configured `domain`, `sans`, `identityUri`, and optionally a custom subject.
3. Writes the key to a pending path (`archive/{name}/pending.key`) and calls `POST /agents/{nodeId}/renew/{name}` on Shepherd with the CSR PEM.
4. Defers installation to the next sync cycle while the renewal job runs.

### 4. Shepherd Drives ACME Issuance

On receiving a CSR from Corgi (or a renewal trigger), Shepherd creates a `RenewalJob` and drives the ACME state machine asynchronously:

```
RenewalJob state machine:

  Queued
    → SubmittingOrder    (new ACME order placed with CA)
    → Validating         (challenge set; polling for authorization)
    → Finalizing         (submitting CSR to CA; fetching cert chain)
    → Installing         (writing cert to cert store, updating live/ symlinks)
    → Completed          (fingerprint recorded; Corgi can fetch)
    ↘ Failed             (ACME error or timeout)
    ↘ Cancelled          (superseded by a newer job)
    ↘ RateLimited        (CA rejected; retries after rate_limited_until)
```

For HTTP-01 validation, Shepherd forwards the `httpChallengePort` from Corgi's inventory to Vigil, which places the challenge token. Corgi's HTTP challenge listener must be reachable on that port from Vigil.

For DNS-01 validation, Shepherd updates TXT records via a configured DNS provider (e.g., Hurricane Electric DDNS), then polls authoritative nameservers for propagation before notifying the CA.

Shepherd stores completed cert material in a certstore under `archive/` and `live/` directories, mirroring certbot's layout. The `live/{name}/` symlinks always point to the most recent archive entry. Each entry's `fingerprint256` is what Corgi uses to detect when it needs to fetch new material.

### 5. Corgi Fetches and Installs

On the next sync cycle after a renewal job completes:

1. Fingerprint mismatch detected (or no local cert).
2. `GET /agents/{nodeId}/certs/{name}` — Shepherd returns the cert PEM and chain (no private key).
3. Corgi verifies the cert matches the pending key (if a key was generated in step 3).
4. Atomically writes cert, key, chain, and fullchain files with configured permissions and ownership.
5. Promotes the pending key to the archive.
6. If the install produced a change, runs the configured service hooks.

### 6. Service Hooks

Hooks run after a cert is installed and changed. Configured per-cert or as defaults in `corgi.config.json`. Hook failures are logged but non-fatal — Corgi continues reconciling other certs.

---

## Rate Limiting and Issuance Ledger

Shepherd maintains an issuance ledger (`shepherd.issuance-log.json`) that tracks every successful ACME issuance. Before submitting a new order, Shepherd checks:

| Limit | Window |
|-------|--------|
| 50 issuances per domain | Rolling 7 days |
| 5 issuances per identifier set (same set of SANs) | Rolling 7 days |

If either limit is exceeded, the renewal job transitions to `RateLimited` with a `rate_limited_until` timestamp. Shepherd retries automatically after that time. The limits mirror Let's Encrypt's production rate limits and apply regardless of which CA backend is used — they are an internal safeguard, not CA-enforced.

The ledger is pruned automatically (entries older than 7 days are dropped). If the file is missing or corrupt, Shepherd starts with an empty ledger and logs a warning.

---

## Background Loops

Shepherd runs two independent background loops:

### Poll loop (default: every 60s)

1. Hot-reload config files if mtime changed: `shepherd.corgis.json`, `shepherd.accounts.json`, `shepherd.ca.json`.
2. For each Corgi: `GET /flock` → list of `{ certName, fingerprint }`.
3. Compare each fingerprint against Shepherd's cert store.
4. If fingerprints differ, schedule a cert-maintenance pull (Corgi will detect this on its next sync tick via the changed fingerprint in its assignment response).
5. Run cert maintenance: for each assignment, check whether a renewal job is needed (cert expiring soon, cert absent, fingerprint mismatch). If so, create a `RenewalJob` and drive the ACME state machine.

### Health-check loop (default: every 300s)

Separately, a lightweight loop pings `GET /health` on each Corgi. Node status transitions between `Reachable` and `Unreachable`. Shepherd continues issuing certs for unreachable nodes; Corgi will pull when connectivity is restored.

---

## mTLS Bootstrap

Before any service can communicate, the PKI chain must exist and each service must have a valid TLS certificate signed by that chain. Bootstrap runs once, in six phases.

> For exact CLI commands and the wizard-based alternative, see [bootstrap-guide.md](bootstrap-guide.md).

### Phase 1: PKI Ceremony

Run on an air-gapped machine using the `ceremony/` scripts. Produces a root CA and intermediate CA. After the ceremony, build `credo-catrust.pem` (root + intermediate concatenated) and distribute it to every machine. This is the trust bundle all services use to verify peer certificates.

The root key moves to offline storage after the intermediate is issued — it is only needed for intermediate revocation and re-issuance.

### Phase 2: Vigil Self-Bootstrap

Vigil starts in bootstrap mode. It generates an in-memory ECDSA key pair, self-issues a 1-day TLS cert signed by the intermediate CA, and prints a random 256-bit secret to stdout. It exposes a one-shot `POST /bootstrap` endpoint (no mTLS client cert required on this endpoint only). When Shepherd POSTs the correct secret and a CSR, Vigil signs a 1-day cert, deactivates the endpoint, and continues serving using the in-memory cert.

### Phase 3: Shepherd Enrollment

Shepherd's bootstrap CLI generates an in-memory key pair, builds a CSR (CN = `commonName`, URI SAN = `identityUri`), and POSTs it to Vigil's bootstrap endpoint with the secret. Shepherd receives a signed 1-day cert, holds it in memory — **nothing written to disk** — and starts both API servers. It prints a one-time admin token.

### Phase 4: Admin Account Enrollment

An admin generates a personal ECDSA key and cert (via `shepherd bootstrap admin`), using the bootstrap admin token. The key is generated locally; only the CSR is sent. The resulting cert's URI SAN is registered in `shepherd.accounts.json` and grants direct API access to Shepherd's dashboard port.

### Phase 5: Corgi Node Enrollment

Corgi starts in bootstrap mode when it has no valid TLS certificate:

1. Generates an ephemeral self-signed cert and a 64-hex-character random token.
2. Starts a bootstrap HTTPS server on `bootstrapPort` (a separate config field, default `mtlsPort + 1`) and prints the server fingerprint and token to stdout.
3. `shepherd bootstrap corgi` connects to the bootstrap server, verifying the fingerprint out-of-band. It then:
   - `GET /bootstrap/csr` — Corgi generates an ECDSA key + CSR; private key stays on Corgi's machine.
   - `POST /bootstrap/ca` — installs the CA trust bundle.
   - `POST /bootstrap/cert` — installs the signed 1-day certificate.
   - `POST /bootstrap/finalize` — Corgi invalidates the token and exits bootstrap mode.
4. Corgi restarts in normal mode, starts the main mTLS server on `mtlsPort`.

### Phase 6: Automatic Rotation

Once all Corgis are enrolled and running, Shepherd's poll loop detects that each node's certs are short-lived bootstrap certs approaching expiry. It triggers ACME renewal for production-lifetime certs. Corgi installs them and runs service hooks (e.g., `systemctl restart vigil`). The bootstrap window closes automatically.

---

## Identity and Authentication

### Vigil: Admin mTLS

Vigil validates incoming client certificates against its user registry. The URI SAN from the client cert must match a registered user. Role is stored per-user in the registry. No fingerprint or fallback resolution.

### Shepherd: Corgi Agent Port (7010, mTLS)

Shepherd's agent port requires mTLS. The URI SAN from the Corgi's client certificate must match an `identityUri` in the `shepherd.corgis.json` inventory. If no match is found, the request is rejected with 401. Always identity-only; no fingerprint fallbacks.

### Shepherd: Dashboard / Admin API Port (7011)

Two authentication paths, tried in order:

1. **JWT Bearer token** — `Authorization: Bearer <token>`. Shepherd issues ES256 JWTs (1-hour expiry by default). The token carries the subject's identity URI and role. Refresh tokens (opaque, stored in-memory with optional disk persistence) allow the Dashboard BFF to obtain new access tokens without re-enrollment. This is the primary path for the Dashboard BFF acting on behalf of a logged-in user.

2. **mTLS certificate** — the URI SAN from the client cert is looked up in `shepherd.accounts.json`. The account must exist and have `active: true`. Used for direct API access with a personal admin cert (CLI tools, scripts).

### JWT Issuance Flow (Dashboard)

The Dashboard BFF obtains a JWT on behalf of a user at enrollment time:

1. User completes CLI PoP (Proof-of-Possession) enrollment, proving they hold the private key for their Vigil cert.
2. BFF calls `POST /auth/token` on Shepherd, passing the PoP.
3. Shepherd verifies the PoP, looks up the identity URI in `shepherd.accounts.json`, and issues an access token + refresh token pair.
4. BFF stores both tokens in `dashboard.users.json`. On every subsequent `/api/*` request, the BFF sends `Authorization: Bearer <access-token>`. When the access token nears expiry, BFF calls `POST /auth/refresh` to rotate both tokens.

### RBAC Roles

Three roles, ordered by privilege: `readonly` < `operator` < `admin`. Roles are embedded in JWT claims (for token auth) or stored in the account record in `shepherd.accounts.json` (for cert auth). The RBAC check is `user.role >= required_role`.

---

## Hot-Reload

Shepherd reloads config from disk **without a restart** when config file mtimes change. The health-check loop checks for mtime changes on every tick:

- `shepherd.corgis.json` — Corgi fleet inventory. New or removed nodes take effect on the next poll cycle.
- `shepherd.accounts.json` — RBAC accounts. Account changes (role updates, deactivation) take effect on the next API request after a new login or role refresh.
- `shepherd.ca.json` — CA configurations.

Full config hot-reload (via SIGHUP) re-reads `shepherd.config.json`, rebuilds TLS server config, and gracefully restarts both servers. Port or TLS cert changes require SIGHUP.

---

## Failure Modes and Offline Behavior

### Corgi: Shepherd Unreachable

Corgi never blocks on Shepherd availability. On every sync tick:

- If the request to Shepherd succeeds, the response is written to the assignments cache.
- If the request fails, Corgi logs a warning and continues operating from the last cached assignments.
- If the cache age exceeds `shepherdSync.staleWarningSeconds` (default 300s), Corgi emits a stale-cache warning.

Corgi continues serving existing installed certs indefinitely while Shepherd is down. It cannot renew or install new certs until connectivity is restored.

### Corgi: Install Failures

If fetching cert material from Shepherd fails, or if the atomic install fails, Corgi logs the error and retries on the next sync interval. Hook failures are similarly non-fatal.

### Shepherd: Corgi Unreachable

Shepherd marks a Corgi node `Unreachable` after a failed health check (every `corgiHealthCheckIntervalSeconds`, default 300s). Shepherd continues managing other nodes and issuing certs. When connectivity is restored, Shepherd resumes its poll cycle for that node.

### Vigil: Restart Loses In-Flight ACME State

Vigil's ACME state — pending orders, authorizations, challenges, and nonces — is held in memory only. A Vigil restart during an active ACME flow causes the in-flight order to fail. Shepherd's ACME client retries on the next poll cycle by creating a new order. **No issued certificates are lost** — only pending issuance is disrupted.

### Shepherd: Renewal Job Persistence

By default, pending renewal jobs are in-memory only and are lost on Shepherd restart. Set `renewalJobsDir` in `shepherd.config.json` to persist job state to disk. Without this, Shepherd will re-trigger renewal on the next poll cycle after a restart, which is correct but adds latency.

---

## Key Configuration Relationships

```
shepherd.config.json
  ├── agentPort / dashboardPort / bind
  ├── corgisConfigPath    → shepherd.corgis.json       (hot-reloaded)
  ├── assignmentsConfigPath → shepherd.assignments.json (hot-reloaded)
  ├── caConfigPath        → shepherd.ca.json           (hot-reloaded)
  ├── accountsPath        → shepherd.accounts.json     (hot-reloaded)
  ├── certStoreDir        → store/archive/ + store/live/
  ├── renewalJobsDir      → optional job state persistence
  └── auth.jwtSigningKeyPath → ES256 signing key (auto-generated if absent)

shepherd.corgis.json
  ├── defaults.mtls.{certPath,keyPath,caPath}  ← shared across all corgis
  └── corgis[].{name,url,identityUri,httpChallengePort}

shepherd.ca.json
  └── cas.{caName}.{protocol,provider,config.{directoryUrl,accountKeyPath,...}}

shepherd.assignments.json
  └── assignments[].{certName,corgi,ca,domain,sans,identityUri,validation,...}

shepherd.accounts.json
  └── accounts[].{id,name,role,active,identities[]}

corgi.config.json
  ├── nodeId              ← must match an entry in shepherd.corgis.json
  ├── shepherdUrl         ← agent port URL
  ├── mtlsPort            ← normal-mode mTLS server port
  ├── bootstrapPort       ← bootstrap-mode server port (default: mtlsPort + 1)
  ├── certStoreDir        ← root for archive/ + live/ layout
  ├── flock[]             ← static cert definitions (paths, permissions, hooks)
  ├── shepherdSync.{intervalSeconds,staleWarningSeconds,assignmentsCachePath}
  ├── httpChallenge.{enabled,port,bind}
  └── tls / mtls          ← server TLS + outbound client cert paths
```

Config files use camelCase JSON field names. All services support `$VAR` interpolation from environment variables and a `vars` block. Changes to hot-reloaded files take effect on the next poll cycle with no restart.

---

## Known Limitations

- **Vigil ACME state is in-memory.** A Vigil restart during ACME issuance loses the in-flight order. Shepherd retries automatically on the next poll cycle, at the cost of one interval's delay.
- **Single Shepherd instance.** No built-in HA or failover for Shepherd. Corgis tolerate outages via the fail-stale cache but cannot renew certs while Shepherd is down.
- **Renewal job persistence requires `renewalJobsDir`.** Without it, in-progress jobs are lost on Shepherd restart. Set this in production.
- **Private keys are generated on Corgi.** Shepherd never holds or rotates private keys. If a Corgi node is lost and its key store is unrecoverable, Shepherd must issue a new cert against a new CSR from a replacement node.
- **Rate limiting is internal.** The 50/7-day and 5/7-day issuance limits are Shepherd-internal safeguards mirroring Let's Encrypt's production limits. They do not reflect actual CA-side enforcement and cannot be bypassed by deleting the ledger file without also triggering real CA rate limits.
