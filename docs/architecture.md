# Credo Architecture

This document describes how credo works at a conceptual level — the certificate lifecycle, how trust is established, how identities are resolved, and how the system behaves when things go wrong. For step-by-step operator instructions, see [bootstrap-guide.md](bootstrap-guide.md) and the per-service config references in each service's `docs/config.md`.

---

## System Topology

Credo is a hub-and-spoke certificate management system. Shepherd is the single control plane; Corgi agents run on every managed node and are the only component that needs a routable network path to Shepherd, assuming the dashboard runs on the same machien as Shepherd.

```
                      ┌──────────────────────────────────┐
                      │  Machine A (vigil + corgi-01)    │
                      │                                  │
                      │  vigil ──── private CA           │
                      │  corgi-01 ─ manages vigil cert   │
                      └────────────────┬─────────────────┘
                                       │ mTLS (7020)
                      ┌────────────────▼─────────────────┐
                      │  Machine B (shepherd + corgi-02) │
                      │                                  │
                      │  shepherd ─ control plane        │
                      │  corgi-02 ─ manages shepherd cert│
                      └───────┬────────────────┬─────────┘
                              │ mTLS (7010)    │ HTTPS (7011)
               ┌──────────────▼──┐         ┌──▼──────────────┐
               │ corgi-03        │   ...   │ dashboard BFF   │
               │ managed node    │         │ (7030)          │
               └─────────────────┘         └─────────────────┘
```

**Component roles:**

- **Shepherd** — holds assignment records (which cert goes where), runs ACME issuance against a CA, distributes non-private cert material to Corgi agents on demand.
- **Corgi** — runs on every managed node. Periodically pulls its assignments from Shepherd, compares certificate fingerprints, fetches updated material when needed, installs certs atomically, and runs service hooks.  Creates certificat esigning requests (CSR) and private keys.
- **Vigil** — ACME-compatible private CA used internally. Signs certs for all services and for end-entity certificates when configured. Shepherd talks to Vigil as an ACME client.
- **Ceremony scripts** — offline shell scripts for generating the root CA and intermediate CA. Run once, air-gapped.
- **Dashboard** — React + Vite SPA served by an Express BFF. Provides a UI for managing assignments, accounts, and viewing cert status. Talks only to Shepherd's dashboard API port (7011).

---

## Certificate Lifecycle

### 1. Assignment Creation

An operator adds a `ManagedAssignment` record to `shepherd.assignments.json`, specifying the certificate name, the target Corgi node, the domains, and which CA to use. Shepherd hot-reloads this file when its mtime changes — no restart required.

### 2. Shepherd Issues the Certificate

Shepherd's poll loop (default every 60s) runs a three-phase cycle for each assignment:

1. **Flock poll** — Shepherd queries each Corgi's `/flock` endpoint to learn the current cert name, fingerprint, and validity.
2. **Fingerprint sync check** — if Shepherd's stored cert for an assignment is newer than what a Corgi is running, Shepherd tells the Corgi to re-sync immediately.
3. **Cert maintenance** — Shepherd decides whether renewal is needed (cert expiring soon, cert absent, assignment just created). When renewal is triggered, Shepherd creates a `RenewalJob` and drives ACME:

```
RenewalJob state machine:
  Queued → SubmittingOrder → Validating → Completed
                                        ↘ Failed
                                        ↘ Cancelled
```

Shepherd stores completed cert material in a certstore under `archive/` and `live/` directories (mirroring certbot's layout). Each cert entry has a `fingerprint256` that Corgi uses for comparison.

### 3. Corgi Pulls and Installs

Corgi runs its own sync loop (default every 60s) independent of Shepherd's poll. Each tick:

1. GET `/agents/{nodeId}/assignments` from Shepherd.
2. Write the response to the assignments cache file (for fail-stale behavior).
3. Merge the dynamic assignments with any static flock entries in the local config.
4. For each assignment, read the local cert's fingerprint (if the file exists). Compare against `fingerprint256` from Shepherd (normalizing format — colons stripped, lowercase). If they differ, fetch the cert material.
5. If directed by shepherd, create a private key and CSR for the certificate 
6. Install: atomically write cert, key, chain, and fullchain files with configured permissions and ownership.
7. If the install produced a change, run the configured service hooks.

### 4. Service Hooks

Hooks run after a cert is installed and changed. They are configured per-cert or as defaults in `corgi.config.json`. Hook failures are logged but non-fatal — Corgi continues reconciling other certs.

---

## mTLS Bootstrap

Before any service can communicate, the PKI chain must exist and each service must have a valid TLS certificate signed by that chain. Bootstrap runs once, in six phases.

> For exact CLI commands, see [bootstrap-guide.md](bootstrap-guide.md).

### Phase 1: PKI Ceremony

Run on an air-gapped machine using the `ceremony/` scripts:

- `bootstrap-roots.sh` — generates the root CA key (ECDSA, encrypted) and self-signed root cert.
- `issue-intermediary.sh` — generates an intermediate CA signed by the root. Shepherd and Corgi certs are issued from this intermediate.

After the ceremony, build `credo-catrust.pem` (root + intermediate chain) and distribute it to every machine. This is the trust bundle all services use to verify peer certificates.

The root key should move to offline storage after the intermediate is issued — it is only needed for intermediate revocation and re-issuance. Note: This is NOT how a real root ceremony should be run according to CA/B Forum Guidelines. This is intended for internal use only. Even so, your needs may dictate using a much more stringent procedure.

### Phase 2: Vigil Self-Bootstrap

Vigil starts in bootstrap mode. It generates a random 256-bit secret, prints it to stdout, and exposes a one-shot `POST /bootstrap` endpoint. When Shepherd (or an admin script) POSTs the correct secret plus a CSR, Vigil signs a short-lived (1-day) TLS cert and deactivates the endpoint. Vigil then restarts with its signed cert and begins serving normally.

### Phase 3: Shepherd Enrollment

Shepherd's bootstrap CLI command generates a CSR, POSTs it to Vigil's bootstrap endpoint with the secret, receives a signed cert, and writes it to disk. Shepherd then starts its main servers.

### Phase 4: Admin Account Enrollment

An admin generates a personal ECDSA key and certificate (signed by Vigil), then registers the certificate's URI SAN in `shepherd.accounts.json`. This account gains RBAC access to Shepherd's dashboard API.

### Phase 5: Corgi Node Enrollment

Corgi starts in bootstrap mode when it has no valid TLS certificate:

1. Generates an ephemeral self-signed cert and a 48-character random token.
2. Starts a bootstrap HTTPS server on its bootstrap port (default 7002) and prints the server fingerprint and token to stdout.
3. An operator (or Shepherd's `bootstrap corgi` CLI command) verifies the fingerprint out-of-band, then POSTs a request with the token to:
   - `POST /bootstrap/csr` — Corgi generates an ECDSA key + CSR and returns the CSR PEM.
   - `POST /bootstrap/ca` — installs the CA trust bundle.
   - `POST /bootstrap/cert` — installs the signed certificate.
   - `POST /bootstrap/finalize` — Corgi exits bootstrap mode and starts the main mTLS server.

### Phase 6: Automatic Rotation

Once all Corgis are enrolled and running, Shepherd's poll loop detects that each node's certs are short-lived bootstrap certs. It triggers ACME renewal for production-lifetime certs. Corgi installs them and runs service hooks (e.g., `systemctl reload nginx`). The bootstrap window closes automatically.

---

## Identity and Authentication

### Vigil: Admin mTLS

Vigil validates incoming client certificates against its user registry (`vigil.users.json`). The URI SAN from the client cert must match a registered user. Role is stored per-user in the registry. No fallbacks.

### Shepherd: Corgi Agent Port (7010, mTLS)

Shepherd's agent port requires mTLS. The URI SAN from the Corgi's client certificate must match a `identityUri` in the `shepherd.corgis.json` inventory. If no match is found, the request is rejected with 401. There are no fingerprint or fallback resolution paths — it is always identity-only.

### Shepherd: Dashboard / Admin API Port (7011)

Two authentication paths, tried in order:

1. **JWT Bearer token** — `Authorization: Bearer <token>`. Shepherd issues ES256 JWTs with a 1-hour expiry. The token carries the subject's identity URI, role, and (optionally) account name. JWT auth is the primary path used by the Dashboard BFF on behalf of logged-in users.

2. **mTLS certificate** — the URI SAN from the client cert is looked up in `shepherd.accounts.json`. The account must exist and have `active: true`. This path is used for direct API access with a personal admin cert (e.g., CLI tools, scripts).

### RBAC Roles

Roles are embedded in JWT claims (for token auth) or stored in the account record (for cert auth). The role determines what API operations are permitted. Role definitions are stable but not enumerated here — see the route handler source in `shepherd/src/routes_api.rs`.

---

## Failure Modes and Offline Behavior

### Corgi: Shepherd Unreachable

Corgi never blocks on Shepherd availability. On every sync tick:

- If the request to Shepherd succeeds, the response is written to the assignments cache.
- If the request fails, Corgi logs a warning and continues operating from the last cached assignments.
- If the cache age exceeds `shepherd_sync.stale_warning_seconds` (default 300s), Corgi emits a stale-cache warning in the log.

The cache path is configurable via `shepherd_sync.assignments_cache_path`. Corgi will serve existing installed certs indefinitely while Shepherd is down; it cannot renew or install new certs until connectivity is restored.

### Corgi: Install Failures

If fetching cert material from Shepherd fails, or if the atomic install fails, Corgi logs the error, skips that cert for this tick, and retries on the next sync interval. Hook failures are similarly non-fatal.

### Shepherd: Corgi Unreachable

Shepherd marks a Corgi node `Unreachable` after a failed health check (checked every 300s by default). Shepherd continues managing other nodes and issuing certs normally. When the Corgi becomes reachable again, Shepherd resumes its poll cycle for that node.

### Vigil: Restart Loses In-Flight ACME State

Vigil's ACME state — pending orders, authorizations, challenges, and nonces — is held in memory only. A Vigil restart during an active ACME flow causes the client (Shepherd) to receive errors on subsequent requests. Shepherd's ACME client will retry on the next poll cycle, creating a new order. **There is no data loss for issued certificates** — only pending issuance is disrupted. SQLite persistence is a planned improvement (tracked in `vigil/src/acme.rs`).

---

## Key Configuration Relationships

```
shepherd.config.json
  ├── agent_port / dashboard_port / bind
  ├── cas[]            ← ACME directory URLs, EAB, validation methods
  ├── corgisConfigPath → shepherd.corgis.json  (hot-reloaded)
  ├── assignmentsPath  → shepherd.assignments.json  (hot-reloaded)
  ├── accountsPath     → shepherd.accounts.json
  └── jwt.keyPath      → ES256 signing key (auto-generated if absent)

corgi.config.json
  ├── node_id          ← must match an entry in shepherd.corgis.json
  ├── shepherd_sync    ← URL, interval, cache path, stale warning threshold
  ├── flock[]          ← static cert definitions (paths, permissions, hooks)
  └── tls              ← mTLS cert/key paths for the Corgi server itself

vigil.config.json
  ├── port / bind
  ├── ca               ← intermediate key + cert paths
  └── issuance_policy  ← allowed DNS suffixes (empty = no enforcement)
```

Config files are JSON, loaded from the service's CWD by default. All three services support an env var override for the config path (`SHEPHERD_CONFIG_PATH`, `CORGI_CONFIG_PATH`, `VIGIL_CONFIG_PATH`). Changes to hot-reloaded files (corgis, assignments) take effect on the next poll cycle with no restart.

---

## Known Limitations

- **Vigil ACME state is in-memory.** A Vigil restart during ACME issuance loses pending orders. Clients retry automatically but there may be a delay of one Shepherd poll interval.
- **Single Shepherd instance.** There is no built-in HA or failover for Shepherd. Corgis tolerate outages via the fail-stale cache but cannot renew certs while Shepherd is down.
