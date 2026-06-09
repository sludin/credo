# Shepherd — CONTEXT.md

## Role

Shepherd is the TLS certificate management control plane. It owns the certificate lifecycle end-to-end: issuing certs via ACME (against Vigil or Let's Encrypt), storing the cert material in a certbot-style archive, and making it available to Corgi agents on demand. It runs two separate authenticated API servers—one for Corgi nodes (mTLS, port 7010) and one for dashboard/admin access (JWT or mTLS, port 7011). Background loops poll each Corgi for health and fingerprint drift; when a Corgi's local fingerprint diverges from Shepherd's store, Shepherd serves the fresh material on the next Corgi pull.

---

## Module Map

| File | Role |
|------|------|
| `main.rs` | CLI entry (`shepherd server start`, bootstrap commands, cert store inspection). Spawns background poll/health loops and the two HTTP servers. |
| `lib.rs` | Module re-exports. |
| `config.rs` | Loads `shepherd.config.json`; supports `$VAR` interpolation from environment/`.env`. Hot-reloads on SIGHUP. |
| `state.rs` | `AppState` — holds everything shared across request handlers: config (via `ArcSwap`), JWT keys, Corgi client pool, renewal job map, accounts, assignments, CA configs, Vigil client. |
| `types.rs` | Core data structures: `Account`, `CorgiNodeConfig`, `ManagedAssignment`, `RenewalJob`, `CaConfig`, `AuthenticatedUser`, `CertStoreEntry`. |
| `server.rs` | Builds the two Axum routers; sets up TLS acceptors with `rustls`; wires auth middleware. |
| `auth.rs` | `corgi_auth_middleware` (mTLS URI SAN → Corgi lookup) and `api_auth_middleware` (JWT Bearer → account, or mTLS URI SAN → account). |
| `jwt.rs` | ES256 JWT sign/verify; JWKS endpoint; key generation and loading. |
| `refresh_tokens.rs` | Opaque refresh token store (in-memory; optional disk persistence). |
| `issuance.rs` | Core ACME flow: CSR → ACME account → new order → challenge → finalize → cert store. |
| `cert_store.rs` | Reads/writes `store/archive/{name}/cert-NNNN.pem`; manages `store/live/{name}/` symlinks; computes SHA256 fingerprints. |
| `renewal_jobs.rs` | Async job state machine: `Queued` → `SubmittingOrder` → `Validating` → `Finalizing` → `Installing` → `Completed`/`Failed`. |
| `poll.rs` | Background tasks: lightweight health pings (configurable interval) and full poll cycle (fingerprint sync, cert maintenance). |
| `acme_client.rs` | Per-CA ACME account cache; builds `instant-acme` HTTP client with mTLS/EAB support. |
| `corgi_client.rs` | Per-Corgi mTLS `reqwest` client pool; `corgi_get`/`corgi_post` helpers; bootstrap identity fallback. |
| `corgis.rs` | Parses `shepherd.corgis.json`; resolves per-Corgi mTLS credential overrides against defaults. |
| `assignments.rs` | Parses `shepherd.assignments.json`; defaults `certName` to `domain` when omitted. |
| `cas.rs` | Parses `shepherd.ca.json`; builds `CaConfig` with ACME directory URL, validation config, optional mTLS to CA. |
| `accounts.rs` | Parses `shepherd.accounts.json`; CRUD; lookup by identity URI or account ID. |
| `routes_api.rs` | Dashboard port endpoints: `/auth/token`, `/auth/jwks`, `/admin/assignments`, `/admin/certstore`, `/admin/renewal-jobs`, `/admin/cas`, `/accounts`, flock status. |
| `routes_corgi.rs` | Agent port endpoints: `/agents/:id/assignments`, `/agents/:id/certs/:name`, `/agents/:id/provision/:name`, `/agents/:id/renew/:name`, renewal status poll. |
| `routes_bootstrap.rs` | One-time bootstrap endpoints: `/bootstrap/admin-cert` (sign CSR), `/bootstrap/corgi` (enroll node). |
| `log_middleware.rs` | Structured one-line request/response logging for both ports. |
| `dns_providers/he.rs` | Hurricane Electric DDNS dynamic record updates for dns-01 validation. |

---

## Data Flow

### Certificate provisioning (initial, Corgi-triggered)

1. Corgi calls `POST /agents/{id}/provision/{name}` — sends a fresh CSR PEM (and optionally its current fingerprint).
2. `corgi_auth_middleware` validates Corgi's client cert URI SAN against the Corgi registry. Mismatch → 401.
3. Route handler looks up the `ManagedAssignment` by cert name.
4. Calls `issue_cert()` in `issuance.rs`:
   a. Parse CSR PEM → DER.
   b. Get or create ACME account (keyed per CA; credentials cached on disk at `accountKeyPath.acme.json`).
   c. Submit `NewOrder` with DNS identifiers.
   d. Fetch authorizations; for each domain:
      - `Valid` → skip.
      - `Pending` → set DNS-01 record (via HE DDNS) or HTTP-01 challenge.
   e. Poll authoritative NS for DNS propagation.
   f. Notify ACME of challenge completion; poll until `Valid`.
   g. Finalize order with CSR; fetch cert chain.
   h. Split into `cert.pem` (leaf) + `chain.pem` (intermediates) + `fullchain.pem`.
5. `cert_store.rs` writes `store/archive/{name}/cert-NNNN.pem` (ordinal), updates `store/live/{name}/` symlinks.
6. Computes SHA256 fingerprint; stores in cert metadata.
7. Returns cert + chain in response body; Corgi installs locally.

### Certificate renewal (async, job-based)

1. Trigger: admin calls `POST /admin/renew/{name}`, or background poll detects expiry.
2. Shepherd creates a `RenewalJob` (UUID, `Queued`), returns `202 Accepted` with job ID immediately.
3. Async task drives the state machine:
   `Queued` → `SubmittingOrder` → `Validating` → `Finalizing` → `Installing` → `Completed` / `Failed`.
4. Corgi polls `GET /agents/{id}/renew/{name}/status` to track progress.
5. On `Completed`, Corgi fetches the new cert material via `GET /agents/{id}/certs/{name}`.

### Background poll cycle

1. Runs every `pollIntervalSeconds` (default 60 s).
2. For each Corgi: call `GET /flock` → list of `{ certName, fingerprint }`.
3. Compare each fingerprint to Shepherd's cert store.
4. If fingerprints differ and Corgi has a cert → schedule cert-maintenance pull.
5. If Corgi reports `null` fingerprint → skip (initial provisioning handles this).
6. Separately, health-check loop pings `GET /health` every `corgiHealthCheckIntervalSeconds` (default 300 s).

### Hot-reload (SIGHUP)

1. Re-read `shepherd.config.json` from disk.
2. Rebuild TLS server config and Vigil client if URLs/paths changed.
3. Gracefully shut down both servers; restart with new config.
4. Config changes (ports, TLS paths) take effect immediately. All background tasks pick up config via `state.config.load()` (lock-free `ArcSwap`).

---

## Config Schema

**Main file:** `shepherd.config.json` (path overridden by `SHEPHERD_CONFIG_PATH`).

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `agentPort` | number | 7010 | Corgi-facing API |
| `dashboardPort` | number | 7011 | Admin dashboard API |
| `bind` | string | `127.0.0.1` | Bind address for both servers |
| `tls.certPath` | string | — | Server cert (full chain PEM) |
| `tls.keyPath` | string | — | Server private key |
| `tls.clientCaPath` | string | — | Client CA bundle for mTLS validation |
| `auth.jwtSigningKeyPath` | string | — | ES256 private key for JWT signing |
| `corgisConfigPath` | string | `shepherd.corgis.json` | Corgi fleet inventory |
| `assignmentsConfigPath` | string | `shepherd.assignments.json` | Cert assignments |
| `caConfigPath` | string | `shepherd.ca.json` | CA configurations |
| `accountsPath` | string | `shepherd.accounts.json` | RBAC accounts |
| `certStoreDir` | string | `store` | Root for archive/live cert layout |
| `renewalJobsDir` | string | — | If set, job state persisted here; otherwise in-memory only |
| `renewBeforeDays` | number | 7 | Start renewal this many days before expiry |
| `pollIntervalSeconds` | number | 60 | Full poll cycle interval |
| `corgiHealthCheckIntervalSeconds` | number | 300 | Lightweight health check interval |
| `logLevel` | string | `info` | `fatal` / `warn` / `info` / `debug` |
| `dnsOverride` | object | `{}` | Hostname → IP overrides for Corgi connections |
| `identityUri` | string | — | Shepherd's URI SAN (required for Vigil auth) |
| `vigilUrl` | string | — | Vigil CA base URL; if absent, bootstrap endpoints are unavailable |
| `shepherdCaPath` | string | — | CA bundle to verify Vigil; falls back to `tls.clientCaPath` |

**Companion files** (all support `$VAR` interpolation):

- **`shepherd.corgis.json`** — fleet inventory. `defaults.mtlsCert/Key/Ca` apply to all Corgis; per-node fields override.
- **`shepherd.ca.json`** — keyed by CA name. Each entry: `protocol: "acme"`, `directoryUrl`, `accountKeyPath`, ACME-specific fields (`externalAccountBinding`, `validation`, `days`).
- **`shepherd.assignments.json`** — array of `ManagedAssignment`: `certName`, `corgi`, `ca`, `domain`, `sans`, `days`, `validation`, `keyAlgorithm`.
- **`shepherd.accounts.json`** — array of `Account`: `id`, `name`, `role` (`admin`/`operator`/`readonly`), `active`, `identities` (URI SANs).

---

## Error Handling

**Pattern:** Internal functions return `anyhow::Result<T>` with contextual `.with_context(|| "...")`. Route handlers convert `AppError` (from `credo-lib`) into HTTP responses via `IntoResponse`.

| `AppError` variant | HTTP status | Typical trigger |
|---|---|---|
| `Unauthorized` | 401 | Unknown Corgi cert, JWT verification failure, missing credentials |
| `Forbidden` | 403 | Corgi requesting another node's certs, insufficient role |
| `NotFound` | 404 | Unknown cert name, unknown Corgi ID |
| `BadRequest` | 400 | Malformed CSR, invalid request body |
| `Conflict` | 409 | Duplicate resource, race condition |
| `Internal` | 500 | Unexpected failures |

Background tasks (poll loop, renewal jobs) log errors but do not crash the process. ACME failures are captured in `RenewalJob.error` for retrieval via the API.

---

## Known Gotchas

1. **Shepherd never stores Corgi's private key.** When Shepherd provisions a cert, it generates a CSR internally via `rcgen` but holds no key material. Corgi must send a new CSR on every renewal — there is no Shepherd-side key reuse.

2. **Cert store ordinals are permanent.** Certs are stored as `cert-NNNN.pem` (zero-padded 4-digit ordinal). Old files remain in `archive/`; only `live/` symlinks are updated. Do not delete archive files — `next_ordinal()` increments past the highest existing file.

3. **Fingerprint sync does not push certs.** If the poll cycle finds a fingerprint mismatch, it only schedules a cert-maintenance action (Corgi will pull). Shepherd never pushes cert material unsolicited.

4. **`renewalJobsDir` is required for persistence.** Without it, all pending renewal jobs are lost on restart. Set this in production.

5. **Vigil client requires `vigilUrl`.** If `vigilUrl` is absent from config, `state.vigil_client` is `None` and all bootstrap endpoints return `503 Service Unavailable`.

6. **Identity URI matching is case-sensitive and exact.** Account `identities` must match the cert's URI SAN byte-for-byte. A trailing slash or casing difference causes 401.

7. **Role hierarchy is implicit.** `readonly` < `operator` < `admin`. Endpoints use `check_min_role()`; double-check the required role when adding new endpoints.

8. **Bootstrap cert is held in-memory initially.** On first boot in bootstrap mode, Shepherd's identity cert/key are stored as in-memory PEM strings in `AppState`. After deployment, update config to point to persistent file paths.

9. **SIGHUP doesn't persist config changes.** Hot-reload reads config *from disk*. If config was mutated in memory (not written back to the file), the in-memory change is lost on reload.

10. **ACME account credentials are plain JSON.** `{accountKeyPath}.acme.json` contains the ACME private key. Protect this file with restrictive permissions (readable only by the Shepherd process). Losing it forces account re-creation at the CA.

11. **Flat vs. nested config field names.** Config supports both `tls.certPath` (nested, preferred) and `tlsCert` (flat, legacy). Use nested form for new configs.

12. **dns-01 propagation adds latency.** For each challenge, Shepherd polls authoritative nameservers before notifying the ACME server. Add `propagation_delay_seconds` to CA validation config for CAs that are strict about propagation timing.

---

## Dev Commands

```bash
# Build
cargo build --bin shepherd                     # debug build
cargo build --release --bin shepherd           # release build

# Run
cargo run --bin shepherd -- server start       # start with config in CWD
SHEPHERD_CONFIG_PATH=/path/to/config.json \
  cargo run --bin shepherd -- server start     # explicit config path

# Validate config only (exits without starting servers)
cargo run --bin shepherd -- server check-config

# Bootstrap (one-time initial deployment)
cargo run --bin shepherd -- bootstrap server --vigil-secret <secret>   # prints admin token
cargo run --bin shepherd -- bootstrap admin --admin-token <token> ...
cargo run --bin shepherd -- bootstrap corgi --admin-token <token> ...

# Cert store inspection
cargo run --bin shepherd -- cert store         # list all certs
cargo run --bin shepherd -- cert inspect <name>

# Tests
cargo test -p shepherd                         # shepherd unit + integration tests
cargo test                                     # full workspace

# Hot-reload
kill -HUP $(pgrep shepherd)
```

---

## Integration Points

**Outbound (Shepherd calls these):**

| Target | Auth | What Shepherd calls |
|--------|------|---------------------|
| Vigil CA (`:7020`) | mTLS (Shepherd identity cert) | ACME directory, new-order, authz, challenge, finalize |
| Corgi nodes (`:7001`) | mTLS (Shepherd identity cert) | `/health`, `/flock`, `/agents/:id/certs/:name`, `/agents/:id/provision/:name`, `/agents/:id/renew/:name` |
| DNS (HE DDNS) | API key | Dynamic TXT record updates for dns-01 challenges |
| Authoritative NS | None | Propagation polling via `hickory-resolver` |

**Inbound (these call Shepherd):**

| Caller | Port | Auth | Key endpoints |
|--------|------|------|--------------|
| Corgi nodes | 7010 | mTLS URI SAN → Corgi registry | `/agents/:id/assignments`, `/agents/:id/certs/:name`, `/agents/:id/provision/:name`, `/agents/:id/renew/:name` |
| Dashboard / admin | 7011 | JWT Bearer or mTLS URI SAN → account | `/auth/token`, `/admin/certstore`, `/admin/renewal-jobs`, `/accounts`, flock status |
| Bootstrap client (one-time) | 7011 | In-memory admin token | `/bootstrap/admin-cert`, `/bootstrap/corgi` |
