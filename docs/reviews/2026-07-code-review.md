# Credo Code Review — July 2026

**Scope:** Full-codebase review of the four services (`vigil`, `corgi`, `shepherd`, `dashboard`) plus the shared `credo-lib`. Focus areas: correctness bugs, security (checked against the CLAUDE.md invariants), code quality/idiom, and architecture/test coverage.

**Method:** Manual read of all significant source files. This is a review document for later triage — findings are not filed as issues. Line references are to the state of `main` at review time (commit `77dbf1b`).

## How to read this

Each finding has a **severity** and a **category**:

- **Severity** — `Critical` / `High` / `Medium` / `Low` / `Info`. Severity reflects impact assuming a realistic threat model (services talk mTLS-to-mTLS; the dashboard BFF is the main human-facing surface).
- **Category** — `Security`, `Correctness`, `Quality`, `Architecture/Tests`.

Findings are grouped by service, most-severe first within each group. A summary table is at the end.

Two important trust-boundary notes that recur below:

1. **Vigil and the Shepherd agent port only accept configured mTLS identities.** Many issues are gated behind "must already be a valid mTLS peer," which bounds blast radius but does *not* make cross-tenant / cross-identity abuse acceptable — the auth model is explicitly URI-SAN-scoped.
2. **The dashboard BFF is reachable by any authenticated dashboard user** (including `readonly`), so BFF-side SSRF/argument-injection is more exposed than the Rust services.

---

## Vigil (private CA / ACME server)

Vigil is the highest-value target in the system: it signs certificates. The findings here matter most.

### V1 — ACME `revoke-cert` does not prove control of the certificate key `[High] [Security]`

`vigil/src/acme.rs` `revoke_cert` calls `validate_jws(&state, &request_url, &body, false, false, None)` — i.e. it accepts either the `kid` (account-key) path or the `jwk` (certificate-key) path, and passes `auth_user_id = None`.

RFC 8555 §7.6 allows revocation signed by the certificate's own key pair, but the server must then verify the JWS was signed by *that certificate's* key. Here it does not:

- On the `jwk` path, `validate_jws` only checks the JWS is internally consistent with the supplied JWK (lines 366–452). It never compares the JWK to the public key of the certificate being revoked.
- `jws.account_id` is `None` on the `jwk` path, so the account-ownership check at `acme.rs:1677` (`if let Some(ref account_id) = jws.account_id { … }`) is **skipped entirely**.

**Failure scenario:** any client holding a valid mTLS cert in `rbacIdentities` (including a `readonly` identity) generates a throwaway keypair, signs a `revoke-cert` JWS with it via the `jwk` path, and supplies the `certificateId` (or DER) of *any* certificate Vigil ever issued — belonging to any ACME account or any other tenant. Vigil revokes it. This is broken access control with a denial-of-service payload against arbitrary certificates.

**Fix direction:** on the `jwk` path, require that the JWK's public key equals the SubjectPublicKeyInfo of the certificate identified in the payload before revoking; otherwise reject. On the `kid` path the existing account-ownership check is correct.

### V2 — CSR signature (proof-of-possession) is never verified before signing `[Medium] [Security]`

`vigil/src/ca.rs` `sign_csr` → `extract_csr_fields` parses the CSR's subject, SANs, and SubjectPublicKeyInfo but never calls the CSR's `verify_signature()`. A grep confirms no CSR self-signature check exists anywhere in `vigil/src`.

A well-behaved CA verifies the CSR's self-signature so the requester proves possession of the private key for the key being certified. Without it, Vigil will sign a certificate binding *any* SubjectPublicKeyInfo the caller pastes in, regardless of whether the caller controls that key.

**Impact is bounded** on the ACME path (domain control is still proven by the challenge) and by `issuance_policy` (SAN suffixes are restricted), so this is Medium rather than High. But it removes a standard CA integrity check on both the direct `/certificates/sign` endpoint and ACME `finalize`, and it means the "issued to" key in a cert isn't guaranteed to be the requester's. Add `csr.verify_signature()` (x509-parser supports it) and reject on failure.

### V3 — All ACME protocol state is in-memory; nonces and orders die on restart `[Medium] [Architecture/Tests]`

Orders, authorizations, challenges, and replay nonces live only in `state.inner.*` maps (`acme.rs` header TODO already flags this). Consequences:

- A Vigil restart mid-issuance invalidates every in-flight order and every outstanding nonce, so clients get `badNonce`/`order not found` and must restart the flow.
- Replay-nonce protection resets on restart (all previously issued nonces are forgotten), which is acceptable for security but means no cross-restart continuity.
- ACME *accounts* are persisted (`save_accounts`/`restore_accounts`) but the objects that reference them are not, so account counters and order references can drift.

This is called out as planned work in `docs/vigil-rs-port-plan.md`; recording it here because it affects correctness under normal operational events (deploys, crashes), not just disaster scenarios.

### V4 — Header-derived URLs are inserted into `HeaderMap` with `.parse().unwrap()` `[Low] [Correctness]`

Throughout `acme.rs`, `Location` and `Replay-Nonce` values are built from the request `Host` header and inserted via `loc.parse().unwrap()` (e.g. lines 625, 683, 742, 964). `extract_host_scheme` takes the `Host` header verbatim. A `Host` value containing bytes illegal in an HTTP header value would make `.parse::<HeaderValue>()` return `Err`, and the `.unwrap()` panics the connection task. It only kills the one request, but it is a client-triggerable panic. Validate/normalize the host, or handle the parse error.

### V5 — Hand-rolled DER certificate builder is correct but fragile and untested `[Low] [Quality]`

`vigil/src/ca.rs` constructs `TBSCertificate` by hand (`der_*` helpers, `sign_csr`). It works, but:

- Issued certs carry only BasicConstraints + KeyUsage(digitalSignature) + SAN. No SubjectKeyIdentifier, AuthorityKeyIdentifier, or ExtendedKeyUsage. Some strict TLS stacks and chain-builders want AKI/SKI; absence can cause path-building failures against certain clients.
- There are no unit tests over `sign_csr` output (e.g. re-parsing the emitted DER and asserting fields/extensions). Given this is security-critical, hand-rolled DER, it deserves round-trip tests.

Not a correctness bug today, but a maintenance and interop risk worth a test harness.

### V6 — `none-01` validation is reported to clients as `http-01` `[Info] [Quality]`

In `new_order`, a `none-01` challenge is emitted with `challenge_type: "http-01"` (acme.rs:906) so standard clients can deserialize it. This is a deliberate shim (commented), but it means the wire type misrepresents the actual validation performed. Fine internally; note it as a surprise for anyone debugging with a real ACME client. Keep `none-01` gated behind `allow_none_validation` (it is).

---

## Corgi (node agent)

### C1 — Private keys are written world-readable, then `chmod`ed (TOCTOU window) `[Medium] [Security]`

`corgi/src/archive.rs` `write_file` does `fs::write(path, data)` then `set_permissions(path, mode)`. The same pattern is in `cert_ops.rs` `generate_key` / `generate_key_and_csr` (write key, then `set_permissions(0o600)`). `fs::write` creates the file with `0666 & ~umask` (typically `0644`), so between the write and the chmod the **private key exists group/world-readable** on disk. A local unprivileged user can win that race and read the key.

This directly touches the CLAUDE.md invariant *"Cert files must respect the file-policy permissions."* Fix by creating the file with restrictive mode up front — `OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)` (or `0o640` for keys with a group) — rather than writing then chmod'ing. Also relevant to `credo-lib` (see L2).

### C2 — `acme_challenge_create` writes to an arbitrary `filePath` from the request body `[Low] [Security]`

`corgi/src/routes.rs` `acme_challenge_create` takes `filePath` from the JSON body and does `create_dir_all(parent)` + `write(path, …)`. The endpoint is `Role::Admin`-gated and only Shepherd's mTLS identity can reach it, so this is inside the trust boundary — but a compromised or buggy Shepherd could make Corgi write attacker-chosen content to any path the Corgi process can write (e.g. a cron drop, an authorized_keys). Defense-in-depth: constrain challenge writes to a configured challenge web-root and reject paths that escape it.

### C3 — Reconcile uses a hardcoded 30-day renewal threshold, ignoring `renew_before_days` `[Low] [Correctness]`

`corgi/src/sync.rs` `reconcile_once`, the `(Some(_), None)` branch (local cert present, Shepherd reports no fingerprint) triggers a refetch only when `cert_days_remaining < 30`. The `30` is hardcoded and ignores the assignment's configured `renew_before_days`. For certs with a renewal window other than 30 days this makes Corgi's local fallback behavior inconsistent with Shepherd's policy. Thread the configured value through.

### C4 — Corgi→Shepherd client silently disables server verification when no CA is configured `[Low] [Security]`

`corgi/src/shepherd.rs` `build_shepherd_client`: if `mtls.ca_path` is `None`, it sets `danger_accept_invalid_certs(true)` (mirroring the old Node `rejectUnauthorized:false`). In normal operation the Shepherd CA is installed during bootstrap, so this is a misconfiguration fallback — but it fails *open*: a Corgi with a missing/empty CA path will accept any server cert and pull assignments (and challenge material) from an unauthenticated peer. Prefer failing closed (error out) when no CA is configured, or log a loud warning. (The `corgi server config-check` path at `main.rs:318` also uses `danger_accept_invalid_certs(true)`, which is acceptable for a diagnostic-only reachability probe.)

### C5 — Reconciliation is strictly sequential; one slow cert blocks the rest `[Low] [Correctness]`

`reconcile_once` loops assignments and `await`s each fetch/install inline. A single cert whose Shepherd fetch or hook is slow delays reconciliation of every other cert in the loop for that cycle. Fine at small fleet sizes; worth bounded concurrency if assignment counts grow.

### C6 — Parameterized hooks are safe; simple hooks intentionally use a shell `[Info] [Security]`

Noting the positive: `corgi/src/hooks.rs` runs parameterized hooks through `spawn_no_shell` with per-arg regex validation (good — no injection even if an arg contains shell metacharacters). `Simple` hooks run through `sh -c`, but those command strings come from operator config, not from the wire. This is a reasonable design; no change needed, documented so it isn't "fixed" by mistake.

---

## Shepherd (control plane)

### S1 — PoP/bootstrap CA chain verification skips validity and constraints `[Medium] [Security]`

`shepherd/src/routes_api.rs` `verify_pop_cert` (and the identical pattern in the dashboard's `pop.ts` `verifyCertChain`) establishes trust purely by walking signature links (`is_signed_by`) from the leaf to the CA bundle. It never checks:

- certificate **validity dates** (an expired leaf or expired intermediate passes),
- **BasicConstraints `cA`** on promoted intermediates,
- key usage.

So a PoP presented with an expired enrollment certificate still exchanges for a live JWT + refresh token. Since the refresh token TTL is derived from the cert `notAfter` (`routes_api.rs:205`, `cert_not_after`), an expired cert yields an already-expired refresh token in the normal path — but the *access token* is still minted (1h) and the PoP is accepted, which is more than an expired identity should get. Use a real path validator (or at minimum check `not_before`/`not_after` and `cA`) instead of raw signature chaining.

### S2 — Bootstrap admin-token comparison is not constant-time `[Low] [Security]`

`shepherd/src/routes_api.rs` `token()` compares the env-provided `SHEPHERD_BOOTSTRAP_ADMIN_TOKEN` with `provided == bootstrap_token` (`==` on `&str`), granting `Role::Admin` + a 24h refresh token on match. Corgi's bootstrap path correctly uses `subtle::ConstantTimeEq` (`corgi/src/bootstrap.rs:47`); Shepherd should too. Bootstrap-only and network-gated, hence Low, but it's an easy consistency fix.

### S3 — `cancel_renewal_job` deletes the record but doesn't stop the running task `[Low] [Correctness]`

`routes_api.rs` `cancel_renewal_job` does `jobs.remove(&job_id)`. The async issuance task spawned in `renew_cert`/`admin_provision_or_renew` keeps running; its later `update_phase`/`complete_job`/`fail_job` calls use `get_mut(&id)` and become silent no-ops once the record is gone (confirmed in `renewal_jobs.rs`). Net effect: "cancel" hides the job from the UI but the ACME order still completes server-side and the cert may still be installed on the corgi. Either mark a cancel flag the task checks at phase boundaries, or document that cancel is cosmetic.

### S4 — Pervasive `.unwrap()` on mutex locks and JSON serialization `[Low] [Quality]`

~72 `.unwrap()` calls in `shepherd/src` outside tests. Two classes matter:

- `*state.corgis_mtime.lock().unwrap()` (and the other `_mtime` mutexes) — a panic while holding one of these poisons the lock, turning subsequent reloads into hard panics.
- `serde_json::to_value(job).unwrap()` / `to_value(account).unwrap()` in handlers — serialization of these types won't fail in practice, but the pattern is fragile.

Prefer `?`-propagation into `AppError::Internal` for the serialization cases and a poison-tolerant lock strategy (or `parking_lot`) for the mtime mutexes.

### S5 — `get_cert` (agent port) returns any corgi's cert material without checking the authenticated node `[Low] [Security]`

`shepherd/src/routes_corgi.rs` `get_cert` binds `_node` (the authenticated `CorgiNodeConfig`) but ignores it, looking up the assignment purely by the `:id` path parameter. Contrast with `get_assignments`, which enforces `node.name != corgi_id → 403`. So corgi A, authenticated with its own cert, can fetch cert material (including any private key Shepherd holds) for an assignment addressed to corgi B by calling `/agents/B/certs/<name>`. In practice Shepherd rarely stores private keys for CSR-issued certs (they stay on the corgi), which limits exposure to public cert/chain material — but the authorization check that exists on the sibling endpoint is missing here. Add the same `node.name == corgi_id` guard.

### S6 — Two `urlencoded` helpers with different behavior `[Info] [Quality]`

`routes_corgi.rs::urlencoded` only replaces `/` → `%2F`; `issuance.rs::urlencoded` does full percent-encoding. Same name, different semantics, used for building corgi URLs. Consolidate into one helper in `credo-lib` to avoid a future mismatch when a cert name contains other special characters.

---

## Dashboard (React SPA + Express BFF)

The BFF holds the mTLS credentials and is reachable by any authenticated session, so its server-side endpoints are the sharpest surface.

### D1 — `/api/cert-remote` is an authenticated SSRF primitive `[Medium] [Security]`

`dashboard/server/index.ts` `GET /api/cert-remote` opens `tls.connect({ host: hostParam, port, rejectUnauthorized: false })` to any host/port taken from query params, then returns parsed certificate info. Any logged-in user (readonly suffices) can make the BFF connect to arbitrary internal addresses and ports — a network scanner / SSRF that also reports whether a TLS service is present and its cert. Restrict to an allowlist, block private/link-local ranges, or gate behind a higher role and log usage.

### D2 — `dig` argument injection via user-controlled hostname/nameserver `[Medium] [Security]`

In `runJobDnsQueries`, the command is `execFileAsync('dig', ['@'+ip, 'TXT', hostname, '+short', …])`. `execFile` avoids shell interpretation (good, no shell injection), but `hostname` is user-controlled and passed as a positional arg with no `--` terminator or validation. A hostname like `-f/etc/passwd` is interpreted by `dig` as the `-f <file>` batch option → argument injection (arbitrary file read into batch mode, or other flag abuse). The `/api/dns/txt` path similarly feeds a user `nameserver` into `resolver.setServers([...])`. Validate hostnames against a DNS-name regex and reject `-`-prefixed values (and insert `--`/`+`-guarded args where `dig` supports it).

### D3 — Dashboard PoP chain verification shares S1's weakness `[Medium] [Security]`

`dashboard/server/auth/pop.ts` `verifyCertChain` mirrors Shepherd's `verify_pop_cert`: it anchors intermediates and checks `leaf` signature linkage via `X509Certificate.verify(publicKey)`, but never checks validity dates or `cA`. Node's `.verify()` checks only the signature, not `notAfter`. So an enrollment PoP with an expired cert passes chain verification at `/auth/enroll/verify`. Add explicit `validTo`/`validFrom` checks (and ideally basic-constraints) before trusting the chain. (Same root cause as S1; fixing both together is sensible.)

### D4 — BFF error handler reflects internal error messages to clients `[Low] [Security]`

`normalizeError` returns `clientMessage: error.message` for generic `Error`s and echoes upstream Shepherd error bodies. This can leak internal paths, stack-adjacent details, or upstream diagnostics to the browser. Return a generic client message and keep the detail in `logMessage` only.

### D5 — WebAuthn is configured with `requireUserVerification: false` / `userVerification: 'preferred'` `[Low] [Security]`

`dashboard/server/auth/webauthn.ts` registration and authentication both set `requireUserVerification: false` (and `'preferred'`). For an admin console governing a private CA, `'required'` UV is the stronger default and closes the gap where a present-but-unverified authenticator is accepted. Consider requiring UV, at least for `admin`-role accounts.

### D6 — Login/enroll challenge store is process-local in-memory `[Low] [Architecture/Tests]`

`routes-auth.ts` `pendingChallenges` and `index.ts` `dnsJobs` are module-level `Map`s. With a single BFF process this is fine, but it silently breaks under any horizontal scaling / restart (an in-flight WebAuthn ceremony or DNS job vanishes). Document the single-instance assumption or move to the shared session/file store.

### D7 — Frontend `Certificates.tsx` is 1,308 lines `[Info] [Quality]`

The largest client file by far; a candidate for decomposition (table, detail drawer, renew flow) to keep it reviewable. No functional issue.

---

## credo-lib (shared)

### L1 — `identity_from_header` percent-decoding is byte-lossy `[Low] [Correctness]`

`credo-lib/src/auth.rs` `percent_decode` pushes decoded bytes as `byte as char`, which is only correct for ASCII; any non-ASCII byte in a percent-encoded proxy header is mangled (each byte becomes a `char`, not decoded as UTF-8). For PEM/base64 cert headers this is harmless in practice (they're ASCII), but the helper is subtly wrong and would corrupt any non-ASCII SAN. Decode into a `Vec<u8>` and parse from bytes.

### L2 — File-policy helpers don't create files atomically with restrictive modes `[Medium] [Security]`

`credo-lib/src/file_policy.rs` `apply_file_policy` chmods *after* the file exists — same TOCTOU class as C1, and this is the canonical helper the invariant refers to. Consider providing a `write_secret(path, bytes, mode, owner, group)` in `credo-lib` that creates with the target mode via `OpenOptions.mode()` before writing, and route all key/cert writes (corgi archive, jwt key, refresh tokens) through it. This would fix C1 and the JWT-key/refresh-token writers in one place.

### L3 — `config::interpolate` is O(vars × replaces) and does full-string scans `[Info] [Quality]`

`interpolate` loops every var and does a `String::replace` per var, repeated to a fixpoint in `vars_with_env`. Fine for small configs; just noting it's quadratic-ish and unbounded-iteration if a var can reference itself (the fixpoint loop would spin — though `map == snapshot` breaks it once stable). Low priority.

---

## Cross-cutting observations

- **Auth invariants are respected** where it counts: mTLS is required on all inter-service ports, URI-SAN matching is used consistently (no fingerprint/fleet fallbacks), and the agent vs dashboard auth chains are separate as documented. S5 is the one place a per-endpoint authZ check is missing relative to its sibling.
- **The custom X.509 chain verification pattern is duplicated** in three places (`shepherd verify_pop_cert`, `dashboard verifyCertChain`, and implicitly the WebPKI verifier in `credo-lib`) with the first two sharing the same validity-check gap (S1/D3). Worth consolidating onto a real path validator.
- **Private-key-at-rest handling has a systemic TOCTOU** (C1/L2) across every writer that creates a key then chmods it. This is the single highest-value quality fix because one shared helper closes all instances.
- **Test coverage is thin on the security-critical paths.** Good unit tests exist for `build_domains`, PID handling, http-01 validation, and rate-limit serialization, but there are no tests over `sign_csr` DER output, JWS/PoP verification edge cases, or the revoke authorization paths (V1). Those are exactly the paths where a regression is most costly.

## Summary table

| ID | Service | Severity | Category | One-line |
|----|---------|----------|----------|----------|
| V1 | vigil | High | Security | `revoke-cert` jwk path revokes any cert without proving key control |
| V2 | vigil | Medium | Security | CSR self-signature (proof-of-possession) never verified before signing |
| V3 | vigil | Medium | Architecture | ACME orders/authzs/challenges/nonces are in-memory; lost on restart |
| V4 | vigil | Low | Correctness | Host-header-derived headers inserted with `.parse().unwrap()` (panic) |
| V5 | vigil | Low | Quality | Hand-rolled DER cert builder lacks AKI/SKI and round-trip tests |
| V6 | vigil | Info | Quality | `none-01` reported on the wire as `http-01` |
| C1 | corgi | Medium | Security | Private keys written world-readable then chmod'ed (TOCTOU) |
| C2 | corgi | Low | Security | `acme_challenge_create` writes to arbitrary `filePath` from body |
| C3 | corgi | Low | Correctness | Hardcoded 30-day renewal threshold ignores `renewBeforeDays` |
| C4 | corgi | Low | Security | Corgi→Shepherd client fails open (no server verify) when CA unset |
| C5 | corgi | Low | Correctness | Reconciliation is strictly sequential |
| C6 | corgi | Info | Security | (Positive) parameterized hooks are injection-safe by design |
| S1 | shepherd | Medium | Security | PoP CA chain check skips validity dates and basic constraints |
| S2 | shepherd | Low | Security | Bootstrap admin-token compared non-constant-time |
| S3 | shepherd | Low | Correctness | `cancel_renewal_job` deletes record but running task continues |
| S4 | shepherd | Low | Quality | Pervasive `.unwrap()` on mutex locks / JSON serialization |
| S5 | shepherd | Low | Security | `get_cert` ignores authenticated node identity (missing authZ) |
| S6 | shepherd | Info | Quality | Two `urlencoded` helpers with divergent behavior |
| D1 | dashboard | Medium | Security | `/api/cert-remote` is an authenticated SSRF primitive |
| D2 | dashboard | Medium | Security | `dig` argument injection via user-controlled hostname/nameserver |
| D3 | dashboard | Medium | Security | PoP chain verification skips validity/constraints (mirrors S1) |
| D4 | dashboard | Low | Security | BFF error handler reflects internal error text to clients |
| D5 | dashboard | Low | Security | WebAuthn accepts unverified user presence (`UV: preferred`) |
| D6 | dashboard | Low | Architecture | Challenge / DNS-job stores are process-local in-memory |
| D7 | dashboard | Info | Quality | `Certificates.tsx` is 1,308 lines |
| L1 | credo-lib | Low | Correctness | `percent_decode` is byte-lossy for non-ASCII |
| L2 | credo-lib | Medium | Security | File-policy helper chmods after create (systemic TOCTOU) |
| L3 | credo-lib | Info | Quality | `interpolate` is quadratic; fixpoint loop is unbounded-in-theory |

**Suggested triage order:** V1 (authorization bug on the CA) → the private-key TOCTOU cluster L2/C1 (one shared fix) → V2 (CSR PoP) → the chain-validation cluster S1/D3 → the dashboard SSRF/argument-injection pair D1/D2 → everything else.
