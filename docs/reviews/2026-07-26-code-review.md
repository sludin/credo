# Credo Code Review — 2026-07-26

**Scope:** Full-codebase, fresh-eyes review of `vigil`, `corgi`, `shepherd`, `credo-lib`, `dashboard` (client + BFF), and the operational scripts under `deploy/` and `ceremony/`. Security is the primary focus; correctness, architecture-invariant adherence, and code quality are secondary. Line references are to the state of `logs-timestamp-display` / effectively `main` at commit `fe87052`.

**Method:** Eight parallel review passes (one or two per service/area), each with direct file reads and `git diff`/`git log` against the previous review's baseline (`77dbf1b`, 2026-07-08) to separate genuinely new code from unchanged code. The most severe findings below were independently re-verified against the actual source by the synthesizing pass, not just trusted from the sub-review.

**Predecessor doc:** `docs/reviews/2026-07-code-review.md` (2026-07-08, commit `77dbf1b`). Every open finding from that review (`V1`–`V6`, `C1`, `S1`, `S2`, `S5`) was explicitly re-checked; status noted inline below.

---

## Prioritized list

Ordered most-severe-first. Security issues are called out explicitly; a few high-value correctness/architecture issues are interleaved where they materially affect security posture.

1. **[Critical] Vigil: `revoke-cert` never verifies proof-of-possession on the certificate-key path — any mTLS peer can revoke *any* certificate the CA ever issued.** `vigil/src/acme.rs` `revoke_cert`. Still open since the last review (was V1), now confirmed to have a bigger blast radius than originally scored. → [Vigil §1](#v1)
2. **[Critical] Dashboard: PoP/enrollment CA-chain verification silently no-ops if `mtls.caPath` is unset, collapsing identity proofing to "knows the invite token."** `dashboard/server/auth/pop.ts:99-115`. → [Dashboard §1](#d1)
3. **[Critical] `deploy/migrate-credo-store.sh` leaves Vigil's intermediate CA signing key and Shepherd's own archived private keys world-readable (644) after migration.** Only corgi's `privkey-*.pem` and one named Shepherd JWT key file are protected; Vigil and Dashboard get no exception at all. → [Ops §1](#o1)
4. **[High] Vigil: `finalize_order` unions the client's CSR SANs into the issued certificate instead of restricting to validated order identifiers — lets a client smuggle an unchallenged domain into a cert.** `vigil/src/ca.rs:554-569`. → [Vigil §2](#v2)
5. **[High] Shepherd: agent-port `get_cert`/`provision_cert`/`renew_cert`/`renew_status` trust the URL's `:corgi_id` instead of the authenticated corgi identity — any corgi can read/manipulate any other corgi's cert (and future private-key) material.** `shepherd/src/routes_corgi.rs`. Previously flagged as Low (S5); re-rated High because the response schema already wires `keyPem` through. → [Shepherd §1](#s1)
6. **[High] Shepherd: `POST /auth/refresh` doesn't check the account is still `active`, letting a deactivated/deleted account keep refreshing its session indefinitely.** `shepherd/src/routes_api.rs:251-280`. → [Shepherd §2](#s2)
7. **[High] Shepherd: HE DDNS provider logs the `ddnsKey` credential in cleartext at `info`, and disables TLS verification on that same outbound call.** `shepherd/src/dns_providers/he.rs:38-44,29`. → [Shepherd §3](#s3)
8. **[High] Dashboard: admin user-management routes (`/auth/admin/*`) never get the cached session role revalidated against Shepherd** — a demoted/deactivated admin keeps admin-panel access for the life of the session cookie. `dashboard/server/index.ts:310` vs. `:320`. → [Dashboard §2](#d2)
9. **[High] credo-lib: `file_policy::apply_file_policy` — the shared helper meant to enforce safe permissions on cert/key files — has zero callers anywhere in the codebase.** Corgi (`cert_ops.rs`, `archive.rs`) and Shepherd (`jwt.rs`) each independently reimplement an unsafe write-then-chmod pattern instead (confirms/generalizes prior **C1**, still open). → [credo-lib §1](#cl1)
10. **[High] Shepherd: reconcile loop conflates cheap liveness probing with long synchronous ACME issuance work — a single fleet-wide config reload can stall liveness/nudge detection for the *entire fleet* for as long as queued issuances take (potentially tens of minutes).** `shepherd/src/poll.rs`. → [Shepherd §4](#s4)
11. **[High/Architecture] Shepherd's renewal path actually *pushes* signed cert material to Corgi (`POST /flock/:name/install`) — this is a real violation of the documented "Shepherd never pushes cert material" invariant**, not just the data-free nudge. Pre-existing, not part of this diff, but newly identified. → [Shepherd §5](#s5)
12. **[Medium] Shepherd: percent-encoded path traversal in `/admin/certstore/:name` lets any authenticated account (including `readonly`) read `cert.pem`/`fullchain.pem` outside the intended certstore tree.** Empirically confirmed against axum 0.7.9's path-decoding behavior. `shepherd/src/routes_api.rs:361-395`. → [Shepherd §6](#s6)
13. **[Medium] `Role::from_str` (credo-lib) fails open to `Role::Admin` on any unrecognized string, and Shepherd's `update_account` feeds raw user input straight into it.** `credo-lib/src/types.rs:52-58`, `shepherd/src/routes_api.rs:1080`. → [credo-lib §2](#cl2)
14. **[Medium] Cross-loop TOCTOU race: Shepherd's reconcile-triggered and periodic-sweep renewal paths can both request a fresh CSR for the same cert before either registers a job, so Corgi's single pending-key file can be overwritten mid-flight, installing a cert against the wrong key.** `shepherd/src/poll.rs::cert_maintenance`. → [Shepherd §7](#s7)
15. **[Medium] Corgi silently disables TLS verification on its outbound mTLS client to Shepherd when `mtls.caPath` is unset — no warning logged.** `corgi/src/shepherd.rs:21-24`. → [Corgi §2](#c2)
16. **[Medium] credo-lib log-query subsystem has no upper bound on caller-supplied `limit` and does full synchronous file reads on the async runtime — a resource-exhaustion vector reachable via `/admin/logs`, `/logs`.** `credo-lib/src/log_query/historical.rs`, `follow.rs`. → [credo-lib §3](#cl3)
17. **[Medium] Vigil: unbounded recursive DER parsing of untrusted OCSP request bodies — a crafted deeply-nested DER can exhaust the stack (DoS) via any authenticated mTLS peer.** `vigil/src/pki_wire.rs:72-100`. → [Vigil §3](#v3)
18. **[Medium] Vigil: `storage_lock` mutex is declared but never acquired — JSON-backed cert/account/user stores have unguarded read-modify-write races that can silently drop concurrent updates.** `vigil/src/state.rs:28,65`, `storage.rs`. → [Vigil §4](#v4)
19. **[Medium] Dashboard: 30-minute stale-role fallback window plus no single-use replay protection on PoP tokens.** `dashboard/server/auth/middleware.ts`, `pop.ts`. → [Dashboard §3](#d3)
20. **[Medium] Dashboard: no session regeneration on login/enrollment (session fixation), mitigated but not eliminated by `sameSite: strict`.** `dashboard/server/routes-auth.ts`. → [Dashboard §4](#d4)
21. **[Medium] `deploy/migrate-credo-store.sh`: path-based `chown`/`chmod` on a live filesystem with no service-stop requirement — a TOCTOU window on a store that's continuously being written by the very services being migrated.** → [Ops §2](#o2)
22. **[Medium] `deploy/migrate-credo-store.sh`: the `shepherd.jwt.key.pem` special case matches an assumed filename that Shepherd's config never actually enforces — a differently-named JWT key silently falls to 644.** → [Ops §3](#o3)
23. **[Medium] Shepherd: PoP/bootstrap CA chain verification skips validity-date and `BasicConstraints` checks (still open, previously S1).** `shepherd/src/routes_api.rs:1364-1418`. → [Shepherd §8](#s8)
24. **[Medium] Shepherd `acme_client` permits plaintext HTTP with no client identity if a CA's `directoryUrl` is ever misconfigured as `http://`.** `shepherd/src/acme_client.rs:237-241`. → [Shepherd §9](#s9)
25. **[Medium] Dashboard: `/api/dns/jobs` forwards an unvalidated `hostname` as a positional `dig` argument — a value starting with `@`/`+`/`-` is interpreted as a dig directive, letting an authenticated user redirect the DNS query to an arbitrary internal nameserver.** `dashboard/server/index.ts:679,166`. → [Dashboard §5](#d5)
26. **[Medium, pre-existing] Dashboard: `/api/cert-remote` performs `tls.connect` to a fully user-supplied host/port with no destination allowlist — authenticated SSRF/internal port-scan primitive.** Confirmed byte-for-byte unchanged since `77dbf1b`; not a regression, but still open and worth a ticket. `dashboard/server/index.ts:384-414`. → [Dashboard §6](#d6)

Lower-severity items (Low/Info — hand-rolled DER extensions, `none-01` mislabeling, unbounded pre-auth challenge map, WebAuthn UV not required, missing recursion-depth-independent panics, etc.) are recorded in the per-area sections below and the summary table, not repeated here.

---

## Vigil (private CA / ACME server)

Highest-value target in the system (signs certificates for the whole fleet). `git diff 77dbf1b..HEAD -- vigil` confirms `acme.rs`, `ca.rs`, `pki_wire.rs`, `issuance_policy.rs`, `revocation.rs`, `openssl_db.rs`, `storage.rs`, `auth.rs` are **byte-for-byte unchanged** since the last review — only `config.rs`/`routes.rs`/`state.rs`/`cli.rs` changed, to wire config-driven logging. Every finding below (except the logging-mount note) was already present at the last review's baseline; they're repeated/re-scored here because "full codebase, fresh eyes" was the explicit ask.

### V1 — ACME `revoke-cert` still lacks proof-of-possession on the jwk path `[Critical] [Security]` <a name="v1"></a>

Re-scored from High to **Critical**. `vigil/src/acme.rs:1613-1690` `revoke_cert` calls `validate_jws(&state, &request_url, &body, false, false, None)`, permitting the `jwk` (certificate-key) path. On that path `jws.account_id` is `None`, so the ownership check at line 1677 (`if let Some(ref account_id) = jws.account_id { ... }`) is **entirely skipped** — verified directly by reading the current handler. There is no comparison anywhere of the submitted JWK's public key against the target certificate's SubjectPublicKeyInfo.

**Failure scenario:** any client with a valid mTLS cert in `rbacIdentities` (the fleet-wide auth floor for reaching Vigil at all) generates a throwaway keypair, signs a `revoke-cert` JWS with it via the jwk path, and supplies the `certificateId` (or DER — certs aren't secret) of **any** certificate Vigil has ever issued. Vigil revokes it. An attacker with one legitimate ACME client credential anywhere in the fleet can systematically revoke every live certificate — a fleet-wide outage, not just abuse of their own certs.

**Fix:** on the jwk path, parse the target certificate's SPKI and require it match the submitted JWK before revoking; reject otherwise.

### V2 (new) — `finalize_order` unions CSR SANs into the cert instead of restricting to validated identifiers `[High] [Security]` <a name="v2"></a>

`vigil/src/ca.rs:554-569` (`sign_csr`): `san_set` starts as the CSR's own `san_names`, then unions in the order's validated `extra_sans` — it never intersects the CSR's SANs against `order.identifiers`. `vigil/src/acme.rs:1449-1477` (`finalize_order`) only runs the CSR through the general `issuance_policy` suffix check, never asserts the CSR's SANs are a subset of the order's challenged identifiers.

**Failure scenario:** a client completes challenge validation for `foo.example.com`, then submits a finalize CSR that also contains `bar.example.com` (never challenged) but shares a suffix the general policy allows. Vigil issues a cert covering both — bypassing per-domain ACME validation.

**Fix:** reject (or drop) any CSR SAN not present in `order.identifiers`.

### Prior findings, re-checked

- **V2 (old, CSR proof-of-possession) → still open.** `ca.rs` `extract_csr_fields`/`sign_csr` never call a CSR self-signature check. `x509-parser` is pulled in without the `verify` feature, but the codebase already hand-rolls ECDSA/RSA verification for ACME JWS, so adding this is a contained fix. **[Medium] [Security]**
- **V3 (in-memory ACME state) → still open, unchanged.** Orders/authzs/challenges/nonces remain in-memory only; only ACME accounts persist. **[Medium] [Architecture]**
- **V4 (`.parse().unwrap()` on header values) → code unchanged, but re-traced: every currently-wired call site is gated behind a prior existence check that 404s before the unwrap, so the originally-described panic isn't reachable through the wired routes today.** The fragile pattern itself remains and should still be hardened defensively. **[Low] [Correctness]**
- **V5 (hand-rolled DER, no SKID/AKID/EKU, no round-trip tests) → still open, unchanged.** **[Low] [Quality]**
- **V6 (`none-01` reported as `http-01`) → still open, unchanged, deliberate shim.** **[Info] [Quality]**

### V3 (new) — Unbounded recursive DER parsing of untrusted OCSP requests `[Medium] [Security]` <a name="v3"></a>

`vigil/src/pki_wire.rs:72-100` (`find_first_cert_id`) recurses into every nested TLV of a client-supplied DER body with no depth cap, reachable from `POST /ocsp` behind mTLS auth. A deeply-nested DER (cheap to construct — ~2 bytes per nesting level) can exhaust the stack and crash the worker.

**Fix:** cap recursion depth (16–32) in `find_first_cert_id`.

### V4 (new) — `storage_lock` declared but never acquired `[Medium] [Correctness]` <a name="v4"></a>

`vigil/src/state.rs:28,65` declares `storage_lock: Mutex<()>` specifically to serialize file writes; `grep -rn "storage_lock"` shows it is never `.lock()`'d. `storage.rs`'s certificate/account/user stores all do plain read-json → mutate → write-json with no locking — two concurrent requests (e.g. simultaneous finalizes) can silently drop one writer's update.

**Fix:** actually acquire the lock around each read-modify-write in `storage.rs`.

### Additional Low/Info findings

- **`rbacIdentities` entries default to `role: "admin"` when config omits `role`** — fail-open on operator typo. `config.rs:253`. **[Low] [Security]**
- `Box::leak` in `openssl_db.rs:104` permanently leaks a small string per revocation — harmless at typical volume, avoidable. **[Low] [Quality]**
- No private key/raw cert bytes found logged at info+ anywhere in scope. The one intentionally-unauthenticated route, `POST /bootstrap`, is a documented one-shot enrollment channel gated by a constant-time-compared secret that self-disables after first use — a deliberate, reasonable exception to mTLS.

---

## Corgi (node agent)

### C1 — Private keys still written world-readable, then chmod'd (TOCTOU) `[Medium] [Security]`

**Still open.** No `OpenOptions`-with-mode-at-create path exists anywhere in corgi. `cert_ops.rs:130-142` (`generate_key`), `cert_ops.rs:273-293` (`generate_key_and_csr`), and `archive.rs:243-248` (`write_file`, used for every archived `privkey-NNN.pem`) all do plain `fs::write` followed by a separate `set_permissions` call. The containing directories (`pending/`, `archive/<name>/`) are created with plain `create_dir_all` (typically `0755` under a standard umask), so the window is real, not theoretical — see [credo-lib §1](#cl1) for the systemic fix.

### C2 (new) — Outbound mTLS client to Shepherd silently disables verification if `mtls.caPath` is unset `[Medium] [Security]` <a name="c2"></a>

`corgi/src/shepherd.rs:21-24`:
```rust
} else {
    // No CA configured — skip server cert verification (mirrors Node.js rejectUnauthorized: false)
    builder = builder.danger_accept_invalid_certs(true);
}
```
No startup validation forces `mtls.caPath` to be set, and nothing is logged when this fallback triggers.

**Failure scenario:** an operator omits/mistypes `mtls.caPath`. Corgi starts normally with no warning and will accept any TLS certificate from wherever `shepherd_url` resolves — MITM of assignment pulls and cert-material fetches, with zero log signal that verification is off.

**Fix:** fail closed at startup if `ca_path` is missing for a real (non-bootstrap) client; if a permissive dev mode is wanted, gate it behind an explicit flag and log loudly every time it's exercised.

### Additional Low/Info findings

- **No path-traversal guard on `cert_name` used to build archive/live/pending paths** — currently bounded by the trust model (names come from Shepherd assignments), but a single missing guard away from a real issue if that boundary ever changes. **[Low] [Security]**
- **`AuthMode::ProxyHeaders` trusts a client-supplied header verbatim with no binding to actual proxy topology** — if the control port is ever reachable directly (not only through the intended reverse proxy), any caller can set the header and impersonate any identity. Pre-existing, documented as opt-in. **[Low] [Security]**
- `monitor.rs` (new, 773 lines): reviewed in full — the untrusted leaf cert from `AcceptAnyServerCert` is used only for comparison against the locally-installed cert, chain-trust checking is diagnostic-only and degrades safely, monitor targets come only from already-trusted assignment/config data, and test coverage is good. **No issues found.**
- `/sync/assignments` confirmed genuinely data-free (`sync_assignments` takes no body). No private key/cert bytes logged at info+.

---

## Shepherd (control plane)

### S1 — Agent-port BOLA: corgi identity from the URL, not the mTLS-authenticated client `[High] [Security]` <a name="s1"></a>

`shepherd/src/routes_corgi.rs`: `get_cert` (binds `Extension(_node)` — unused), `provision_cert`, `renew_cert`, `renew_status` all look up the assignment by the **untrusted path parameter** `corgi_id` alone, with no check that the authenticated `node.name == corgi_id`. Confirmed by direct read: `get_assignments` (the sibling handler) *does* check this (`if node.name != corgi_id { return Err(Forbidden) }`); the other four don't.

**Failure scenario:** corgi "alpha," authenticated with its own valid mTLS client cert, calls `GET /agents/beta/certs/beta-cert` and gets beta's cert material back verbatim — the response schema already includes `"keyPem": material.key_pem`. Today `key_pem` happens to always be `None` (Shepherd doesn't currently persist corgi-generated keys), but that's one data-path change away from full cross-tenant key exfiltration, and the cert-material/provisioning-trigger cross-read is exploitable right now. This was flagged as Low (S5) in the last review on the reasoning that Shepherd rarely holds keys; re-rated High given the schema already wires the field through and ~3 weeks have passed unfixed.

**Fix:** add the same `node.name != corgi_id → 403` guard used in `get_assignments` to all four handlers.

### S2 (new) — `POST /auth/refresh` doesn't enforce `active: true` `[High] [Security]` <a name="s2"></a>

`shepherd/src/routes_api.rs:251-258`: when the account lookup (`accounts.iter().find(|a| a.active && ...)`) returns `None` — because the account was deactivated or deleted — the code falls back to `Role::from_str(&entry.role)` (the role cached in the refresh-token entry at issuance time) rather than rejecting. It then proceeds to mint a fresh 1h access JWT plus a new refresh token.

**Failure scenario:** revoking or deleting an account does not stop it from indefinitely refreshing its own session — directly defeating both the "`active: true`" invariant and the 1h JWT expiry's purpose of bounding access after revocation.

**Fix:** if the account isn't found active, revoke the presented refresh token and return `Unauthorized`.

### S3 (new) — HE DNS provider logs the DDNS credential in cleartext and disables TLS verification `[High] [Security]` <a name="s3"></a>

`shepherd/src/dns_providers/he.rs:38-44`: `tracing::info!(..., password = %ddns_key, ...)` logs the actual long-lived Hurricane Electric DDNS API key on every dns-01 challenge. Line 29: `.danger_accept_invalid_certs(true)` on the client used for this call, against a public CA-trusted endpoint with no reason to skip verification.

**Failure scenario:** any log sink/aggregator exposure leaks a credential that grants standing ability to rewrite TXT records for the zone — enough to solve future dns-01 challenges and mint certs for that domain. Separately, since the connection doesn't validate the server cert, a network-position attacker can MITM the request and capture the same key directly. This is a direct violation of "never log secrets at INFO or above" (extended in spirit from key material to bearer credentials) and the mTLS/verification invariant.

**Fix:** remove `password`/`ddns_key` from the log line; remove `danger_accept_invalid_certs(true)`.

### S4 (new) — Reconcile loop conflates liveness probing with long synchronous issuance `[High] [Correctness]` <a name="s4"></a>

`shepherd/src/poll.rs`: `run_reconcile_loop`/`reconcile_cycle` do liveness probing (Phase 1) and, when triggered, `cert_maintenance_for` (Phase 3, awaited synchronously) in the same sequential task. `cert_maintenance → issue_cert → run_issuance` can block for minutes (`verify_dns_propagation` alone can poll up to ~1000s worst case). `routes_api.rs:1306`'s `reload_assignments` calls `request_reconcile(&state, None, true)` — `corgis: None` means **every configured corgi**.

**Failure scenario:** an admin bulk-edits `shepherd.assignments.json` and reloads. A single synchronous, sequential issuance sweep across the entire fleet runs inside the one reconcile task; no corgi's liveness is re-probed and no drift nudges are sent to *any* corgi for however long the queued issuances take. This undercuts `shepherd/CONTEXT.md`'s stated design goal ("changes apply within seconds").

**Fix:** don't await cert maintenance inline in the reconcile loop; spawn it (bounded concurrency) so liveness probing and issuance run on independent schedules, matching how `run_renewal_loop` already works.

### S5 (new) — Renewal path pushes signed cert material to Corgi, violating the pull-only invariant `[High] [Architecture]` <a name="s5"></a>

`shepherd/src/poll.rs::cert_maintenance` calls `corgi_client::push_cert_install(...)` after issuance, which does `POST /flock/{name}/install` with `certPem`/`chainPem`/`fullchainPem` in the body — confirmed server-side at `corgi/src/routes.rs::flock_install`, which installs whatever is posted. CLAUDE.md states as a hard invariant: *"Shepherd never pushes config or cert material to Corgi... the nudge must never carry config or cert payload."* This renewal-install call does exactly what that invariant prohibits. It's pre-existing (predates the 77dbf1b baseline), not introduced by this branch, but it wasn't previously flagged and sits squarely in a reviewed path.

**Fix direction:** either explicitly document this as an intentional second, authenticated push channel distinct from the sync-now nudge (and narrow the invariant's wording accordingly), or change the flow so Corgi fetches newly-issued material itself after a nudge, to keep one consistent mental model.

### S6 (new) — Path traversal in `/admin/certstore/:name` via percent-encoded segments `[Medium] [Security]` <a name="s6"></a>

`shepherd/src/routes_api.rs:361-395` (`get_certstore_pem`/`get_certstore_fullchain`) and `cert_store.rs::read_cert_store_entry` join the raw `:name` path parameter directly into a filesystem path with no rejection of `..`/`/`. Empirically confirmed (standalone axum 0.7.9 harness) that axum's `Path<String>` extractor percent-decodes the *entire* captured segment — including `%2F` — after route matching already split on literal `/`. A request to `/admin/certstore/..%2f..%2f..%2fetc%2fpasswd/pem` decodes `name` to `"../../../etc/passwd"`.

**Impact:** any authenticated account at the `Readonly` floor can read `cert.pem`/`fullchain.pem` anywhere reachable via `..` from the certstore's `live/` directory — not limited to certs the operator has an assignment for. Doesn't reach `privkey.pem` directly (filename is hardcoded), but is a real boundary bypass.

**Fix:** reject `name` containing `/`, `\`, or `..` before joining, or canonicalize and verify the result stays under `cert_store_dir`.

### S7 (new) — Cross-loop TOCTOU race can install a cert against the wrong key `[Medium] [Correctness]` <a name="s7"></a>

`cert_maintenance` checks for an already-in-flight job, then does a full round-trip requesting a fresh CSR from Corgi, and only *after* that registers the job. `run_reconcile_loop` (mutation-triggered) and `run_renewal_loop` (periodic sweep) are independent spawned tasks that can both call `cert_maintenance_for` for the same cert, both passing the guard before either registers. Corgi's `/flock/:name/csr` handler always regenerates a fresh key at a single fixed pending-key path, so the second CSR's key generation can overwrite the first's before the first's install lands — installing a cert with no matching (or the wrong) private key until the next cycle self-heals it.

**Fix:** reserve the job slot before calling out to Corgi for a CSR, not after.

### S8 — PoP/bootstrap CA chain verification skips validity dates and `BasicConstraints` `[Medium] [Security]`

**Still open** (previously S1). `shepherd/src/routes_api.rs:1364-1418` (`verify_pop_cert`) walks signature links leaf-to-CA but never checks `not_before`/`not_after` or `cA`/path-length on promoted intermediates. An expired enrollment cert still passes and gets exchanged for a live 1h access JWT.

### S9 (new) — ACME client permits plaintext HTTP with no client identity `[Medium] [Security]` <a name="s9"></a>

`shepherd/src/acme_client.rs:237-241` uses `.https_or_http()` with nothing validating `directoryUrl` is `https://`. A misconfigured CA entry (`http://...`) connects with no server authentication and no client mTLS cert. Config-gated, but code-permitted violation of the mTLS invariant.

**Fix:** reject non-`https://` `directoryUrl` at config load, or use `.https_only()`.

### Additional findings

- **`persist_issued_material` (`cert_store.rs:84-119`) bypasses `file_policy` entirely** — dormant today (its `key_pem` parameter is always `None`), but a latent, worse-than-C1 TOCTOU (no chmod at all) waiting for a future caller. **[Medium] [Security]**
- **Bootstrap admin-token comparison isn't constant-time** (still open, previously S2) — `routes_api.rs:93-95` uses plain `==` while the sibling `routes_bootstrap.rs::check_bootstrap_token` already models the correct constant-time compare. **[Low] [Security]**
- **Issuance-ledger rate-limit is check-then-append, not reserved** — two concurrent issuances for the same domain can jointly exceed a configured quota. **[Low] [Correctness]**
- **Shepherd fully trusts a corgi's self-reported `key_exists`** to gate forced reissuance, with no independent corroboration or backoff — a misbehaving (already-trusted) corgi can force a continuous reissue loop that eats the shared per-domain rate-limit budget for unrelated certs. **[Low] [Security]**
- **`/flock` and `/flock/:name` remain unauthenticated by design** — pre-existing, returns corgi names/URLs/health/error strings to anyone reaching the dashboard port. Worth a conscious confirm since CLAUDE.md's auth description doesn't call out unauthenticated dashboard-port routes. **[Info]**
- JWT algorithm confusion is properly blocked (`Validation::new(Algorithm::ES256)`); both auth chains are correctly URI-SAN-only with no fallback, matching CLAUDE.md.

---

## credo-lib (shared)

`auth.rs`, `tls.rs`, `file_policy.rs` confirmed byte-for-byte unchanged since `77dbf1b`. The logging/log-query subsystem (`log.rs`, `rotating_log.rs`, `log_query/*`, `types.rs`, `timing.rs`) is entirely new.

### credo-lib §1 — `apply_file_policy` is dead code; every real caller reimplements an unsafe version `[High] [Security]` <a name="cl1"></a>

`file_policy.rs::apply_file_policy` only `chmod`/`chown`s a path that must already exist — it has no create-with-restrictive-mode primitive, and `grep -rn "apply_file_policy"` across the whole repo turns up zero callers besides its own definition/tests. The real cert/key-writing code reimplements the same TOCTOU-prone pattern independently:
- `corgi/src/cert_ops.rs:130-142` (private key `fs::write` then `set_permissions(0o600)`)
- `corgi/src/archive.rs:243-247` (every archived private key)
- `shepherd/src/jwt.rs:53-75` (the ES256 JWT signing key)

This is the systemic root of Corgi's C1 and generalizes it to Shepherd's JWT signing key as well.

**Fix:** add an atomic create-then-secure helper to `file_policy.rs` (e.g. `OpenOptions::new().mode(0o600).create_new(true)` before writing) and migrate all three call sites onto it — rather than leaving the shared, designed-for-this module unused.

### credo-lib §2 — `Role::from_str` fails open to `Admin` `[Medium] [Security]` <a name="cl2"></a>

`credo-lib/src/types.rs:52-58` defaults any unrecognized role string to `Role::Admin` rather than rejecting or defaulting to least privilege. Reachable with operator/attacker-adjacent input at `shepherd/src/routes_api.rs:1080` (`update_account`, an Admin-gated endpoint that takes the role as a raw JSON string) — note `create_account`'s serde-derived strict enum deserialization correctly rejects unknown roles, so the two code paths are inconsistent with each other. Also feeds the refresh-token role fallback ([S2](#s2)) and `vigil/src/config.rs:253`'s `rbacIdentities` default.

**Fix:** make `from_str` fallible and reject unknown input (or default to `Readonly`, never `Admin`); have `update_account` propagate a 400 on parse failure.

### credo-lib §3 — Log-query subsystem: unbounded `limit`, synchronous full-file reads on the async runtime `[Medium] [Security]` <a name="cl3"></a>

`log_query/historical.rs:59`: `params.limit` has no upper bound — a caller can request an arbitrarily large `limit` and get back the service's entire retained log history in one response. `historical.rs:70` reads each log file fully into memory before filtering, with no early-skip by file mtime against `since`/`until`. Both `historical_logs` and `follow.rs::build_follow_stream` (used by every `follow=true` SSE connection) call this blocking work directly from `async fn`s with no `spawn_blocking`, so one such request can stall a Tokio worker thread. Reachable via Shepherd's `/admin/logs`, Corgi's `/logs`, Vigil's `/logs` — none of the three services clamp `limit` before calling in.

**Fix:** clamp `limit` server-side to a hard maximum; skip files outside the `since`/`until` window by mtime before reading; wrap the read in `spawn_blocking`.

**Confirmed sound:** `parse_last_duration` (`log_query/filter.rs:17-42`) is fully panic-free on attacker input (the fix commit referenced in scoping is complete); no path-traversal risk exists in this subsystem — `dir`/`basename` always come from server-side logging config, never from query parameters.

### Additional findings

- **`tls.rs`'s documented "no client CA → accept any client cert" mode actually fails to build the TLS config at all** (empirically verified against the pinned `rustls 0.23.40`: an empty `RootCertStore` with `allow_unauthenticated()` returns `Err(NoRootAnchors)`, not "accept any cert"). This fails *closed* (corgi refuses to start / hot-reload fails) rather than silently bypassing auth, so it's not the mTLS-bypass invariant violation it might look like — but it's dead, untested, and documented-incorrectly functionality. **[Medium] [Correctness]**
- **Proxy-header identity (`auth.rs::identity_from_header`) has no built-in trust boundary** — sound matching logic, but no peer-IP allowlist or shared secret ties it to actually having transited a trusted proxy. Same underlying concern as Corgi's [C2](#c2)-adjacent `ProxyHeaders` mode. **[Low/Medium] [Architecture]**
- `parse_mode_octal` silently treats `""`/`"0"`/`"0o"` as mode `0` instead of a config error — fails closed (locks the file to no access), low impact, locally-controlled input only. **[Low] [Quality]**
- Rotating log files get default-umask (typically 0644) permissions with no `file_policy` applied — inconsistent with the strict discipline elsewhere, though log content is lower-sensitivity than key material. **[Low] [Quality]**
- No private-key/raw-cert-byte logging found. `PeerCertDer` derives `Debug` and could dump raw DER if ever `{:?}`-logged, but no call site does so today — a latent footgun, not a current violation.

---

## Dashboard (BFF + client)

### Dashboard §1 — PoP CA-chain verification silently skipped if `mtls.caPath` unset `[Critical] [Security]` <a name="d1"></a>

`dashboard/server/auth/pop.ts:99-115`: the entire CA-chain-verification step is wrapped in `if (config.mtls.caPath) { ... }` with no `else` branch — if the field is absent, `verifyPopToken` falls straight through to the SAN-vs-claimed-identity match and signature check, **with no verification that the presented cert was ever issued by Vigil at all**. `config.mtls.caPath` is optional end-to-end (`config.ts:158`, no `requiredString` enforcement) and nothing at startup asserts it's present when auth/enrollment is enabled.

**Failure scenario:** the signature check alone only proves the presenter holds the private key matching whatever self-signed cert they submit. An attacker who obtains a valid invite/challenge token (e.g. via URL leak, referrer, log exposure) can generate their own self-signed cert with an arbitrary `URI:vigil://...` SAN, sign the challenge themselves, and enroll as that identity — completely bypassing the "this really is a Vigil-issued cert" guarantee the PoP design exists for. The shipped example config does set `caPath`, lowering practical exposure today, but the code fails open rather than closed.

**Fix:** make CA verification mandatory — error at config-load time if `mtls.caPath` is missing while auth is configured, and make `verifyPopToken` return `ok: false` unconditionally when no CA bundle is available.

### Dashboard §2 — Admin user-management routes never get cached role revalidated `[High] [Security]` <a name="d2"></a>

`dashboard/server/index.ts:310` mounts the auth router (including `/auth/admin/users`, `PUT /auth/admin/users/:id`, etc., gated by `requireRole('admin'/'operator')`) directly on `/auth`, independent of `app.use('/api', makeRoleRefresh(...))` at `index.ts:320`. `requireRole` only checks the session's cached role; only `makeRoleRefresh` (mounted solely under `/api`) ever re-checks against Shepherd.

**Failure scenario:** a session that was `admin` at login keeps `requireRole('admin')` access to create/deactivate users, revoke passkeys, and issue enrollment links via `/auth/admin/*` for as long as the session cookie lives, regardless of the configured role-staleness policy — that policy only ever gets exercised as a side effect of the same browser also hitting an `/api/*` endpoint.

**Fix:** mount admin user-management routes under `/api`, or apply `makeRoleRefresh` to the `/auth` router's `/admin/*` sub-path too.

### Dashboard §3 — 30-minute stale-role fallback plus replayable PoP tokens `[Medium] [Security]` <a name="d3"></a>

`makeRoleRefresh` serves requests with the cached role for up to `roleStaleTimeoutSeconds` (default 1800s) when Shepherd is unreachable — a meaningful window for a revoked admin/operator during an incident that coincides with a Shepherd outage. Separately, `verifyPopToken` only checks `issuedAt` freshness (5-minute window) with no single-use/consumed-token tracking; the invite is only cleared at `/enroll/finish`, not at successful PoP verification, so a captured-in-transit valid PoP token is replayable against `/enroll/verify` any number of times within 5 minutes, each time minting a fresh token pair.

**Fix:** shorten the stale-role window or fail closed on Shepherd-unreachable; add single-use tracking to PoP verification.

### Dashboard §4 — No session regeneration on login/enrollment `[Medium] [Security/Correctness]` <a name="d4"></a>

Neither `/auth/login/finish` nor `/auth/enroll/finish` calls `req.session.regenerate()` before assigning `req.session.user`, reusing a possibly-pre-existing session ID across the anonymous→authenticated trust transition. `sameSite: 'strict'` + `secure: true` cookies block most cross-site fixation vectors, but any same-site cookie-setting primitive would let an attacker fix then hijack a session.

**Fix:** regenerate the session ID immediately before writing `session.user` in both handlers.

### Dashboard §5 (new) — `/api/dns/jobs` argument injection into `dig` `[Medium] [Security]` <a name="d5"></a>

`dashboard/server/index.ts:679` (`hostname`, trimmed only) feeds `index.ts:166`'s `execFile('dig', ['@'+ip, 'TXT', hostname, '+short', ...])`. `execFile` avoids shell injection, but `dig` parses `@`/`+`/`-`-prefixed tokens as directives regardless of argv position — a `hostname` value like `"@10.0.0.5"` makes dig query that arbitrary internal IP instead of the resolved authoritative nameserver, using the BFF as a DNS-query relay against internal-only hosts.

**Fix:** validate `hostname` against an actual hostname/FQDN character class before use, rejecting leading `@`/`-`/`+`; or use Node's own `dns.resolveTxt`/`Resolver.setServers` (as the adjacent `/api/dns/txt` already does) instead of shelling out.

### Dashboard §6 — `/api/cert-remote` unrestricted-destination SSRF `[Medium] [Security, pre-existing]` <a name="d6"></a>

`dashboard/server/index.ts:384-414`: `tls.connect` to a fully user-supplied `host`/`port` (only range-checked) with no allowlist/blocklist. Confirmed byte-for-byte unchanged since `77dbf1b` — pre-existing, not a regression, but still open. `rejectUnauthorized: false` here is intentional (the endpoint's job is inspecting untrusted certs); the gap is the total absence of a destination restriction, letting an authenticated (even `readonly`) user probe internal hosts/ports (e.g. cloud metadata endpoints, internal admin ports).

**Fix:** restrict to hosts matching the managed fleet/corgi inventory, or block RFC1918/loopback/link-local unless explicitly allowed.

### Confirmed clean in the new logs feature

The new `/api/logs` + `/api/logs/stream` proxy (`routes-logs.ts`, `log-query.ts`, `logging.ts`) introduces **no new SSRF/traversal/injection surface**: the `source`/`target` pass-through to Shepherd's `/admin/logs` is validated correctly server-side ([confirmed against](#s6) `shepherd/src/routes_api.rs`'s exact-match `target` handling), query params are percent-encoded through `reqwest::Url::query_pairs_mut()`, and the local (non-proxy) log-search path builds file paths only from server-controlled `logDir`/`basename`, never from any request parameter. `config-utils.ts::resolveIncludes` is confirmed startup-only, never HTTP-reachable.

### Dashboard client (`src/`)

No issues found. No `dangerouslySetInnerHTML`/`innerHTML`/`eval` in the Logs feature; log lines render via plain JSX text interpolation. No sensitive data (tokens, keys) in `localStorage`/`sessionStorage` — only display preferences. `AuthContext` authenticates purely via cookie-based `/auth/me`. Server-side `requireAuth`/`makeRoleRefresh` gate the actual API, so the client is not a load-bearing security boundary for this feature.

### Additional findings

- **PoP cert-chain builder doesn't check validity window or `basicConstraints`** — defense-in-depth gap (forging still requires the real CA key), but an expired enrollment cert or a non-CA leaf "vouching" for another cert would still validate. **[Low] [Security]**
- **WebAuthn `userVerification: 'preferred'` / `requireUserVerification: false`** — accepts presence-only authenticators; likely an intentional UX tradeoff, worth confirming for `admin`-capable accounts. **[Low] [Security/Quality]**
- **Unbounded, unauthenticated `pendingChallenges` map** in `routes-auth.ts` with no capacity bound or sweep — a low-effort pre-auth memory-growth vector. **[Low] [Quality/Availability]**
- Session cookie config (`httpOnly`, `secure`, `sameSite: strict`), JWT-decode-without-verify (confirmed never fed by user input), and `shepherd-client.ts`'s `rejectUnauthorized` default (confirmed operator-only, defaults `true`) are all sound.

---

## Ops scripts

### Ops §1 — `deploy/migrate-credo-store.sh` leaves Vigil's CA key and Shepherd's archived keys world-readable `[Critical] [Security]` <a name="o1"></a>

`fix_service()` has exactly two exceptions to the 644 default: `service = "corgi" && fname == privkey-*.pem` (→ 640, `credo-cert` group) and `service = "shepherd" && fname == "shepherd.jwt.key.pem"` (→ 600). Confirmed by direct read of the current script. Neither `vigil` nor `dashboard` are ever matched by either branch, regardless of filename:

- **Vigil's intermediate CA signing key** (`vigil/src/config.rs:190` default `./ca/int-ecdsa/private/int-ecdsa.key.pem`, confirmed as the real on-disk name via `ceremony/scripts/issue-intermediary.sh`) — the single most sensitive secret in the system, signs every cert the fleet trusts — falls to 644.
- **Vigil's own TLS serving key** (`./certs/privkey.pem`, no dash suffix) also falls to 644.
- **Dashboard's TLS/mTLS keys** (`dashboard/server/config.ts` — fully operator-named, no fixed convention) fall to 644.
- **Shepherd's own certstore-archived private keys** (`shepherd/src/cert_store.rs` — `privkey-NNNN.pem`, same archive/live layout as corgi, confirmed to contain real key material) fall to 644 too, because the `privkey-*.pem` exception is scoped to `service = "corgi"` only.

**Failure scenario:** running `--fix-in-place` or `--copy` as documented in the script's own usage examples flips these from `664` (owner + `credo` group) to world-readable `644`. Any unprivileged local account can then read the CA signing key and forge certificates for the whole fleet, or read the dashboard's Shepherd mTLS client key.

**Fix:** don't rely on a per-service filename allowlist. Default any file under a `private/`/`archive/`-style directory (or matching `*.key.pem`/`privkey*`) to `600`, with explicit exceptions only where a *broader* permission is actually needed; verify against each service's live config rather than a hardcoded filename.

### Ops §2 (new) — Live-filesystem TOCTOU, no service-stop requirement `[Medium] [Security]` <a name="o2"></a>

`fix_service` snapshots paths via `find ... -print0`, then `chmod`/`chown`s each by path in a later loop — both dereferencing symlinks (only the symlinks branch uses `lchown`). Nothing in the script requires services to be stopped first, and Corgi/Shepherd continuously write new archive files and repoint `live/` symlinks during normal operation.

**Failure scenario:** between the `find` snapshot and the later chmod/chown, a path can be rotated out from under the loop (at minimum causing `set -euo pipefail` to abort mid-migration leaving mixed old/new ownership; at worst, if replaced by a symlink, silently re-permissioning a file outside the intended tree).

**Fix:** require services stopped before running (or detect/refuse if still running); treat a vanished path as skip-not-abort.

### Ops §3 (new) — `shepherd.jwt.key.pem` special case matches an assumed filename `[Medium] [Correctness]` <a name="o3"></a>

`shepherd/src/config.rs` makes `auth.jwtSigningKeyPath` a required but arbitrarily-named config field — there is no code-level default of `shepherd.jwt.key.pem`. A config that names this file anything else silently falls through to the 644 default.

**Fix:** read the JWT key path from the live `shepherd.config.json` at migration time instead of hardcoding a filename, and log whether a matching file was actually found and re-permissioned.

### Additional findings

- **General design flaw underlying Ops §1–3:** 644 is the default rather than deny-by-default for a tree known to hold secrets; the allowlist reads as exhaustive when it isn't. **[Low] [Security]**
- No `SOURCE_ROOT`/`DEST_ROOT` canonicalization (no `realpath`, no `..` rejection) — low exploitability since only root/the operator controls these values, but no defense-in-depth. **[Low] [Quality]**
- Confirmed **no command injection**: no `eval`; all variable expansions checked are quoted; `--services` values are checked against a fixed `case` whitelist before any filesystem action runs.
- `ceremony/` confirmed genuinely untouched since the last review (`git log 77dbf1b..HEAD -- ceremony` returns nothing); light skim of its four scripts shows nothing missed (keys chmod'd 600 immediately after generation, no `eval`, quoted expansions).

---

## Summary table

| ID | Area | Severity | Category | One-line |
|---|---|---|---|---|
| V1 | Vigil | Critical | Security | `revoke-cert` jwk path skips ownership check — fleet-wide arbitrary revocation |
| D1 | Dashboard | Critical | Security | PoP CA verification no-ops if `mtls.caPath` unset |
| O1 | Ops | Critical | Security | migrate script leaves Vigil CA key + Shepherd archived keys world-readable |
| V2 | Vigil | High | Security | `finalize_order` doesn't restrict CSR SANs to validated identifiers |
| S1 | Shepherd | High | Security | Agent-port BOLA — corgi identity from URL, not auth |
| S2 | Shepherd | High | Security | `/auth/refresh` doesn't check `active: true` |
| S3 | Shepherd | High | Security | HE DDNS key logged cleartext + TLS verification disabled |
| D2 | Dashboard | High | Security | Admin routes never get cached role revalidated |
| CL1 | credo-lib | High | Security | `file_policy` helper unused; every caller reimplements unsafely |
| S4 | Shepherd | High | Correctness | Reconcile loop blocks fleet-wide liveness on synchronous issuance |
| S5 | Shepherd | High | Architecture | Renewal path pushes cert material to Corgi, violates pull-only invariant |
| S6 | Shepherd | Medium | Security | Path traversal in `/admin/certstore/:name` |
| CL2 | credo-lib/Shepherd | Medium | Security | `Role::from_str` fails open to Admin |
| S7 | Shepherd | Medium | Correctness | Cross-loop TOCTOU can install cert against wrong key |
| C2 | Corgi | Medium | Security | Silent TLS-verification bypass toward Shepherd if CA unset |
| CL3 | credo-lib | Medium | Security | Unbounded log-query `limit`, sync reads on async runtime |
| V3 | Vigil | Medium | Security | Unbounded recursive OCSP DER parsing (stack DoS) |
| V4 | Vigil | Medium | Correctness | `storage_lock` never acquired — RMW races on JSON stores |
| D3 | Dashboard | Medium | Security | 30-min stale-role window + replayable PoP tokens |
| D4 | Dashboard | Medium | Security | No session regeneration on login/enrollment |
| O2 | Ops | Medium | Security | Live-filesystem TOCTOU in migrate script |
| O3 | Ops | Medium | Correctness | JWT key filename assumed, not read from config |
| S8 | Shepherd | Medium | Security | PoP chain verification skips validity/BasicConstraints |
| S9 | Shepherd | Medium | Security | ACME client permits plaintext HTTP |
| D5 | Dashboard | Medium | Security | `/api/dns/jobs` argument injection into `dig` |
| D6 | Dashboard | Medium (pre-existing) | Security | `/api/cert-remote` unrestricted SSRF |
| C1 | Corgi | Medium | Security | Key write-then-chmod TOCTOU (see CL1) |
| CL-tls | credo-lib | Medium | Correctness | "Accept any client cert" mode actually fails to build (fails closed) |
| — | Vigil | Medium | Security | CSR proof-of-possession still not verified (old V2) |
| — | Shepherd | Medium | Security | `persist_issued_material` bypasses `file_policy` (dormant) |
| — | Vigil | Medium | Architecture | In-memory-only ACME state (old V3) |
| Several | Vigil/Corgi/credo-lib/Dashboard | Low/Info | Various | See per-area sections — DER extensions, rate-limit races, WebAuthn UV, unauthenticated `/flock`, etc. |

---

## Notable non-issues (explicitly verified, worth recording)

- Shepherd's two auth chains are correctly URI-SAN-only with no fingerprint/fleet fallback; JWT algorithm confusion is properly blocked.
- Corgi's `monitor.rs` (new, 773 lines) handles its untrusted-cert-as-data model correctly throughout.
- The new dashboard logs proxy introduces no new SSRF/traversal/injection surface; the `source`/`target` deferral to Shepherd is genuinely validated on the Shepherd side.
- The dashboard client is not a load-bearing security boundary for the new Logs feature; no XSS, no sensitive client-side storage.
- `parse_last_duration`'s prior panic-on-attacker-input fix is complete; no similar gap remains in the log-query subsystem.
- The sync-now nudge is genuinely data-free at both Shepherd and Corgi ends.
- `ceremony/` remains untouched and shows no gaps on a spot-check.
