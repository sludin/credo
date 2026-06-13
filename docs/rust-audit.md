# Rust Codebase Audit: Refactoring & Dead Code

Audit of the Rust workspace (shepherd, corgi, vigil, credo-lib) identifying dead code, duplicate functionality, and refactoring opportunities. Goal: reduce maintenance burden, improve consistency, consolidate shared logic into credo-lib. Dashboard (TypeScript) and ceremony (bash) are out of scope.

---

## Category 1: Cross-Service Duplication (Highest Value)

Patterns duplicated across 2–3 services that should be unified.

### 1A. `LogLevel` Enum — Defined 3 Times (HIGH)

Each service (`shepherd/src/config.rs`, `corgi/src/config.rs`, `vigil/src/config.rs`) defines an identical `LogLevel` enum with `Fatal/Warn/Info/Debug` variants and an identical `as_tracing_filter()` method. Each also has a converter to/from credo-lib's own `LogLevel` in `credo-lib/src/log.rs`.

**Fix:** Remove service-level `LogLevel` enums entirely. Use `credo_lib::LogLevel` directly in service configs. Delete the 3 converter functions.

### 1B. Log Request Middleware — Defined 3 Times (HIGH)

`shepherd/src/log_middleware.rs`, `corgi/src/log_middleware.rs`, and `vigil/src/log_middleware.rs` are 95% identical. All three extract host, peer IP, timing, and identity the same way; the only difference is a hardcoded service code string (`"S"`, `"C"`, `"V"`).

**Fix:** Add a factory function to credo-lib:
```rust
pub fn make_log_middleware(code: &'static str) -> impl Layer<...>
```
Each service calls it with its code and drops its local copy.

### 1C. Archive Ordinal Functions — Reimplemented in Corgi (HIGH)

`credo-lib/src/archive.rs` exports `ordinal_string()`, `next_archive_ordinal()`, and `replace_symlink()`. `corgi/src/archive.rs` reimplements all three identically instead of importing from credo-lib.

**Fix:** Delete the duplicates in `corgi/src/archive.rs` and import from credo-lib.

### 1D. mTLS HTTP Client Building — Duplicated Across Services (MEDIUM)

`shepherd/src/main.rs` has `build_shepherd_plain_client()` and `build_shepherd_mtls_client()`. `corgi/src/shepherd.rs` has its own `build_shepherd_client()`. The pattern is nearly identical (load CA + client cert/key → build `reqwest::Client`).

**Fix:** Add `credo_lib::tls::build_http_client(ca, cert, key, timeout) -> Result<reqwest::Client>` (and a plain variant). Services call it instead.

### 1E. RBAC Identity Resolution — Same Pattern in All Three Services (MEDIUM)

All three services do the same thing: call `credo_lib::auth::identity_from_der()` to extract a `ClientIdentity`, then scan its `san_uris` against a registry to find a matching role. The code shape is:

- **Shepherd agent port** (`auth.rs:47–57`): scan `corgis` config for a matching `identityUri`
- **Shepherd dashboard port** (`auth.rs:129`): scan `accounts` for a matching identity
- **Corgi** (`auth.rs:17–26`): `resolve_role()` scans config users for a matching URI
- **Vigil** (`auth.rs:49–52`): `.find(|entry| identity.san_uris.contains(&entry.uri))`

The extraction primitive (`identity_from_der`) is already in credo-lib. The registry-lookup step is re-implemented in each service.

**Fix:** Add `credo_lib::auth::find_role_by_san(identity: &ClientIdentity, registry: impl Iterator<Item = (&str, Role)>) -> Option<Role>` (or similar). All services call it with their own registry iterator. Shepherd calls it twice (once for corgis, once for accounts).

### 1F. Bootstrap Token Comparison — Inconsistent (LOW)

Corgi uses a hand-rolled bitwise constant-time comparison; Vigil uses the `subtle` crate's `ConstantTimeEq`. Both are timing-safe, but inconsistent.

**Fix:** Standardize on `subtle` in corgi (or extract a `credo_lib::auth::constant_time_eq(a, b)` wrapper). Eliminates custom crypto code.

---

## Category 2: Blanket `#![allow(dead_code)]` Suppression (HIGH)

Several shepherd source files suppress all dead-code warnings at the crate/module level, masking legitimate unused code:

- `shepherd/src/main.rs` — `#![allow(dead_code)]` on entire crate
- `shepherd/src/lib.rs` — same
- `shepherd/src/assignments.rs` — same
- `shepherd/src/dns_providers/mod.rs` — same

**Fix:** Remove blanket allows. Add targeted `#[allow(dead_code)]` only on intentional stubs (e.g., the compile-time type checker `_issue_cert_accepts_job_store()` in `issuance.rs:783`). This will surface any real unused items to address in subsequent steps.

---

## Category 3: Unused / Dead Config Fields and Parameters

### 3A. `dns_override` in Shepherd Config (LOW — document only)

`shepherd/src/config.rs:54` — `dns_override: HashMap<String, String>` is parsed from the config file but never read anywhere in the service logic.

**Decision:** This is intentional future work. Keep the field. Add a code comment marking it unimplemented, and document it in `shepherd/docs/config.md` as "To be implemented."

### 3B. `_force_revalidate` in Issuance (LOW — document only)

`shepherd/src/issuance.rs:185` — `_force_revalidate: bool` is extracted from the assignment record but prefixed with `_` and never used in `run_issuance()`.

**Decision:** This is a useful feature for testing (bypass the cert-age check and force a revalidation cycle). Keep the stub. Document the field in `shepherd/docs/config.md` as "To be implemented."

### 3C. Corgi `check-config` TLS Path Bug (LOW)

`corgi/src/main.rs:253` — the diagnostic command checks `("TLS key", &config.tls.cert_path)` for both the cert and the key, never checking `config.tls.key_path`. Not a runtime bug (diagnostic only), but misleading.

**Fix:** Change one instance to `("TLS key", &config.tls.key_path)`.

### 3D. Unused `ok` Variable in Corgi `check-config` (LOW)

`corgi/src/main.rs:231` — `let ok = true;` is set but never read.

**Fix:** Remove the line.

---

## Category 4: Dead Code in credo-lib (MEDIUM)

Several functions in credo-lib are internal helpers exposed as `pub` but never called by any service. They should be `pub(crate)` (or removed if provably unneeded):

| Function | File | Action |
|---|---|---|
| `collect_vars()` | `config.rs` | → `pub(crate)` |
| `interpolate_json()` | `config.rs` | → `pub(crate)` |
| `deep_merge()` | `config.rs` | → `pub(crate)` |
| `strip_underscore_keys()` | `config.rs` | → `pub(crate)` |
| `vars_with_env()` | `config.rs` | → `pub(crate)` |
| `parse_certs_pem()` | `tls.rs` | → `pub(crate)` (remove if unused after audit) |
| `parse_private_key_pem()` | `tls.rs` | → `pub(crate)` (remove if unused after audit) |
| `build_server_tls_from_pem()` | `tls.rs` | → `pub(crate)` (remove if unused after audit) |
| `CertStorePaths` struct | `archive.rs` | → `pub(crate)` or remove |
| `apply_file_policy()` | `file_policy.rs` | Consolidate with corgi's version (see 7A) |

**Fix:** Make all of the above `pub(crate)`. The PEM-based TLS functions have no service caller and no obvious planned use; remove them unless a specific future use is identified. After audit, a clean `cargo build` with `pub(crate)` will confirm nothing external was relying on them.

---

## Category 5: Incomplete / Stub Features

### 5A. Alert System — Complete Stub (LOW — mark future work)

`shepherd/src/alerts.rs` — `send_alert()` only logs a warning. It is called from the renewal poll job on failures, meaning real alert delivery never happens.

**Decision:** This is planned future work. Keep the stub and the call sites. Add a `// TODO: implement alert dispatch (email/webhook)` comment to `send_alert()`. Add a `// TODO: alert config` comment to any config field that will eventually hold dispatch settings.

### 5B. Dead Struct Fields in Corgi Archive (MEDIUM)

`corgi/src/archive.rs:140–146` — `ArchiveInstallPaths` has fields `fullchain_archive`, `chain_archive`, `key_archive` marked `#[allow(dead_code)]`. The return value of `install_to_archive()` is discarded at the call site in `cert_ops.rs:358–365`.

**Fix:** Remove the unused fields and change `install_to_archive()` to return `()`. If the paths are ever needed for logging, they can be added back at that time. (This also falls under 7A if `install_to_archive` moves to credo-lib.)

### 5C. JWS URL Validation Incomplete in Vigil (MEDIUM — needs design)

`vigil/src/acme.rs:301` — `scheme`, `host`, `request_path` are extracted from the JWS URL but discarded with `let _ = (...)`. Comment says "we check this loosely." This is an incomplete ACME security check.

**Decision:** This should be implemented properly. The JWS `url` field in an ACME request must match the request URL being processed (RFC 8555 §6.4). This requires design work to plumb the actual request URL through to `validate_jws()`. Track as a separate work item; do not remove the extraction — it documents the intended check.

**Immediate fix:** Replace `let _ = (scheme, host, request_path)` with a `// TODO: validate JWS url matches request URL (RFC 8555 §6.4)` comment and remove the dead binding.

### 5D. Dead `ca_block` in Vigil Config (LOW)

`vigil/src/config.rs:233–238` — `ca_block` is built and immediately discarded with `let _ = ca_block`.

**Fix:** Remove these lines.

---

## Category 6: Workspace Dependency Management (MEDIUM)

The root `Cargo.toml` has no `[workspace.dependencies]` section. All three services independently specify identical crate versions for ~15 shared crates (tokio, axum, hyper, rustls, serde, tracing, clap, etc.), totaling ~45 redundant entries.

**Fix:** Add `[workspace.dependencies]` to root `Cargo.toml` and reference with `{ workspace = true }` in member `Cargo.toml` files. This prevents version drift and simplifies future upgrades (one-line version bumps instead of three).

---

## Category 7: Candidate for Moving High-Level Logic to credo-lib

### 7A. `install_to_archive()` — Should Move to credo-lib (MEDIUM)

Both shepherd and corgi manage a certstore with the `archive/` + `live/` layout (CLAUDE.md confirms shepherd "runs its own ACME issuance and stores cert material in a certstore mirroring certbot"). Shepherd has its own cert-writing logic in `issuance.rs`; corgi has `install_to_archive()` in `archive.rs`. These are two separate implementations of the same store layout.

**Fix:** Move corgi's `install_to_archive()`, `set_permissions()`, `set_owner()`, and `write_file()` to `credo_lib::archive`. Consolidate `apply_file_policy()` (currently in credo-lib's `file_policy` but never called) with corgi's more capable version. Then audit shepherd's cert-writing code to see if it can also use the shared implementation.

### 7B. Cert Parsing Utilities in Shepherd (LOW — defer)

`shepherd/src/issuance.rs` contains `split_cert_chain()`, `leaf_fingerprint()`, and `pem_to_csr_der()` — generic utilities.

**Fix:** Defer until there is a concrete second consumer. If corgi or vigil needs one of these, move it at that point.

---

## Iteration Plan

**Iteration 1 — Quick Wins (Low Risk)**
- Remove blanket `#![allow(dead_code)]` in shepherd; add targeted allows only where needed (Category 2)
- Fix corgi `check-config` TLS key path bug and dead `ok` variable (3C, 3D)
- Make credo-lib internal functions `pub(crate)`; remove unused PEM TLS functions (Category 4)
- Remove dead `ca_block` in vigil (5D)
- Replace dead JWS binding with TODO comment in vigil (5C immediate fix)
- Add TODO comments to `alerts.rs` stub and config fields (5A)
- Add "To be implemented" notes to `dns_override` and `force_revalidate` in config docs (3A, 3B)

**Iteration 2 — Enum and Middleware Consolidation**
- Unify `LogLevel` enum: remove from all services, use `credo_lib::LogLevel` directly (1A)
- Extract log middleware factory to credo-lib (1B)
- Workspace dependency management: add `[workspace.dependencies]` (Category 6)

**Iteration 3 — Functional Duplication**
- Fix archive ordinal duplication in corgi: import from credo-lib instead of redefining (1C)
- Extract mTLS HTTP client builder to credo-lib (1D)
- Clean up `ArchiveInstallPaths` dead fields in corgi (5B)
- Standardize bootstrap token comparison on `subtle` (1F)

**Iteration 4 — Structural Refactoring (Needs Design)**
- Extract `find_role_by_san()` to credo-lib; use in all three services (1E)
- Move `install_to_archive()` and file policy helpers to credo-lib (7A)
- Design and implement JWS URL validation in vigil (5C full implementation)
