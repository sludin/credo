# Credo Security Fix Confirmation — 2026-07-28

**Scope:** Confirmation pass over the fix work done in response to `docs/reviews/2026-07-26-code-review.md`, plus a fresh-eyes look at exactly those diffs for anything new. Not a full whole-codebase re-review — nothing outside these diffs changed since the 2026-07-26 baseline (`fe87052`).

**What was actually found:** the fix work was done as three severity-tiered branches, all forked from the same commit `aba249c`:

| Branch | Findings | Merged to `main`? |
|---|---|---|
| `security-fix-critical-pop-revoke` | V1, D1 | **Yes**, as of `db2d37a` (2026-07-28, post-review) |
| `security-fix-high-priority` | V2, S1, S2, S3, D2, CL1, S4, S5 | **Yes**, as of `32d4b6c` (2026-07-28, post-review) |
| `security-fix-medium-priority` | S6, CL2, S7, C2, CL3, V3, V4, D3, D4, S8, S9, D5, D6 | Yes — was already on `main` at `db4600a` |

All three tiers are now on `main`. The Critical and High branches were merged in that order (medium was already in) after this confirmation pass validated them; two real conflicts came up during the merge (`dashboard/server/auth/pop.test.ts`, `vigil/tests/acme_flow.rs`) and were resolved by hand — see "Post-review merge" below. Full workspace `cargo test`/`clippy`/`fmt` and dashboard `vitest`/`typecheck` all pass on the merged result. **O1** (`deploy/migrate-credo-store.sh` world-readable keys, Critical) still has no fix commit anywhere — confirmed via `git log --all -- deploy/migrate-credo-store.sh` returning nothing past baseline. It remains fully open and is the only originally-Critical finding with no fix in progress.

**Method:** 6 parallel verification passes (one per branch/package grouping), each reading the full diff plus the complete current function bodies at the branch tip (not just diff hunks), tracing the failure scenario independently, checking regression tests actually exercise the described attack, and flagging anything else suspicious in the touched files. Findings below were cross-checked against the sub-passes before write-up; one (C2) was independently re-verified directly by reading `corgi/src/state.rs`.

---

## Headline result

22 of 23 fix commits close their described vulnerability. Two fixes are **incomplete** in a way that leaves most of the originally-described attack surface reachable (S5, S7), and one fix (**C2**) does not actually close the vulnerability at all — it only adds a warning log, and the commit's own stated reason for not fixing it further does not hold up under independent verification.

---

## Per-finding verdicts

### Critical — `security-fix-critical-pop-revoke` (unmerged)

| ID | Commit | Verdict | Notes |
|---|---|---|---|
| **V1** | `3409587` | ✅ Fixed & Verified | New `jwk_matches_cert_public_key` compares the submitted JWK against the target cert's SPKI; combined with `validate_jws`'s pre-existing signature check, this genuinely proves possession. Test covers both the attack and the legitimate RFC 8555 §7.6 case. No other route into `revoke_cert`'s jwk path exists. |
| **D1** | `430b8b7` | ✅ Fixed & Verified | `verifyPopToken` now unconditionally fails closed when `mtls.caPath` is unset — no fallthrough path left. Test proves it checks *which* CA signed the cert, not just that a file exists. **Caveat:** `dashboard/server/config.ts` still doesn't enforce `caPath` as required at config-load time (the doc's suggested fix had two parts; only the runtime fail-closed half landed). Not a live security hole — enrollment simply always fails at runtime instead — but an operator gets no startup error, only a confusing runtime failure. |

### High — `security-fix-high-priority` (unmerged)

| ID | Commit | Verdict | Notes |
|---|---|---|---|
| **V2** | `2b3d090` | ✅ Fixed & Verified | `sign_csr_restricted` requires every CSR name be in `order.identifiers` before issuance; structurally sound, not a check bolted in front of unchanged logic. Minor cosmetic-only gap: case isn't normalized in the final cert SAN (e.g. `Foo.Example.COM` vs `foo.example.com` — same identity, no security impact). |
| **S1** | `c566872` | ✅ Fixed & Verified | All 5 corgi-facing handlers (including the sibling `get_assignments` that was already correct) now check `node.name != corgi_id → 403`. Cross-checked against the full route table — no handler missed. |
| **S2** | `7b6610b` | ✅ Fixed & Verified | Deactivated/missing account now revokes the presented refresh token and rejects, instead of falling back to the cached role. `revoke_token` genuinely removes+persists, not a soft no-op. |
| **S3** | `d23ac5e` | ✅ Fixed & Verified | `danger_accept_invalid_certs(true)` removed; credential no longer in the log line. Test captures actual emitted `tracing` output and asserts the secret never appears — not just a diff check. |
| **D2** | `2ba006a` | ✅ Fixed & Verified | `/admin/*` now gets `roleRefresh` middleware via router-level `.use()` before the role-gated handlers. Confirmed no other role-gated router exists outside `/api` and `/auth/admin`. |
| **CL1** | `caa4451` | ✅ Fixed & Verified | New `write_file_with_mode` (atomic create-with-mode) migrated onto all 3 originally-cited call sites, plus a 4th (`cert_ops.rs::generate_key_and_csr`) the finding only implicitly covered. Re-issuance/overwrite case explicitly tested and doesn't regress. |
| **S4** | `1e18e4f` | ⚠️ Fixed, with a regression | Reconcile-loop liveness/nudging is now genuinely decoupled from issuance (the described fleet-wide stall is closed). **But** spawning `cert_maintenance_for` instead of awaiting it inline removes the implicit serialization that previously existed between rapid reconcile triggers — this *widens* the pre-existing S7 race (two admin-triggered reloads can now both spawn maintenance for the same cert before either registers a job). No test added for either the fixed behavior or the widened race. **This is closed in practice once S7's fix (already on the Medium branch, `3aa4aef`) is also merged** — see S7 below — but the two branches need to land together, not independently, or there's a window where S4 is merged without S7. |
| **S5** | `b1cf87e` | ⚠️ Fixed, incomplete (1 of 4 channels) | The specific background-renewal path (`poll.rs::cert_maintenance`) is genuinely converted push→pull: it now sends a data-free nudge and lets Corgi fetch via its own `GET /agents/:id/certs/:name`, using a live-fingerprint enrichment on `get_assignments` — well tested. **But** `routes_corgi.rs::provision_cert`, `routes_corgi.rs::renew_cert`, and the admin-triggered renewal handler in `routes_api.rs` (~line 977) all still call `push_cert_install` → `POST /flock/:name/install`, and `corgi/src/routes.rs::flock_install` still accepts and installs whatever's posted. CLAUDE.md's invariant ("Shepherd never pushes config or cert material to Corgi") is written unconditionally — this fix narrows the violation to 3 of 4 original channels rather than closing it. |

### Medium — `security-fix-medium-priority` (merged, == `main`)

| ID | Commit | Verdict | Notes |
|---|---|---|---|
| **S6** | `ec32d78` | ✅ Fixed & Verified | `is_safe_cert_name()` applied at all 4 relevant call sites. Percent-encoded traversal regression tests pass; no regression for legitimate dotted/hyphenated names. |
| **CL2** | `cf44fdd` | ✅ Fixed & Verified | Defaults to `Readonly`, not `Admin`. `update_account` now uses fallible `try_from_str` → 400 on bad input. All downstream consumers (JWT claims, refresh-token fallback, CLI, vigil `rbacIdentities`) checked — the one intentional exception (vigil's *omitted*-role-defaults-to-admin) is confirmed out of CL2's scope, matching the original review's own note. |
| **S7** | `3aa4aef` | ⚠️ Fixed, incomplete (1 of 4 handlers) | The specific race in `poll.rs::cert_maintenance` (both automatic loops) is closed via a properly atomic `create_job_if_not_active`. **But** the identical unpatched read-check-then-create pattern still exists in `routes_corgi.rs::provision_cert`, `routes_corgi.rs::renew_cert`, and `routes_api.rs::admin_provision_or_renew` (the last has **no** dedup guard at all) — all three write to the same `JobStore` and hit the same Corgi pending-key endpoint, so the same wrong-key-installed race is still reachable through them. |
| **C2** | `26ceca2` | ❌ Not actually fixed (visibility only) | Only adds a `tracing::warn!`; `danger_accept_invalid_certs(true)` is left in place, so the MITM exposure is unchanged. The commit's stated reason — that hard-failing would push traffic onto an "even less secure" fallback client in `AppState::new` — **does not hold up**: I read `corgi/src/state.rs:44-50` directly, and that fallback (`reqwest::Client::builder().use_rustls_tls().build()`, no `danger_accept_invalid_certs`) does normal TLS verification against public roots. Since Shepherd's real cert is issued by Vigil's private CA, that fallback would simply fail closed against a real deployment — it's safer, not less safe, than the caPath-unset path. It's also a different code path entirely (triggered by `build_shepherd_client` erroring, not by `caPath` being unset — `build_shepherd_client` returns `Ok` either way when `caPath` is merely unset). The comparison in the commit message compares two unrelated failure conditions. **Net effect: an operator who omits/mistypes `mtls.caPath` still gets full, silent-except-for-one-log-line MITM exposure on every Shepherd call.** Treat this as still open. |
| **CL3** | `5ffd0ce` | ✅ Fixed & Verified (partial) | `limit` clamped to 20,000 and file reads moved to `spawn_blocking`, confirmed applied uniformly across all 3 services via the single `respond_to_log_query` dispatch point. The finding's second half — skip files outside the `since`/`until` window by mtime before reading — was **not** implemented; each file is still read fully into memory before time-filtering. Smaller residual gap, not a regression. |
| **V3** | `8971e85` | ✅ Fixed & Verified | Recursion depth capped at 32 on both recursive call sites; the enclosing loop still advances position independent of depth, so there's no separate unbounded-loop path. Crafted-deep-DER test passes. |
| **V4** | `91f64a6` | ✅ Fixed & Verified | Confirmed all 5 claimed call sites acquire `storage_lock` (3 in `acme.rs`, 2 in `routes.rs`). Regression test reproduces the actual lost-update race with an artificial delay under the lock. Minor gap outside the commit's stated scope: `vigil/src/cli.rs::run_ca_add_user` (offline CLI-only) still does an unlocked read-modify-write — low practical risk. |
| **D3** | `093b889` | ✅ Fixed & Verified (both halves) | Stale-role default lowered 1800s→300s (behavior during a Shepherd outage deliberately unchanged, only the window shrank — stated as intentional). Single-use PoP tokens via a `consumedSignatures` map, checked after signature verification, TTL-pruned; replay-of-same-token test passes. Two low-severity caveats: the example config still ships the old `1800` value (docs drift, not a code defect), and single-use tracking is in-memory/single-process only (fine for the current single-instance deployment model, would need shared state if the BFF is ever run as multiple replicas). |
| **D4** | `c32282a` | ✅ Fixed & Verified | Both `/auth/login/finish` and `/auth/enroll/finish` call `regenerateSession()` before assigning `session.user`, correct relative to express-session's regenerate semantics. Test asserts the session ID actually changes. |
| **S8** | `3efaec9` | ✅ Fixed & Verified | Rejects expired leaves; only promotes intermediates that are both currently valid and `cA=true`. Minor residual gap: `pathLenConstraint` isn't checked — low risk given the single-intermediate deployment model. |
| **S9** | `29f9a2b` | ✅ Fixed & Verified | `parse_ca_entry` rejects non-`https://` directory URLs at all 3 CA-loading paths (startup, periodic reload, admin reload endpoint) with no bypass. Connector-level `.https_or_http()` is unchanged, but is fine today since config-load is the sole `CaConfig` construction site. |
| **D5** | `aa52c4f` | ✅ Fixed & Verified | Positive-allowlist regex rejects `@`/`+`/`-` (and everything else outside hostname characters) *anywhere* in the string, stronger than the doc's minimal "reject leading" suggestion. Applied at intake, before storage or reuse in re-polling. |
| **D6** | `db4600a` | ✅ Fixed & Verified | Resolves the hostname once via `dns.promises.lookup`, checks the **resolved IP** against the blocklist, and connects to that same resolved IP (closing the DNS-rebinding gap). IPv4 + IPv6 loopback/link-local/mapped forms all covered. RFC1918 deliberately left unblocked — documented as an intentional scope decision (the endpoint's job is inspecting fleet certs on private addresses), not an oversight. |

---

## New issues surfaced by this pass

1. **C2 (corgi MITM-if-caPath-unset) is effectively still open** — see verdict above. Recommend either implementing the doc's original suggested fix (fail closed at startup, gated behind an explicit opt-in flag for dev use) or, at minimum, correcting the commit's rationale and re-evaluating.
2. **S5 and S7 are both partial fixes leaving 3 of 4 vulnerable call sites open** in each case (different call sites: S5 is about push channels, S7 is about the job-registration race, but both share the pattern "the automatic/background path got fixed, the three admin/API-triggered paths didn't"). Worth a fast follow-up commit on each, since the hard part (the correct pattern) is already proven out in the one fixed call site — it's a mechanical port to the other three.
3. **S4 widens the S7 race** until S7's fix is also present — these two must merge together, not independently, or there's a window with the regression and no mitigation.
4. **Expected merge conflict:** `dashboard/server/auth/pop.ts` is rewritten by both the unmerged `security-fix-critical-pop-revoke` branch (D1: restructures the `caPath`-unset block into an early-return) and the already-merged `security-fix-medium-priority` branch (D3: appends single-use-token logic immediately after that same block). These touch overlapping regions of the same function and will need a manual merge, not just conflict-marker cleanup — worth planning for before merging the critical branch.
5. **`vigil/src/acme.rs` is touched by all three branches** (V1 in `revoke_cert`, V2's call site in `finalize_order`, V4's lock acquisition around `finalize_order`/`revoke_cert`/`save_accounts`) — different regions of the same functions in some cases. Not confirmed as a textual conflict, but worth merging one branch at a time and re-running the full `acme_flow.rs` test suite after each, rather than merging all three simultaneously.

---

## Still open (no fix commit on any branch)

- **O1** [Critical] — `deploy/migrate-credo-store.sh` leaves Vigil's CA key and Shepherd's archived keys world-readable.
- **O2** [Medium] — same script: live-filesystem TOCTOU, no service-stop requirement.
- **O3** [Medium] — same script: `shepherd.jwt.key.pem` filename assumed, not read from config.
- All originally-catalogued Low/Info items (hand-rolled DER extensions, `none-01` mislabeling, unbounded pre-auth challenge map, WebAuthn UV not required, bootstrap-token non-constant-time comparison, issuance-ledger check-then-append race, `persist_issued_material` bypassing `file_policy`, unauthenticated `/flock`, etc.) — untouched, status unchanged from the 2026-07-26 doc.

---

## Post-review merge (2026-07-28, after this confirmation pass)

All three branches are now on `main`, merged in the recommended order (medium was already there; high then critical):

- `32d4b6c` — merge `security-fix-high-priority`. No conflicts; `cargo build`/`test`/`clippy -D warnings` and `dashboard` `typecheck` all clean.
- `db2d37a` — merge `security-fix-critical-pop-revoke`. Two real conflicts, both anticipated in this doc's "New issues" section above and resolved by hand:
  - `dashboard/server/auth/pop.ts` itself auto-merged cleanly (git resolved it without markers) and correctly retains both D1's mandatory CA-chain check and D3's single-use-token check in sequence.
  - `dashboard/server/auth/pop.test.ts` was an add/add conflict (both branches added a test file at this path for different things). Merged into one file with two `describe` blocks; D3's replay-protection tests were rewritten to sign against a CA-issued leaf with a configured `caPath` instead of a bare self-signed cert, since D1's now-merged fix fails closed without a CA and the old test setup would otherwise fail for the wrong reason.
  - `vigil/tests/acme_flow.rs` conflicted because both branches appended a test function and independently changed `build_csr_der`'s signature (V2 needed multiple SANs; V1 needed an externally-supplied key so the test could reuse it to sign a jwk-path revoke). Merged the signature to accept both (`sans: &[&str], key: &SigningKey`); kept both test functions.
  - Post-resolution: full workspace `cargo test` (all packages, 0 failures), `cargo clippy --workspace -- -D warnings` (clean), `cargo fmt --check` (clean), `npx vitest run` in `dashboard/` (155/155 passed), `npm run typecheck` (clean).

Not pushed to `origin/main` — `main` is 12 commits ahead of `origin/main` locally, pending a decision on when to push.

O1 (Ops, `deploy/migrate-credo-store.sh`) has no branch and still needs new work — untouched by this merge.
