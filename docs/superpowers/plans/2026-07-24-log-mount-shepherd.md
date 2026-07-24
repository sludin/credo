# Shepherd Log Mount Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give shepherd a `GET /admin/logs` endpoint that serves its own logs (`target=shepherd`, the default) and proxies historical log queries to vigil (`target=vigil`) and a named corgi (`target=corgi:<name>`), completing the JSON (non-streaming) half of Phase 3 from the on-demand log retrieval design (`docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`). Shepherd's own config-driven logging (the prerequisite `LoggingConfig`/`LoggingHandle` wiring — mirroring what corgi and vigil already have) was completed in a preceding commit on this branch and is not part of this plan.

**Scope cut, deliberate:** this plan is JSON-only. Live-tail (`?follow=true`) proxying to vigil/corgi — which needs a streaming-capable outbound client, the `reqwest` `"stream"` feature, per-request timeout overrides on the existing 15s/30s client-level timeouts, and verbatim SSE byte passthrough — is real, separate design risk and is deferred to its own future plan. `AdminLogsQuery` in this plan has no `follow` field for the same reason `LogQueryParams` didn't gain `follow` until the slice that actually used it.

**Architecture:** `GET /admin/logs?target=...` dispatches on `target` (`"shepherd"` default, `"vigil"`, or `"corgi:<name>"`), reusing the exact three-service topology already established: `target=shepherd` calls `credo_lib::log_query::historical_logs` directly against shepherd's own `LoggingHandle` (the same function corgi/vigil call locally); `target=vigil` reuses the **existing** `state.vigil_client` (already used for `/ca`, `/health`) to call vigil's own `GET /logs`; `target=corgi:<name>` resolves the node from `state.corgis` (the same linear-scan-by-name pattern already used by `get_corgi_hooks`) and reuses the **existing** `corgi_client::corgi_get<T>` helper to call that corgi's `GET /logs`. Both proxy targets forward the query params as a properly percent-encoded query string built via `reqwest::Url`'s query-pair builder (not `#[serde(flatten)]` — axum's `Query` extractor uses `serde_urlencoded`, which doesn't support flatten reliably, confirmed against the pinned axum 0.7.9 source before writing this plan). All three branches return the identical `Json<Vec<String>>` shape, since `historical_logs` already returns exactly that.

**Tech Stack:** Rust, axum (already a dependency), `reqwest::Url` (re-export of the `url` crate, already available transitively via `reqwest`, no new dependency).

## Global Constraints

- This plan touches `shepherd` only (plus its `credo-test` harness, if needed — it shouldn't be, since no new required constructor args are introduced).
- No `follow` field on `AdminLogsQuery` — live-tail proxying is out of scope, a separate future plan.
- Do not modify `corgi_client::corgi_get` or `state.vigil_client`'s construction — both are reused exactly as they exist today (including their current 30s/15s client-level timeouts, which are fine for JSON queries and only become a problem once live-tail proxying needs them overridden, in the future plan that adds that).
- `cargo fmt --check` and `cargo clippy -p shepherd --all-targets -- -D warnings` must pass for every commit **except** for the 5 pre-existing, unrelated clippy errors in `shepherd/src/routes_api.rs` and elsewhere (`items_after_test_module` ×3, `too_many_arguments` on an unrelated function, `non_binding_let`) — confirmed pre-existing by stashing changes and reproducing identically on two separate branches; do not attempt to fix them here, and do not let CI/local runs mistake them for a regression introduced by this plan. Verify no *new* clippy errors appear beyond those exact 5.
- Commit after each task with a message explaining *why*, not just what.
- No placeholder/TODO code. Every function must be fully implemented and covered by a test in the same task.

---

### Task 1: `AdminLogsQuery` and its pure helpers

**Files:**
- Modify: `shepherd/src/routes_api.rs`

**Interfaces:**
- Produces (used by Task 2): `pub struct AdminLogsQuery { pub target: Option<String>, pub since: Option<String>, pub until: Option<String>, pub last: Option<String>, pub level: Option<String>, pub q: Option<String>, pub limit: Option<usize> }` (`Debug + Deserialize + Default`), `AdminLogsQuery::to_log_query_params(&self) -> credo_lib::log_query::LogQueryParams`, `AdminLogsQuery::forward_pairs(&self) -> Vec<(&'static str, String)>`, `fn build_query_string(pairs: &[(&str, String)]) -> String`.

- [ ] **Step 1: Write the failing tests**

Add this code to `shepherd/src/routes_api.rs`. Find the file's existing `#[cfg(test)] mod tests` block (shepherd's `routes_api.rs` already has one, per the file's existing structure — confirm this before writing; if no test module exists yet, create `#[cfg(test)] mod tests { use super::*; ... }` at the end of the file instead) and add these test functions to it:

```rust
    #[test]
    fn admin_logs_query_converts_to_log_query_params_with_follow_false() {
        let query = AdminLogsQuery {
            target: Some("shepherd".to_string()),
            since: Some("2024-01-15T09:00:00Z".to_string()),
            until: Some("2024-01-15T10:00:00Z".to_string()),
            last: Some("5m".to_string()),
            level: Some("warn".to_string()),
            q: Some("corgi".to_string()),
            limit: Some(100),
        };
        let params = query.to_log_query_params();
        assert_eq!(params.since, Some("2024-01-15T09:00:00Z".to_string()));
        assert_eq!(params.until, Some("2024-01-15T10:00:00Z".to_string()));
        assert_eq!(params.last, Some("5m".to_string()));
        assert_eq!(params.level, Some("warn".to_string()));
        assert_eq!(params.q, Some("corgi".to_string()));
        assert_eq!(params.limit, Some(100));
        assert!(!params.follow);
    }

    #[test]
    fn admin_logs_query_forward_pairs_only_includes_set_fields() {
        let query = AdminLogsQuery {
            target: Some("vigil".to_string()),
            level: Some("warn".to_string()),
            limit: Some(50),
            ..Default::default()
        };
        let pairs = query.forward_pairs();
        assert_eq!(
            pairs,
            vec![("level", "warn".to_string()), ("limit", "50".to_string())]
        );
    }

    #[test]
    fn admin_logs_query_forward_pairs_empty_when_nothing_set() {
        let query = AdminLogsQuery::default();
        assert!(query.forward_pairs().is_empty());
    }

    #[test]
    fn build_query_string_empty_pairs_returns_empty_string() {
        assert_eq!(build_query_string(&[]), "");
    }

    #[test]
    fn build_query_string_round_trips_values_with_special_characters() {
        let pairs = vec![
            ("q", "hello world & more".to_string()),
            ("level", "warn".to_string()),
        ];
        let qs = build_query_string(&pairs);
        assert!(qs.starts_with('?'), "expected a leading '?', got {qs:?}");
        // Round-trip through a real URL parse rather than asserting an exact
        // percent-encoding scheme, since the specific encoding (e.g. spaces
        // as '+' vs '%20') is an implementation detail of the `url` crate.
        let url = reqwest::Url::parse(&format!("http://x.invalid/{qs}")).expect("parse url");
        let collected: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(
            collected,
            vec![
                ("q".to_string(), "hello world & more".to_string()),
                ("level".to_string(), "warn".to_string()),
            ]
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p shepherd admin_logs_query`
Expected: compile error — `AdminLogsQuery`, `build_query_string` are referenced but not yet defined.

- [ ] **Step 3: Implement `AdminLogsQuery` and the helpers**

Insert this code in `shepherd/src/routes_api.rs`, near the other small query-param structs in the file (if none exist nearby, place it directly above wherever `get_vigil_ca`/`get_vigil_status` are defined, since `get_logs` — added in Task 2 — belongs next to them):

```rust
/// Query parameters for `GET /admin/logs`. Reuses the field set of
/// `credo_lib::log_query::LogQueryParams` directly rather than
/// `#[serde(flatten)]`-ing it: axum's `Query` extractor uses
/// `serde_urlencoded`, which doesn't support flatten reliably. `target`
/// selects the log source: `"shepherd"` (default), `"vigil"`, or
/// `"corgi:<name>"`. `follow` (live tail) is deliberately not a field here -
/// this endpoint is JSON-only; live-tail proxying is a separate future plan.
#[derive(Debug, serde::Deserialize, Default)]
pub struct AdminLogsQuery {
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub last: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}

impl AdminLogsQuery {
    /// Converts to `LogQueryParams` for a direct, in-process call into
    /// `credo_lib::log_query` - used for `target=shepherd`. `follow` is
    /// always `false`: this endpoint doesn't support live tail yet.
    fn to_log_query_params(&self) -> credo_lib::log_query::LogQueryParams {
        credo_lib::log_query::LogQueryParams {
            since: self.since.clone(),
            until: self.until.clone(),
            last: self.last.clone(),
            level: self.level.clone(),
            q: self.q.clone(),
            limit: self.limit,
            follow: false,
        }
    }

    /// Key/value pairs to forward to a proxied service's own `/logs`
    /// endpoint - everything except `target` (shepherd-only) and `follow`
    /// (omitted; the proxied endpoint defaults to `false` when absent).
    fn forward_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(v) = &self.since {
            pairs.push(("since", v.clone()));
        }
        if let Some(v) = &self.until {
            pairs.push(("until", v.clone()));
        }
        if let Some(v) = &self.last {
            pairs.push(("last", v.clone()));
        }
        if let Some(v) = &self.level {
            pairs.push(("level", v.clone()));
        }
        if let Some(v) = &self.q {
            pairs.push(("q", v.clone()));
        }
        if let Some(v) = self.limit {
            pairs.push(("limit", v.to_string()));
        }
        pairs
    }
}

/// Builds a `?key=value&...` query string (percent-encoded via `url`'s
/// query-pair builder, re-exported as `reqwest::Url`) from `pairs`, or an
/// empty string if `pairs` is empty.
fn build_query_string(pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let mut url = reqwest::Url::parse("http://placeholder.invalid/").expect("static URL must parse");
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in pairs {
            qp.append_pair(k, v);
        }
    }
    format!("?{}", url.query().unwrap_or_default())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p shepherd admin_logs_query build_query_string`
Expected: all 5 new tests pass (`admin_logs_query_converts_to_log_query_params_with_follow_false`, `admin_logs_query_forward_pairs_only_includes_set_fields`, `admin_logs_query_forward_pairs_empty_when_nothing_set`, `build_query_string_empty_pairs_returns_empty_string`, `build_query_string_round_trips_values_with_special_characters`).

- [ ] **Step 5: Lint and format**

Run: `cargo fmt -p shepherd && cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep -v "routes_api.rs:1334\|items after a test module\|too many arguments (13/7)\|non-binding \`let\`"`
Expected: after filtering out the 5 known pre-existing errors, no output (no new clippy issues). Run the unfiltered command too and confirm the error count is still exactly 5, not more.

- [ ] **Step 6: Commit**

```bash
git add shepherd/src/routes_api.rs
git commit -m "$(cat <<'EOF'
feat(shepherd): add AdminLogsQuery and query-forwarding helpers

Pure building blocks for the /admin/logs endpoint (added next): the
query struct doesn't #[serde(flatten)] LogQueryParams because axum's
Query extractor uses serde_urlencoded, which doesn't support flatten
reliably - confirmed against the pinned axum source rather than
guessed. build_query_string reuses url's query-pair builder (already
available via reqwest's re-export) for correct percent-encoding when
forwarding a query to vigil/corgi's own /logs endpoint, rather than
hand-rolling encoding or adding a new dependency.
EOF
)"
```

---

### Task 2: `get_logs` handler, route registration, and tests

**Files:**
- Modify: `shepherd/src/routes_api.rs`
- Modify: `shepherd/src/server.rs`
- Modify: `shepherd/docs/config.md`
- Create: `shepherd/tests/admin_logs.rs`

**Interfaces:**
- Consumes (from Task 1): `AdminLogsQuery`.
- Consumes (already existing, unmodified): `credo_lib::log_query::historical_logs`, `state.vigil_client`, `state.corgis`, `corgi_client::corgi_get`, `check_min_role`, `AuthenticatedUser`.
- Produces: `pub async fn get_logs(State(state): State<AppState>, axum::Extension(user): axum::Extension<AuthenticatedUser>, Query(query): Query<AdminLogsQuery>) -> Result<Json<Vec<String>>, AppError>`, mounted at `GET /admin/logs`.

- [ ] **Step 1: Write the failing tests**

Create `shepherd/tests/admin_logs.rs`:

```rust
use credo_test::shepherd_harness::TestShepherd;

/// GET /admin/logs requires auth - returns 401 without a token/cert.
#[tokio::test]
async fn admin_logs_requires_auth() {
    let shepherd = TestShepherd::start().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "/admin/logs must require auth");
}

/// An unrecognized target value is a 400, not a panic or 500.
#[tokio::test]
async fn admin_logs_unknown_target_returns_400() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs?target=bogus", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=shepherd (the default) reaches credo_lib::log_query::historical_logs
/// against shepherd's own LoggingHandle - which, in the test harness, is
/// always LoggingHandle::disabled() (the harness can't call
/// init_logging_with_config: it installs a process-global tracing
/// subscriber, only allowed once per process). So a successfully-authed,
/// default-target request deterministically gets a 400 ("file logging is
/// not enabled"), proving the dispatch and delegation, not the query logic
/// itself (credo-lib's own tests already cover that in depth).
#[tokio::test]
async fn admin_logs_default_target_shepherd_reaches_handler() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=vigil with no Vigil configured (the test harness's default) is a
/// 400, not a panic - proves the "Vigil not configured" / "Vigil client
/// unavailable" guard rather than the real proxy call (which needs a live
/// Vigil instance - out of scope for this test).
#[tokio::test]
async fn admin_logs_target_vigil_not_configured_returns_400() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs?target=vigil", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=corgi:<name> for a name that isn't in state.corgis is a clean 404.
#[tokio::test]
async fn admin_logs_target_unknown_corgi_returns_404() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/logs?target=corgi:nonexistent",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p shepherd --test admin_logs`
Expected: compile error or connection error — `GET /admin/logs` doesn't exist yet (404 fallback at best, but the code won't even compile against `TestShepherd` until the route exists — actually the harness itself compiles fine; expect the 401 test to accidentally pass via the fallback 404-vs-401 mismatch, and the rest to fail on wrong status codes, since the route isn't registered yet and every request falls through to `api_fallback`). Note in your report which specific assertions failed and why, since "route not registered" produces a different failure mode than a compile error - don't assume the RED step looks like a compile error here.

- [ ] **Step 3: Implement `get_logs` and register the route**

Insert this code in `shepherd/src/routes_api.rs`, directly above (or below — whichever keeps related code together per the file's existing organization) the `AdminLogsQuery`/helpers added in Task 1:

```rust
/// Historical log retrieval, aggregated across services. `target=shepherd`
/// (default) serves this shepherd's own logs; `target=vigil` and
/// `target=corgi:<name>` proxy to that service's own `/logs` endpoint using
/// the existing outbound clients (`state.vigil_client`, `state.corgi_client_pool`)
/// already used for `/ca`, `/health`, and hook fetches. JSON-only for now -
/// `?follow=true` live-tail proxying is a separate future endpoint.
pub async fn get_logs(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Query(query): Query<AdminLogsQuery>,
) -> Result<Json<Vec<String>>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;

    let target = query.target.as_deref().unwrap_or("shepherd");

    if target == "shepherd" {
        let params = query.to_log_query_params();
        return credo_lib::log_query::historical_logs(&state.logging_handle, &params).await;
    }

    if target == "vigil" {
        let config = state.config.load_full();
        let url = config
            .vigil_url
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Vigil not configured".to_string()))?;
        let client = state
            .vigil_client
            .read()
            .await
            .clone()
            .ok_or_else(|| AppError::BadRequest("Vigil client unavailable".to_string()))?;
        let body: Vec<String> = client
            .get(format!("{}/logs", url.trim_end_matches('/')))
            .query(&query.forward_pairs())
            .send()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil response parse error: {}", e)))?;
        return Ok(Json(body));
    }

    if let Some(name) = target.strip_prefix("corgi:") {
        let corgis = state.corgis.read().await;
        let node = corgis
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| AppError::NotFound(format!("Corgi '{name}' not found")))?
            .clone();
        drop(corgis);
        let path = format!("/logs{}", build_query_string(&query.forward_pairs()));
        let body: Vec<String> =
            crate::corgi_client::corgi_get(&state.corgi_client_pool, &node, &path)
                .await
                .map_err(AppError::Internal)?;
        return Ok(Json(body));
    }

    Err(AppError::BadRequest(format!("unknown target '{target}'")))
}
```

In `shepherd/src/server.rs`, add the route to the `authenticated` block inside `build_api_router` — insert it right after `.route("/admin/config-summary", get(api::config_summary))`:

```rust
        .route("/admin/config-summary", get(api::config_summary))
        .route("/admin/logs", get(api::get_logs))
```

In `shepherd/docs/config.md`, extend the existing `## Logging` table (the one already documenting `logLevel`/`logging.*` from the preceding commit on this branch) — add a short new section documenting the endpoint itself, following whatever heading style the file uses for other endpoints/admin routes (check the file for an existing `## Admin API` or similar section to match; if none exists, add a new `## GET /admin/logs` section near the Logging section):

```markdown
## GET /admin/logs

Query params: `target` (`"shepherd"` default, `"vigil"`, or `"corgi:<name>"`), `since`, `until`, `last` (duration shorthand like `"5m"`/`"1h"`), `level` (`"error"`/`"warn"`/`"info"`/`"debug"`, minimum severity), `q` (case-insensitive substring), `limit`. Returns a JSON array of log lines. Requires Readonly role or higher. Live tail (`?follow=true`) is not yet supported on this endpoint.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p shepherd --test admin_logs`
Expected: all 5 tests pass (`admin_logs_requires_auth`, `admin_logs_unknown_target_returns_400`, `admin_logs_default_target_shepherd_reaches_handler`, `admin_logs_target_vigil_not_configured_returns_400`, `admin_logs_target_unknown_corgi_returns_404`).

- [ ] **Step 5: Run the full shepherd suite plus lint**

Run: `cargo test -p shepherd --all-targets && cargo fmt -p shepherd -- --check`
Expected: every test in the crate passes (Task 1's 5 new unit tests, this task's 5 new integration tests, plus all pre-existing shepherd tests), no fmt diff.

Run: `cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep -c "^error:"`
Expected: exactly `5` (the pre-existing, unrelated count established in the Global Constraints section) - not 6 or more. If it's more than 5, something in this task introduced a new clippy issue; find and fix it before committing.

- [ ] **Step 6: Confirm the whole workspace still builds**

Run: `cargo build && cargo test 2>&1 | grep -E "test result: ok\. [0-9]+ passed; [1-9]"`
Expected: workspace builds; the grep finds no lines (meaning no test binary anywhere reported an actual failure — the pattern only matches "N passed; M failed" where M is 1 or more).

- [ ] **Step 7: Commit**

```bash
git add shepherd/src/routes_api.rs shepherd/src/server.rs shepherd/docs/config.md shepherd/tests/admin_logs.rs
git commit -m "$(cat <<'EOF'
feat(shepherd): add GET /admin/logs, aggregating shepherd/vigil/corgi

target=shepherd (default) delegates to credo_lib::log_query::historical_logs
against shepherd's own LoggingHandle, the same function corgi/vigil call
locally. target=vigil and target=corgi:<name> proxy to that service's own
/logs endpoint using the existing outbound clients (state.vigil_client,
state.corgi_client_pool via corgi_client::corgi_get) already used for
/ca, /health, and hook fetches - no new client code needed. JSON-only:
live-tail (?follow=true) proxying needs a streaming-capable client,
the reqwest "stream" feature, and timeout overrides on the existing
15s/30s client-level timeouts - real, separate design risk deliberately
left for its own future plan rather than folded in here.

No genuine cross-service proxy-success test exists yet (no TestShepherd
+ TestCorgi/TestVigil harness composition pattern exists anywhere in
this codebase - confirmed by research before writing this plan). This
task's tests thoroughly cover the dispatch/auth/error-handling surface
via the existing single-harness pattern; actual end-to-end proxying
was verified manually (real shepherd+corgi+vigil, curl through
shepherd) rather than as an automated test in this commit.
EOF
)"
```

---

## Verification (whole plan)

1. `cargo build && cargo test && cargo fmt --check` — full workspace, must be clean (tests: zero failures anywhere; fmt: no diff).
2. `cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep -c "^error:"` — must be exactly `5` (the pre-existing count), confirming this plan introduced no new clippy issues.
3. Confirm no files outside `shepherd/` (and its `shepherd/tests/`, `shepherd/docs/`) changed: `git diff --stat <plan-start-commit>..HEAD`.
4. **Manual end-to-end verification** (do this before considering the plan done - it's the only proof the actual proxying works, since no automated cross-service test exists yet): use the `verify` skill (or `run-service` skill) to bring up a local shepherd + corgi + vigil mTLS sandbox with `logging.enabled: true` on all three. Then:
   - `curl` shepherd's `/admin/logs?target=shepherd&last=5m` with a valid dashboard token/cert — confirm a JSON array of shepherd's own recent log lines.
   - `curl` shepherd's `/admin/logs?target=vigil&last=5m` — confirm it matches what `curl`-ing vigil's own `/logs?last=5m` directly returns.
   - `curl` shepherd's `/admin/logs?target=corgi:<real-node-name>&last=5m` — confirm it matches that corgi's own `/logs?last=5m` directly.
   - `curl` shepherd's `/admin/logs?target=corgi:nonexistent` — confirm a clean 404, not a panic or 500.
   - Try a `q`/`level`/`since`/`until` combination through the proxy path and confirm the filtering is actually applied (i.e., the query really reaches the target service, not just an unfiltered dump).

## Next Plan (not in this one)

Live-tail (`?follow=true`) proxying for `target=vigil`/`target=corgi:<name>`: add the `reqwest` `"stream"` feature workspace-wide, per-request timeout overrides on `state.vigil_client` and the `corgi_client` pool (both currently have fixed 15s/30s client-level timeouts that would kill a long-lived SSE tail), a streaming-capable outbound call (`.bytes_stream()`) for both proxy targets, and verbatim byte passthrough into an axum SSE/streaming response (no re-parsing into new `Event`s at the proxy hop — only the innermost service's `credo_lib::log_query::follow_logs` should ever construct real SSE events). After that: the dashboard BFF (Node-side logging + proxy routes) and the frontend Logs tab.
