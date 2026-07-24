# Shepherd Follow Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add live-tail (`?follow=true`) support to shepherd's `GET /admin/logs`, completing Phase 3 of the on-demand log retrieval design (`docs/superpowers/specs/2026-07-23-on-demand-log-retrieval-design.md`). This is the deferred half of the JSON-only endpoint shipped in a preceding, separately-merged plan (`docs/superpowers/plans/2026-07-24-log-mount-shepherd.md`), plus a prerequisite commit already on this branch (`shepherd/src/corgi_client.rs`'s `corgi_get_stream` + the workspace-wide `reqwest` `"stream"` feature — both mechanical, closely mirroring already-reviewed code, implemented directly and verified via full build/test/clippy/fmt rather than through this plan's task pipeline).

**Architecture:** `target=shepherd&follow=true` needs no new code at all beyond passing `follow` through correctly — `credo_lib::log_query::respond_to_log_query` (already used by corgi/vigil for their own `/logs`) already branches on `params.follow` internally, so switching shepherd's local dispatch from `historical_logs` (JSON-only) to `respond_to_log_query` (handles both) is the entire change for that target. `target=vigil&follow=true` and `target=corgi:<name>&follow=true` make an outbound `follow=true` request to that service's own `/logs` (already SSE-capable, from the earlier corgi/vigil mounting plan) using a per-request timeout override (`corgi_get_stream`'s `FOLLOW_TIMEOUT_SECS`, already committed) instead of the pool's normal 15s/30s client-level timeout, then proxy the response bytes through **verbatim** into an axum streaming `Response` (`axum::body::Body::from_stream`) — not re-parsed into new SSE `Event`s. Verified directly against the pinned axum 0.7.9 source before writing this plan: `Body::from_stream<S>(stream: S) -> Self where S: TryStream + Send + 'static, S::Ok: Into<Bytes>, S::Error: Into<BoxError>` (any `Stream<Item = Result<Bytes, reqwest::Error>>`, which is exactly what `reqwest::Response::bytes_stream()` produces, satisfies this via the standard blanket `TryStream` impl), and axum's own `Sse` type sets exactly two headers on success (`Content-Type: text/event-stream`, `Cache-Control: no-cache`) — this plan's proxy sets the identical two, not guessed.

**Tech Stack:** Rust, `axum::body::Body::from_stream` (already available via the existing `axum` dependency, no new crate), `reqwest::Response::bytes_stream()` (now available via the `"stream"` feature already added in the prerequisite commit).

## Global Constraints

- This plan touches `shepherd` only.
- Do not modify `credo_lib::log_query` (any of its files) — it already fully supports `follow` for corgi/vigil's own `/logs`; this plan only changes how shepherd calls out to it and to vigil/corgi.
- Do not modify `corgi_client::corgi_get`, `corgi_client::corgi_get_stream`, or `state.vigil_client`'s construction — all reused exactly as they exist (the `"stream"` feature and `corgi_get_stream` were already added in a prerequisite commit on this branch).
- `cargo fmt --check` and `cargo clippy -p shepherd --all-targets -- -D warnings` must show exactly the same 5 pre-existing, unrelated errors as before (3× `items_after_test_module`, 1× `too_many_arguments` on an unrelated function, 1× `non_binding_let`) — not fewer, not more. Verify with `cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep "^error:" | grep -v "could not compile"` (excluding the summary line, which a naive count has been miscounted by before in this exact series).
- All 5 existing tests in `shepherd/tests/admin_logs.rs` must continue to pass unchanged (non-follow behavior must not regress).
- Commit after each task with a message explaining *why*, not just what.
- No placeholder/TODO code. Every function must be fully implemented and covered by a test in the same task.

---

### Task 1: `follow` on `AdminLogsQuery` and the stream-proxying helper

**Files:**
- Modify: `shepherd/src/routes_api.rs`

**Interfaces:**
- Produces (used by Task 2): `AdminLogsQuery.follow: bool` (new field), updated `AdminLogsQuery::to_log_query_params` (now passes `follow` through instead of hardcoding `false`), updated `AdminLogsQuery::forward_pairs` (now includes `("follow", "true")` when set), `async fn stream_upstream_logs_response(upstream: reqwest::Response) -> Result<axum::response::Response, AppError>`.

- [ ] **Step 1: Write the failing tests**

Change `AdminLogsQuery`'s struct definition in `shepherd/src/routes_api.rs` from:

```rust
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
```

to:

```rust
#[derive(Debug, serde::Deserialize, Default)]
pub struct AdminLogsQuery {
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub last: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
    /// Live-tail via Server-Sent Events instead of a historical JSON array.
    #[serde(default)]
    pub follow: bool,
}
```

Also update the struct's doc comment (the one immediately above `#[derive(...)]`) — it currently ends with a sentence about `follow` being deliberately absent; change that sentence from whatever it currently says about omitting `follow` to: `` `follow` requests a live-tailing SSE stream instead of a historical JSON array. ``

Add these test functions to the existing `#[cfg(test)] mod tests` block in `shepherd/src/routes_api.rs` (append them near the other `admin_logs_query_*` tests from the preceding plan):

```rust
    #[test]
    fn admin_logs_query_forward_pairs_includes_follow_when_true() {
        let query = AdminLogsQuery {
            follow: true,
            ..Default::default()
        };
        assert_eq!(query.forward_pairs(), vec![("follow", "true".to_string())]);
    }

    #[test]
    fn admin_logs_query_forward_pairs_omits_follow_when_false() {
        let query = AdminLogsQuery::default();
        assert!(query.forward_pairs().is_empty());
    }

    #[test]
    fn admin_logs_query_to_log_query_params_passes_through_follow() {
        let query = AdminLogsQuery {
            follow: true,
            ..Default::default()
        };
        assert!(query.to_log_query_params().follow);
    }

    #[tokio::test]
    async fn stream_upstream_logs_response_passes_sse_bytes_through_verbatim() {
        // Minimal mock server standing in for a real corgi/vigil
        // /logs?follow=true SSE endpoint - proves the byte-passthrough and
        // header-setting logic in isolation, without needing the corgi
        // client pool's mTLS machinery or a full TestCorgi/TestVigil
        // harness (no composable cross-service harness pattern exists in
        // this codebase - confirmed before writing this plan).
        let app = axum::Router::new().route(
            "/logs",
            axum::routing::get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    "data: {\"line\":\"hello\",\"source\":\"mock\"}\n\n",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = reqwest::Client::new();
        let upstream = client
            .get(format!("http://{addr}/logs"))
            .send()
            .await
            .expect("request");

        let response = stream_upstream_logs_response(upstream)
            .await
            .expect("stream response");
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .expect("content-type header"),
            "text/event-stream"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .expect("cache-control header"),
            "no-cache"
        );

        use http_body_util::BodyExt;
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(
            body_bytes.as_ref(),
            b"data: {\"line\":\"hello\",\"source\":\"mock\"}\n\n".as_slice()
        );
    }

    #[tokio::test]
    async fn stream_upstream_logs_response_maps_upstream_error_to_internal() {
        let app = axum::Router::new().route(
            "/logs",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "file logging is not enabled",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = reqwest::Client::new();
        let upstream = client
            .get(format!("http://{addr}/logs"))
            .send()
            .await
            .expect("request");

        let result = stream_upstream_logs_response(upstream).await;
        assert!(result.is_err(), "non-2xx upstream must map to an error");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p shepherd --lib routes_api::tests`
Expected: compile errors — `AdminLogsQuery.follow` doesn't exist as a struct-literal field yet, `forward_pairs`/`to_log_query_params` don't reference it, `stream_upstream_logs_response` is referenced but not yet defined.

- [ ] **Step 3: Implement the `follow` field, update the two methods, and add `stream_upstream_logs_response`**

Change `AdminLogsQuery::to_log_query_params` from:

```rust
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
```

to:

```rust
    fn to_log_query_params(&self) -> credo_lib::log_query::LogQueryParams {
        credo_lib::log_query::LogQueryParams {
            since: self.since.clone(),
            until: self.until.clone(),
            last: self.last.clone(),
            level: self.level.clone(),
            q: self.q.clone(),
            limit: self.limit,
            follow: self.follow,
        }
    }
```

Change `AdminLogsQuery::forward_pairs` from:

```rust
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
```

to:

```rust
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
        if self.follow {
            pairs.push(("follow", "true".to_string()));
        }
        pairs
    }
```

Insert this new function directly after `build_query_string` (the last helper from the preceding plan, right before `get_logs`):

```rust
/// Converts a successful upstream `follow=true` SSE response into an axum
/// streaming Response, proxying the bytes through verbatim - not re-parsed
/// into new SSE `Event`s. Only the innermost service's own `/logs` handler
/// (`credo_lib::log_query::follow_logs`) should ever construct real SSE
/// events; every proxy hop after that just forwards bytes, avoiding
/// framing bugs. Headers match exactly what axum's own `Sse` type sets on
/// success (`Content-Type: text/event-stream`, `Cache-Control: no-cache` -
/// verified against the pinned axum 0.7.9 source, not guessed).
///
/// Returns `AppError::Internal` if the upstream response itself is an
/// error (e.g. that service's own logging is disabled) - the specific
/// upstream status/message isn't preserved through the proxy for now, the
/// same known, already-accepted limitation as the non-follow proxy
/// branches in `get_logs`.
async fn stream_upstream_logs_response(
    upstream: reqwest::Response,
) -> Result<axum::response::Response, AppError> {
    if !upstream.status().is_success() {
        let status = upstream.status();
        let body = upstream.text().await.unwrap_or_default();
        return Err(AppError::Internal(anyhow::anyhow!(
            "upstream /logs?follow=true failed ({status}): {body}"
        )));
    }
    let body = axum::body::Body::from_stream(upstream.bytes_stream());
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .body(body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("building streaming response: {e}")))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p shepherd --lib routes_api::tests`
Expected: all pass, including the 5 new tests (`admin_logs_query_forward_pairs_includes_follow_when_true`, `admin_logs_query_forward_pairs_omits_follow_when_false`, `admin_logs_query_to_log_query_params_passes_through_follow`, `stream_upstream_logs_response_passes_sse_bytes_through_verbatim`, `stream_upstream_logs_response_maps_upstream_error_to_internal`) plus all pre-existing `routes_api` unit tests.

- [ ] **Step 5: Lint and format**

Run: `cargo fmt -p shepherd && cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep "^error:" | grep -v "could not compile"`
Expected: exactly the same 5 pre-existing error lines as before this task — no new ones. (`get_logs` itself hasn't been updated to call `stream_upstream_logs_response`/pass `follow` through yet — that's Task 2 — so expect a `dead_code` warning risk here too, same as the previous plan's Task 1: if clippy flags `stream_upstream_logs_response` as unused, add `#[allow(dead_code)]` with a one-line comment noting Task 2 wires it in, exactly like the precedent from the preceding plan's Task 1 — and remember to remove it in Task 2 once there's a real caller.)

- [ ] **Step 6: Commit**

```bash
git add shepherd/src/routes_api.rs
git commit -m "$(cat <<'EOF'
feat(shepherd): add follow support to AdminLogsQuery and a stream proxy helper

follow now threads through to_log_query_params (so target=shepherd's
existing respond_to_log_query call, wired in next, gets it for free)
and forward_pairs (so target=vigil/corgi's outbound request carries
it). stream_upstream_logs_response is the actual proxy: turns a
successful upstream SSE response into an axum streaming Response via
Body::from_stream, setting the exact two headers axum's own Sse type
sets on success (verified against the pinned axum 0.7.9 source, not
guessed) - proxying bytes through verbatim rather than re-parsing into
new Events, since only the innermost service's own /logs handler
should ever construct real SSE events. Tested against a real (if
minimal) mock HTTP server rather than mocked at the type level, since
the actual byte-passthrough and header behavior is exactly what a type
signature can't prove.

Not yet called from get_logs - that's the next task.
EOF
)"
```

---

### Task 2: Wire `follow` into `get_logs`, add tests, update docs

**Files:**
- Modify: `shepherd/src/routes_api.rs`
- Modify: `shepherd/docs/config.md`
- Modify: `shepherd/tests/admin_logs.rs`

**Interfaces:**
- Consumes (from Task 1): `AdminLogsQuery.follow`, `stream_upstream_logs_response`.
- Consumes (already existing, unmodified): `credo_lib::log_query::respond_to_log_query`, `corgi_client::corgi_get_stream`, `corgi_client::FOLLOW_TIMEOUT_SECS`.
- Changes: `get_logs`'s return type from `Result<Json<Vec<String>>, AppError>` to `Result<axum::response::Response, AppError>`.

- [ ] **Step 1: Write the failing tests**

Add these test functions to `shepherd/tests/admin_logs.rs` (append after the existing 5 tests):

```rust
/// target=shepherd&follow=true reaches the same shared dispatch as the
/// non-follow case - credo_lib::log_query::respond_to_log_query internally
/// branches on follow. Against the test harness's disabled LoggingHandle,
/// both paths get the same 400 ("file logging is not enabled"), proving
/// follow is correctly threaded through rather than silently ignored.
#[tokio::test]
async fn admin_logs_target_shepherd_follow_reaches_handler() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs?follow=true", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=vigil&follow=true hits the same "Vigil not configured" guard as
/// the non-follow case - proving that guard runs before any follow-specific
/// streaming logic, not after (i.e. the config/client checks aren't
/// accidentally skipped on the follow path).
#[tokio::test]
async fn admin_logs_target_vigil_follow_not_configured_returns_400() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/logs?target=vigil&follow=true",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=corgi:<unknown>&follow=true still returns a clean 404 - the
/// corgi-lookup guard runs before any follow-specific streaming logic.
#[tokio::test]
async fn admin_logs_target_unknown_corgi_follow_returns_404() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/logs?target=corgi:nonexistent&follow=true",
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
Expected: the 3 new tests fail (the current handler ignores `follow` entirely and always takes the JSON-only path, but since these particular scenarios all fail *before* reaching any follow-specific code — on the "not configured"/"unavailable"/"not found" guards — they may actually already return the expected status even before this task's changes. If so, note this explicitly in your report rather than assuming something is wrong: these 3 tests are guard-ordering regression tests, not proof that follow works yet. `admin_logs_target_shepherd_follow_reaches_handler` is the one that's guaranteed meaningful pre-change, since the current code calls `historical_logs` (not `respond_to_log_query`) for `target=shepherd` regardless of `follow` — but it happens to produce the identical 400 either way, since `historical_logs` and `respond_to_log_query`'s non-follow branch both check the same "file logging is not enabled" condition. This is expected — the real proof that `follow` is wired in comes from Task 1's already-passing unit tests plus the manual end-to-end verification in this plan's final Verification section, not from these 3 particular integration tests, which exist to catch a *regression* in guard ordering, not to prove streaming itself works.)

- [ ] **Step 3: Wire `follow` into `get_logs`**

Replace the entire current `get_logs` function body in `shepherd/src/routes_api.rs` — from:

```rust
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
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!("Vigil response parse error: {}", e))
            })?;
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

to:

```rust
pub async fn get_logs(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Query(query): Query<AdminLogsQuery>,
) -> Result<axum::response::Response, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;

    let target = query.target.as_deref().unwrap_or("shepherd");

    if target == "shepherd" {
        let params = query.to_log_query_params();
        return credo_lib::log_query::respond_to_log_query(&state.logging_handle, &params).await;
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

        if query.follow {
            // Reusing corgi_client's timeout constant here too - it's just
            // a shared "effectively unbounded for a live tail" value, not
            // corgi-specific.
            let upstream = client
                .get(format!("{}/logs", url.trim_end_matches('/')))
                .query(&query.forward_pairs())
                .timeout(std::time::Duration::from_secs(
                    crate::corgi_client::FOLLOW_TIMEOUT_SECS,
                ))
                .send()
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?;
            return stream_upstream_logs_response(upstream).await;
        }

        let body: Vec<String> = client
            .get(format!("{}/logs", url.trim_end_matches('/')))
            .query(&query.forward_pairs())
            .send()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!("Vigil response parse error: {}", e))
            })?;
        return Ok(Json(body).into_response());
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

        if query.follow {
            let upstream =
                crate::corgi_client::corgi_get_stream(&state.corgi_client_pool, &node, &path)
                    .await
                    .map_err(AppError::Internal)?;
            return stream_upstream_logs_response(upstream).await;
        }

        let body: Vec<String> =
            crate::corgi_client::corgi_get(&state.corgi_client_pool, &node, &path)
                .await
                .map_err(AppError::Internal)?;
        return Ok(Json(body).into_response());
    }

    Err(AppError::BadRequest(format!("unknown target '{target}'")))
}
```

Also update `get_logs`'s doc comment (the block directly above `pub async fn get_logs`) — it currently ends with a sentence saying this endpoint is JSON-only and `follow=true` is a separate future endpoint. Replace that sentence with: `` `?follow=true` requests a live-tailing SSE stream instead, proxied through verbatim from whichever service actually produced it. ``

In `shepherd/docs/config.md`, update the `## GET /admin/logs` section — change the query-params list to include `follow`, and remove the "Live tail (`?follow=true`) is not yet supported on this endpoint." sentence:

```markdown
## GET /admin/logs

Query params: `target` (`"shepherd"` default, `"vigil"`, or `"corgi:<name>"`), `since`, `until`, `last` (duration shorthand like `"5m"`/`"1h"`), `level` (`"error"`/`"warn"`/`"info"`/`"debug"`, minimum severity), `q` (case-insensitive substring), `limit`, `follow` (boolean - live-tail via Server-Sent Events instead of a JSON array). Requires Readonly role or higher.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p shepherd --test admin_logs`
Expected: all 8 tests pass — the 5 pre-existing ones (unchanged behavior, confirming no regression) plus the 3 new ones from Step 1.

- [ ] **Step 5: Run the full shepherd suite plus lint**

Run: `cargo test -p shepherd --all-targets && cargo fmt -p shepherd -- --check`
Expected: every test in the crate passes, no fmt diff.

Run: `cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep "^error:" | grep -v "could not compile" | wc -l`
Expected: exactly `5`. If `stream_upstream_logs_response` had an `#[allow(dead_code)]` from Task 1, remove it now that `get_logs` actually calls it, and re-verify the count is still exactly 5 (not 4 — the dead_code allow being removed should not itself have been hiding one of the 5 baseline errors; not 6 — removing it shouldn't surface a NEW dead_code error either, since there's now a real caller).

- [ ] **Step 6: Confirm the whole workspace still builds**

Run: `cargo build && cargo test 2>&1 | grep -E "test result: ok\. [0-9]+ passed; [1-9]"`
Expected: workspace builds; the grep finds no lines (no test binary anywhere reports an actual failure).

- [ ] **Step 7: Commit**

```bash
git add shepherd/src/routes_api.rs shepherd/docs/config.md shepherd/tests/admin_logs.rs
git commit -m "$(cat <<'EOF'
feat(shepherd): wire follow=true into GET /admin/logs

target=shepherd needed no new logic - swapping historical_logs for
respond_to_log_query (which already branches on follow internally,
since corgi/vigil call the exact same function for their own /logs)
was the whole change. target=vigil/corgi:<name> now make their
outbound request with the FOLLOW_TIMEOUT_SECS override instead of the
client's normal 15s/30s timeout, and hand the response to
stream_upstream_logs_response for verbatim byte passthrough as SSE.

The 3 new tests are guard-ordering regression tests (config/lookup
checks still run before any follow-specific code, for all three
targets) - they can't prove streaming itself works, since the test
harness has no real vigil/corgi to stream from. That proof is Task 1's
mock-server unit tests (byte passthrough, header correctness, error
mapping) plus manual end-to-end verification against a real sandbox,
per this plan's Verification section - consistent with the same
tradeoff already accepted for the non-follow proxy paths in the
preceding plan.
EOF
)"
```

---

## Verification (whole plan)

1. `cargo build && cargo test && cargo fmt --check` — full workspace, must be clean (zero test failures anywhere, no fmt diff).
2. `cargo clippy -p shepherd --all-targets -- -D warnings 2>&1 | grep "^error:" | grep -v "could not compile" | wc -l` — must be exactly `5`.
3. Confirm no files outside `shepherd/` changed: `git diff --stat <plan-start-commit>..HEAD`.
4. **Manual end-to-end verification** (do this before considering the plan done — no automated test proves real cross-service streaming, per the same accepted limitation as the preceding plan): bring up a local shepherd + corgi + vigil sandbox (`verify` skill) with `logging.enabled: true` on all three. Then:
   - `curl -N 'https://shepherd:7011/admin/logs?target=shepherd&follow=true'` with a valid dashboard token/cert — confirm it streams real-time lines as shepherd itself logs (e.g. trigger its own reconcile-loop activity in a second terminal) and that early SSE frames include any recent historical backlog first (replay-then-continue).
   - `curl -N 'https://shepherd:7011/admin/logs?target=vigil&follow=true'` — confirm it matches `curl -N` against vigil's own `/logs?follow=true` directly (same lines, same timing, same `"source":"vigil"` in each event's JSON payload).
   - `curl -N 'https://shepherd:7011/admin/logs?target=corgi:<real-node-name>&follow=true'` — same check against that corgi directly.
   - Hold one of the above connections open past 15 seconds (vigil) and past 30 seconds (corgi) — confirm the connection does NOT drop at those marks, proving the `FOLLOW_TIMEOUT_SECS` override is actually taking effect and not just present in the code.
   - Combine `follow=true` with `last=15m` on at least one target — confirm the historical replay window appears first, then live lines continue, matching the credo-lib-level behavior already proven in the earlier live-tail plan.
