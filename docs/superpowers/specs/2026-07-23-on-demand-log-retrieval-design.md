# On-Demand Log Retrieval

## Context

Debugging a fleet issue today means SSH-ing to a box and reading `journalctl` or a truncated dev log file — there's no way to see what a specific corgi, vigil, or shepherd is logging from the dashboard. The ask is an on-demand (no continuous shipping/collection) log-retrieval feature: historical windows ("last 5 minutes", or a custom range) and live tail, combinable, filterable by level and free text, across shepherd, corgi (one node at a time), vigil, and the dashboard's own BFF — surfaced as a new dashboard tab. Shepherd is the aggregation point the dashboard talks to; corgi/vigil expose the same retrieval endpoint shepherd calls out to over their existing mTLS APIs.

None of this exists as infrastructure yet: every Rust service logs to stdout only via `tracing`/`tracing-subscriber` (`credo_lib::log::init_logging`), with no app-owned file, no rotation, no in-memory buffer — production relies entirely on `journalctl` (systemd captures stdout there), dev relies on a shell redirect that truncates on every restart. There's already an **unimplemented roadmap doc** for the missing rotation piece (`docs/roadmap/plan-unified-rust-log-rotation.prompt.md`) — this plan adopts and extends it, since the user confirmed changing how logging works internally is fine if it makes this feature uniform and easier to build.

Confirmed scope/decisions (from user Q&A):
- 4 sources: shepherd, corgi (single node at a time, no multi-corgi aggregated view in v1), vigil, dashboard-BFF.
- ~24-48h historical lookback target.
- Filtering: log level (min-severity) **and** free-text substring, applied identically to historical reads and live tail.
- The per-service `/logs` endpoint implementation must be shared (one handler in credo-lib, mounted identically in shepherd/corgi/vigil) — dashboard-BFF is a separate (Node) implementation since it can't share Rust code, but mirrors the same query-param contract.
- Transport: SSE, not WebSocket (one-way fits logs; no existing streaming code in this codebase to conflict with; `EventSource` gives the browser↔BFF leg auth "for free" via cookies).

## Architecture

```
browser --EventSource/fetch--> dashboard BFF --axios(stream)--> shepherd /admin/logs?target=X
                                    |                                  |
                                    v                                  v
                          dashboard's own log file          target=shepherd: local
                          (Node, mirrors Rust format)        target=vigil: proxy to vigil mTLS /logs
                                                              target=corgi:<name>: proxy to corgi mTLS /logs
```

Each Rust service gains: a rotating log file (credo-lib, config-driven) + an in-memory broadcast channel fed by the *same* write path (no format drift) + one shared axum handler (`credo_lib`) that serves historical reads (JSON) and live tail (SSE: replay-then-continue). Shepherd additionally proxies that same endpoint for corgi/vigil, re-streaming SSE bytes verbatim rather than re-parsing at each hop. The BFF mirrors this in Node for its own process and otherwise proxies to shepherd.

## Phase 0 — Foundation: rotating file logging in credo-lib

**Status: done** (`docs/superpowers/plans/2026-07-23-log-rotation-foundation.md`, merged into `monitor-diagnostics-multi-endpoint`). Implementation notes where it diverged from the original guess below, for anyone reading this as the historical record:
- No `file-rotate` crate dependency — hand-rolled `RotatingFileWriter` in a new `credo-lib/src/rotating_log.rs` instead (`file-rotate`'s exact API across majors was unverified at design time; a hand-rolled size-rotate-and-prune writer turned out simple enough not to need the dependency).
- No `basename` config field — `init_logging_with_config(level, config, service_name)` takes the log file's basename as a plain argument rather than a config field, since it's always the service's own name.
- `also_stdout` dual-layer wiring needed `Option<Layer>` (`config.also_stdout.then(|| ...)`) rather than an `if`/`else` producing two different `Layered<...>` types, which doesn't type-check against a single `.init()` call — the type-level subtlety the original design didn't anticipate.
- `compress` was dropped from the config entirely (not just defaulted false) — no compression support at all in v1, simplifying Phase 1's historical reader (no `.gz` decompression path needed).
- `LoggingHandle` is `#[must_use]` — dropping it silently stops file logging and live tail while stdout output looks unaffected, so this is enforced at compile time.

Original design text, still accurate as the *intent*:

Adopt `docs/roadmap/plan-unified-rust-log-rotation.prompt.md`, with one deliberate v1 simplification: **no compression** (`compress: false`), to avoid the historical reader needing to transparently decompress `.gz` siblings — trade a bit more disk for materially simpler Phase 1 code. Revisit later if disk becomes a real constraint.

- `credo-lib/src/log.rs`: add `LoggingConfig`/`RotationConfig` (`enabled`, `dir`, `basename`, `rotate_on.size_mb`, `keep_files`, `also_stdout`), `init_logging_with_config(LogLevel, &LoggingConfig, service_name) -> LoggingHandle`. Keep `init_logging(LogLevel)` as a shim (disabled config = current stdout-only behavior, fully backward compatible). Restructure from the current single `tracing_subscriber::fmt().init()` builder to `tracing_subscriber::registry().with(stdout_layer).with(file_layer).init()` — a plain `fmt()` builder can't fan out to two sinks. Use the `file-rotate` crate for the rotating writer, wrapped via `tracing_appender::non_blocking` (each service must keep the returned `WorkerGuard`/`LoggingHandle` alive for process lifetime — hold it in `main()`, drop last on shutdown).
- Default policy: `size_mb: 100`, `keep_files: 12` per service (~1.2GB ceiling) — sized generously against the 24-48h target since rotation is size- not time-triggered; note in docs this is a design intent, not a hard guarantee under load spikes.
- `credo-lib/src/lib.rs`: re-export new types.
- `credo-lib/Cargo.toml` + root `Cargo.toml`: add `file-rotate` — **pin a version and verify its current constructor/enum names before coding**, the API has shifted across majors.
- `shepherd/src/config.rs`, `corgi/src/config.rs`, `vigil/src/config.rs`: add a `logging` block parsed like `log_level` is today (absent → disabled, same as now).
- `shepherd/src/main.rs:331`, `corgi/src/main.rs:158`, `vigil/src/cli.rs:117`: swap to `init_logging_with_config`, retain the guard.
- Example configs + `docs/config.md` for all three services: document the new block, and call out that `logging.dir` should be a relative path so it stays inside each systemd unit's `ReadWritePaths` (no unit file changes needed).

## Phase 0b — In-memory tail broadcast (extends Phase 0, same file)

**Status: done**, same commit range as Phase 0.

- Add a `broadcast::Sender<String>` (capacity ~2048) to `LoggingHandle`, with `pub fn subscribe(&self) -> broadcast::Receiver<String>`.
- **Format-drift is the main risk here** — the file sink and the broadcast sink must emit byte-identical lines. Don't implement this as a second independent `tracing_subscriber::Layer` with its own formatter (drift risk). Instead, wrap the file writer's `Write` impl so every `write()` call both writes to `file-rotate` *and* pushes the same bytes to the broadcast channel — one formatter, two destinations, no drift possible by construction.
- Handle `Lagged(n)` on the receiver side (Phase 1) by skipping ahead and emitting a synthetic "dropped N lines" marker rather than erroring.

**Phase 0/0b verification:** `cargo build/test/clippy/fmt --check`; start each service with `logging` enabled, confirm file creation + line-format match with stdout; drive enough volume to trigger rotation, confirm `keep_files` pruning; confirm no-`logging`-block behavior is unchanged; SIGTERM mid-burst, confirm no truncated lines.

## Phase 1 — Shared credo-lib `/logs` handler

New module `credo-lib/src/log_query.rs` (kept separate from the already-dense `log.rs`), re-exported from `lib.rs`.

- `LogQueryParams` (axum `Query<>`): `since`, `until`, `last` (shorthand like `"5m"`/`"1h"`), `level` (min-severity, matching `LogLevel`'s existing mental model), `q` (case-insensitive substring), `follow`, `limit` (default 5000 for non-follow).
- One filter function, `line_passes_filter(line, level, q)`, used by **both** the historical-read path and the live-broadcast path — this is what makes level/text filtering "uniform" per the requirement.
- Non-follow: read current + rotated files covering the requested window, filter, cap at `limit`, return `Json(Vec<String>)` of raw formatted lines (skip structured per-line parsing for v1 — raw text is simplest and the UI doesn't need per-line coloring to be useful).
- Follow (`follow=true`): axum SSE (`Sse::new(stream).keep_alive(...)`), JSON-wrapped events (`{"line": "...", "source": "<service>"}` — wrap now even though `source` is only needed once shepherd starts aggregating in Phase 3, so Phase 5's frontend has one SSE shape to parse everywhere). Sequencing to avoid gaps: subscribe to the broadcast channel **before** reading the historical backlog, buffer anything that arrives during the read, replay the historical window, then drain the buffer (skip any buffered line that exact-matches one of the last ~50 historical lines, as a cheap dedup heuristic — document as a known limitation for genuinely-duplicate content), then continue forwarding from the live receiver indefinitely, applying the same filter to every line.
- Auth/role gating happens **inside** this shared function, not in three per-service wrapper closures — each service's auth middleware injects a different extension type (shepherd: `AuthenticatedUser`, corgi: `Option<Extension<Role>>`, vigil: `AuthUser(VigilUser)`), so define a small `trait HasRole { fn role(&self) -> Option<&Role>; }` implemented by all three, and have the shared handler take `Extension<impl HasRole>` and call `check_min_role(..., &Role::Readonly)` once, in one place. This is the one spot where "fully shared" needs a thin adapter to actually hold — worth getting right since the user explicitly asked for sharing.
- Each service's `AppState` needs to expose its `LoggingHandle` — add a `logging_handle: LoggingHandle` field alongside existing state (shepherd `state.rs`, corgi `state.rs`, vigil `state.rs`), handler generic over `S: HasLoggingHandle + Clone + Send + Sync + 'static`.

**Verification:** credo-lib tests writing synthetic lines to a temp rotating file and asserting filter correctness across `since/until/last/level/q` combos; a follow-path test asserting replay-then-continue with no gaps/dupes under scripted concurrent writes (use `tokio::time::pause`/`advance`, not real sleeps).

## Phase 2 — Mount in corgi + vigil

Mechanical once Phase 1 is generic — no new auth code, just mounting.

- `corgi/src/server.rs`: `.route("/logs", get(...))` inside `build_control_router` (existing `auth_middleware` + `log_request("C", ...)` already wrap this router).
- `vigil/src/routes.rs`: same, inside the `protected` sub-router.
- Implement `HasRole` for corgi's `Role` extension and vigil's `AuthUser(VigilUser)`.
- Document the new endpoint + query params in each service's `docs/config.md`.

**Verification:** `cargo test -p corgi -p vigil`; manual `curl` with a valid client cert against `GET /logs?last=5m` and `GET /logs?follow=true` on each, confirm role gating (sub-Readonly identity → 403).

## Phase 3 — Mount in shepherd + aggregation/proxy

Shepherd is both a source (`target=shepherd`) and a proxy (`target=vigil`, `target=corgi:<name>`).

- `shepherd/src/server.rs`: `.route("/admin/logs", get(routes_api::get_logs))` in the authenticated dashboard-port router, gated `check_min_role(Some(&user.role), &Role::Readonly)` — matches the existing `/admin/*` convention (e.g. `get_vigil_ca`).
- `shepherd/src/routes_api.rs`: `get_logs` branches on `target`:
  - `shepherd` (default) → delegate to the shared handler using shepherd's own `LoggingHandle`.
  - `vigil` → reuse the **existing** `state.vigil_client` (`shepherd/src/state.rs:47`, already used for `/ca`, `/health`, CSR signing — no new client module needed). Verify (don't rebuild) that shepherd's existing rbac identity in vigil's config already carries `role >= Readonly` (`Role::rank()` in `credo-lib/src/types.rs:37-47` confirms `Admin(2) > Operator(1) > Readonly(0)`, so any identity currently used for CSR-signing/admin work already qualifies).
  - `corgi:<name>` → resolve against `state.corgis`, get/create a client via the existing `CorgiClientPool` (`shepherd/src/corgi_client.rs`).
  - Both proxy paths: non-follow is simple buffered JSON passthrough (reuse `corgi_get<T>`-style helpers, don't route through the streaming path). Follow=true needs a new streaming-capable call — add `corgi_get_stream`/reuse `vigil_client` with `.bytes_stream()`, proxying the upstream SSE bytes through **verbatim** rather than re-parsing into new `Event`s (only Phase 1's innermost handler should ever construct "real" SSE events — every proxy hop after that just forwards bytes, avoiding framing bugs).
- **Timeout fix, all three hops need this**: shepherd→vigil client has a hardcoded 15s timeout (`state.rs:217`), shepherd→corgi has 30s (`corgi_client.rs:113`), BFF→shepherd uses `requestTimeoutSeconds` (`dashboard/server/config.ts` via `shepherd-client.ts:40`). A `follow=true` connection must not inherit any of these — override per-request (reqwest/axios both support per-call timeout overrides) rather than building second no-timeout clients. Test each hop independently by holding a stream open past its default timeout.
- Root `Cargo.toml:62`: add `"stream"` to reqwest's feature list (currently `["rustls-tls", "json"]` only, no `"stream"` — required for `.bytes_stream()`). Rebuild the whole workspace after to catch feature-unification surprises.
- `shepherd/docs/config.md`: document `/admin/logs` + `target` param.

**Verification:** `cargo test -p shepherd`; manual `curl` through shepherd directly for all 3 targets (JSON and `-N` SSE); hold a `target=vigil&follow=true` connection open >15s to confirm the timeout fix works; `target=corgi:<unknown>` returns clean 404.

## Phase 4 — Dashboard BFF

- New `dashboard/server/logging.ts`: Node-side mirror of the Rust logging module — structured one-line format (new code `"D"`, same field order as `RequestLogEntry`), backed by `rotating-file-stream` (npm) for rotation, a Node `EventEmitter`/small ring buffer for live tail. Export the same conceptual query surface (`since/until/last/level/q/follow/limit`) so Phase 5's frontend code doesn't need per-source special cases.
- `dashboard/server/index.ts`: wire the request-log middleware early; add:
  - `GET /api/logs?source=...` — `source=dashboard` serves directly from `logging.ts`; anything else does a buffered `clients.api.get('/admin/logs', {params: {target: mapped, ...}})` passthrough, same shape as the existing `/api/flock` route (`index.ts:344-347`).
  - `GET /api/logs/stream?source=...` — separate route (streaming needs different response setup than `res.json()`: `res.setHeader('Content-Type','text/event-stream')`, `res.flushHeaders()`). `source=dashboard` pipes from the local emitter/ring buffer; other sources issue `axios.get(..., {responseType:'stream', timeout: 0})` and pipe the upstream body straight through (verbatim, per the Phase 3 framing decision). **Must** register `req.on('close', ...)` to abort the upstream request — this codebase has no long-lived request today, so nothing currently guards against a leaked upstream connection when a browser tab closes.
- `dashboard/server/config.ts`: add a `logging` config block mirroring the Rust shape; default dir stays within the existing systemd `ReadWritePaths` (no unit change needed).
- `dashboard/package.json`: add `rotating-file-stream`.

**Verification:** `npm run typecheck && npm test`; manual `curl` (with session cookie) against `/api/logs?source=dashboard` and `/api/logs/stream?source=dashboard&follow=true`, then repeat for `source=shepherd|vigil|corgi:<name>`; close a curl/browser mid-stream and confirm the upstream connection is actually aborted (not leaked).

## Phase 5 — Dashboard frontend: Logs tab

- `dashboard/src/components/Shell.tsx`: new top-level nav section "Logs" (spans all 4 sources, doesn't fit the existing per-service groupings).
- `dashboard/src/App.tsx`: lazy route `/logs` → new `dashboard/src/pages/Logs.tsx`.
- `dashboard/src/pages/Logs.tsx`:
  - Source picker: shepherd / vigil / dashboard / one corgi — reuse the existing ad hoc `<select>`-from-`fetchAssignments()`/`fetchFlock()` pattern already used in `Certificates.tsx` (~line 544, 1152-1156) for the corgi dropdown, rather than building a new picker component.
  - Time range: presets (5m/15m/1h/24h) + custom since/until, plus a "Live tail" toggle that composes with the selected range — this maps directly onto one request (`last=15m&follow=true`), not two separate fetches.
  - Level + free-text filters. Since filtering is server-side (per the shared-handler design), changing either while tailing live means **closing and reopening** the SSE connection with new query params (debounced ~500ms) rather than client-side filtering of an unfiltered stream.
  - Viewer: scrolling monospace view, closest existing precedent is the job-trace `<pre>` rendering in `Certificates.tsx`'s `LastJobSection`/`ActiveJobSection` (~line 159-165, 973-986) — new behavior needed here that precedent doesn't have: autoscroll-to-bottom on new lines, paused when the user scrolls up to read history.
  - Data fetching: plain `useState`/`useEffect` for the historical fetch (no react-query anywhere in this codebase); native `EventSource` for tailing — but **manage reconnection manually** rather than relying on `EventSource`'s built-in auto-reconnect: on `onerror`, close and reopen with a trimmed `last=30s` (not the original range) so a network blip doesn't silently re-replay the full original historical window and flood the viewer with duplicates.
- `dashboard/src/api.ts`: add `fetchLogsHistorical(params)` and `openLogsStream(params)` alongside the existing `fetch*`/`create*Job` helpers.

**Verification:** `npm run typecheck && npm run build && npm test`; manual browser walkthrough for all 4 sources — historical fetch with filters, live tail alone, combined historical+live (no gap/dup at the transition), filter change while tailing (stream reopens, only matching lines appear), navigate away (old `EventSource` actually closes — check via devtools Network or BFF connection count); cross-source scenario: tail shepherd and a corgi simultaneously in two tabs, trigger a real sync between them, confirm corresponding lines land in both within a couple seconds.

## Cross-cutting checklist

1. `HasRole` adapter (Phase 1/2) — the one place "shared implementation" needs a thin trait to actually stay shared across 3 different auth extension types.
2. `reqwest` `"stream"` feature is workspace-wide (Phase 3) — rebuild everything after adding it.
3. Three separate client timeouts (shepherd→vigil 15s, shepherd→corgi 30s, BFF→shepherd `requestTimeoutSeconds`) all need per-request overrides for `follow=true` — test each independently, it's an easy one to half-fix.
4. Format-drift between file sink and broadcast sink (Phase 0b) — solved by one `Write` impl feeding both, not two independent formatters.
5. SSE re-framing — verbatim byte passthrough at every proxy hop (Phase 3, Phase 4); only Phase 1's innermost handler constructs real SSE events.
6. `file-rotate` (Rust) and `rotating-file-stream` (Node) — pin versions and confirm current constructor APIs before writing code; both have shifted across majors.

## Related plans/records

- `docs/superpowers/plans/2026-07-23-log-rotation-foundation.md` — the executed task-by-task plan for Phase 0 + 0b.
