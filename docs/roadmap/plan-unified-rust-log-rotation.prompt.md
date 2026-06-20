## Plan: Unified Rust Log Rotation

Adopt one rotation implementation in credo-lib and route all Rust service logs through it so shepherd, corgi, and vigil produce identical rotating files with the same format, retention, and rollover triggers. Recommended crate: file-rotate (size/time rotation + retention + optional compression) integrated under existing tracing/tracing-subscriber setup.

**Steps**
1. Define shared logging model in credo-lib (*foundation phase*): add `LoggingConfig` and `RotationConfig` types in credo-lib, including `enabled`, `dir`, `basename`, `rotate_on` (`size_mb` and optional `daily`), `keep_files`, `compress`, and `also_stdout`.
2. Extend shared logger entrypoint in credo-lib (*depends on 1*): replace single-arg `init_logging(LogLevel)` with a shared API like `init_logging_with_config(LogLevel, &LoggingConfig, service_name)` and keep a compatibility shim `init_logging(LogLevel)` for transition safety.
3. Implement rotating writer in credo-lib via 3p crate (*depends on 2*): build the writer with file-rotate and wrap it in the tracing subscriber output path; preserve current one-line structured format and existing request middleware behavior.
4. Keep non-blocking logging and flush safety (*parallel with 3 if API allows*): wire non-blocking writer guard ownership so each service keeps its guard alive for process lifetime and avoids log loss under burst traffic.
5. Normalize service config schema (*depends on 1*): add identical `logging` object to shepherd, corgi, and vigil config structs and docs, with shared defaults if missing so behavior is predictable.
6. Update all logger call sites to shared API (*depends on 2 and 5*): shepherd startup/bootstrap paths, corgi startup/bootstrap/check-config paths, and vigil server startup path should all call the same credo-lib initializer with service-specific basename only.
7. Provide deterministic naming and path rules (*depends on 3 and 5*): default files to `<dir>/<service>.log`, rotate siblings with consistent suffix format, and enforce identical retention semantics across services.
8. Add migration-safe defaults (*depends on 5*): if no `logging` block is present, retain current stdout-only behavior; if present, apply exactly the same rotation policy in all three services.
9. Document ops behavior and rollout (*depends on 6-8*): include examples for local/dev and systemd deployments, disk sizing guidance, and restart expectations.

**Relevant files**
- `/Users/sludin/Documents/projects/credo/credo-lib/src/log.rs` — central logging initializer; add shared rotating writer path and config-driven sink selection.
- `/Users/sludin/Documents/projects/credo/credo-lib/src/lib.rs` — re-export new logging config types for all services.
- `/Users/sludin/Documents/projects/credo/Cargo.toml` — add workspace dependency for `file-rotate` (and any helper crate needed for compression).
- `/Users/sludin/Documents/projects/credo/shepherd/src/config.rs` — add shared `logging` config fields and defaults.
- `/Users/sludin/Documents/projects/credo/corgi/src/config.rs` — add shared `logging` config fields and defaults.
- `/Users/sludin/Documents/projects/credo/vigil/src/config.rs` — add shared `logging` config fields and defaults.
- `/Users/sludin/Documents/projects/credo/shepherd/src/main.rs` — pass config to new credo-lib logger initializer in both normal and bootstrap code paths.
- `/Users/sludin/Documents/projects/credo/corgi/src/main.rs` — pass config to new credo-lib logger initializer in all command paths.
- `/Users/sludin/Documents/projects/credo/vigil/src/cli.rs` — pass config to new credo-lib logger initializer.
- `/Users/sludin/Documents/projects/credo/shepherd/examples/shepherd.config.example.json` — add `logging` example block.
- `/Users/sludin/Documents/projects/credo/corgi/examples/corgi.config.example.json` — add `logging` example block.
- `/Users/sludin/Documents/projects/credo/vigil/examples/vigil.config.example.json` — add `logging` example block.
- `/Users/sludin/Documents/projects/credo/shepherd/docs/config.md` — document shared logging settings.
- `/Users/sludin/Documents/projects/credo/corgi/docs/config.md` — document shared logging settings.
- `/Users/sludin/Documents/projects/credo/vigil/docs/config.md` — document shared logging settings.

**Verification**
1. Build and test Rust workspace: run `cargo build` then `cargo test` to ensure API/signature migration is complete.
2. Per-service smoke check with identical config: start each service with the same `logging` policy and verify files are created under expected directory with same naming convention.
3. Rotation trigger test (size): emit synthetic logs until threshold is crossed and verify rollover occurs at configured boundary for all three services.
4. Retention test: force enough rollovers to exceed `keep_files`; confirm oldest files are pruned identically.
5. Compression test (if enabled): verify rolled files are compressed and active file remains plain text.
6. Continuity test during load: generate concurrent request logs and validate no malformed lines or dropped tail logs on shutdown.
7. Backward-compat check: run with configs that only define `logLevel`; confirm stdout-only behavior remains unchanged.

**Decisions**
- Included scope: Rust services only (`shepherd`, `corgi`, `vigil`) and shared implementation in `credo-lib`.
- Excluded scope: dashboard logging and external log shipping stack changes (ELK/Loki/journald pipeline redesign).
- Recommended policy baseline: size-based rotation (for predictability) with optional daily boundary; fixed retention count and optional compression.
- Single implementation owner: only credo-lib creates writers/subscribers; services pass config and service name.

**Further Considerations**
1. Default baseline recommendation: `size_mb=50`, `keep_files=10`, `compress=true`, `also_stdout=true` in production systemd/container environments.
2. If strict startup compatibility is required, keep old `init_logging(LogLevel)` wrapper for one release and deprecate later.
3. If per-service overrides are needed later, keep schema identical but allow overriding only `basename` while rotation policy stays global by default.