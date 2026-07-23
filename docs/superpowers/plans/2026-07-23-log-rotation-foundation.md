# Log Rotation Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `credo-lib` a config-driven, size-rotated log file plus a live in-memory broadcast of completed lines, as the foundation for an on-demand log-retrieval feature (full design: `docs/superpowers/specs/on-demand-log-retrieval` context lives in the approved plan at `/Users/sludin/.claude/plans/i-would-like-to-eager-bonbon.md` — this plan implements just its Phase 0 + Phase 0b, scoped to `credo-lib` only).

**Architecture:** A new `RotatingFileWriter` (plain `std::io::Write`) appends to `<dir>/<basename>.log`, rotates to `.1.log`/`.2.log`/... on a size threshold, prunes beyond `keep_files`, and — critically — broadcasts every *complete* line (buffered across however many raw `write()` calls it takes to see a `\n`, so partial writes never leak fragments) over a `tokio::sync::broadcast` channel shared by all clones of the writer. `init_logging_with_config` wires this writer into a `tracing_subscriber::registry()` with two independently-filtered layers (stdout + file) via `tracing_appender::non_blocking`, alongside the existing stdout-only `init_logging` which is left untouched for full backward compatibility. No service (shepherd/corgi/vigil) is wired to call the new function yet — that happens in a follow-up plan once the shared HTTP log-retrieval handler needs it.

**Tech Stack:** Rust, `tracing`/`tracing-subscriber` (already a dependency), `tracing-appender` (new), `tokio::sync::broadcast` (already available via `tokio`'s `full` feature), `serde` (already a dependency).

## Global Constraints

- `init_logging(level: LogLevel)` (existing function in `credo-lib/src/log.rs`) must keep its exact current signature and behavior — do not touch it. It is the backward-compatibility path every service currently calls.
- This plan touches `credo-lib` only. Do not modify `shepherd/`, `corgi/`, `vigil/`, or any config file/example — that wiring is a separate follow-up plan.
- `cargo fmt --check` and `cargo clippy -- -D warnings` must pass for every commit (repo pre-commit hook enforces this for any changed `*.rs` file — see `/Users/sludin/Documents/projects/credo/CLAUDE.md`).
- Commit after each task with a message explaining *why*, not just what (per `/Users/sludin/Documents/projects/credo/CLAUDE.md`'s Committing section). Do not use `--no-verify`.
- `LoggingConfig::default().enabled` must be `false` — logging-to-file is strictly opt-in, matching the "migration-safe defaults" requirement from the roadmap doc this plan supersedes (`docs/roadmap/plan-unified-rust-log-rotation.prompt.md`).
- No placeholder/TODO code. Every function in this plan must be fully implemented and covered by a test in the same task.

---

### Task 1: `RotatingFileWriter` + `LoggingConfig`/`RotationConfig` in a new `credo-lib` module

**Files:**
- Create: `credo-lib/src/rotating_log.rs`
- Modify: `credo-lib/src/lib.rs`

**Interfaces:**
- Produces (used by Task 2 and by every later plan that reads this): `pub struct LoggingConfig { pub enabled: bool, pub dir: String, pub rotate_on: RotationConfig, pub also_stdout: bool }`, `pub struct RotationConfig { pub size_mb: u64, pub keep_files: usize }` (both `Debug + Clone + Deserialize + Serialize`, both `Default`), `pub struct RotatingFileWriter` (`Clone`, implements `std::io::Write`) with `pub fn new(dir: &std::path::Path, basename: &str, rotate_on: &RotationConfig) -> std::io::Result<Self>` and `pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String>`.

- [ ] **Step 1: Write the failing tests**

Create `credo-lib/src/rotating_log.rs` with only this content (types referenced don't exist yet — this is deliberate, it's the RED step):

```rust
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// How a service's rotating log file grows and prunes old segments.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationConfig {
    pub size_mb: u64,
    pub keep_files: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        RotationConfig {
            size_mb: 100,
            keep_files: 12,
        }
    }
}

/// Config-driven logging sink: an app-owned rotating file plus an in-memory
/// broadcast of each completed line, in addition to (optionally) stdout.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_log_dir")]
    pub dir: String,
    #[serde(default)]
    pub rotate_on: RotationConfig,
    #[serde(default = "default_also_stdout")]
    pub also_stdout: bool,
}

fn default_log_dir() -> String {
    "logs".to_string()
}

fn default_also_stdout() -> bool {
    true
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            enabled: false,
            dir: default_log_dir(),
            rotate_on: RotationConfig::default(),
            also_stdout: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn rotate_on(size_mb: u64, keep_files: usize) -> RotationConfig {
        RotationConfig { size_mb, keep_files }
    }

    #[test]
    fn write_appends_to_current_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer =
            RotatingFileWriter::new(dir.path(), "svc", &rotate_on(100, 12)).expect("new writer");
        writer.write_all(b"line one\n").expect("write 1");
        writer.write_all(b"line two\n").expect("write 2");
        writer.flush().expect("flush");

        let contents = fs::read_to_string(dir.path().join("svc.log")).expect("read log file");
        assert_eq!(contents, "line one\nline two\n");
    }

    #[test]
    fn rotation_prunes_beyond_keep_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 1 MB threshold, keep 2 backups. Each chunk below is ~600KB so two
        // chunks together always cross the threshold, forcing rotation on
        // every write after the first.
        let mut writer =
            RotatingFileWriter::new(dir.path(), "svc", &rotate_on(1, 2)).expect("new writer");

        let chunk = |byte: u8| {
            let mut v = vec![byte; 600_000];
            v.push(b'\n');
            v
        };
        writer.write_all(&chunk(b'A')).expect("write A"); // current = A
        writer.write_all(&chunk(b'B')).expect("write B"); // rotate: .1=A, current=B
        writer.write_all(&chunk(b'C')).expect("write C"); // rotate: .2=A, .1=B, current=C
        writer.write_all(&chunk(b'D')).expect("write D"); // rotate: .2=B (A pruned), .1=C, current=D
        writer.flush().expect("flush");

        let current = fs::read(dir.path().join("svc.log")).expect("read current");
        let backup1 = fs::read(dir.path().join("svc.1.log")).expect("read .1");
        let backup2 = fs::read(dir.path().join("svc.2.log")).expect("read .2");
        assert_eq!(current[0], b'D');
        assert_eq!(backup1[0], b'C');
        assert_eq!(backup2[0], b'B');
        assert!(
            !dir.path().join("svc.3.log").exists(),
            "must not keep more than keep_files backups"
        );
    }

    #[test]
    fn write_broadcasts_completed_lines_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer =
            RotatingFileWriter::new(dir.path(), "svc", &rotate_on(100, 12)).expect("new writer");
        let mut rx = writer.subscribe();

        // A write with no newline yet must not broadcast anything - this is
        // the case tracing's fmt layer can hit if it calls write() more
        // than once per event.
        writer.write_all(b"partial-").expect("write partial");
        assert!(matches!(rx.try_recv(), Err(broadcast::error::TryRecvError::Empty)));

        writer.write_all(b"rest\n").expect("write rest");
        let line = rx.try_recv().expect("expected one broadcast line");
        assert_eq!(line, "partial-rest");
        assert!(matches!(rx.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
    }

    #[test]
    fn logging_config_deserializes_with_defaults() {
        let config: LoggingConfig = serde_json::from_str(r#"{"enabled": true}"#).expect("parse");
        assert!(config.enabled);
        assert_eq!(config.dir, "logs");
        assert_eq!(config.rotate_on.size_mb, 100);
        assert_eq!(config.rotate_on.keep_files, 12);
        assert!(config.also_stdout);
    }
}
```

Add `pub mod rotating_log;` to `credo-lib/src/lib.rs` (insert alphabetically, after `pub mod pid;` and before `pub mod timing;`):

```rust
pub mod archive;
pub mod auth;
pub mod config;
pub mod error;
pub mod file_policy;
pub mod log;
pub mod pid;
pub mod rotating_log;
pub mod timing;
pub mod tls;
pub mod types;

// Convenience re-exports used by every service
pub use error::AppError;
pub use log::{LogIdentity, LogLevel};
pub use tls::PeerCertDer;
pub use types::{ClientIdentity, HookRef, Role};
```

(The re-export line stays as-is for now — `RotatingFileWriter`/`LoggingConfig` re-exports are added in Task 2 once `log.rs` actually needs to reference them, to keep this step's diff minimal.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p credo-lib rotating_log`
Expected: compile error — `RotatingFileWriter` is not defined (referenced in the test module but not yet implemented above it).

- [ ] **Step 3: Implement `RotatingFileWriter`**

Insert this code in `credo-lib/src/rotating_log.rs`, directly above the `#[cfg(test)] mod tests` block (i.e. after the `LoggingConfig`/`Default` impl already written in Step 1):

```rust
struct RotatingFileState {
    dir: PathBuf,
    basename: String,
    max_bytes: u64,
    keep_files: usize,
    file: File,
    current_bytes: u64,
    pending: Vec<u8>,
}

impl RotatingFileState {
    fn open_current(dir: &Path, basename: &str) -> io::Result<(File, u64)> {
        fs::create_dir_all(dir)?;
        let path = dir.join(format!("{basename}.log"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let current_bytes = file.metadata()?.len();
        Ok((file, current_bytes))
    }

    fn rotate(&mut self) -> io::Result<()> {
        for i in (1..self.keep_files).rev() {
            let from = self.dir.join(format!("{}.{}.log", self.basename, i));
            let to = self.dir.join(format!("{}.{}.log", self.basename, i + 1));
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }
        let current = self.dir.join(format!("{}.log", self.basename));
        let first_rotated = self.dir.join(format!("{}.1.log", self.basename));
        fs::rename(&current, &first_rotated)?;
        let (file, _) = Self::open_current(&self.dir, &self.basename)?;
        self.file = file;
        self.current_bytes = 0;
        Ok(())
    }
}

/// A `std::io::Write` sink that appends to a size-rotated file and
/// broadcasts every completed line to any live subscribers. Cloning shares
/// the same underlying file handle and broadcast channel.
#[derive(Clone)]
pub struct RotatingFileWriter {
    state: Arc<Mutex<RotatingFileState>>,
    tx: broadcast::Sender<String>,
}

const BROADCAST_CAPACITY: usize = 2048;

impl RotatingFileWriter {
    pub fn new(dir: &Path, basename: &str, rotate_on: &RotationConfig) -> io::Result<Self> {
        let (file, current_bytes) = RotatingFileState::open_current(dir, basename)?;
        let state = RotatingFileState {
            dir: dir.to_path_buf(),
            basename: basename.to_string(),
            max_bytes: rotate_on.size_mb.max(1) * 1024 * 1024,
            keep_files: rotate_on.keep_files.max(1),
            file,
            current_bytes,
            pending: Vec::new(),
        };
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(RotatingFileWriter {
            state: Arc::new(Mutex::new(state)),
            tx,
        })
    }

    /// Subscribe to a live feed of completed lines written from this point on.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .expect("rotating file writer state poisoned");
        if state.current_bytes > 0 && state.current_bytes + buf.len() as u64 > state.max_bytes {
            state.rotate()?;
        }
        state.file.write_all(buf)?;
        state.current_bytes += buf.len() as u64;
        state.pending.extend_from_slice(buf);
        while let Some(pos) = state.pending.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = state.pending.drain(..=pos).collect();
            if let Ok(text) = std::str::from_utf8(&line_bytes) {
                let _ = self.tx.send(text.trim_end_matches(['\n', '\r']).to_string());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state
            .lock()
            .expect("rotating file writer state poisoned")
            .file
            .flush()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p credo-lib rotating_log`
Expected: `4 passed; 0 failed` (`write_appends_to_current_file`, `rotation_prunes_beyond_keep_files`, `write_broadcasts_completed_lines_only`, `logging_config_deserializes_with_defaults`).

- [ ] **Step 5: Lint and format**

Run: `cargo fmt -p credo-lib && cargo clippy -p credo-lib -- -D warnings`
Expected: no warnings, no diff from `cargo fmt`.

- [ ] **Step 6: Commit**

```bash
git add credo-lib/src/rotating_log.rs credo-lib/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): add size-rotating log writer with live broadcast tail

Foundation for on-demand log retrieval: services need an app-owned log
file (not just stdout/journald) to read historical lines from, plus a
way to tail new lines without filesystem polling. RotatingFileWriter
gives both from one Write impl, so the file and the live broadcast can
never drift out of format sync with each other.
EOF
)"
```

---

### Task 2: Wire `RotatingFileWriter` into a config-driven logging initializer

**Files:**
- Modify: `credo-lib/src/log.rs`
- Modify: `credo-lib/src/lib.rs`
- Modify: `credo-lib/Cargo.toml`
- Modify: `Cargo.toml` (workspace root)
- Create: `credo-lib/tests/log_init.rs`

**Interfaces:**
- Consumes (from Task 1): `credo_lib::rotating_log::{LoggingConfig, RotatingFileWriter}`.
- Produces (used by the follow-up plan that wires this into shepherd/corgi/vigil): `pub struct LoggingHandle` with `pub fn subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<String>>`; `pub fn init_logging_with_config(level: LogLevel, config: &LoggingConfig, service_name: &str) -> LoggingHandle`.

- [ ] **Step 1: Add the `tracing-appender` dependency**

In `Cargo.toml` (workspace root), add this line to the `[workspace.dependencies]` block's `# Logging` section (currently at line 47-49), so it reads:

```toml
# Logging
tracing            = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
tracing-appender   = "0.2"
```

In `credo-lib/Cargo.toml`, add this line to the `# Logging` section (currently at line 40-42), so it reads:

```toml
# Logging
tracing            = { workspace = true }
tracing-subscriber = { workspace = true }
tracing-appender   = { workspace = true }
```

Run: `cargo build -p credo-lib`
Expected: builds successfully (new dependency fetched, nothing uses it yet so no behavior change).

- [ ] **Step 2: Write the failing integration test**

Create `credo-lib/tests/log_init.rs`:

```rust
use credo_lib::{init_logging_with_config, LogLevel, LoggingConfig, RotationConfig};
use std::time::Duration;

#[tokio::test]
async fn init_logging_with_config_writes_file_and_broadcasts_live() {
    // Ambient RUST_LOG in the dev/CI shell could otherwise override the
    // level this test expects - keep the test deterministic.
    std::env::remove_var("RUST_LOG");

    let dir = tempfile::tempdir().expect("tempdir");
    let config = LoggingConfig {
        enabled: true,
        dir: dir.path().to_string_lossy().to_string(),
        rotate_on: RotationConfig {
            size_mb: 100,
            keep_files: 12,
        },
        also_stdout: false,
    };

    let handle = init_logging_with_config(LogLevel::Info, &config, "testsvc");
    let mut rx = handle
        .subscribe()
        .expect("logging enabled, subscribe must succeed");

    tracing::info!("hello from log_init test");

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for broadcast line")
        .expect("channel closed unexpectedly");
    assert!(received.contains("hello from log_init test"));

    drop(handle); // flush the non-blocking writer before reading the file

    let contents =
        std::fs::read_to_string(dir.path().join("testsvc.log")).expect("read log file");
    assert!(contents.contains("hello from log_init test"));
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p credo-lib --test log_init`
Expected: compile error — `init_logging_with_config`, `LoggingConfig`, `RotationConfig` are not exported from `credo_lib` yet.

- [ ] **Step 4: Implement `init_logging_with_config` and `LoggingHandle`**

In `credo-lib/src/log.rs`, add these imports at the top of the file (after the existing `use` lines, before `pub struct LogIdentity`):

```rust
use crate::rotating_log::{LoggingConfig, RotatingFileWriter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
```

Add this code directly after the existing `init_logging` function (after its closing brace, before the `// --- Shared request logging middleware ---` section comment):

```rust
/// Returned by `init_logging_with_config`. Keep this alive for the process
/// lifetime (e.g. bind it in `main()`) - dropping it flushes and stops the
/// non-blocking file writer.
pub struct LoggingHandle {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    writer: Option<RotatingFileWriter>,
}

impl LoggingHandle {
    /// Subscribe to a live feed of this service's log lines. Returns `None`
    /// if rotating-file logging is not enabled in `config`.
    pub fn subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<String>> {
        self.writer.as_ref().map(|w| w.subscribe())
    }
}

/// Like `init_logging`, but config-driven: when `config.enabled` is true,
/// also writes to a size-rotated file and exposes a live broadcast of
/// completed lines via the returned `LoggingHandle`. When `config.enabled`
/// is false, behavior is identical to `init_logging` (stdout only).
pub fn init_logging_with_config(
    level: LogLevel,
    config: &LoggingConfig,
    service_name: &str,
) -> LoggingHandle {
    let filter_str =
        std::env::var("RUST_LOG").unwrap_or_else(|_| level.as_tracing_filter().to_string());

    if !config.enabled {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter_str))
            .with_target(false)
            .compact()
            .init();
        return LoggingHandle {
            _guard: None,
            writer: None,
        };
    }

    let writer = RotatingFileWriter::new(
        std::path::Path::new(&config.dir),
        service_name,
        &config.rotate_on,
    )
    .expect("failed to open rotating log file");
    let (non_blocking, guard) = tracing_appender::non_blocking(writer.clone());

    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .with_writer(non_blocking)
        .with_filter(EnvFilter::new(filter_str.clone()));

    if config.also_stdout {
        let stdout_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .compact()
            .with_writer(std::io::stdout)
            .with_filter(EnvFilter::new(filter_str));
        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry().with(file_layer).init();
    }

    LoggingHandle {
        _guard: Some(guard),
        writer: Some(writer),
    }
}
```

In `credo-lib/src/lib.rs`, update the re-export block so it reads:

```rust
pub mod archive;
pub mod auth;
pub mod config;
pub mod error;
pub mod file_policy;
pub mod log;
pub mod pid;
pub mod rotating_log;
pub mod timing;
pub mod tls;
pub mod types;

// Convenience re-exports used by every service
pub use error::AppError;
pub use log::{init_logging_with_config, LogIdentity, LogLevel, LoggingHandle};
pub use rotating_log::{LoggingConfig, RotationConfig};
pub use tls::PeerCertDer;
pub use types::{ClientIdentity, HookRef, Role};
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p credo-lib --test log_init`
Expected: `1 passed; 0 failed`.

- [ ] **Step 6: Run the full credo-lib test suite plus lint**

Run: `cargo test -p credo-lib && cargo fmt -p credo-lib && cargo clippy -p credo-lib -- -D warnings`
Expected: all tests pass (Task 1's 4 unit tests + this task's integration test + any pre-existing credo-lib tests), no clippy warnings, no fmt diff.

- [ ] **Step 7: Confirm the whole workspace still builds**

Run: `cargo build && cargo test`
Expected: workspace builds and all tests pass — this confirms the new workspace-level `tracing-appender` dependency didn't cause a feature-unification conflict for shepherd/corgi/vigil, and that `init_logging` (still called by all three services, untouched) continues to work.

- [ ] **Step 8: Commit**

```bash
git add credo-lib/src/log.rs credo-lib/src/lib.rs credo-lib/Cargo.toml Cargo.toml credo-lib/tests/log_init.rs
git commit -m "$(cat <<'EOF'
feat(credo-lib): add config-driven logging initializer with file + tail

init_logging_with_config lets a service opt into rotating-file output
and a live broadcast handle while leaving the existing stdout-only
init_logging path (and every current caller of it) completely
untouched. No service calls the new function yet - that lands with
the shared log-retrieval HTTP handler in a follow-up plan.
EOF
)"
```

---

## Verification (whole plan)

1. `cargo build && cargo test && cargo fmt --check && cargo clippy -- -D warnings` — full workspace, must be clean.
2. Manual sanity check: in a scratch directory, write a tiny Rust snippet (or extend the `log_init` test temporarily) that calls `init_logging_with_config` with `rotate_on.size_mb: 1` and writes >1MB of `tracing::info!` lines in a loop; confirm `<dir>/<basename>.1.log` appears alongside `<dir>/<basename>.log`.
3. Confirm `init_logging` (the pre-existing function) is byte-for-byte unmodified in `credo-lib/src/log.rs` — `git diff` for this plan's commits should show only additions to that file, no changes inside the existing `init_logging` function body.

## Next Plan (not in this one)

Once this lands, the follow-up plan wires `init_logging_with_config` into shepherd/corgi/vigil (`logging` config block in each service's config struct + example config + docs, swap the `main.rs`/`cli.rs` call site, store the `LoggingHandle` on each service's `AppState`), and builds the shared `credo-lib` HTTP handler (historical query + SSE tail) that Phase 1 of the approved design (`/Users/sludin/.claude/plans/i-would-like-to-eager-bonbon.md`) describes.
