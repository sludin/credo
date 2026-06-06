/// Persistent or temporary test output directory.
///
/// By default each harness gets an auto-cleaned `TempDir`. When the env var
/// `CREDO_TEST_KEEP_OUTPUT=1` is set, directories are written to
/// `target/credo-test-output/<test-name>/<service>/` and are NOT cleaned up,
/// so you can inspect cert files, JSON databases, etc. after the run.
///
/// Usage — nothing changes in test code; the harnesses call `make_test_dir`
/// internally and the thread name (which Rust sets to the test function path)
/// is used as the subdirectory label automatically.
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub struct TestDir {
    path: PathBuf,
    // Holds the TempDir alive when in ephemeral mode so cleanup happens on drop.
    _temp: Option<TempDir>,
}

impl TestDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Create a test directory for the given service (e.g. `"vigil"`, `"shepherd"`).
///
/// When `CREDO_TEST_KEEP_OUTPUT=1`:
///   `target/credo-test-output/<test-name>/<service>/`  (persistent, printed to stdout)
///
/// Otherwise:
///   OS temp dir, auto-deleted on drop.
pub fn make_test_dir(service: &str) -> Result<TestDir> {
    if std::env::var("CREDO_TEST_KEEP_OUTPUT").is_ok() {
        // Rust test threads are named after the test function path.
        let test_name = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .replace("::", "__");

        let dir = workspace_output_root()
            .join(&test_name)
            .join(service);

        // Remove stale output from a previous run before writing fresh files.
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("clearing stale output dir: {}", dir.display()))?;
        }
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating output dir: {}", dir.display()))?;

        println!("[credo-test] output → {}", dir.display());

        Ok(TestDir { path: dir, _temp: None })
    } else {
        let tmp = TempDir::new().context("creating temp dir")?;
        let path = tmp.path().to_path_buf();
        Ok(TestDir { path, _temp: Some(tmp) })
    }
}

fn workspace_output_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the credo-test package dir; parent is workspace root.
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .parent()
        .expect("credo-test has no parent")
        .join("target")
        .join("credo-test-output")
}
