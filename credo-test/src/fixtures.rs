use std::path::PathBuf;

/// Returns the path to the workspace-level `tests/fixtures/` directory.
/// Panics if the directory doesn't exist (run `cargo run -p gen-fixtures`).
pub fn fixtures_dir() -> PathBuf {
    // Cargo sets CARGO_MANIFEST_DIR to the credo-test package directory.
    // Walk up one level to reach the workspace root.
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set — run via cargo test");
    let workspace_root = PathBuf::from(manifest)
        .parent()
        .expect("credo-test has no parent directory")
        .to_path_buf();
    let dir = workspace_root.join("tests/fixtures");
    assert!(
        dir.exists(),
        "tests/fixtures/ not found; run: cargo run -p gen-fixtures"
    );
    dir
}

pub fn root_ca_pem() -> PathBuf {
    fixtures_dir().join("root-ca.pem")
}
pub fn root_ca_key() -> PathBuf {
    fixtures_dir().join("root-ca.key")
}
pub fn intermediate_ca_pem() -> PathBuf {
    fixtures_dir().join("intermediate-ca.pem")
}
pub fn intermediate_ca_key() -> PathBuf {
    fixtures_dir().join("intermediate-ca.key")
}
pub fn catrust_pem() -> PathBuf {
    fixtures_dir().join("catrust.pem")
}
