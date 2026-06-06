/// Test harness for credo integration tests.
///
/// Each `Test*` struct starts the corresponding service's Axum router
/// over plain HTTP on a random port inside a temporary directory.
/// Services communicate with each other using test PKI fixtures committed
/// under `tests/fixtures/` at the workspace root.
pub mod test_dir;
pub mod vigil_harness;
pub mod shepherd_harness;
pub mod corgi_harness;
pub mod fixtures;
pub mod cert_gen;
