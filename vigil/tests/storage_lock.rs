/// Regression test for a Medium finding: `state.inner.storage_lock` was
/// declared but never acquired anywhere, so concurrent read-modify-write
/// calls against the JSON-backed ACME account store (or the cert/user
/// stores) could interleave and silently drop one writer's update.
///
/// This exercises the lock directly rather than going through a specific
/// HTTP handler: two "concurrent" writers each read the current accounts
/// file, append their own record, and write back, mirroring the shape of
/// the real mutating storage functions. Without the lock serializing them,
/// the second writer's read (taken before the first's write lands) misses
/// the first update, and only one of the two appended records survives.
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use vigil::state::AppState;
use vigil::storage;
use vigil::types::{AcmeAccountRecord, AcmeRsaJwk, RootCAMetadata};

fn dummy_ca_metadata() -> RootCAMetadata {
    RootCAMetadata {
        subject: "CN=test".to_string(),
        serial_number: "01".to_string(),
        valid_from: "2026-01-01T00:00:00Z".to_string(),
        valid_to: "2027-01-01T00:00:00Z".to_string(),
        fingerprint256: "sha256:test".to_string(),
        key_path: String::new(),
        cert_path: String::new(),
    }
}

fn dummy_account(id: &str) -> AcmeAccountRecord {
    AcmeAccountRecord {
        id: id.to_string(),
        status: "valid".to_string(),
        vigil_user_id: "test".to_string(),
        contact: vec![],
        orders: vec![],
        jwk_thumbprint: format!("thumb-{id}"),
        public_jwk: AcmeRsaJwk {
            kty: "EC".to_string(),
            n: String::new(),
            e: String::new(),
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: "y".to_string(),
        },
    }
}

fn test_state(tmp: &TempDir) -> AppState {
    let config = credo_test::cert_gen::signing_config(tmp.path());
    AppState::new(
        config,
        dummy_ca_metadata(),
        None,
        Arc::new(credo_lib::LoggingHandle::disabled()),
    )
}

#[tokio::test]
async fn storage_lock_serializes_concurrent_writers_preventing_lost_update() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let accounts_path = tmp.path().join("acme-accounts.json");
    storage::write_acme_accounts(&accounts_path, &[dummy_account("seed")]).unwrap();

    let state1 = state.clone();
    let path1 = accounts_path.clone();
    let t1 = tokio::spawn(async move {
        let _guard = state1.inner.storage_lock.lock().await;
        let mut accounts = storage::read_acme_accounts(&path1).unwrap();
        // Widen the race window: without the lock, the second writer's read
        // (below) would land in this gap and miss this writer's append.
        tokio::time::sleep(Duration::from_millis(50)).await;
        accounts.push(dummy_account("writer-a"));
        storage::write_acme_accounts(&path1, &accounts).unwrap();
    });

    // Give t1 a moment to acquire the lock first, so t2 is the one forced to
    // wait — otherwise which task wins the race is arbitrary.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let state2 = state.clone();
    let path2 = accounts_path.clone();
    let t2 = tokio::spawn(async move {
        let _guard = state2.inner.storage_lock.lock().await;
        let mut accounts = storage::read_acme_accounts(&path2).unwrap();
        accounts.push(dummy_account("writer-b"));
        storage::write_acme_accounts(&path2, &accounts).unwrap();
    });

    t1.await.unwrap();
    t2.await.unwrap();

    let final_accounts = storage::read_acme_accounts(&accounts_path).unwrap();
    let ids: Vec<&str> = final_accounts.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["seed", "writer-a", "writer-b"],
        "both concurrent writers' updates must survive — no lost update"
    );
}
