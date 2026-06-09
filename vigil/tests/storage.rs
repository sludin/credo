/// Storage layer tests — direct function calls, no HTTP.
/// Covers the cert record CRUD, serial normalization, and stats that underpin all API tests.
use std::path::Path;
use tempfile::TempDir;
use vigil::storage;
use vigil::types::CertificateRecord;

fn tmp() -> TempDir {
    TempDir::new().unwrap()
}

fn dummy_cert_record(id: &str, serial: &str) -> CertificateRecord {
    CertificateRecord {
        id: id.to_string(),
        serial_number: serial.to_string(),
        subject: format!("CN={}", id),
        fingerprint256: format!("sha256:{}", id),
        valid_from: "2026-01-01T00:00:00Z".to_string(),
        valid_to: "2027-01-01T00:00:00Z".to_string(),
        cert_path: String::new(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        issued_by: "test".to_string(),
        owner_vigil_user_id: "test".to_string(),
        issuing_acme_account_id: None,
        revoked: false,
        revoked_at: None,
        revoked_by: None,
        revoked_by_vigil_user_id: None,
        revoked_by_acme_account_id: None,
        revoked_via: None,
        revoke_reason: None,
    }
}

const DUMMY_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----\n";

/// Issuing a cert record writes the PEM to disk and the metadata to the JSON DB;
/// the record can then be retrieved by ID.
#[test]
fn issue_and_retrieve_cert_record() {
    let dir = tmp();
    let db = dir.path().join("certs.json");
    let store = dir.path().join("certs");
    storage::ensure_certs_db(&db, &store).unwrap();

    let record = dummy_cert_record("cert-a", "AABB");
    let stored = storage::issue_certificate_record(&db, &store, record, DUMMY_CERT).unwrap();

    assert_eq!(stored.id, "cert-a");
    assert!(!stored.cert_path.is_empty(), "cert_path must be populated");
    assert!(
        Path::new(&stored.cert_path).exists(),
        "cert PEM file must exist on disk"
    );

    let fetched = storage::get_certificate_record(&db, "cert-a").unwrap();
    assert!(fetched.is_some(), "must be retrievable by ID");
    assert_eq!(fetched.unwrap().serial_number, "AABB");
}

/// `find_certificate_by_serial` normalizes the serial: strip leading zeros and
/// lowercase — so "00AbCd" and "abcd" both find the same record.
#[test]
fn find_cert_by_serial_normalizes_hex() {
    let dir = tmp();
    let db = dir.path().join("certs.json");
    let store = dir.path().join("certs");
    storage::ensure_certs_db(&db, &store).unwrap();

    let record = dummy_cert_record("cert-b", "00abcd");
    storage::issue_certificate_record(&db, &store, record, DUMMY_CERT).unwrap();

    // Exact stored value
    let r1 = storage::find_certificate_by_serial(&db, "00abcd").unwrap();
    assert!(r1.is_some(), "must find with stored serial");

    // Uppercase + leading zeros stripped
    let r2 = storage::find_certificate_by_serial(&db, "00AbCd").unwrap();
    assert!(
        r2.is_some(),
        "must find with mixed-case, leading-zero serial"
    );
    assert_eq!(
        r1.unwrap().id,
        r2.unwrap().id,
        "both queries must return same cert"
    );

    // Bare normalized form
    let r3 = storage::find_certificate_by_serial(&db, "abcd").unwrap();
    assert!(r3.is_some(), "must find with stripped lowercase serial");
}

/// Revoking a cert sets `revoked: true` and `revoke_reason`; `certificate_stats`
/// reflects the new counts immediately.
#[test]
fn revoke_cert_updates_stats() {
    let dir = tmp();
    let db = dir.path().join("certs.json");
    let store = dir.path().join("certs");
    storage::ensure_certs_db(&db, &store).unwrap();

    storage::issue_certificate_record(&db, &store, dummy_cert_record("c1", "01"), DUMMY_CERT)
        .unwrap();
    storage::issue_certificate_record(&db, &store, dummy_cert_record("c2", "02"), DUMMY_CERT)
        .unwrap();

    let (total, revoked, active) = storage::certificate_stats(&db).unwrap();
    assert_eq!((total, revoked, active), (2, 0, 2));

    let updated = storage::revoke_certificate(
        &db,
        "c1",
        "tester",
        "keyCompromise",
        Some("tester".to_string()),
        None,
        Some("api".to_string()),
    )
    .unwrap();
    assert!(updated.is_some(), "revoke must return the updated record");
    let updated = updated.unwrap();
    assert!(updated.revoked, "revoked flag must be true");
    assert_eq!(updated.revoke_reason.as_deref(), Some("keyCompromise"));
    assert!(updated.revoked_at.is_some(), "revoked_at must be set");

    let (total2, revoked2, active2) = storage::certificate_stats(&db).unwrap();
    assert_eq!((total2, revoked2, active2), (2, 1, 1));
}

/// `ensure_certs_db` and `ensure_users_db` create the files and directories if absent.
#[test]
fn ensure_dbs_initializes_empty_state() {
    let dir = tmp();
    let certs_db = dir.path().join("certs.json");
    let users_db = dir.path().join("users.json");
    let certs_dir = dir.path().join("certs");

    assert!(!certs_db.exists());
    assert!(!users_db.exists());

    storage::ensure_certs_db(&certs_db, &certs_dir).unwrap();
    storage::ensure_users_db(&users_db).unwrap();

    assert!(certs_db.exists(), "certs.json must be created");
    assert!(users_db.exists(), "users.json must be created");
    assert!(certs_dir.exists(), "certs/ directory must be created");

    // Second call must be idempotent (no error, no corruption)
    storage::ensure_certs_db(&certs_db, &certs_dir).unwrap();
    storage::ensure_users_db(&users_db).unwrap();

    let (total, revoked, active) = storage::certificate_stats(&certs_db).unwrap();
    assert_eq!((total, revoked, active), (0, 0, 0));
}

/// `list_certificate_records` returns all issued records in insertion order.
#[test]
fn list_certificate_records_returns_all() {
    let dir = tmp();
    let db = dir.path().join("certs.json");
    let store = dir.path().join("certs");
    storage::ensure_certs_db(&db, &store).unwrap();

    for i in 1u8..=3 {
        storage::issue_certificate_record(
            &db,
            &store,
            dummy_cert_record(&format!("cert-{i}"), &format!("{i:02x}")),
            DUMMY_CERT,
        )
        .unwrap();
    }

    let records = storage::list_certificate_records(&db).unwrap();
    assert_eq!(records.len(), 3);
}
