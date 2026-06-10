/// Revocation tests — direct calls to vigil::revocation, vigil::storage, and vigil::pki_wire.
/// No HTTP: tests the underlying logic that the API routes call through to.
use std::path::PathBuf;
use tempfile::TempDir;
use vigil::revocation::{generate_crl, get_ocsp_status_by_cert_id, get_ocsp_status_by_serial};
use vigil::storage;
use vigil::types::{CertificateRecord, RootCAMetadata};

fn fixtures() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .join("tests/fixtures")
}

fn dummy_record(id: &str, serial: &str) -> CertificateRecord {
    CertificateRecord {
        id: id.to_string(),
        serial_number: serial.to_string(),
        subject: format!("CN={id}"),
        fingerprint256: format!("sha256:{id}"),
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

const DUMMY_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----\n";

fn setup_db(dir: &TempDir) -> (PathBuf, PathBuf) {
    let db = dir.path().join("certs.json");
    let store = dir.path().join("certs");
    storage::ensure_certs_db(&db, &store).unwrap();
    (db, store)
}

fn test_ca_metadata() -> RootCAMetadata {
    use vigil::config::{CaConfig, IssuancePolicyConfig, LogLevel, TlsConfig, VigilConfig};
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("certs")).unwrap();
    let f = fixtures();
    let config = VigilConfig {
        port: 0,
        bind: "127.0.0.1".to_string(),
        ca_dir: tmp.path().join("ca"),
        ca_key_path: f.join("intermediate-ca.key"),
        ca_cert_path: f.join("intermediate-ca.pem"),
        ca_ecdsa_intermediate_key_path: f.join("intermediate-ca.key"),
        ca_ecdsa_intermediate_cert_path: f.join("intermediate-ca.pem"),
        ca: CaConfig {
            curve: "P-256".to_string(),
            cert_default_days: 365,
            crl_next_update_hours: 24,
            ocsp_max_age_seconds: 60,
        },
        users_db_path: tmp.path().join("users.json"),
        cert_db_path: tmp.path().join("certs.json"),
        acme_accounts_db_path: tmp.path().join("acme-accounts.json"),
        certs_dir: tmp.path().join("certs"),
        ct_log_path: tmp.path().join("ct.log"),
        common_name: "vigil.credo.test".to_string(),
        tls: TlsConfig {
            key_path: tmp.path().join("k"),
            cert_path: tmp.path().join("c"),
            client_ca_path: f.join("catrust.pem"),
        },
        log_level: LogLevel::Warn,
        rbac_identities: vec![],
        issuance_policy: IssuancePolicyConfig {
            allowed_dns_suffixes: vec!["credo.test".to_string()],
            allow_subdomains: true,
            allow_bare_suffix: true,
            allowed_identity_uri_prefixes: vec!["vigil://credo/".to_string()],
            allow_ip_sans: false,
        },
        config_dir: tmp.path().to_path_buf(),
        allow_none_validation: true,
        allowed_http_challenge_ports: vec![80],
        challenge_check_count: 1,
        challenge_check_interval_secs: 0,
        dns_resolver_addrs: vec![],
    };
    vigil::ca::load_ca_metadata(&config).unwrap()
}

/// An active (non-revoked) cert shows OCSP status "good" when queried by cert ID or serial.
#[test]
fn ocsp_good_status_for_active_cert() {
    let dir = TempDir::new().unwrap();
    let (db, store) = setup_db(&dir);

    let _rec =
        storage::issue_certificate_record(&db, &store, dummy_record("c1", "ff10"), DUMMY_PEM)
            .unwrap();

    let by_id = get_ocsp_status_by_cert_id(&db, "c1", 60).unwrap();
    assert_eq!(by_id.status, "good");
    assert!(
        by_id.next_update > by_id.this_update,
        "nextUpdate must be after thisUpdate"
    );

    let by_serial = get_ocsp_status_by_serial(&db, "ff10", 60).unwrap();
    assert_eq!(by_serial.status, "good");
}

/// After revoking a cert, OCSP status is "revoked" with metadata populated.
#[test]
fn ocsp_revoked_status_after_revocation() {
    let dir = TempDir::new().unwrap();
    let (db, store) = setup_db(&dir);

    storage::issue_certificate_record(&db, &store, dummy_record("c2", "aa01"), DUMMY_PEM).unwrap();
    storage::revoke_certificate(
        &db,
        "c2",
        "admin",
        "superseded",
        Some("admin".to_string()),
        None,
        Some("api".to_string()),
    )
    .unwrap();

    let ocsp = get_ocsp_status_by_cert_id(&db, "c2", 60).unwrap();
    assert_eq!(ocsp.status, "revoked");
    assert!(ocsp.revoked_at.is_some(), "revokedAt must be populated");
    assert_eq!(ocsp.revoke_reason.as_deref(), Some("superseded"));
}

/// `generate_crl` includes only revoked certs, with correct count and metadata.
#[test]
fn crl_contains_only_revoked_certs() {
    let dir = TempDir::new().unwrap();
    let (db, store) = setup_db(&dir);

    storage::issue_certificate_record(&db, &store, dummy_record("active", "0001"), DUMMY_PEM)
        .unwrap();
    storage::issue_certificate_record(&db, &store, dummy_record("revoked", "0002"), DUMMY_PEM)
        .unwrap();
    storage::revoke_certificate(&db, "revoked", "admin", "keyCompromise", None, None, None)
        .unwrap();

    let ca = test_ca_metadata();
    let crl = generate_crl(&db, &ca, 24).unwrap();

    assert_eq!(
        crl.revoked_certificates.len(),
        1,
        "CRL must contain exactly the 1 revoked cert"
    );
    assert_eq!(crl.revoked_certificates[0].certificate_id, "revoked");
}

/// `generate_crl` returns an empty list when no certs are revoked.
#[test]
fn crl_is_empty_when_nothing_revoked() {
    let dir = TempDir::new().unwrap();
    let (db, store) = setup_db(&dir);

    storage::issue_certificate_record(&db, &store, dummy_record("active", "0001"), DUMMY_PEM)
        .unwrap();

    let ca = test_ca_metadata();
    let crl = generate_crl(&db, &ca, 24).unwrap();

    assert!(
        crl.revoked_certificates.is_empty(),
        "CRL must be empty when nothing is revoked"
    );
}
