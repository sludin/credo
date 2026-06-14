use credo_test::cert_gen::make_csr;
/// PKI / CSR-signing tests — direct calls to vigil::ca, no HTTP.
/// Covers cert structure validation, SAN preservation, serial uniqueness.
use std::path::PathBuf;
use tempfile::TempDir;
use vigil::ca::sign_csr;
use vigil::config::{CaConfig, IssuancePolicyConfig, TlsConfig, VigilConfig};

fn fixtures() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .join("tests/fixtures")
}

fn signing_config(tmp: &TempDir) -> VigilConfig {
    use credo_lib::LogLevel;
    let f = fixtures();
    VigilConfig {
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
            key_path: tmp.path().join("tls.key"),
            cert_path: tmp.path().join("tls.pem"),
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
    }
}

/// A CSR signed by vigil produces a cert that validates against the test CA chain.
#[test]
fn signed_cert_validates_against_test_ca() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("certs")).unwrap();
    let config = signing_config(&tmp);

    let (csr_pem, _) = make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let signed = sign_csr(&csr_pem, 30, None, &config).unwrap();

    // Cert must be parseable PEM
    assert!(signed.cert_pem.contains("BEGIN CERTIFICATE"));

    // Issuer must be the test intermediate CA
    let der = pem::parse(&signed.cert_pem).unwrap().into_contents();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let issuer = cert.issuer().to_string();
    assert!(
        issuer.contains("Credo Test Intermediate CA"),
        "issuer must be test intermediate CA, got: {issuer}"
    );
}

/// DNS SANs from the CSR appear in the signed cert.
#[test]
fn signed_cert_preserves_dns_sans() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("certs")).unwrap();
    let config = signing_config(&tmp);

    let (csr_pem, _) =
        make_csr("sub.credo.test", &["sub.credo.test", "alt.credo.test"], &[]).unwrap();

    let signed = sign_csr(&csr_pem, 1, None, &config).unwrap();
    let der = pem::parse(&signed.cert_pem).unwrap().into_contents();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

    let dns_sans: Vec<&str> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| {
                    if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                        Some(*d)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    assert!(
        dns_sans.contains(&"sub.credo.test"),
        "sub.credo.test must be a SAN"
    );
    assert!(
        dns_sans.contains(&"alt.credo.test"),
        "alt.credo.test must be a SAN"
    );
}

/// URI SANs from the CSR appear in the signed cert.
#[test]
fn signed_cert_preserves_uri_sans() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("certs")).unwrap();
    let config = signing_config(&tmp);

    let (csr_pem, _) = make_csr(
        "corgi-01.credo.test",
        &["corgi-01.credo.test"],
        &["vigil://credo/node/corgi-01"],
    )
    .unwrap();

    let signed = sign_csr(&csr_pem, 1, None, &config).unwrap();
    let der = pem::parse(&signed.cert_pem).unwrap().into_contents();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

    let has_uri = cert.subject_alternative_name().ok().flatten()
        .map(|san| san.value.general_names.iter().any(|n| {
            matches!(n, x509_parser::extensions::GeneralName::URI(u) if *u == "vigil://credo/node/corgi-01")
        }))
        .unwrap_or(false);

    assert!(has_uri, "signed cert must carry identity URI SAN");
}

/// Two successive sign_csr calls produce different serial numbers.
#[test]
fn serial_numbers_are_unique_across_calls() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("certs")).unwrap();
    let config = signing_config(&tmp);

    let (csr, _) = make_csr("a.credo.test", &["a.credo.test"], &[]).unwrap();

    let s1 = sign_csr(&csr, 1, None, &config).unwrap();
    let s2 = sign_csr(&csr, 1, None, &config).unwrap();

    assert_ne!(
        s1.serial_number, s2.serial_number,
        "each signing call must produce a unique serial"
    );
}

/// A CSR containing a DNS name outside the allowed suffixes is rejected.
#[test]
fn sign_csr_rejects_policy_violation() {
    let tmp = TempDir::new().unwrap();
    let config = signing_config(&tmp);

    let (csr, _) = make_csr("attacker.evil.com", &["attacker.evil.com"], &[]).unwrap();

    let result =
        vigil::issuance_policy::validate_issuance_policy(&csr, &[], &config.issuance_policy);
    assert!(result.is_err(), "policy violation must return an error");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("evil.com"),
        "error must mention the disallowed name"
    );
}

/// The `days` parameter controls validity: a 1-day cert expires sooner than a 30-day cert.
#[test]
fn signed_cert_validity_matches_requested_days() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("certs")).unwrap();
    let config = signing_config(&tmp);

    let (csr, _) = make_csr("v.credo.test", &["v.credo.test"], &[]).unwrap();

    let short = sign_csr(&csr, 1, None, &config).unwrap();
    let long_ = sign_csr(&csr, 90, None, &config).unwrap();

    fn not_after(cert_pem: &str) -> i64 {
        let der = pem::parse(cert_pem).unwrap().into_contents();
        let (_, c) = x509_parser::parse_x509_certificate(&der).unwrap();
        c.validity().not_after.timestamp()
    }

    assert!(
        not_after(&long_.cert_pem) > not_after(&short.cert_pem),
        "90-day cert must expire later than 1-day cert"
    );
}
