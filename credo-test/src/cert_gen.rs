/// Generates test TLS certificates signed by the test intermediate CA.
///
/// Uses vigil's raw CA signing path (ca::sign_csr) directly — no running
/// vigil server required.  Used by test harnesses that need real mTLS certs.
use anyhow::{Context, Result};
use std::path::Path;
use vigil::config::{CaConfig, IssuancePolicyConfig, TlsConfig, VigilConfig};

/// Returns a minimal VigilConfig suitable only for signing CSRs via ca::sign_csr.
/// All paths except the CA key/cert are set to non-existent temp values.
pub fn signing_config(tmp_dir: &Path) -> VigilConfig {
    use vigil::config::LogLevel;
    VigilConfig {
        port: 0,
        bind: "127.0.0.1".to_string(),
        ca_dir: tmp_dir.join("ca"),
        ca_key_path: crate::fixtures::intermediate_ca_key(),
        ca_cert_path: crate::fixtures::intermediate_ca_pem(),
        ca_ecdsa_intermediate_key_path: crate::fixtures::intermediate_ca_key(),
        ca_ecdsa_intermediate_cert_path: crate::fixtures::intermediate_ca_pem(),
        ca: CaConfig {
            curve: "P-256".to_string(),
            cert_default_days: 365,
            crl_next_update_hours: 24,
            ocsp_max_age_seconds: 60,
        },
        users_db_path: tmp_dir.join("users.json"),
        cert_db_path: tmp_dir.join("certs.json"),
        acme_accounts_db_path: tmp_dir.join("acme-accounts.json"),
        certs_dir: tmp_dir.join("certs"),
        ct_log_path: tmp_dir.join("ct.log"),
        common_name: "test.credo.test".to_string(),
        tls: TlsConfig {
            key_path: tmp_dir.join("tls.key"),
            cert_path: tmp_dir.join("tls.pem"),
            client_ca_path: crate::fixtures::catrust_pem(),
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
        config_dir: tmp_dir.to_path_buf(),
        allow_none_validation: true,
    }
}

/// Generate just a CSR (no signing). Returns (csr_pem, key_pem).
/// Use for bootstrap tests where the caller signs the CSR separately.
pub fn make_csr(cn: &str, dns_sans: &[&str], uri_sans: &[&str]) -> Result<(String, String)> {
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};

    let mut params =
        CertificateParams::new(dns_sans.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    for uri in uri_sans {
        params.subject_alt_names.push(SanType::URI(uri.to_string()));
    }
    let cert = Certificate::from_params(params).context("rcgen cert params")?;
    let key_pem = cert.serialize_private_key_pem();
    let csr_pem = cert.serialize_request_pem().context("serialize CSR")?;
    Ok((csr_pem, key_pem))
}

/// Sign a CSR with the test intermediate CA and return the SignedCertificate.
/// This calls vigil's signing logic directly — no running vigil server needed.
pub fn sign_csr_with_test_ca(
    csr_pem: &str,
    days: u32,
    tmp_dir: &Path,
) -> Result<vigil::types::SignedCertificate> {
    let config = signing_config(tmp_dir);
    std::fs::create_dir_all(&config.certs_dir).ok();
    vigil::ca::sign_csr(csr_pem, days, None, &config)
        .context("signing CSR with test intermediate CA")
}

/// Generate a key + CSR using rcgen, then sign it with the test intermediate CA.
/// Returns (cert_pem, key_pem, fullchain_pem).
pub fn generate_signed_cert(
    common_name: &str,
    dns_sans: &[&str],
    uri_sans: &[&str],
    days: u32,
    tmp_dir: &Path,
) -> Result<(String, String, String)> {
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};

    let mut sans: Vec<String> = dns_sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(sans.clone());
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    for uri in uri_sans {
        params.subject_alt_names.push(SanType::URI(uri.to_string()));
        sans.push(uri.to_string());
    }

    let cert = Certificate::from_params(params).context("rcgen cert params")?;
    let key_pem = cert.serialize_private_key_pem();
    let csr_pem = cert.serialize_request_pem().context("rcgen CSR")?;

    let config = signing_config(tmp_dir);
    std::fs::create_dir_all(&config.certs_dir).ok();
    std::fs::create_dir_all(&tmp_dir).ok();

    let signed =
        vigil::ca::sign_csr(&csr_pem, days, None, &config).context("signing CSR with test CA")?;

    Ok((signed.cert_pem, key_pem, signed.fullchain_pem))
}
