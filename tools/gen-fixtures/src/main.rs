/// Generate test PKI fixtures for the credo test suite.
///
/// Usage: cargo run -p gen-fixtures -- <output-dir>
/// Defaults to tests/fixtures/ relative to the workspace root.
///
/// This tool is intentionally simple and has no external deps beyond rcgen.
/// Run once, commit the output, and regenerate only when certs expire (10 years).
use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose, SanType,
};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;

fn make_dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "Credo Testing");
    dn.push(DnType::OrganizationalUnitName, "Test Infrastructure");
    dn
}

fn ten_years_from_now() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::days(3650)
}

fn make_root_ca() -> Result<Certificate> {
    let mut params = CertificateParams::default();
    params.distinguished_name = make_dn("Credo Test Root CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = ten_years_from_now();
    params.subject_alt_names = vec![SanType::DnsName("root-ca.credo.test".to_string())];
    Certificate::from_params(params).context("generating root CA")
}

fn make_intermediate_ca() -> Result<Certificate> {
    let mut params = CertificateParams::default();
    params.distinguished_name = make_dn("Credo Test Intermediate CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = ten_years_from_now();
    params.subject_alt_names = vec![SanType::DnsName("intermediate-ca.credo.test".to_string())];
    Certificate::from_params(params).context("generating intermediate CA")
}

fn write(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

fn main() -> Result<()> {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures".to_string());
    let out = Path::new(&out_dir);
    fs::create_dir_all(out).context("creating output directory")?;

    println!("Generating test PKI fixtures in: {}", out.display());

    let root = make_root_ca()?;
    let intermediate = make_intermediate_ca()?;

    let root_cert_pem = root.serialize_pem().context("serializing root cert")?;
    let root_key_pem = root.serialize_private_key_pem();

    let intermediate_cert_pem = intermediate
        .serialize_pem_with_signer(&root)
        .context("signing intermediate cert with root")?;
    let intermediate_key_pem = intermediate.serialize_private_key_pem();

    write(&out.join("root-ca.pem"), &root_cert_pem)?;
    write(&out.join("root-ca.key"), &root_key_pem)?;
    write(&out.join("intermediate-ca.pem"), &intermediate_cert_pem)?;
    write(&out.join("intermediate-ca.key"), &intermediate_key_pem)?;
    // catrust.pem is the trust anchor (root CA cert only)
    write(&out.join("catrust.pem"), &root_cert_pem)?;

    println!("  root-ca.pem          (self-signed root CA, 10-year validity)");
    println!("  root-ca.key          (root CA private key — TEST USE ONLY)");
    println!("  intermediate-ca.pem  (intermediate CA signed by root, 10-year validity)");
    println!("  intermediate-ca.key  (intermediate CA private key — TEST USE ONLY)");
    println!("  catrust.pem          (= root-ca.pem, trust anchor for all test services)");
    println!();
    println!("Verify chain with:");
    println!(
        "  openssl verify -CAfile {}/catrust.pem {}/intermediate-ca.pem",
        out.display(),
        out.display()
    );

    Ok(())
}
