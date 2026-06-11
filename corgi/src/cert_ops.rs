use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SanType};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::archive::{ensure_parent, install_to_archive, set_permissions};
use crate::config::FlockEntry;
use crate::types::{CsrRequest, InstallRequest};

// ---------------------------------------------------------------------------
// CSR path helpers
// ---------------------------------------------------------------------------

/// Derive the on-disk CSR path for a flock entry.
/// Uses `entry.csr_path` if configured; otherwise places `csr.pem` in the
/// same directory as the certificate (e.g. `live/<name>/csr.pem`).
fn csr_path_for_entry(entry: &FlockEntry) -> std::path::PathBuf {
    if let Some(ref p) = entry.csr_path {
        return p.clone();
    }
    entry
        .path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("csr.pem")
}

fn save_csr(entry: &FlockEntry, csr_pem: &str) -> Result<()> {
    let path = csr_path_for_entry(entry);
    ensure_parent(&path)?;
    std::fs::write(&path, csr_pem).with_context(|| format!("Writing CSR to {}", path.display()))?;
    set_permissions(&path, 0o644)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint as uppercase colon-separated hex — matches Node.js
/// `X509Certificate.fingerprint256` format that the dashboard expects.
pub fn fingerprint_display(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Internal lowercase-no-colon fingerprint used only for fast equality checks.
fn fingerprint_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Returns days remaining until the cert at `cert_path` expires, or None if unreadable.
pub fn cert_days_remaining(cert_path: &Path) -> Option<i64> {
    use x509_parser::prelude::*;
    let pem_str = std::fs::read_to_string(cert_path).ok()?;
    let der = pem_cert_to_der(&pem_str).ok()?;
    let (_, cert) = X509Certificate::from_der(&der).ok()?;
    let na = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    Some((na - now) / 86400)
}

/// Read the leaf certificate from `cert_path` and return its display fingerprint.
pub fn read_cert_fingerprint(cert_path: &Path) -> Option<String> {
    let pem_str = std::fs::read_to_string(cert_path).ok()?;
    let der = pem_cert_to_der(&pem_str).ok()?;
    Some(fingerprint_display(&der))
}

/// Parse the first certificate from a PEM string and return DER bytes.
pub fn pem_cert_to_der(pem_str: &str) -> Result<Vec<u8>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(pem_str.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("Parsing PEM certificate")?;
    certs
        .into_iter()
        .next()
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| anyhow::anyhow!("No certificate found in PEM"))
}

// ---------------------------------------------------------------------------
// Key operations (ECDSA P-256 only)
// ---------------------------------------------------------------------------

/// Generate a new ECDSA P-256 private key and write it to `key_path` (mode 0600).
/// Returns the PEM-encoded PKCS#8 key.
pub fn generate_key(key_path: &Path) -> Result<String> {
    // rcgen generates ECDSA P-256 by default
    let params = CertificateParams::default();
    let cert = Certificate::from_params(params).context("Generating key")?;
    let key_pem = cert.serialize_private_key_pem();

    ensure_parent(key_path)?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("Writing key to {}", key_path.display()))?;
    set_permissions(key_path, 0o600)?;

    Ok(key_pem)
}

/// Load a key from disk and return its PEM string.
pub fn load_key_pem(key_path: &Path) -> Result<String> {
    std::fs::read_to_string(key_path)
        .with_context(|| format!("Reading key from {}", key_path.display()))
}

/// Returns true if a key file exists and appears to be an EC key (ECDSA P-256).
pub fn is_ecdsa_key(key_path: &Path) -> bool {
    let Ok(pem) = std::fs::read_to_string(key_path) else {
        return false;
    };
    // PKCS#8 EC key header or SEC1 EC key header
    pem.contains("EC PRIVATE KEY") || pem.contains("PRIVATE KEY")
}

// ---------------------------------------------------------------------------
// SAN collection
// ---------------------------------------------------------------------------

/// Merge all sources of SANs for a CSR, deduplicated.
/// Order: entry.sans → request.sans → entry.domain → identity_uri (as URI SAN).
pub fn collect_sans(
    entry: &FlockEntry,
    req: &CsrRequest,
    config_identity_uri: Option<&str>,
) -> Vec<SanType> {
    let mut seen = std::collections::HashSet::new();
    let mut dns_sans: Vec<String> = vec![];
    let mut uri_sans: Vec<String> = vec![];

    // Inline deduplication to avoid two closures capturing `seen` mutably at once
    macro_rules! add_dns {
        ($s:expr) => {
            let s: &str = $s;
            if !s.is_empty() && seen.insert(s.to_string()) {
                dns_sans.push(s.to_string());
            }
        };
    }
    macro_rules! add_uri {
        ($s:expr) => {
            let s: &str = $s;
            if !s.is_empty() && seen.insert(s.to_string()) {
                uri_sans.push(s.to_string());
            }
        };
    }

    for san in &entry.sans {
        add_dns!(san);
    }
    if let Some(body_sans) = &req.sans {
        for san in body_sans {
            add_dns!(san);
        }
    }
    if let Some(domain) = &entry.domain {
        add_dns!(domain);
    }

    let identity_uri = req
        .identity_uri
        .as_deref()
        .or(entry.identity_uri.as_deref())
        .or(config_identity_uri);
    if let Some(uri) = identity_uri {
        add_uri!(uri);
    }

    if dns_sans.is_empty() && uri_sans.is_empty() {
        let fallback = entry.domain.as_deref().unwrap_or(&entry.name);
        dns_sans.push(fallback.to_string());
    }

    let mut result: Vec<SanType> = dns_sans.into_iter().map(SanType::DnsName).collect();
    result.extend(uri_sans.into_iter().map(SanType::URI));
    result
}

// ---------------------------------------------------------------------------
// CSR / key generation
// ---------------------------------------------------------------------------

/// Build rcgen CertificateParams from a FlockEntry and optional CSR request body.
fn build_params(
    entry: &FlockEntry,
    req: &CsrRequest,
    config_identity_uri: Option<&str>,
) -> CertificateParams {
    let mut params = CertificateParams::default();

    let subject = req.csr_subject.as_ref().or(entry.csr_subject.as_ref());
    let cn = subject
        .and_then(|s| s.common_name.as_deref())
        .or(entry.domain.as_deref())
        .unwrap_or(&entry.name);

    params.distinguished_name.push(DnType::CommonName, cn);
    if let Some(s) = subject {
        if let Some(c) = &s.country {
            params.distinguished_name.push(DnType::CountryName, c);
        }
        if let Some(st) = &s.state {
            params
                .distinguished_name
                .push(DnType::StateOrProvinceName, st);
        }
        if let Some(l) = &s.locality {
            params.distinguished_name.push(DnType::LocalityName, l);
        }
        if let Some(o) = &s.organization {
            params.distinguished_name.push(DnType::OrganizationName, o);
        }
        if let Some(ou) = &s.organizational_unit {
            params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, ou);
        }
    }

    params.subject_alt_names = collect_sans(entry, req, config_identity_uri);
    params
}

/// Generate a new ECDSA P-256 key + CSR.
/// The key is written to `key_path` (mode 0600), which must be the pending staging
/// path (`archive::pending_key_path`), never a path inside `live/`.
/// `install_to_archive` moves it to `archive/` and creates the `live/` symlink when
/// the signed cert arrives.
pub fn generate_key_and_csr(
    entry: &FlockEntry,
    key_path: &Path,
    req: &CsrRequest,
    config_identity_uri: Option<&str>,
) -> Result<String> {
    let params = build_params(entry, req, config_identity_uri);
    let cert = Certificate::from_params(params).context("Building CSR params")?;
    let key_pem = cert.serialize_private_key_pem();

    ensure_parent(key_path)?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("Writing key to {}", key_path.display()))?;
    set_permissions(key_path, 0o600)?;

    let csr_pem = cert
        .serialize_request_pem()
        .context("Serializing CSR PEM")?;
    save_csr(entry, &csr_pem)?;
    Ok(csr_pem)
}

/// Generate a CSR reusing the existing key at `entry.key_path`, or generating a
/// new key there if none exists. Callers should prefer `generate_key_and_csr` with
/// an explicit pending staging path instead of writing into `live/` directly.
pub fn generate_csr(
    entry: &FlockEntry,
    req: &CsrRequest,
    config_identity_uri: Option<&str>,
) -> Result<String> {
    if !entry.key_path.exists() || !is_ecdsa_key(&entry.key_path) {
        return generate_key_and_csr(entry, &entry.key_path.clone(), req, config_identity_uri);
    }

    let key_pem = load_key_pem(&entry.key_path)?;
    let key_pair = KeyPair::from_pem(&key_pem).context("Loading existing key pair")?;
    generate_csr_with_keypair(entry, req, config_identity_uri, key_pair)
}

/// Generate a CSR using a pre-loaded key pair (for routes that load the key themselves).
pub fn generate_csr_with_keypair(
    entry: &FlockEntry,
    req: &CsrRequest,
    config_identity_uri: Option<&str>,
    key_pair: KeyPair,
) -> Result<String> {
    let mut params = build_params(entry, req, config_identity_uri);
    params.key_pair = Some(key_pair);
    let cert = Certificate::from_params(params).context("Building CSR with key pair")?;
    let csr_pem = cert
        .serialize_request_pem()
        .context("Serializing CSR PEM")?;
    save_csr(entry, &csr_pem)?;
    Ok(csr_pem)
}

// ---------------------------------------------------------------------------
// Bootstrap self-signed certificate
// ---------------------------------------------------------------------------

/// Generate an ephemeral self-signed ECDSA P-256 certificate for bootstrap mode.
/// Returns (cert_pem, key_pem). Validity: 1 day.
pub fn generate_bootstrap_cert(
    common_name: &str,
    identity_uri: Option<&str>,
) -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);

    // 1-day validity
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(1);

    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".to_string()));
    if let Some(uri) = identity_uri {
        params.subject_alt_names.push(SanType::URI(uri.to_string()));
    }

    let cert = Certificate::from_params(params).context("Building bootstrap cert")?;
    let cert_pem = cert.serialize_pem().context("Serializing bootstrap cert")?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem, key_pem))
}

// ---------------------------------------------------------------------------
// Certificate installation
// ---------------------------------------------------------------------------

pub struct InstallResult {
    pub changed: bool,
    pub previous_fingerprint: Option<String>,
    pub next_fingerprint: String,
}

pub fn install_certificate(
    entry: &FlockEntry,
    cert_store_dir: &Path,
    req: &InstallRequest,
) -> Result<InstallResult> {
    let cert_pem = req
        .cert_pem
        .as_deref()
        .or(req.fullchain_pem.as_deref())
        .ok_or_else(|| anyhow::anyhow!("certPem or fullchainPem is required"))?;

    let previous_fingerprint = read_cert_fingerprint(&entry.path); // display format

    let cert_der = pem_cert_to_der(cert_pem)?;
    let next_fingerprint = fingerprint_display(&cert_der); // display format

    // Normalize both sides for comparison so format differences don't matter
    let normalize = |s: &str| s.replace(':', "").to_lowercase();
    let changed =
        previous_fingerprint.as_deref().map(&normalize) != Some(normalize(&next_fingerprint));

    install_to_archive(
        entry,
        cert_store_dir,
        cert_pem,
        req.fullchain_pem.as_deref(),
        req.chain_pem.as_deref(),
        req.key_pem.as_deref(),
    )?;

    Ok(InstallResult {
        changed,
        previous_fingerprint,
        next_fingerprint,
    })
}

// ---------------------------------------------------------------------------
// Certificate status reading
// ---------------------------------------------------------------------------

pub fn read_cert_status(entry: &FlockEntry) -> crate::types::CertificateStatus {
    use x509_parser::prelude::*;

    let cert_exists = entry.path.exists();
    let key_exists = entry.key_path.exists();
    let mut subject = None;
    let mut issuer = None;
    let mut serial_number = None;
    let mut fingerprint256 = None;
    let mut valid_from = None;
    let mut valid_to = None;
    let mut expires_in_days = None;
    let mut cert_matches_key = false;

    if cert_exists {
        if let Ok(pem_str) = std::fs::read_to_string(&entry.path) {
            if let Ok(der) = pem_cert_to_der(&pem_str) {
                fingerprint256 = Some(fingerprint_display(&der));
                if let Ok((_, cert)) = X509Certificate::from_der(&der) {
                    subject = Some(cert.subject().to_string());
                    issuer = Some(cert.issuer().to_string());
                    serial_number = Some(format!("{:x}", cert.serial));
                    let nb = cert.validity().not_before.timestamp();
                    let na = cert.validity().not_after.timestamp();
                    // OpenSSL text format matches Node.js X509Certificate.validFrom/validTo
                    // e.g. "May 30 13:56:45 2027 GMT" — required by the dashboard's fmtDate().
                    valid_from = chrono::DateTime::<chrono::Utc>::from_timestamp(nb, 0)
                        .map(|dt| dt.format("%b %e %H:%M:%S %Y GMT").to_string());
                    valid_to = chrono::DateTime::<chrono::Utc>::from_timestamp(na, 0)
                        .map(|dt| dt.format("%b %e %H:%M:%S %Y GMT").to_string());
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    expires_in_days = Some((na - now) / 86400);
                }
            }
        }
    }

    if cert_exists && key_exists {
        cert_matches_key = check_cert_matches_key(&entry.path, &entry.key_path);
    }

    let hooks: Vec<String> = entry.hooks.iter().map(|h| h.name().to_string()).collect();

    crate::types::CertificateStatus {
        name: entry.name.clone(),
        domain: entry.domain.clone(),
        cert_path: entry.path.to_string_lossy().to_string(),
        key_path: entry.key_path.to_string_lossy().to_string(),
        cert_exists,
        key_exists,
        cert_matches_key,
        subject,
        issuer,
        serial_number,
        fingerprint256,
        valid_from,
        valid_to,
        expires_in_days,
        hooks,
        // ISO format with ms + Z suffix — matches new Date().toISOString() from TypeScript.
        last_checked_at: chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
    }
}

pub fn to_flock_summary(entry: &FlockEntry) -> crate::types::FlockSummary {
    let fingerprint256 = read_cert_fingerprint(&entry.path);

    struct CertFields {
        valid_to: Option<String>,
        lifetime_days: Option<f64>,
        san_names: Vec<String>,
    }

    let fields = std::fs::read_to_string(&entry.path)
        .ok()
        .and_then(|pem| pem_cert_to_der(&pem).ok())
        .and_then(|der| {
            use x509_parser::extensions::GeneralName;
            use x509_parser::prelude::*;
            X509Certificate::from_der(&der).ok().map(|(_, cert)| {
                let na = cert.validity().not_after.timestamp();
                let now = chrono::Utc::now().timestamp();
                let valid_to = chrono::DateTime::<chrono::Utc>::from_timestamp(na, 0)
                    .map(|dt| dt.format("%b %e %H:%M:%S %Y GMT").to_string());
                let lifetime_days = (na - now) as f64 / 86400.0;
                let mut san_names: Vec<String> = Vec::new();
                for ext in cert.extensions() {
                    if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                        for name in &san.general_names {
                            if let GeneralName::DNSName(dns) = name {
                                san_names.push(dns.to_string());
                            }
                        }
                    }
                }
                CertFields {
                    valid_to,
                    lifetime_days: Some(lifetime_days),
                    san_names,
                }
            })
        })
        .unwrap_or(CertFields {
            valid_to: None,
            lifetime_days: None,
            san_names: vec![],
        });

    let status = if fingerprint256.is_some() {
        "ok"
    } else {
        "not-ok"
    }
    .to_string();

    crate::types::FlockSummary {
        name: entry.name.clone(),
        fingerprint256,
        valid_to: fields.valid_to,
        lifetime_days: fields.lifetime_days,
        san_names: fields.san_names,
        domain: entry.domain.clone(),
        status,
        key_exists: entry.key_path.exists(),
    }
}

// ---------------------------------------------------------------------------
// Cert/key matching
// ---------------------------------------------------------------------------

pub fn check_cert_matches_key(cert_path: &Path, key_path: &Path) -> bool {
    let cert_pubkey = get_cert_spki_bytes(cert_path);
    let key_pubkey = get_key_public_point(key_path);
    match (cert_pubkey, key_pubkey) {
        (Some(c), Some(k)) => c == k,
        _ => false,
    }
}

fn get_cert_spki_bytes(cert_path: &Path) -> Option<Vec<u8>> {
    let pem_str = std::fs::read_to_string(cert_path).ok()?;
    get_cert_spki_bytes_from_pem(&pem_str)
}

fn get_cert_spki_bytes_from_pem(cert_pem: &str) -> Option<Vec<u8>> {
    let der = pem_cert_to_der(cert_pem).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(cert.public_key().raw.to_vec())
}

/// Returns true if `cert_pem` was signed for the public key corresponding to
/// the private key stored at `key_path`.  Used to guard against installing a
/// cert whose key doesn't match a pending key that is waiting to be archived.
pub fn cert_pem_matches_key_file(cert_pem: &str, key_path: &Path) -> bool {
    match (get_cert_spki_bytes_from_pem(cert_pem), get_key_public_point(key_path)) {
        (Some(c), Some(k)) => c == k,
        _ => false,
    }
}

fn get_key_public_point(key_path: &Path) -> Option<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;
    let pem_str = std::fs::read_to_string(key_path).ok()?;
    let sk = p256::SecretKey::from_pkcs8_pem(&pem_str).ok()?;
    let point = sk.public_key().to_encoded_point(false);
    Some(point.as_bytes().to_vec())
}
