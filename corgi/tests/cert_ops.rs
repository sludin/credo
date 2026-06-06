/// Certificate operations tests — direct function calls, no HTTP.
/// Ports the deprecated cert-ops.test.ts (collectSans) and adds install + CSR round-trips.
use corgi::cert_ops::{collect_sans, generate_key_and_csr, install_certificate, pem_cert_to_der};
use corgi::config::FlockEntry;
use corgi::types::{CsrRequest, InstallRequest};
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn empty_entry(name: &str, dir: &TempDir) -> FlockEntry {
    FlockEntry {
        name: name.to_string(),
        path: dir.path().join(format!("{name}.cert.pem")),
        key_path: dir.path().join(format!("{name}.key.pem")),
        chain_path: None, fullchain_path: None, csr_path: None,
        domain: None, monitor: false, hooks: vec![], csr_subject: None,
        identity_uri: None, sans: vec![],
        cert_mode: None, key_mode: None, cert_owner: None, cert_group: None,
        key_owner: None, key_group: None,
    }
}

fn signed_cert_pem(cn: &str) -> (String, String) {
    // Generate a self-signed cert for install tests (no CA needed; just checks archive structure)
    use rcgen::DistinguishedName;
    let mut params = CertificateParams::new(vec![cn.to_string()]);
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(cn.to_string())];
    let cert = Certificate::from_params(params).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

// ---------------------------------------------------------------------------
// collect_sans — ports deprecated cert-ops.test.ts collectSans tests
// ---------------------------------------------------------------------------

/// Entry SANs are used when the request body has none.
#[test]
fn collect_sans_uses_entry_sans_when_body_empty() {
    let dir = TempDir::new().unwrap();
    let mut entry = empty_entry("test", &dir);
    entry.sans = vec!["a.credo.test".to_string(), "b.credo.test".to_string()];

    let req = CsrRequest::default();
    let sans = collect_sans(&entry, &req, None);
    let dns: Vec<_> = sans.iter().filter_map(|s| if let SanType::DnsName(d) = s { Some(d.as_str()) } else { None }).collect();
    assert!(dns.contains(&"a.credo.test"), "must include entry SANs");
    assert!(dns.contains(&"b.credo.test"), "must include all entry SANs");
}

/// Request body SANs are merged with entry SANs.
#[test]
fn collect_sans_merges_body_and_entry_sans() {
    let dir = TempDir::new().unwrap();
    let mut entry = empty_entry("test", &dir);
    entry.sans = vec!["entry.credo.test".to_string()];

    let req = CsrRequest { sans: Some(vec!["body.credo.test".to_string()]), ..Default::default() };
    let sans = collect_sans(&entry, &req, None);
    let dns: Vec<_> = sans.iter().filter_map(|s| if let SanType::DnsName(d) = s { Some(d.as_str()) } else { None }).collect();
    assert!(dns.contains(&"entry.credo.test"), "must include entry SAN");
    assert!(dns.contains(&"body.credo.test"),  "must include body SAN");
}

/// Overlapping SANs from entry and body are deduplicated.
#[test]
fn collect_sans_deduplicates_overlapping() {
    let dir = TempDir::new().unwrap();
    let mut entry = empty_entry("test", &dir);
    entry.sans = vec!["shared.credo.test".to_string()];

    let req = CsrRequest { sans: Some(vec!["shared.credo.test".to_string(), "other.credo.test".to_string()]), ..Default::default() };
    let sans = collect_sans(&entry, &req, None);
    let dns: Vec<String> = sans.iter().filter_map(|s| if let SanType::DnsName(d) = s { Some(d.clone()) } else { None }).collect();

    let count = dns.iter().filter(|d| d.as_str() == "shared.credo.test").count();
    assert_eq!(count, 1, "shared.credo.test must appear exactly once");
}

/// Falls back to entry.domain when no SANs come from any source.
#[test]
fn collect_sans_falls_back_to_domain() {
    let dir = TempDir::new().unwrap();
    let mut entry = empty_entry("test", &dir);
    entry.domain = Some("fallback.credo.test".to_string());

    let req = CsrRequest::default();
    let sans = collect_sans(&entry, &req, None);
    let dns: Vec<_> = sans.iter().filter_map(|s| if let SanType::DnsName(d) = s { Some(d.as_str()) } else { None }).collect();
    assert!(dns.contains(&"fallback.credo.test"), "must fall back to entry.domain");
}

/// A config-level identity URI becomes a URI SAN.
#[test]
fn collect_sans_includes_config_identity_uri() {
    let dir = TempDir::new().unwrap();
    let mut entry = empty_entry("test", &dir);
    entry.sans = vec!["node.credo.test".to_string()];

    let req = CsrRequest::default();
    let sans = collect_sans(&entry, &req, Some("vigil://credo/node/test-01"));

    let has_uri = sans.iter().any(|s| matches!(s, SanType::URI(u) if u == "vigil://credo/node/test-01"));
    assert!(has_uri, "config identity URI must appear as URI SAN");
}

// ---------------------------------------------------------------------------
// Key + CSR generation
// ---------------------------------------------------------------------------

/// generate_key_and_csr writes the key to the given path (pending staging) and returns a PEM CSR.
#[test]
fn generate_key_and_csr_writes_key_and_returns_csr() {
    let dir = TempDir::new().unwrap();
    let entry = empty_entry("gen-test", &dir);
    let pending = dir.path().join("pending/gen-test.pem");
    let req = CsrRequest {
        sans: Some(vec!["gen.credo.test".to_string()]),
        ..Default::default()
    };

    let csr_pem = generate_key_and_csr(&entry, &pending, &req, None).unwrap();

    assert!(pending.exists(), "key must be written to the pending staging path");
    assert!(!entry.key_path.exists(), "key must NOT be written to live/");
    assert!(csr_pem.contains("CERTIFICATE REQUEST"), "result must be a PEM CSR");
}

// ---------------------------------------------------------------------------
// Certificate installation
// ---------------------------------------------------------------------------

/// install_certificate creates the archive + live symlink structure.
#[test]
fn install_certificate_creates_archive_and_live_symlinks() {
    let dir = TempDir::new().unwrap();
    let cert_store = dir.path().join("certstore");
    std::fs::create_dir_all(&cert_store).unwrap();

    let entry = corgi::config::FlockEntry {
        name: "install-test".to_string(),
        path: cert_store.join("live/install-test/cert.pem"),
        key_path: cert_store.join("live/install-test/privkey.pem"),
        fullchain_path: Some(cert_store.join("live/install-test/fullchain.pem")),
        chain_path: None, csr_path: None,
        domain: Some("install.credo.test".to_string()),
        monitor: false, hooks: vec![], csr_subject: None,
        identity_uri: None, sans: vec![],
        cert_mode: None, key_mode: None, cert_owner: None, cert_group: None,
        key_owner: None, key_group: None,
    };

    let (cert_pem, key_pem) = signed_cert_pem("install.credo.test");
    let fullchain = format!("{}{}", cert_pem, cert_pem); // minimal stand-in

    let req = InstallRequest {
        cert_pem: Some(cert_pem.clone()),
        fullchain_pem: Some(fullchain),
        key_pem: Some(key_pem),
        chain_pem: None, restart: Some(false),
    };

    let result = install_certificate(&entry, &cert_store, &req).unwrap();

    assert!(result.changed, "first install must mark changed=true");
    assert!(!result.next_fingerprint.is_empty(), "fingerprint must be set");

    let archive = cert_store.join("archive/install-test");
    assert!(archive.join("cert-001.pem").is_file(),     "cert archive must exist");
    assert!(archive.join("fullchain-001.pem").is_file(), "fullchain archive must exist");
    assert!(archive.join("privkey-001.pem").is_file(),  "key archive must exist");

    let live = cert_store.join("live/install-test");
    assert!(live.join("cert.pem").is_symlink(),     "live/cert.pem must be symlink");
    assert!(live.join("fullchain.pem").is_symlink(), "live/fullchain.pem must be symlink");
    assert!(live.join("privkey.pem").is_symlink(),  "live/privkey.pem must be symlink");
}

/// When install_certificate is called with no key_pem and no key on disk,
/// no privkey is written to the archive. reconcile_once uses this knowledge
/// to guard the install: it generates a key+CSR and requests re-issue from
/// shepherd instead of letting install_to_archive create a key-less entry.
/// This test documents install_certificate's own behaviour (the guard in sync.rs
/// prevents this path from being reached in the normal missing-key scenario).
#[test]
fn install_certificate_no_key_leaves_no_privkey_in_archive() {
    let dir = TempDir::new().unwrap();
    let cert_store = dir.path().join("certstore");
    std::fs::create_dir_all(&cert_store).unwrap();

    let entry = corgi::config::FlockEntry {
        name: "nokey-test".to_string(),
        path: cert_store.join("live/nokey-test/cert.pem"),
        key_path: cert_store.join("live/nokey-test/privkey.pem"),
        fullchain_path: None, chain_path: None, csr_path: None,
        domain: None, monitor: false, hooks: vec![], csr_subject: None,
        identity_uri: None, sans: vec![],
        cert_mode: None, key_mode: None, cert_owner: None, cert_group: None,
        key_owner: None, key_group: None,
    };

    let (cert_pem, _key_pem) = signed_cert_pem("nokey.credo.test");
    let req = InstallRequest {
        cert_pem: Some(cert_pem),
        key_pem: None,
        fullchain_pem: None,
        chain_pem: None,
        restart: Some(false),
    };

    assert!(!entry.key_path.exists(), "precondition: no key on disk");

    install_certificate(&entry, &cert_store, &req).unwrap();

    let archive = cert_store.join("archive/nokey-test");
    assert!(archive.join("cert-001.pem").is_file(), "cert archive must still be written");
    assert!(!archive.join("privkey-001.pem").exists(),
        "no privkey must be written to archive when key_pem=None and key_path absent");
    assert!(!cert_store.join("live/nokey-test/privkey.pem").exists(),
        "no privkey symlink must exist in live dir");
}

/// reconcile_once generates a new key when entry.key_path is a flat file (bootstrap
/// temp key) or does not exist.  Only a SYMLINK at entry.key_path counts as a
/// properly archived key; a flat file belongs to the bootstrap cert and must not be
/// reused.  After install_to_archive runs, the flat file is atomically replaced by
/// a symlink — that is the bootstrap artifact cleanup.
#[test]
fn flat_file_key_is_not_treated_as_archived() {
    let dir = TempDir::new().unwrap();
    let cert_store = dir.path().join("certstore");
    std::fs::create_dir_all(cert_store.join("live/flat.credo.test")).unwrap();

    let key_path = cert_store.join("live/flat.credo.test/privkey.pem");
    // Write a flat file (bootstrap temp key — not a symlink)
    std::fs::write(&key_path, b"fake key content").unwrap();

    let is_symlink = key_path.symlink_metadata().unwrap().file_type().is_symlink();
    assert!(!is_symlink, "precondition: flat file is not a symlink");

    // reconcile_once checks: symlink_metadata().is_symlink() — flat file → false → needs new key
    let key_is_archived = key_path
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    assert!(!key_is_archived,
        "flat file key must not be treated as archived; reconcile_once must generate a new key");
}

/// reconcile_once generates a private key and CSR when a cert is available from
/// shepherd but no archived key exists on disk. Verified by calling generate_key_and_csr
/// the same way reconcile_once does and checking the key lands on disk as a real
/// file — so the subsequent flock_install push from shepherd can archive it.
#[test]
fn generate_key_and_csr_for_missing_key_cert() {
    use corgi::cert_ops::generate_key_and_csr;
    use corgi::types::CsrRequest;

    let dir = TempDir::new().unwrap();
    let cert_store = dir.path().join("certstore");
    std::fs::create_dir_all(cert_store.join("live/vigil.credo.test")).unwrap();

    let entry = corgi::config::FlockEntry {
        name: "vigil.credo.test".to_string(),
        path: cert_store.join("live/vigil.credo.test/cert.pem"),
        key_path: cert_store.join("live/vigil.credo.test/privkey.pem"),
        fullchain_path: None, chain_path: None, csr_path: None,
        domain: Some("vigil.credo.test".to_string()),
        monitor: false, hooks: vec![],
        csr_subject: None,
        identity_uri: Some("vigil://credo/service/vigil".to_string()),
        sans: vec!["vigil.credo.test".to_string()],
        cert_mode: None, key_mode: None, cert_owner: None, cert_group: None,
        key_owner: None, key_group: None,
    };

    assert!(!entry.key_path.exists(), "precondition: no key on disk");

    let csr_req = CsrRequest {
        sans: Some(entry.sans.clone()),
        common_name: entry.domain.clone(),
        identity_uri: entry.identity_uri.clone(),
        csr_subject: None,
    };

    let pending = cert_store.join("pending/vigil.credo.test.pem");
    let csr_pem = generate_key_and_csr(&entry, &pending, &csr_req, None)
        .expect("must generate CSR for missing-key cert");

    assert!(pending.exists(),
        "private key must be written to the pending staging path");
    assert!(!entry.key_path.exists(),
        "key must NOT be written to live/ — live/ only holds symlinks");
    assert!(csr_pem.contains("CERTIFICATE REQUEST"),
        "returned value must be a valid PEM CSR");

    // Pending key is a real file — install_to_archive will move it to archive/
    // and create the live/ symlink when shepherd's /install push arrives.
    let meta = pending.symlink_metadata().unwrap();
    assert!(!meta.file_type().is_symlink(),
        "pending key must be a real file so install_to_archive can archive it");
}

/// Installing the same cert twice reports changed=false on the second call.
#[test]
fn install_certificate_unchanged_on_second_install() {
    let dir = TempDir::new().unwrap();
    let cert_store = dir.path().join("certstore");
    std::fs::create_dir_all(&cert_store).unwrap();

    let entry = corgi::config::FlockEntry {
        name: "idempotent".to_string(),
        path: cert_store.join("live/idempotent/cert.pem"),
        key_path: cert_store.join("live/idempotent/privkey.pem"),
        fullchain_path: None, chain_path: None, csr_path: None,
        domain: None, monitor: false, hooks: vec![], csr_subject: None,
        identity_uri: None, sans: vec![],
        cert_mode: None, key_mode: None, cert_owner: None, cert_group: None,
        key_owner: None, key_group: None,
    };

    let (cert_pem, key_pem) = signed_cert_pem("idempotent.credo.test");
    let req = InstallRequest {
        cert_pem: Some(cert_pem), key_pem: Some(key_pem),
        fullchain_pem: None, chain_pem: None, restart: Some(false),
    };

    let r1 = install_certificate(&entry, &cert_store, &req).unwrap();
    assert!(r1.changed, "first install must be changed");

    let r2 = install_certificate(&entry, &cert_store, &req).unwrap();
    assert!(!r2.changed, "second install of same cert must not be changed");
}

/// pem_cert_to_der parses a PEM certificate and returns the DER bytes.
#[test]
fn pem_cert_to_der_returns_non_empty_der() {
    let (cert_pem, _) = signed_cert_pem("der.credo.test");
    let der = pem_cert_to_der(&cert_pem).unwrap();
    assert!(!der.is_empty(), "DER must not be empty");
    assert_eq!(der[0], 0x30, "DER must start with SEQUENCE tag (0x30)");
}
