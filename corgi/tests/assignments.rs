/// Assignment merge tests — direct function calls, no HTTP.
/// Ports deprecated assignments.test.ts and covers production merge behavior.
use corgi::assignments::merge_assignments;
use corgi::config::{
    AuthConfig, AuthMode, FilePolicyConfig, FlockEntry, HttpChallengeConfig, LogLevel, MtlsConfig,
    ProxyAuthConfig, ShepherdSyncConfig, TlsConfig,
};
use corgi::types::ManagedAssignment;
use std::collections::HashMap;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_config(dir: &TempDir) -> corgi::config::CorgiConfig {
    corgi::config::CorgiConfig {
        node_id: "corgi-01".to_string(),
        common_name: "corgi-01.credo.test".to_string(),
        identity_uri: Some("vigil://credo/node/corgi-01".to_string()),
        shepherd_url: "http://127.0.0.1:0".to_string(),
        dns_override: HashMap::new(),
        tls: TlsConfig {
            cert_path: dir.path().join("tls.pem"),
            key_path: dir.path().join("tls.key"),
        },
        mtls: MtlsConfig {
            cert_path: dir.path().join("mtls.pem"),
            key_path: dir.path().join("mtls.key"),
            ca_path: None,
        },
        cert_store_dir: dir.path().join("certstore"),
        flock: vec![],
        http_challenge: HttpChallengeConfig {
            enabled: false,
            port: 0,
            bind: "127.0.0.1".to_string(),
        },
        mtls_port: 0,
        bind: "127.0.0.1".to_string(),
        service_hooks: HashMap::new(),
        default_hooks: vec![],
        log_level: LogLevel::Warn,
        auth: AuthConfig {
            mode: AuthMode::Mtls,
        },
        rbac_identities: vec![],
        proxy_auth: ProxyAuthConfig {
            client_cert_header: "X-Client-Cert".to_string(),
            client_fingerprint_header: "X-Client-Fingerprint".to_string(),
            client_subject_header: "X-Client-Subject".to_string(),
            client_san_uri_header: "X-Client-San-Uri".to_string(),
        },
        shepherd_sync: ShepherdSyncConfig {
            enabled: false,
            interval_seconds: 60,
            stale_warning_seconds: 300,
            assignments_cache_path: dir.path().join("assignments.json"),
        },
        config_path: dir.path().join("corgi.config.json"),
        accounts_path: dir.path().join("corgi.accounts.json"),
        chain_path: None,
        fullchain_path: None,
        csr_path: None,
        file_policy: FilePolicyConfig {
            owner: None,
            group: None,
            cert_mode: None,
            key_mode: None,
        },
        cert_hooks: HashMap::new(),
    }
}

fn base_entry(name: &str, dir: &TempDir) -> FlockEntry {
    FlockEntry {
        name: name.to_string(),
        path: dir.path().join(format!("{name}.cert.pem")),
        key_path: dir.path().join(format!("{name}.key.pem")),
        chain_path: None,
        fullchain_path: None,
        csr_path: None,
        domain: Some(format!("{name}.credo.test")),
        monitor: false,
        hooks: vec![],
        csr_subject: None,
        identity_uri: None,
        sans: vec![],
        cert_mode: None,
        key_mode: None,
        cert_owner: None,
        cert_group: None,
        key_owner: None,
        key_group: None,
    }
}

fn assignment(cert_name: &str) -> ManagedAssignment {
    ManagedAssignment {
        corgi: "corgi-01".to_string(),
        cert_name: cert_name.to_string(),
        fingerprint256: None,
        ca: None,
        issuer: None,
        renew_before_days: None,
        days: None,
        domain: None,
        identity_uri: None,
        monitor: None,
        hooks: vec![],
        csr_subject: None,
        sans: vec![],
        restart: None,
        cert_mode: None,
        key_mode: None,
        cert_owner: None,
        cert_group: None,
        key_owner: None,
        key_group: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// An assignment matching a config entry overrides domain but preserves config paths.
#[test]
fn assignment_overrides_domain_preserves_paths() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let config_flock = vec![base_entry("webapp", &dir)];

    let mut a = assignment("webapp");
    a.domain = Some("override.credo.test".to_string());

    let merged = merge_assignments(&config_flock, &[a], &config);

    assert_eq!(merged.len(), 1);
    assert_eq!(
        merged[0].domain.as_deref(),
        Some("override.credo.test"),
        "assignment domain must override config entry domain"
    );
    assert_eq!(
        merged[0].path,
        dir.path().join("webapp.cert.pem"),
        "path must remain from config entry"
    );
}

/// An assignment for an unknown cert creates a dynamic entry under certstore/live/.
#[test]
fn unknown_assignment_creates_dynamic_entry() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let config_flock: Vec<FlockEntry> = vec![];

    let mut a = assignment("new-cert");
    a.domain = Some("new.credo.test".to_string());

    let merged = merge_assignments(&config_flock, &[a], &config);

    assert_eq!(merged.len(), 1, "must create a dynamic entry");
    assert!(
        merged[0].path.starts_with(&config.cert_store_dir),
        "dynamic entry path must be under certstore: {:?}",
        merged[0].path
    );
}

/// SANs from the assignment are present in the merged entry.
#[test]
fn assignment_sans_appear_in_merged_entry() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let config_flock = vec![base_entry("san-test", &dir)];

    let mut a = assignment("san-test");
    a.sans = vec!["alt1.credo.test".to_string(), "alt2.credo.test".to_string()];

    let merged = merge_assignments(&config_flock, &[a], &config);

    assert!(
        merged[0].sans.contains(&"alt1.credo.test".to_string()),
        "alt1 must be present"
    );
    assert!(
        merged[0].sans.contains(&"alt2.credo.test".to_string()),
        "alt2 must be present"
    );
}

/// `identity_uri` from an assignment appears in the merged entry.
#[test]
fn assignment_identity_uri_preserved() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let config_flock = vec![base_entry("id-test", &dir)];

    let mut a = assignment("id-test");
    a.identity_uri = Some("vigil://credo/node/corgi-01".to_string());

    let merged = merge_assignments(&config_flock, &[a], &config);

    assert_eq!(
        merged[0].identity_uri.as_deref(),
        Some("vigil://credo/node/corgi-01")
    );
}

/// Config flock entries with no matching assignment are preserved unchanged.
#[test]
fn config_entries_without_assignments_preserved() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let config_flock = vec![
        base_entry("config-only", &dir),
        base_entry("has-assignment", &dir),
    ];

    let a = assignment("has-assignment");
    let merged = merge_assignments(&config_flock, &[a], &config);

    assert_eq!(merged.len(), 2, "both entries must be in result");
    assert!(
        merged.iter().any(|e| e.name == "config-only"),
        "config-only entry must be preserved"
    );
}

/// Multiple assignments are all merged; dynamic entries appear after config entries.
#[test]
fn multiple_assignments_all_merged() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let config_flock = vec![base_entry("existing", &dir)];

    let merged = merge_assignments(
        &config_flock,
        &[assignment("existing"), assignment("dynamic-new")],
        &config,
    );

    assert_eq!(merged.len(), 2);
}
