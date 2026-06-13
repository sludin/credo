use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub client_ca_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub curve: String,
    pub cert_default_days: u32,
    pub crl_next_update_hours: u32,
    pub ocsp_max_age_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct IssuancePolicyConfig {
    pub allowed_dns_suffixes: Vec<String>,
    pub allow_subdomains: bool,
    pub allow_bare_suffix: bool,
    pub allowed_identity_uri_prefixes: Vec<String>,
    pub allow_ip_sans: bool,
}

#[derive(Debug, Clone)]
pub struct RbacIdentityConfig {
    pub uri: String,
    pub role: crate::types::Role,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VigilConfig {
    pub port: u16,
    pub bind: String,
    pub ca_dir: PathBuf,
    pub ca_key_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub ca_ecdsa_intermediate_key_path: PathBuf,
    pub ca_ecdsa_intermediate_cert_path: PathBuf,
    pub ca: CaConfig,
    pub users_db_path: PathBuf,
    pub cert_db_path: PathBuf,
    pub acme_accounts_db_path: PathBuf,
    pub certs_dir: PathBuf,
    pub ct_log_path: PathBuf,
    pub common_name: String,
    pub tls: TlsConfig,
    pub log_level: credo_lib::LogLevel,
    pub rbac_identities: Vec<RbacIdentityConfig>,
    pub issuance_policy: IssuancePolicyConfig,
    pub config_dir: PathBuf,
    /// Allow none-01 challenge auto-approval. Off by default; emit a startup warning when enabled.
    pub allow_none_validation: bool,
    /// Ports Vigil may contact for http-01 challenge validation. Default [80].
    /// Add non-privileged ports (e.g. 7080) to allow Corgi's challenge listener without a proxy.
    pub allowed_http_challenge_ports: Vec<u16>,
    /// How many times to poll for a challenge before declaring it invalid. Default 5.
    pub challenge_check_count: u32,
    /// Seconds between challenge polling attempts (after the first immediate check). Default 60.
    pub challenge_check_interval_secs: u64,
    /// Explicit recursive resolver IPs for http-01 validation and dns-01 NS lookups.
    /// Empty (default) means use the system resolver from /etc/resolv.conf.
    pub dns_resolver_addrs: Vec<std::net::IpAddr>,
}

// ---------------------------------------------------------------------------
// Raw JSON shape (all optional for forward-compat)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawTlsBlock {
    key_path: Option<String>,
    cert_path: Option<String>,
    client_ca_path: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawCaBlock {
    curve: Option<String>,
    cert_default_days: Option<u32>,
    crl_next_update_hours: Option<u32>,
    ocsp_max_age_seconds: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawIssuancePolicy {
    allowed_dns_suffixes: Option<Vec<String>>,
    allow_subdomains: Option<bool>,
    allow_bare_suffix: Option<bool>,
    allowed_identity_uri_prefixes: Option<Vec<String>>,
    allow_ip_sans: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawRbacIdentity {
    uri: Option<String>,
    role: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    vars: Option<serde_json::Value>,
    port: Option<u16>,
    bind: Option<String>,
    base_dir: Option<String>,
    ca_dir: Option<String>,
    ca_ecdsa_intermediate_key_path: Option<String>,
    ca_ecdsa_intermediate_cert_path: Option<String>,
    data_dir: Option<String>,
    users_db_path: Option<String>,
    cert_db_path: Option<String>,
    acme_accounts_db_path: Option<String>,
    certs_dir: Option<String>,
    ct_log_path: Option<String>,
    common_name: Option<String>,
    tls: Option<RawTlsBlock>,
    log_level: Option<String>,
    rbac_identities: Option<Vec<RawRbacIdentity>>,
    issuance_policy: Option<RawIssuancePolicy>,
    allow_none_validation: Option<bool>,
    allowed_http_challenge_ports: Option<Vec<u16>>,
    challenge_check_count: Option<u32>,
    challenge_check_interval_secs: Option<u64>,
    dns_resolver_addrs: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Config utilities — from credo-lib
// ---------------------------------------------------------------------------

use credo_lib::config::{load_json_config, resolve_path};

fn resolve(base: &Path, raw: Option<&str>, fallback: &str) -> PathBuf {
    resolve_path(base, raw.unwrap_or(fallback))
}

// ---------------------------------------------------------------------------
// Public loader
// ---------------------------------------------------------------------------

pub fn load_config() -> Result<VigilConfig> {
    let config_path = std::env::var("VIGIL_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("vigil.config.json")
        });

    let config_path = config_path.canonicalize().unwrap_or(config_path.clone());

    let processed = load_json_config(&config_path)
        .with_context(|| format!("Loading vigil config: {}", config_path.display()))?;

    let raw: RawConfig =
        serde_json::from_value(processed.clone()).context("Deserializing vigil config")?;

    let config_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let base_dir = raw
        .base_dir
        .as_deref()
        .map(|s| {
            let p = Path::new(s);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                config_dir.join(p)
            }
        })
        .unwrap_or_else(|| config_dir.clone());

    let data_dir = resolve(&base_dir, raw.data_dir.as_deref(), "./data");

    let ecdsa_key = resolve(
        &base_dir,
        raw.ca_ecdsa_intermediate_key_path.as_deref(),
        "./ca/int-ecdsa/private/int-ecdsa.key.pem",
    );
    let ecdsa_cert = resolve(
        &base_dir,
        raw.ca_ecdsa_intermediate_cert_path.as_deref(),
        "./ca/int-ecdsa/certs/int-ecdsa.cert.pem",
    );

    let tls_block = raw.tls.unwrap_or_default();
    let tls = TlsConfig {
        key_path: resolve(
            &base_dir,
            tls_block.key_path.as_deref(),
            "./certs/privkey.pem",
        ),
        cert_path: resolve(
            &base_dir,
            tls_block.cert_path.as_deref(),
            "./certs/fullchain.pem",
        ),
        client_ca_path: resolve(
            &base_dir,
            tls_block.client_ca_path.as_deref(),
            "./certs/root-ca.cert.pem",
        ),
    };

    let ca_config = {
        let raw_ca: RawCaBlock = processed
            .get("ca")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        CaConfig {
            curve: raw_ca.curve.unwrap_or_else(|| "P-384".to_string()),
            cert_default_days: raw_ca.cert_default_days.unwrap_or(365),
            crl_next_update_hours: raw_ca.crl_next_update_hours.unwrap_or(24),
            ocsp_max_age_seconds: raw_ca.ocsp_max_age_seconds.unwrap_or(60),
        }
    };

    let policy = {
        let pol: RawIssuancePolicy = raw.issuance_policy.unwrap_or_default();
        IssuancePolicyConfig {
            allowed_dns_suffixes: pol.allowed_dns_suffixes.unwrap_or_default(),
            allow_subdomains: pol.allow_subdomains.unwrap_or(true),
            allow_bare_suffix: pol.allow_bare_suffix.unwrap_or(true),
            allowed_identity_uri_prefixes: pol.allowed_identity_uri_prefixes.unwrap_or_default(),
            allow_ip_sans: pol.allow_ip_sans.unwrap_or(false),
        }
    };

    let rbac_identities = raw
        .rbac_identities
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, entry)| {
            let uri = entry
                .uri
                .filter(|s| !s.trim().is_empty())
                .with_context(|| format!("rbacIdentities[{}].uri must be a non-empty string", i))?;
            Ok(RbacIdentityConfig {
                uri: uri.trim().to_string(),
                role: crate::types::Role::from_str(entry.role.as_deref().unwrap_or("admin")),
                name: entry.name.filter(|s| !s.trim().is_empty()),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let log_level =
        credo_lib::LogLevel::from_str(raw.log_level.as_deref().unwrap_or("info").trim());

    // Apply env-var overrides for CA paths (set by run-with-config-ca.sh)
    let ca_key_path = std::env::var("VIGIL_CA_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| ecdsa_key.clone());
    let ca_cert_path = std::env::var("VIGIL_CA_CERT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| ecdsa_cert.clone());

    Ok(VigilConfig {
        port: raw.port.unwrap_or(7020),
        bind: raw.bind.unwrap_or_else(|| "127.0.0.1".to_string()),
        ca_dir: resolve(&base_dir, raw.ca_dir.as_deref(), "./ca"),
        ca_key_path,
        ca_cert_path,
        ca_ecdsa_intermediate_key_path: ecdsa_key,
        ca_ecdsa_intermediate_cert_path: ecdsa_cert,
        ca: ca_config,
        users_db_path: resolve(&data_dir, raw.users_db_path.as_deref(), "users.json"),
        cert_db_path: resolve(&data_dir, raw.cert_db_path.as_deref(), "certificates.json"),
        acme_accounts_db_path: resolve(
            &data_dir,
            raw.acme_accounts_db_path.as_deref(),
            "acme-accounts.json",
        ),
        certs_dir: resolve(&data_dir, raw.certs_dir.as_deref(), "certs"),
        ct_log_path: resolve(&base_dir, raw.ct_log_path.as_deref(), "./logs/ct.log"),
        common_name: raw.common_name.unwrap_or_default(),
        tls,
        log_level,
        rbac_identities,
        issuance_policy: policy,
        config_dir,
        allow_none_validation: raw.allow_none_validation.unwrap_or(false),
        allowed_http_challenge_ports: raw.allowed_http_challenge_ports.unwrap_or_else(|| vec![80]),
        challenge_check_count: raw.challenge_check_count.unwrap_or(5),
        challenge_check_interval_secs: raw.challenge_check_interval_secs.unwrap_or(60),
        dns_resolver_addrs: raw
            .dns_resolver_addrs
            .unwrap_or_default()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
    })
}
