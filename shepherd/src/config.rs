use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use credo_lib::config::{
    load_json_config, resolve_path, resolve_path_opt, resolve_path_or, u16_from_env,
};

// ---------------------------------------------------------------------------
// Public config struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ShepherdConfig {
    pub config_path: PathBuf,
    pub base_dir: PathBuf,

    // Ports
    pub agent_port: u16,
    pub dashboard_port: u16,
    pub bind: String,

    // TLS (server cert + mTLS client CA)
    pub tls: TlsConfig,

    // JWT signing key
    pub jwt_signing_key_path: PathBuf,

    // Sub-config file paths
    pub corgis_config_path: PathBuf,
    pub assignments_config_path: PathBuf,
    pub ca_config_path: PathBuf,
    pub accounts_path: PathBuf,

    // Cert store
    pub cert_store_dir: PathBuf,

    // Timers
    pub renew_before_days: f64,
    pub poll_interval_seconds: u64,
    pub corgi_health_check_interval_seconds: u64,

    // Renewal jobs persistence (optional)
    pub renewal_jobs_dir: Option<PathBuf>,

    // Logging
    pub log_level: LogLevel,

    // DNS override for outbound Corgi connections
    pub dns_override: HashMap<String, String>,

    // Identity
    pub common_name: Option<String>,
    pub identity_uri: Option<String>,
    pub vigil_url: Option<String>,
    pub shepherd_ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub client_ca_path: PathBuf,
    /// Written by bootstrap; never inside the corgi certstore.
    pub bootstrap_cert_path: Option<PathBuf>,
    pub bootstrap_key_path:  Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Fatal,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_tracing_filter(self) -> &'static str {
        match self {
            LogLevel::Fatal => "error",
            LogLevel::Warn  => "warn",
            LogLevel::Info  => "info",
            LogLevel::Debug => "debug",
        }
    }
}

// ---------------------------------------------------------------------------
// Raw JSON deserialization (strict — deny_unknown_fields catches typos and
// removed fields; _prefixed keys are stripped before reaching serde)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawShepherdConfig {
    // Ports + bind
    agent_port: Option<u16>,
    dashboard_port: Option<u16>,
    bind: Option<String>,

    // TLS — nested format
    tls: Option<RawTls>,
    // TLS — backward-compat flat names (tlsCert, tlsKey, clientCa, tlsClientCaPath)
    tls_cert: Option<String>,
    tls_key: Option<String>,
    client_ca: Option<String>,
    tls_client_ca_path: Option<String>,

    // Auth
    auth: Option<RawAuth>,

    // Sub-config paths
    corgis_config_path: Option<String>,
    assignments_config_path: Option<String>,
    ca_config_path: Option<String>,
    accounts_path: Option<String>,

    // Cert store
    cert_store_dir: Option<String>,

    // Timers
    renew_before_days: Option<f64>,
    poll_interval_seconds: Option<u64>,
    corgi_health_check_interval_seconds: Option<u64>,

    // Renewal jobs
    renewal_jobs_dir: Option<String>,

    // Logging
    log_level: Option<String>,

    // DNS override
    dns_override: Option<HashMap<String, String>>,

    // Identity
    common_name: Option<String>,
    identity_uri: Option<String>,
    vigil_url: Option<String>,
    shepherd_ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawTls {
    cert_path: Option<String>,
    key_path: Option<String>,
    client_ca_path: Option<String>,
    // Compat names inside the tls block
    ca: Option<String>,
    ca_path: Option<String>,
    // Bootstrap cert written to shepherdRoot/bootstrap/, NOT to the corgi certstore
    bootstrap_cert_path: Option<String>,
    bootstrap_key_path:  Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuth {
    jwt_signing_key_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Load function
// ---------------------------------------------------------------------------

pub fn load_config() -> Result<ShepherdConfig> {
    let config_path = std::env::var("SHEPHERD_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("shepherd.config.json"));

    let mut raw_value = load_json_config(&config_path)
        .with_context(|| format!("Loading config: {}", config_path.display()))?;

    // Extract baseDir before handing to serde (deny_unknown_fields would reject it)
    let base_dir: PathBuf = raw_value
        .get("baseDir")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| config_path.parent().unwrap_or(Path::new(".")).to_path_buf());

    if let Some(obj) = raw_value.as_object_mut() {
        obj.remove("baseDir");
    }

    let raw: RawShepherdConfig = serde_json::from_value(raw_value)
        .map_err(|e| anyhow::anyhow!("Config error in {}: {}", config_path.display(), e))?;

    build_config(raw, base_dir, config_path)
}

// ---------------------------------------------------------------------------
// Build typed config from raw
// ---------------------------------------------------------------------------

fn build_config(raw: RawShepherdConfig, base_dir: PathBuf, config_path: PathBuf) -> Result<ShepherdConfig> {
    let b = base_dir.as_path();

    // --- TLS ---
    let tls_cert_path = raw.tls.as_ref().and_then(|t| t.cert_path.as_deref())
        .or(raw.tls_cert.as_deref())
        .ok_or_else(|| anyhow::anyhow!("Config missing tls.certPath"))?;

    let tls_key_path = raw.tls.as_ref().and_then(|t| t.key_path.as_deref())
        .or(raw.tls_key.as_deref())
        .ok_or_else(|| anyhow::anyhow!("Config missing tls.keyPath"))?;

    let client_ca_path = raw.tls.as_ref().and_then(|t| {
        t.client_ca_path.as_deref()
            .or(t.ca_path.as_deref())
            .or(t.ca.as_deref())
    })
    .or(raw.tls_client_ca_path.as_deref())
    .or(raw.client_ca.as_deref())
    .ok_or_else(|| anyhow::anyhow!(
        "Config missing tls.clientCaPath (required — mTLS client CA must be configured)"
    ))?;

    // --- Auth ---
    let jwt_signing_key_path = raw.auth.as_ref()
        .and_then(|a| a.jwt_signing_key_path.as_deref())
        .ok_or_else(|| anyhow::anyhow!("Config missing auth.jwtSigningKeyPath"))?;

    // --- Ports ---
    let agent_port = raw.agent_port
        .unwrap_or_else(|| u16_from_env("SHEPHERD_AGENT_PORT", 7010));
    let dashboard_port = raw.dashboard_port
        .unwrap_or_else(|| u16_from_env("SHEPHERD_DASHBOARD_PORT", 7011));
    let bind = raw.bind.unwrap_or_else(|| "127.0.0.1".to_string());

    // --- Log level ---
    let log_level = match raw.log_level.as_deref().unwrap_or("info") {
        "fatal" => LogLevel::Fatal,
        "warn"  => LogLevel::Warn,
        "debug" => LogLevel::Debug,
        _       => LogLevel::Info,
    };

    Ok(ShepherdConfig {
        config_path,
        base_dir: base_dir.clone(),
        agent_port,
        dashboard_port,
        bind,
        tls: TlsConfig {
            cert_path:      resolve_path(b, tls_cert_path),
            key_path:       resolve_path(b, tls_key_path),
            client_ca_path: resolve_path(b, client_ca_path),
            bootstrap_cert_path: raw.tls.as_ref()
                .and_then(|t| t.bootstrap_cert_path.as_deref())
                .map(|s| resolve_path(b, s)),
            bootstrap_key_path: raw.tls.as_ref()
                .and_then(|t| t.bootstrap_key_path.as_deref())
                .map(|s| resolve_path(b, s)),
        },
        jwt_signing_key_path: resolve_path(b, jwt_signing_key_path),
        corgis_config_path: resolve_path_or(b, raw.corgis_config_path.as_deref(), "shepherd.corgis.json"),
        assignments_config_path: resolve_path_or(b, raw.assignments_config_path.as_deref(), "shepherd.assignments.json"),
        ca_config_path: resolve_path_or(b, raw.ca_config_path.as_deref(), "shepherd.ca.json"),
        accounts_path: resolve_path_or(b, raw.accounts_path.as_deref(), "shepherd.accounts.json"),
        cert_store_dir: resolve_path_or(b, raw.cert_store_dir.as_deref(), "store"),
        renew_before_days: raw.renew_before_days.unwrap_or(7.0),
        poll_interval_seconds: raw.poll_interval_seconds.unwrap_or(60),
        corgi_health_check_interval_seconds: raw.corgi_health_check_interval_seconds.unwrap_or(300),
        renewal_jobs_dir: resolve_path_opt(b, raw.renewal_jobs_dir.as_deref()),
        log_level,
        dns_override: raw.dns_override.unwrap_or_default(),
        common_name: raw.common_name,
        identity_uri: raw.identity_uri,
        vigil_url: raw.vigil_url,
        shepherd_ca_path: resolve_path_opt(b, raw.shepherd_ca_path.as_deref()),
    })
}

// ---------------------------------------------------------------------------
// Validate that critical paths exist (used by check-config command)
// ---------------------------------------------------------------------------

pub fn validate_paths(config: &ShepherdConfig) -> Vec<(String, bool)> {
    let mut results = vec![];
    for (label, path) in [
        ("TLS cert", &config.tls.cert_path),
        ("TLS key", &config.tls.key_path),
        ("TLS client CA", &config.tls.client_ca_path),
        ("Accounts", &config.accounts_path),
        ("CA config", &config.ca_config_path),
    ] {
        results.push((format!("{}: {}", label, path.display()), path.exists()));
    }
    for (label, path) in [
        ("Corgis config", &config.corgis_config_path),
        ("Assignments config", &config.assignments_config_path),
    ] {
        results.push((format!("{}: {}", label, path.display()), path.exists()));
    }
    results
}
