use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::types::{CsrSubjectWire, HookRef};

// ---------------------------------------------------------------------------
// Hook definitions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HookArgSpec {
    pub kind: HookArgType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HookArgType {
    ContainerName,
    Hostname,
    Signal,
    ServiceName,
    Identifier,
}

impl HookArgType {
    pub fn pattern(&self) -> &'static str {
        match self {
            HookArgType::ContainerName => r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$",
            HookArgType::Hostname => r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$",
            HookArgType::Signal => r"^[A-Z]{2,10}$",
            HookArgType::ServiceName => r"^[a-zA-Z0-9][a-zA-Z0-9@:._-]{0,253}$",
            HookArgType::Identifier => r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$",
        }
    }
}

impl std::str::FromStr for HookArgType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "container-name" => Ok(HookArgType::ContainerName),
            "hostname" => Ok(HookArgType::Hostname),
            "signal" => Ok(HookArgType::Signal),
            "service-name" => Ok(HookArgType::ServiceName),
            "identifier" => Ok(HookArgType::Identifier),
            _ => Err(anyhow::anyhow!("Unknown hook arg type: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServiceHookDef {
    Simple(Vec<String>),
    Parameterized {
        exec: Vec<String>,
        args: HashMap<String, HookArgSpec>,
    },
}

// ---------------------------------------------------------------------------
// File policy config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct FilePolicyConfig {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub cert_mode: Option<u32>,
    pub key_mode: Option<u32>,
}

// ---------------------------------------------------------------------------
// Flock certificate config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FlockEntry {
    pub name: String,
    pub path: PathBuf,
    pub key_path: PathBuf,
    pub chain_path: Option<PathBuf>,
    pub fullchain_path: Option<PathBuf>,
    pub csr_path: Option<PathBuf>,
    pub domain: Option<String>,
    pub monitor: bool,
    /// None = inherit defaultHooks at runtime. Some([]) = no hooks. Some([refs]) = use exactly these.
    pub hooks: Option<Vec<HookRef>>,
    pub csr_subject: Option<CsrSubjectWire>,
    pub identity_uri: Option<String>,
    pub sans: Vec<String>,
    pub cert_mode: Option<u32>,
    pub key_mode: Option<u32>,
    pub cert_owner: Option<String>,
    pub cert_group: Option<String>,
    pub key_owner: Option<String>,
    pub key_group: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum AuthMode {
    Mtls,
    ProxyHeaders,
}

#[derive(Debug, Clone)]
pub struct RbacIdentity {
    pub uri: String,
    pub role: crate::types::Role,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProxyAuthConfig {
    pub client_cert_header: String,
    pub client_fingerprint_header: String,
    pub client_subject_header: String,
    pub client_san_uri_header: String,
}

// ---------------------------------------------------------------------------
// Shepherd sync config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ShepherdSyncConfig {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub stale_warning_seconds: u64,
    pub assignments_cache_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Main config struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CorgiConfig {
    pub node_id: String,
    pub common_name: String,
    pub identity_uri: Option<String>,
    pub shepherd_url: String,
    pub dns_override: HashMap<String, String>,
    pub tls: TlsConfig,
    pub mtls: MtlsConfig,
    pub cert_store_dir: PathBuf,
    pub flock: Vec<FlockEntry>,
    pub http_challenge: HttpChallengeConfig,
    pub mtls_port: u16,
    pub bind: String,
    pub service_hooks: HashMap<String, ServiceHookDef>,
    pub default_hooks: Vec<HookRef>,
    pub log_level: LogLevel,
    pub auth: AuthConfig,
    pub rbac_identities: Vec<RbacIdentity>,
    pub proxy_auth: ProxyAuthConfig,
    pub shepherd_sync: ShepherdSyncConfig,
    pub config_path: PathBuf,
    pub accounts_path: PathBuf,
    pub chain_path: Option<PathBuf>,
    pub fullchain_path: Option<PathBuf>,
    pub csr_path: Option<PathBuf>,
    pub file_policy: FilePolicyConfig,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct MtlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct HttpChallengeConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind: String,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Fatal,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_tracing_filter(&self) -> &'static str {
        match self {
            LogLevel::Fatal => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

// ---------------------------------------------------------------------------
// Raw JSON shape for deserialization (permissive)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    vars: serde_json::Map<String, Value>,
    #[serde(default)]
    includes: Vec<String>,
    node_id: Option<String>,
    #[serde(rename = "nodeId")]
    node_id2: Option<String>,
    common_name: Option<String>,
    #[serde(rename = "commonName")]
    common_name2: Option<String>,
    #[serde(rename = "identityUri")]
    identity_uri: Option<String>,
    #[serde(rename = "shepherdUrl")]
    shepherd_url: Option<String>,
    #[serde(rename = "dnsOverride")]
    dns_override: Option<Value>,
    #[serde(rename = "baseDir")]
    base_dir: Option<String>,

    // TLS (new structured)
    tls: Option<RawTls>,
    // TLS legacy flat
    #[serde(rename = "tlsCert")]
    tls_cert: Option<String>,
    #[serde(rename = "tlsKey")]
    tls_key: Option<String>,

    // mTLS outbound (new structured)
    mtls: Option<RawMtls>,
    // mTLS outbound legacy flat
    #[serde(rename = "shepherdClientCert")]
    shepherd_client_cert: Option<String>,
    #[serde(rename = "shepherdClientKey")]
    shepherd_client_key: Option<String>,
    #[serde(rename = "shepherdClientCa")]
    shepherd_client_ca: Option<String>,

    #[serde(default)]
    flock: Vec<Value>,

    #[serde(rename = "httpChallenge")]
    http_challenge: Option<Value>,
    #[serde(rename = "httpChallengePort")]
    http_challenge_port: Option<u16>,

    #[serde(rename = "mtlsPort")]
    mtls_port: Option<u16>,
    bind: Option<String>,

    #[serde(rename = "serviceHooks", default)]
    service_hooks: serde_json::Map<String, Value>,

    #[serde(rename = "defaultHooks", default)]
    default_hooks: Vec<Value>,

    #[serde(rename = "logLevel")]
    log_level: Option<String>,

    auth: Option<RawAuth>,
    #[serde(rename = "authMode")]
    auth_mode: Option<String>,

    #[serde(rename = "rbacIdentities", default)]
    rbac_identities: Vec<Value>,

    #[serde(rename = "proxyAuth")]
    proxy_auth: Option<RawProxyAuth>,

    #[serde(rename = "shepherdSync")]
    shepherd_sync: Option<RawShepherdSync>,

    #[serde(rename = "accountsPath")]
    accounts_path: Option<String>,
    #[serde(rename = "certStoreDir")]
    cert_store_dir: Option<String>,
    #[serde(rename = "certDir")]
    cert_dir: Option<String>,

    #[serde(rename = "chainPath")]
    chain_path: Option<String>,
    #[serde(rename = "fullchainPath")]
    fullchain_path: Option<String>,
    #[serde(rename = "csrPath")]
    csr_path: Option<String>,

    #[serde(rename = "filePolicy")]
    file_policy: Option<RawFilePolicy>,
}

#[derive(Debug, Deserialize, Default)]
struct RawFilePolicy {
    owner: Option<String>,
    group: Option<String>,
    #[serde(rename = "certMode")]
    cert_mode: Option<String>,
    #[serde(rename = "keyMode")]
    key_mode: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawTls {
    #[serde(rename = "certPath")]
    cert_path: Option<String>,
    #[serde(rename = "keyPath")]
    key_path: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawMtls {
    #[serde(rename = "certPath")]
    cert_path: Option<String>,
    #[serde(rename = "keyPath")]
    key_path: Option<String>,
    #[serde(rename = "caPath")]
    ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAuth {
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawProxyAuth {
    #[serde(rename = "clientCertHeader")]
    client_cert_header: Option<String>,
    #[serde(rename = "clientFingerprintHeader")]
    client_fingerprint_header: Option<String>,
    #[serde(rename = "clientSubjectHeader")]
    client_subject_header: Option<String>,
    #[serde(rename = "clientSanUriHeader")]
    client_san_uri_header: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawShepherdSync {
    enabled: Option<Value>,
    #[serde(rename = "intervalSeconds")]
    interval_seconds: Option<Value>,
    #[serde(rename = "staleWarningSeconds")]
    stale_warning_seconds: Option<Value>,
    #[serde(rename = "assignmentsCachePath")]
    assignments_cache_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Config utilities — from credo-lib
// ---------------------------------------------------------------------------

use credo_lib::config::{
    bool_from_env, bool_from_value, load_json_config, resolve_path, str_from_env, u16_from_env,
    u64_from_env, u64_from_value,
};

fn parse_mode(s: &str) -> Option<u32> {
    credo_lib::file_policy::parse_mode_octal(s).ok()
}

fn parse_hook_refs(raw: &[Value]) -> Vec<HookRef> {
    raw.iter()
        .filter_map(|v| match v {
            Value::String(s) if !s.trim().is_empty() => Some(HookRef::Simple(s.trim().to_string())),
            Value::Object(obj) => {
                let name = obj.get("name")?.as_str()?.trim().to_string();
                if name.is_empty() {
                    return None;
                }
                let args = obj
                    .get("args")
                    .and_then(|a| a.as_object())
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| {
                                v.as_str().map(|s| (k.trim().to_string(), s.to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(HookRef::Parameterized { name, args })
            }
            _ => None,
        })
        .collect()
}

fn parse_hook_def(value: &Value, name: &str) -> Result<ServiceHookDef> {
    if let Some(arr) = value.as_array() {
        let commands: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        if commands.is_empty() {
            return Err(anyhow::anyhow!(
                "serviceHooks['{}'] is an empty array",
                name
            ));
        }
        return Ok(ServiceHookDef::Simple(commands));
    }

    if let Some(obj) = value.as_object() {
        let exec = obj
            .get("exec")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("serviceHooks['{}'].exec must be an array", name))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>();

        if exec.is_empty() {
            return Err(anyhow::anyhow!(
                "serviceHooks['{}'].exec must not be empty",
                name
            ));
        }

        let mut args: HashMap<String, HookArgSpec> = HashMap::new();
        if let Some(args_obj) = obj.get("args").and_then(|v| v.as_object()) {
            for (arg_name, spec_val) in args_obj {
                let kind_str = spec_val
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let kind: HookArgType = kind_str.parse().with_context(|| {
                    format!("serviceHooks['{}'].args['{}'].type", name, arg_name)
                })?;
                args.insert(arg_name.clone(), HookArgSpec { kind });
            }
        }

        return Ok(ServiceHookDef::Parameterized { exec, args });
    }

    Err(anyhow::anyhow!(
        "serviceHooks['{}'] must be an array (simple) or object with exec (parameterized)",
        name
    ))
}

fn parse_role(v: &Value) -> crate::types::Role {
    match v.as_str().unwrap_or("admin").trim().to_lowercase().as_str() {
        "operator" => crate::types::Role::Operator,
        "readonly" => crate::types::Role::Readonly,
        _ => crate::types::Role::Admin,
    }
}

fn parse_flock_entry(
    v: &Value,
    base_dir: &Path,
    cert_store_dir: &Path,
    index: usize,
    file_policy: &FilePolicyConfig,
) -> Result<FlockEntry> {
    let name = v["name"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .with_context(|| format!("flock[{}].name must be a non-empty string", index))?;

    let path = v["path"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(|s| resolve_path(base_dir, s))
        .unwrap_or_else(|| {
            cert_store_dir
                .join("live")
                .join(&name)
                .join("fullchain.pem")
        });

    let key_path = v["keyPath"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(|s| resolve_path(base_dir, s))
        .unwrap_or_else(|| cert_store_dir.join("live").join(&name).join("privkey.pem"));

    let hooks = v
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|arr| parse_hook_refs(arr));

    let csr_subject: Option<CsrSubjectWire> = v
        .get("csrSubject")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    Ok(FlockEntry {
        name,
        path,
        key_path,
        chain_path: v["chainPath"].as_str().map(|s| resolve_path(base_dir, s)),
        fullchain_path: v["fullchainPath"]
            .as_str()
            .map(|s| resolve_path(base_dir, s)),
        csr_path: v["csrPath"].as_str().map(|s| resolve_path(base_dir, s)),
        domain: v["domain"].as_str().map(|s| s.trim().to_string()),
        monitor: v["monitor"].as_bool().unwrap_or(true),
        hooks,
        csr_subject,
        identity_uri: v["identityUri"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        sans: v["sans"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        cert_mode: v["certMode"]
            .as_str()
            .and_then(parse_mode)
            .or(file_policy.cert_mode),
        key_mode: v["keyMode"]
            .as_str()
            .and_then(parse_mode)
            .or(file_policy.key_mode),
        cert_owner: v["certOwner"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| file_policy.owner.clone()),
        cert_group: v["certGroup"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| file_policy.group.clone()),
        key_owner: v["keyOwner"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| file_policy.owner.clone()),
        key_group: v["keyGroup"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| file_policy.group.clone()),
    })
}

// ---------------------------------------------------------------------------
// Main load function
// ---------------------------------------------------------------------------

pub fn load_config() -> Result<CorgiConfig> {
    let config_path = env::var("CORGI_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("corgi.config.json"));

    let config_path = config_path
        .canonicalize()
        .with_context(|| format!("Config file not found: {}", config_path.display()))?;

    let raw_value = load_json_config(&config_path)
        .with_context(|| format!("Loading config: {}", config_path.display()))?;

    let raw: RawConfig =
        serde_json::from_value(raw_value).with_context(|| "Deserializing config")?;

    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let base_dir = raw
        .base_dir
        .as_deref()
        .map(|d| resolve_path(config_dir, d))
        .unwrap_or_else(|| config_dir.to_path_buf());

    // node_id supports both camelCase and snake_case keys
    let node_id = raw
        .node_id2
        .or(raw.node_id)
        .filter(|s| !s.trim().is_empty())
        .with_context(|| "Config field 'nodeId' must be a non-empty string")?;

    let common_name = raw
        .common_name2
        .or(raw.common_name)
        .filter(|s| !s.trim().is_empty())
        .with_context(|| "Config field 'commonName' must be a non-empty string")?;

    let shepherd_url = raw
        .shepherd_url
        .filter(|s| !s.trim().is_empty())
        .with_context(|| "Config field 'shepherdUrl' must be a non-empty string")?;

    // certStoreDir (new) or certDir (legacy)
    let cert_store_dir_str = raw
        .cert_store_dir
        .or(raw.cert_dir)
        .unwrap_or_else(|| "./store".to_string());
    let cert_store_dir = resolve_path(&base_dir, &cert_store_dir_str);

    // tls paths
    let tls_cert = raw
        .tls
        .as_ref()
        .and_then(|t| t.cert_path.as_deref())
        .or(raw.tls_cert.as_deref())
        .map(|p| resolve_path(&base_dir, p))
        .unwrap_or_else(|| {
            cert_store_dir
                .join("live")
                .join(&common_name)
                .join("fullchain.pem")
        });

    let tls_key = raw
        .tls
        .as_ref()
        .and_then(|t| t.key_path.as_deref())
        .or(raw.tls_key.as_deref())
        .map(|p| resolve_path(&base_dir, p))
        .unwrap_or_else(|| {
            cert_store_dir
                .join("live")
                .join(&common_name)
                .join("privkey.pem")
        });

    // mtls outbound paths (new block or legacy shepherdClient* fields)
    let mtls_cert = raw
        .mtls
        .as_ref()
        .and_then(|m| m.cert_path.as_deref())
        .or(raw.shepherd_client_cert.as_deref())
        .map(|p| resolve_path(&base_dir, p))
        .unwrap_or_else(|| tls_cert.clone());

    let mtls_key = raw
        .mtls
        .as_ref()
        .and_then(|m| m.key_path.as_deref())
        .or(raw.shepherd_client_key.as_deref())
        .map(|p| resolve_path(&base_dir, p))
        .unwrap_or_else(|| tls_key.clone());

    let mtls_ca = raw
        .mtls
        .as_ref()
        .and_then(|m| m.ca_path.as_deref())
        .or(raw.shepherd_client_ca.as_deref())
        .map(|p| resolve_path(&base_dir, p));

    // File policy defaults
    let file_policy = FilePolicyConfig {
        owner: raw
            .file_policy
            .as_ref()
            .and_then(|p| p.owner.clone())
            .filter(|s| !s.trim().is_empty()),
        group: raw
            .file_policy
            .as_ref()
            .and_then(|p| p.group.clone())
            .filter(|s| !s.trim().is_empty()),
        cert_mode: raw
            .file_policy
            .as_ref()
            .and_then(|p| p.cert_mode.as_deref())
            .and_then(parse_mode),
        key_mode: raw
            .file_policy
            .as_ref()
            .and_then(|p| p.key_mode.as_deref())
            .and_then(parse_mode),
    };

    // Parse defaultHooks early so flock entries can inherit them
    let default_hooks = parse_hook_refs(&raw.default_hooks);

    // Flock entries
    let flock: Vec<FlockEntry> = raw
        .flock
        .iter()
        .enumerate()
        .map(|(i, v)| parse_flock_entry(v, &base_dir, &cert_store_dir, i, &file_policy))
        .collect::<Result<Vec<_>>>()?;

    // Service hooks
    let mut service_hooks = HashMap::new();
    for (name, val) in &raw.service_hooks {
        service_hooks.insert(name.clone(), parse_hook_def(val, name)?);
    }

    // HTTP challenge
    let http_challenge = {
        let section = raw.http_challenge.as_ref();
        let legacy_port = raw.http_challenge_port;
        let default_enabled = section.is_some() || legacy_port.is_some();
        let default_port = section
            .and_then(|v| v["port"].as_u64())
            .map(|p| p as u16)
            .or(legacy_port)
            .unwrap_or(7080);
        let default_bind = section
            .and_then(|v| v["bind"].as_str())
            .unwrap_or("0.0.0.0")
            .to_string();
        HttpChallengeConfig {
            enabled: bool_from_env("CORGI_HTTP_CHALLENGE_ENABLED", default_enabled),
            port: u16_from_env("CORGI_HTTP_CHALLENGE_PORT", default_port),
            bind: env::var("CORGI_HTTP_CHALLENGE_BIND").unwrap_or(default_bind),
        }
    };

    // Auth mode
    let auth_mode_str = env::var("CORGI_AUTH_MODE").ok().or_else(|| {
        raw.auth
            .as_ref()
            .and_then(|a| a.mode.clone())
            .or(raw.auth_mode.clone())
    });
    let auth_mode = match auth_mode_str.as_deref() {
        Some("proxy-headers") => AuthMode::ProxyHeaders,
        _ => AuthMode::Mtls,
    };

    // RBAC identities
    let rbac_identities: Vec<RbacIdentity> = raw
        .rbac_identities
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            let uri = v["uri"].as_str()?.trim().to_string();
            if uri.is_empty() {
                tracing::warn!("rbacIdentities[{}].uri is empty; skipping", i);
                return None;
            }
            let role = parse_role(&v["role"]);
            let name = v["name"].as_str().map(|s| s.trim().to_string());
            Some(RbacIdentity { uri, role, name })
        })
        .collect();

    // Proxy auth headers
    let pa = raw.proxy_auth.as_ref();
    let proxy_auth = ProxyAuthConfig {
        client_cert_header: str_from_env(
            "CORGI_PROXY_CLIENT_CERT_HEADER",
            pa.and_then(|p| p.client_cert_header.as_deref())
                .unwrap_or("x-corgi-client-cert"),
        )
        .to_lowercase(),
        client_fingerprint_header: str_from_env(
            "CORGI_PROXY_CLIENT_FINGERPRINT_HEADER",
            pa.and_then(|p| p.client_fingerprint_header.as_deref())
                .unwrap_or("x-corgi-client-fingerprint256"),
        )
        .to_lowercase(),
        client_subject_header: str_from_env(
            "CORGI_PROXY_CLIENT_SUBJECT_HEADER",
            pa.and_then(|p| p.client_subject_header.as_deref())
                .unwrap_or("x-corgi-client-subject"),
        )
        .to_lowercase(),
        client_san_uri_header: str_from_env(
            "CORGI_PROXY_CLIENT_SAN_URI_HEADER",
            pa.and_then(|p| p.client_san_uri_header.as_deref())
                .unwrap_or("x-corgi-san-uri"),
        )
        .to_lowercase(),
    };

    // Shepherd sync
    let ss = raw.shepherd_sync.as_ref();
    let assignments_cache_path = env::var("CORGI_SHEPHERD_ASSIGNMENTS_CACHE_PATH")
        .map(|p| resolve_path(&base_dir, &p))
        .or_else(|_| {
            Ok::<_, anyhow::Error>(
                ss.and_then(|s| s.assignments_cache_path.as_deref())
                    .map(|p| resolve_path(&base_dir, p))
                    .unwrap_or_else(|| resolve_path(&base_dir, "corgi.assignments.cache.json")),
            )
        })?;

    let shepherd_sync = ShepherdSyncConfig {
        enabled: bool_from_env(
            "CORGI_SHEPHERD_SYNC_ENABLED",
            ss.and_then(|s| s.enabled.as_ref())
                .map(|v| bool_from_value(v, true))
                .unwrap_or(true),
        ),
        interval_seconds: u64_from_env(
            "CORGI_SHEPHERD_SYNC_INTERVAL_SECONDS",
            ss.and_then(|s| s.interval_seconds.as_ref())
                .map(|v| u64_from_value(v, 60))
                .unwrap_or(60),
        ),
        stale_warning_seconds: u64_from_env(
            "CORGI_SHEPHERD_SYNC_STALE_WARNING_SECONDS",
            ss.and_then(|s| s.stale_warning_seconds.as_ref())
                .map(|v| u64_from_value(v, 300))
                .unwrap_or(300),
        ),
        assignments_cache_path,
    };

    // Log level
    let log_level_str = str_from_env(
        "CORGI_LOG_LEVEL",
        raw.log_level.as_deref().unwrap_or("info"),
    );
    let log_level = match log_level_str.to_lowercase().as_str() {
        "fatal" => LogLevel::Fatal,
        "warn" => LogLevel::Warn,
        "debug" => LogLevel::Debug,
        _ => LogLevel::Info,
    };

    // Ports
    let mtls_port = env::var("CORGI_MTLS_PORT")
        .or_else(|_| env::var("PORT"))
        .ok()
        .and_then(|s| s.parse().ok())
        .or(raw.mtls_port)
        .unwrap_or(7001);

    let bind = env::var("BIND")
        .or_else(|_| env::var("CORGI_BIND"))
        .ok()
        .or(raw.bind)
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let dns_override: HashMap<String, String> = raw
        .dns_override
        .as_ref()
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // Default node identity paths
    let chain_path = raw
        .chain_path
        .map(|p| resolve_path(&base_dir, &p))
        .or_else(|| {
            Some(
                cert_store_dir
                    .join("live")
                    .join(&common_name)
                    .join("chain.pem"),
            )
        });
    let fullchain_path = raw
        .fullchain_path
        .map(|p| resolve_path(&base_dir, &p))
        .or_else(|| {
            Some(
                cert_store_dir
                    .join("live")
                    .join(&common_name)
                    .join("fullchain.pem"),
            )
        });
    let csr_path = raw
        .csr_path
        .map(|p| resolve_path(&base_dir, &p))
        .or_else(|| {
            Some(
                cert_store_dir
                    .join("live")
                    .join(&common_name)
                    .join("csr.pem"),
            )
        });

    let accounts_path = raw
        .accounts_path
        .map(|p| resolve_path(&base_dir, &p))
        .unwrap_or_else(|| base_dir.join("corgi.fleet-accounts.json"));

    Ok(CorgiConfig {
        node_id,
        common_name,
        identity_uri: raw.identity_uri,
        shepherd_url,
        dns_override,
        tls: TlsConfig {
            cert_path: tls_cert,
            key_path: tls_key,
        },
        mtls: MtlsConfig {
            cert_path: mtls_cert,
            key_path: mtls_key,
            ca_path: mtls_ca,
        },
        cert_store_dir,
        flock,
        http_challenge,
        mtls_port,
        bind,
        service_hooks,
        default_hooks,
        log_level,
        auth: AuthConfig { mode: auth_mode },
        rbac_identities,
        proxy_auth,
        shepherd_sync,
        config_path,
        accounts_path,
        chain_path,
        fullchain_path,
        csr_path,
        file_policy,
    })
}
