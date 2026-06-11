use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::acme_client::AcmeAccountCache;
use crate::config::ShepherdConfig;
use crate::corgi_client::CorgiClientPool;
use crate::jwt::JwtKeys;
use crate::refresh_tokens::RefreshTokenStore;
use crate::types::{
    Account, CaConfig, CorgiNodeConfig, CorgiNodeState, ManagedAssignment, RenewalJob,
};

#[derive(Clone)]
pub struct AppState {
    /// Main config — hot-swappable on SIGHUP via ArcSwap (lock-free reads).
    pub config: Arc<ArcSwap<ShepherdConfig>>,
    pub jwt_keys: Arc<JwtKeys>,
    pub corgi_state: Arc<RwLock<HashMap<String, CorgiNodeState>>>,
    pub renewal_jobs: Arc<RwLock<HashMap<Uuid, RenewalJob>>>,
    pub accounts: Arc<RwLock<Vec<Account>>>,
    pub refresh_tokens: Arc<RefreshTokenStore>,
    pub assignments: Arc<RwLock<Vec<ManagedAssignment>>>,
    pub corgis: Arc<RwLock<Vec<CorgiNodeConfig>>>,
    /// Loaded CA configs keyed by CA name — hot-reloaded on mtime change.
    pub cas: Arc<RwLock<HashMap<String, CaConfig>>>,
    /// Last-seen mtimes for hot-reload detection
    pub corgis_mtime: Arc<Mutex<Option<SystemTime>>>,
    pub assignments_mtime: Arc<Mutex<Option<SystemTime>>>,
    pub accounts_mtime: Arc<Mutex<Option<SystemTime>>>,
    pub ca_mtime: Arc<Mutex<Option<SystemTime>>>,
    /// Per-corgi mTLS reqwest client pool (keyed by corgi name)
    pub corgi_client_pool: Arc<RwLock<CorgiClientPool>>,
    /// ACME account cache (avoids re-creating accounts on each renewal)
    pub acme_accounts: AcmeAccountCache,
    /// In-progress issuance deduplication: key = "{ca}:{cert_name}"
    pub in_progress: Arc<Mutex<HashMap<String, Weak<Notify>>>>,
    /// mTLS client for proxying admin requests to Vigil (None if vigilUrl not configured)
    pub vigil_client: Arc<RwLock<Option<reqwest::Client>>>,
    /// One-time admin token for bootstrap API endpoints (None in normal mode)
    pub bootstrap_admin_token: Arc<Mutex<Option<String>>>,
}

impl AppState {
    /// `cert_pem` / `key_pem`: shepherd's own cert+key as in-memory PEM strings.
    /// Provided during bootstrap so the vigil client can be built without reading disk.
    /// `admin_token`: one-time bootstrap token stored for the bootstrap API endpoints.
    pub fn new(
        config: ShepherdConfig,
        jwt_keys: JwtKeys,
        accounts: Vec<Account>,
        cas: HashMap<String, CaConfig>,
        cert_pem: Option<String>,
        key_pem: Option<String>,
        admin_token: Option<String>,
    ) -> Self {
        let refresh_token_path = config
            .renewal_jobs_dir
            .as_ref()
            .map(|d| d.join("refresh-tokens.json"))
            .or_else(|| {
                // Default alongside the assignments config so tokens survive restarts
                // even when renewalJobsDir is not configured.
                config
                    .assignments_config_path
                    .parent()
                    .map(|p| p.join("shepherd-refresh-tokens.json"))
            });

        let vigil_client = if config.vigil_url.is_some() {
            match build_vigil_client(&config, &cas, cert_pem.as_deref(), key_pem.as_deref()) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!("Failed to build Vigil client: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            jwt_keys: Arc::new(jwt_keys),
            corgi_state: Arc::new(RwLock::new(HashMap::new())),
            renewal_jobs: Arc::new(RwLock::new(HashMap::new())),
            accounts: Arc::new(RwLock::new(accounts)),
            refresh_tokens: Arc::new(RefreshTokenStore::new(refresh_token_path)),
            assignments: Arc::new(RwLock::new(vec![])),
            corgis: Arc::new(RwLock::new(vec![])),
            cas: Arc::new(RwLock::new(cas)),
            corgis_mtime: Arc::new(Mutex::new(None)),
            assignments_mtime: Arc::new(Mutex::new(None)),
            accounts_mtime: Arc::new(Mutex::new(None)),
            ca_mtime: Arc::new(Mutex::new(None)),
            corgi_client_pool: Arc::new(RwLock::new(
                match (cert_pem.as_deref(), key_pem.as_deref()) {
                    (Some(c), Some(k)) => CorgiClientPool::with_bootstrap_identity(c, k),
                    _ => CorgiClientPool::new(),
                },
            )),
            acme_accounts: match (cert_pem.as_deref(), key_pem.as_deref()) {
                (Some(c), Some(k)) => AcmeAccountCache::with_identity(c, k),
                _ => AcmeAccountCache::new(),
            },
            in_progress: Arc::new(Mutex::new(HashMap::new())),
            vigil_client: Arc::new(RwLock::new(vigil_client)),
            bootstrap_admin_token: Arc::new(Mutex::new(admin_token)),
        }
    }
}

/// Build the Vigil mTLS reqwest client.
/// Uses in-memory PEM strings when provided (bootstrap mode); falls back to disk paths.
fn build_vigil_client(
    config: &ShepherdConfig,
    cas: &HashMap<String, CaConfig>,
    cert_pem: Option<&str>,
    key_pem: Option<&str>,
) -> anyhow::Result<reqwest::Client> {
    let vigil_ca = cas
        .values()
        .find(|ca| ca.provider == "vigil" && ca.protocol == "acme");
    let insecure = vigil_ca
        .map(|ca| ca.config.insecure_skip_verify)
        .unwrap_or(false);

    // Cert + key: prefer in-memory PEM (bootstrap mode), else read from disk.
    let identity_pem: Vec<u8> = if let (Some(c), Some(k)) = (cert_pem, key_pem) {
        let mut v = c.as_bytes().to_vec();
        v.extend_from_slice(k.as_bytes());
        v
    } else {
        let cert_path = vigil_ca
            .and_then(|ca| ca.config.tls.as_ref()?.cert_path.clone())
            .unwrap_or_else(|| config.tls.cert_path.clone());
        let key_path = vigil_ca
            .and_then(|ca| ca.config.tls.as_ref()?.key_path.clone())
            .unwrap_or_else(|| config.tls.key_path.clone());
        let mut v = std::fs::read(&cert_path).map_err(|e| {
            anyhow::anyhow!("Reading Vigil client cert {}: {}", cert_path.display(), e)
        })?;
        v.extend_from_slice(&std::fs::read(&key_path).map_err(|e| {
            anyhow::anyhow!("Reading Vigil client key {}: {}", key_path.display(), e)
        })?);
        v
    };

    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|e| anyhow::anyhow!("Building Vigil mTLS identity: {}", e))?;

    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .identity(identity);

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        let ca_path = vigil_ca
            .and_then(|ca| ca.config.tls.as_ref()?.ca_path.clone())
            .unwrap_or_else(|| config.tls.client_ca_path.clone());
        let ca_pem = std::fs::read(&ca_path)
            .map_err(|e| anyhow::anyhow!("Reading Vigil CA cert {}: {}", ca_path.display(), e))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|e| anyhow::anyhow!("Parsing Vigil CA cert: {}", e))?;
        builder = builder.add_root_certificate(ca_cert);
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("Building Vigil HTTP client: {}", e))
}
