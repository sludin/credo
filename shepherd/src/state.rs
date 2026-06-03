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
use crate::types::{Account, CaConfig, CorgiNodeConfig, CorgiNodeState, ManagedAssignment, RenewalJob};

#[derive(Clone)]
pub struct AppState {
    pub config:            Arc<ShepherdConfig>,
    pub jwt_keys:          Arc<JwtKeys>,
    pub corgi_state:       Arc<RwLock<HashMap<String, CorgiNodeState>>>,
    pub renewal_jobs:      Arc<RwLock<HashMap<Uuid, RenewalJob>>>,
    pub accounts:          Arc<RwLock<Vec<Account>>>,
    pub refresh_tokens:    Arc<RefreshTokenStore>,
    pub assignments:       Arc<RwLock<Vec<ManagedAssignment>>>,
    pub corgis:            Arc<RwLock<Vec<CorgiNodeConfig>>>,
    /// Loaded CA configs keyed by CA name
    pub cas:               Arc<HashMap<String, CaConfig>>,
    /// Last-seen mtimes for hot-reload detection
    pub corgis_mtime:      Arc<Mutex<Option<SystemTime>>>,
    pub assignments_mtime: Arc<Mutex<Option<SystemTime>>>,
    /// Per-corgi mTLS reqwest client pool (keyed by corgi name)
    pub corgi_client_pool: Arc<RwLock<CorgiClientPool>>,
    /// ACME account cache (avoids re-creating accounts on each renewal)
    pub acme_accounts:     AcmeAccountCache,
    /// In-progress issuance deduplication: key = "{ca}:{cert_name}"
    pub in_progress:       Arc<Mutex<HashMap<String, Weak<Notify>>>>,
    /// mTLS client for proxying admin requests to Vigil (None if vigilUrl not configured)
    pub vigil_client:      Option<reqwest::Client>,
}

impl AppState {
    pub fn new(
        config: ShepherdConfig,
        jwt_keys: JwtKeys,
        accounts: Vec<Account>,
        cas: HashMap<String, CaConfig>,
    ) -> Self {
        let refresh_token_path = config.renewal_jobs_dir.as_ref()
            .map(|d| d.join("refresh-tokens.json"));

        let vigil_client = if config.vigil_url.is_some() {
            match build_vigil_client(&config, &cas) {
                Ok(c) => Some(c),
                Err(e) => { tracing::warn!("Failed to build Vigil client: {}", e); None }
            }
        } else {
            None
        };

        Self {
            config: Arc::new(config),
            jwt_keys: Arc::new(jwt_keys),
            corgi_state: Arc::new(RwLock::new(HashMap::new())),
            renewal_jobs: Arc::new(RwLock::new(HashMap::new())),
            accounts: Arc::new(RwLock::new(accounts)),
            refresh_tokens: Arc::new(RefreshTokenStore::new(refresh_token_path)),
            assignments: Arc::new(RwLock::new(vec![])),
            corgis: Arc::new(RwLock::new(vec![])),
            cas: Arc::new(cas),
            corgis_mtime: Arc::new(Mutex::new(None)),
            assignments_mtime: Arc::new(Mutex::new(None)),
            corgi_client_pool: Arc::new(RwLock::new(HashMap::new())),
            acme_accounts: AcmeAccountCache::new(),
            in_progress: Arc::new(Mutex::new(HashMap::new())),
            vigil_client,
        }
    }
}

fn build_vigil_client(config: &ShepherdConfig, cas: &HashMap<String, CaConfig>) -> anyhow::Result<reqwest::Client> {
    // Prefer cert/key/ca from the vigil ACME CA config, fall back to shepherd's own TLS creds
    let vigil_ca = cas.values().find(|ca| ca.provider == "vigil" && ca.protocol == "acme");

    let cert_path = vigil_ca.and_then(|ca| ca.config.tls.as_ref()?.cert_path.clone())
        .unwrap_or_else(|| config.tls.cert_path.clone());
    let key_path = vigil_ca.and_then(|ca| ca.config.tls.as_ref()?.key_path.clone())
        .unwrap_or_else(|| config.tls.key_path.clone());
    let ca_path = vigil_ca.and_then(|ca| ca.config.tls.as_ref()?.ca_path.clone())
        .unwrap_or_else(|| config.tls.client_ca_path.clone());
    let insecure = vigil_ca.map(|ca| ca.config.insecure_skip_verify).unwrap_or(false);

    let cert_pem = std::fs::read(&cert_path)
        .map_err(|e| anyhow::anyhow!("Reading Vigil client cert {}: {}", cert_path.display(), e))?;
    let key_pem = std::fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("Reading Vigil client key {}: {}", key_path.display(), e))?;
    let mut identity_pem = cert_pem;
    identity_pem.extend_from_slice(&key_pem);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|e| anyhow::anyhow!("Building Vigil mTLS identity: {}", e))?;

    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .identity(identity);

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        let ca_pem = std::fs::read(&ca_path)
            .map_err(|e| anyhow::anyhow!("Reading Vigil CA cert {}: {}", ca_path.display(), e))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|e| anyhow::anyhow!("Parsing Vigil CA cert: {}", e))?;
        builder = builder.add_root_certificate(ca_cert);
    }

    builder.build().map_err(|e| anyhow::anyhow!("Building Vigil HTTP client: {}", e))
}
