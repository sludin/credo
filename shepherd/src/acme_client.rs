use anyhow::{Context, Result};
use instant_acme::{Account, AccountCredentials, ExternalAccountKey, NewAccount};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::types::AcmeCaConfig;

// ---------------------------------------------------------------------------
// Per-CA account cache
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct AcmeAccountCache {
    inner: Arc<Mutex<HashMap<String, Account>>>,
}

impl AcmeAccountCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_create(&self, ca_name: &str, config: &AcmeCaConfig) -> Result<Account> {
        let cache_key = format!("{}|{}", ca_name, config.directory_url);

        {
            let cache = self.inner.lock().unwrap();
            if let Some(account) = cache.get(&cache_key) {
                return Ok(account.clone());
            }
        }

        let creds_path = credentials_path(&config.account_key_path);

        let account = if creds_path.exists() {
            let json = std::fs::read_to_string(&creds_path)
                .with_context(|| format!("Reading ACME credentials: {}", creds_path.display()))?;
            let creds: AccountCredentials = serde_json::from_str(&json)
                .with_context(|| format!("Parsing ACME credentials: {}", creds_path.display()))?;
            Account::from_credentials(creds)
                .await
                .context("Restoring ACME account from credentials")?
        } else {
            let email = config
                .account_email
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("CA '{}': accountEmail is required", ca_name))?;

            let eab = build_eab(config)?;

            tracing::info!(ca = %ca_name, email = %email, "Creating new ACME account");

            let (account, creds) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{email}")],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                &config.directory_url,
                eab.as_ref(),
            )
            .await
            .with_context(|| {
                format!("Creating ACME account for CA '{ca_name}' at {}", config.directory_url)
            })?;

            // Persist credentials as JSON
            if let Some(parent) = creds_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let creds_json = serde_json::to_string_pretty(&creds)
                .context("Serializing ACME credentials")?;
            std::fs::write(&creds_path, creds_json)
                .with_context(|| format!("Writing ACME credentials: {}", creds_path.display()))?;
            tracing::info!(ca = %ca_name, path = %creds_path.display(), "ACME account credentials saved");

            account
        };

        self.inner.lock().unwrap().insert(cache_key, account.clone());
        Ok(account)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Credentials are stored alongside the configured key path with an .acme.json suffix.
fn credentials_path(account_key_path: &std::path::Path) -> std::path::PathBuf {
    let mut p = account_key_path.to_path_buf();
    let name = p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("account")
        .to_string();
    p.set_file_name(format!("{name}.acme.json"));
    p
}

fn build_eab(config: &AcmeCaConfig) -> Result<Option<ExternalAccountKey>> {
    let Some(eab) = &config.eab else { return Ok(None) };
    // The HMAC key is typically base64url-encoded in the config
    let key_bytes = base64::engine::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &eab.hmac_key,
    )
    .or_else(|_| {
        base64::engine::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &eab.hmac_key,
        )
    })
    .with_context(|| format!("Decoding EAB HMAC key (expected base64url)"))?;
    Ok(Some(ExternalAccountKey::new(eab.kid.clone(), &key_bytes)))
}

/// Build a reqwest Client configured for mTLS to the ACME CA.
/// Exposed for callers that need to verify ACME CA TLS configuration.
pub fn build_http_client(config: &AcmeCaConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30));

    if config.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(tls) = &config.tls {
        if let Some(ca_path) = &tls.ca_path {
            let ca_pem = std::fs::read(ca_path)
                .with_context(|| format!("Reading ACME CA cert: {}", ca_path.display()))?;
            let ca = reqwest::Certificate::from_pem(&ca_pem)
                .context("Parsing ACME CA certificate")?;
            builder = builder.add_root_certificate(ca);
        }
        if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("Reading ACME client cert: {}", cert_path.display()))?;
            let key_pem = std::fs::read(key_path)
                .with_context(|| format!("Reading ACME client key: {}", key_path.display()))?;
            let mut identity_pem = cert_pem;
            identity_pem.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&identity_pem)
                .context("Building ACME mTLS identity")?;
            builder = builder.identity(identity);
        }
    }

    builder.build().context("Building ACME HTTP client")
}
