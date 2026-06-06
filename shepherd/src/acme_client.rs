use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
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
    /// Bootstrap-mode fallback identity (cert PEM bytes, key PEM bytes).
    /// Used when the CA config's tls.certPath/keyPath files don't exist yet.
    identity: Option<Arc<(Vec<u8>, Vec<u8>)>>,
}

impl AcmeAccountCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cache pre-loaded with an in-memory cert+key to use when the
    /// configured disk paths are absent (bootstrap mode).
    pub fn with_identity(cert_pem: &str, key_pem: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            identity: Some(Arc::new((
                cert_pem.as_bytes().to_vec(),
                key_pem.as_bytes().to_vec(),
            ))),
        }
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

        let identity_override = self.identity.as_deref()
            .map(|(c, k)| (c.as_slice(), k.as_slice()));

        let account = if creds_path.exists() {
            let json = std::fs::read_to_string(&creds_path)
                .with_context(|| format!("Reading ACME credentials: {}", creds_path.display()))?;
            let creds: AccountCredentials = serde_json::from_str(&json)
                .with_context(|| format!("Parsing ACME credentials: {}", creds_path.display()))?;
            let http = build_instant_acme_client(config, identity_override)
                .with_context(|| format!("Building ACME HTTP client for CA '{ca_name}'"))?;
            Account::from_credentials_and_http(creds, http)
                .await
                .context("Restoring ACME account from credentials")?
        } else {
            let email = config
                .account_email
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("CA '{}': accountEmail is required", ca_name))?;

            let eab = build_eab(config)?;
            let http = build_instant_acme_client(config, identity_override)
                .with_context(|| format!("Building ACME HTTP client for CA '{ca_name}'"))?;

            tracing::info!(ca = %ca_name, email = %email, "Creating new ACME account");

            let (account, creds) = Account::create_with_http(
                &NewAccount {
                    contact: &[&format!("mailto:{email}")],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                &config.directory_url,
                eab.as_ref(),
                http,
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

/// Build a hyper+rustls mTLS client implementing instant_acme's HttpClient trait.
///
/// `identity_override`: in-memory (cert_pem_bytes, key_pem_bytes) used as a
/// fallback when the CA config's tls.certPath/keyPath are absent or the files
/// don't exist yet (bootstrap mode).
fn build_instant_acme_client(
    config: &AcmeCaConfig,
    identity_override: Option<(&[u8], &[u8])>,
) -> Result<Box<dyn instant_acme::HttpClient>> {
    use rustls::ClientConfig;
    use rustls_pemfile::certs as parse_certs;
    use rustls_pemfile::private_key as parse_key;

    let mut root_store = rustls::RootCertStore::empty();

    if let Some(tls) = &config.tls {
        if let Some(ca_path) = &tls.ca_path {
            let ca_pem = std::fs::read(ca_path)
                .with_context(|| format!("Reading ACME CA bundle: {}", ca_path.display()))?;
            for der in parse_certs(&mut ca_pem.as_slice()).flatten() {
                root_store.add(der).ok();
            }
        }
    }

    // No custom CA configured — trust the standard Mozilla root store so
    // public ACME endpoints (Let's Encrypt prod/staging) work out of the box.
    if root_store.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    // Resolve client identity: disk files take priority; fall back to
    // identity_override when files are absent (bootstrap); else no client auth.
    let resolved_identity: Option<(Vec<u8>, Vec<u8>)> = if let Some(tls) = &config.tls {
        match (&tls.cert_path, &tls.key_path) {
            (Some(cert_path), Some(key_path)) => {
                match (std::fs::read(cert_path), std::fs::read(key_path)) {
                    (Ok(cert), Ok(key)) => Some((cert, key)),
                    (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => {
                        if identity_override.is_some() {
                            tracing::debug!(
                                cert = %cert_path.display(),
                                "ACME client cert not on disk; using bootstrap identity"
                            );
                        }
                        identity_override.map(|(c, k)| (c.to_vec(), k.to_vec()))
                    }
                    (Err(e), _) => return Err(anyhow::anyhow!(
                        "Reading ACME client cert {}: {}", cert_path.display(), e
                    )),
                    (_, Err(e)) => return Err(anyhow::anyhow!(
                        "Reading ACME client key {}: {}", key_path.display(), e
                    )),
                }
            }
            _ => identity_override.map(|(c, k)| (c.to_vec(), k.to_vec())),
        }
    } else {
        identity_override.map(|(c, k)| (c.to_vec(), k.to_vec()))
    };

    let tls_config = if let Some((cert_bytes, key_bytes)) = resolved_identity {
        let chain: Vec<_> = parse_certs(&mut cert_bytes.as_slice()).flatten().collect();
        let key = parse_key(&mut key_bytes.as_slice())
            .context("Parsing ACME client key")?
            .ok_or_else(|| anyhow::anyhow!("No private key found in client key PEM"))?;

        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(chain, key)
            .context("Building rustls client config with mTLS")?
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    let client: HyperClient<_, Full<Bytes>> =
        HyperClient::builder(TokioExecutor::new()).build(https);

    Ok(Box::new(client))
}
