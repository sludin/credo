use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::types::CorgiNodeConfig;
use credo_lib::log::RequestLogEntry;

const HOOKS_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorgiHooksResponse {
    pub available_hooks: Vec<String>,
    pub default_hooks: Vec<String>,
}

/// Fetch the available hook list from a corgi node, using a per-node in-memory cache.
pub async fn corgi_get_hooks(
    pool: &Arc<RwLock<CorgiClientPool>>,
    hooks_cache: &Arc<std::sync::Mutex<HashMap<String, (CorgiHooksResponse, Instant)>>>,
    node: &CorgiNodeConfig,
) -> Result<CorgiHooksResponse> {
    {
        let cache = hooks_cache.lock().unwrap();
        if let Some((cached, fetched_at)) = cache.get(&node.name) {
            if fetched_at.elapsed() < HOOKS_CACHE_TTL {
                return Ok(cached.clone());
            }
        }
    }
    let resp: CorgiHooksResponse = corgi_get(pool, node, "/hooks").await?;
    hooks_cache
        .lock()
        .unwrap()
        .insert(node.name.clone(), (resp.clone(), Instant::now()));
    Ok(resp)
}

fn url_hostname(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .and_then(|host_port| host_port.split(':').next())
        .unwrap_or("-")
        .to_string()
}

/// Per-corgi mTLS reqwest client cache.
///
/// In bootstrap mode, carries the in-memory cert+key PEM (Shepherd's own identity,
/// Vigil-signed, never written to disk). `build_client` uses it directly as the
/// mTLS client identity so the poll loop can reach Corgi before production certs exist.
/// In normal server mode the pool is empty and clients are built from disk paths.
pub struct CorgiClientPool {
    clients: HashMap<String, reqwest::Client>,
    bootstrap_identity_pem: Option<Vec<u8>>,
}

impl Default for CorgiClientPool {
    fn default() -> Self {
        Self::new()
    }
}

impl CorgiClientPool {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            bootstrap_identity_pem: None,
        }
    }

    pub fn with_bootstrap_identity(cert_pem: &str, key_pem: &str) -> Self {
        let mut pem = cert_pem.as_bytes().to_vec();
        pem.extend_from_slice(key_pem.as_bytes());
        Self {
            clients: HashMap::new(),
            bootstrap_identity_pem: Some(pem),
        }
    }
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

fn build_client(
    node: &CorgiNodeConfig,
    bootstrap_identity_pem: Option<&[u8]>,
) -> Result<reqwest::Client> {
    let identity_pem: Vec<u8> = if let Some(pem) = bootstrap_identity_pem {
        // Bootstrap mode: use the in-memory identity exclusively — no disk reads.
        pem.to_vec()
    } else {
        let mut cert = std::fs::read(&node.mtls.cert_path).with_context(|| {
            format!("Reading corgi mTLS cert: {}", node.mtls.cert_path.display())
        })?;
        cert.extend_from_slice(&std::fs::read(&node.mtls.key_path).with_context(|| {
            format!("Reading corgi mTLS key: {}", node.mtls.key_path.display())
        })?);
        cert
    };

    let identity =
        reqwest::Identity::from_pem(&identity_pem).context("Building mTLS client identity")?;

    let mut builder = reqwest::ClientBuilder::new()
        .identity(identity)
        .timeout(std::time::Duration::from_secs(30));

    if node.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Some(ca_path) = &node.mtls.ca_path {
        let ca_bytes = std::fs::read(ca_path)
            .with_context(|| format!("Reading corgi CA: {}", ca_path.display()))?;
        let ca =
            reqwest::Certificate::from_pem(&ca_bytes).context("Parsing corgi CA certificate")?;
        builder = builder.add_root_certificate(ca);
    }

    builder.build().context("Building corgi HTTP client")
}

async fn get_or_create(
    pool: &Arc<RwLock<CorgiClientPool>>,
    node: &CorgiNodeConfig,
) -> Result<reqwest::Client> {
    {
        let r = pool.read().await;
        if let Some(client) = r.clients.get(&node.name) {
            return Ok(client.clone());
        }
    }
    let bootstrap_pem = pool.read().await.bootstrap_identity_pem.clone();
    let client = build_client(node, bootstrap_pem.as_deref())?;
    pool.write()
        .await
        .clients
        .insert(node.name.clone(), client.clone());
    Ok(client)
}

/// Evict a cached client for `node_name` so the next request rebuilds it.
/// Called after the production cert is installed on corgi; the next connection
/// will build a fresh client (from disk in normal mode, still in-memory in bootstrap mode).
pub async fn evict(pool: &Arc<RwLock<CorgiClientPool>>, node_name: &str) {
    pool.write().await.clients.remove(node_name);
}

// ---------------------------------------------------------------------------
// Public request helpers
// ---------------------------------------------------------------------------

pub async fn corgi_get<T: DeserializeOwned>(
    pool: &Arc<RwLock<CorgiClientPool>>,
    node: &CorgiNodeConfig,
    path: &str,
) -> Result<T> {
    let client = get_or_create(pool, node).await?;
    let url = format!("{}{}", node.url.trim_end_matches('/'), path);
    let host = url_hostname(&url);
    let start = Instant::now();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            RequestLogEntry {
                code: "F",
                direction: "<",
                status: 0,
                method: "GET",
                path,
                host: &host,
                peer_ip: "-",
                identity: Some(node.name.as_str()),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            }
            .log();
            return Err(anyhow::anyhow!("GET {url}: {e}"));
        }
    };
    let status = resp.status();
    RequestLogEntry {
        code: "F",
        direction: "<",
        status: status.as_u16(),
        method: "GET",
        path,
        host: &host,
        peer_ip: "-",
        identity: Some(node.name.as_str()),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
    .log();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET {url} → {status}: {body}");
    }
    let body = resp
        .text()
        .await
        .with_context(|| format!("Reading response from {url}"))?;
    tracing::debug!(url = %url, body = %body, "Corgi GET response body");
    serde_json::from_str::<T>(&body).with_context(|| format!("Parsing response from {url}"))
}

pub async fn corgi_post<T: DeserializeOwned>(
    pool: &Arc<RwLock<CorgiClientPool>>,
    node: &CorgiNodeConfig,
    path: &str,
    body: &impl Serialize,
) -> Result<T> {
    let client = get_or_create(pool, node).await?;
    let url = format!("{}{}", node.url.trim_end_matches('/'), path);
    let host = url_hostname(&url);
    let start = Instant::now();
    let resp = match client.post(&url).json(body).send().await {
        Ok(r) => r,
        Err(e) => {
            RequestLogEntry {
                code: "F",
                direction: "<",
                status: 0,
                method: "POST",
                path,
                host: &host,
                peer_ip: "-",
                identity: Some(node.name.as_str()),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            }
            .log();
            return Err(anyhow::anyhow!("POST {url}: {e}"));
        }
    };
    let status = resp.status();
    RequestLogEntry {
        code: "F",
        direction: "<",
        status: status.as_u16(),
        method: "POST",
        path,
        host: &host,
        peer_ip: "-",
        identity: Some(node.name.as_str()),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
    .log();
    let resp_body = resp.text().await.unwrap_or_default();
    tracing::debug!(url = %url, status = %status, body = %resp_body, "Corgi POST response body");
    if !status.is_success() {
        anyhow::bail!("POST {url} → {status}: {resp_body}");
    }
    serde_json::from_str::<T>(&resp_body).with_context(|| format!("Parsing response from {url}"))
}

pub async fn corgi_delete(
    pool: &Arc<RwLock<CorgiClientPool>>,
    node: &CorgiNodeConfig,
    path: &str,
) -> Result<()> {
    let client = get_or_create(pool, node).await?;
    let url = format!("{}{}", node.url.trim_end_matches('/'), path);
    let host = url_hostname(&url);
    let start = Instant::now();
    let resp = match client.delete(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            RequestLogEntry {
                code: "F",
                direction: "<",
                status: 0,
                method: "DELETE",
                path,
                host: &host,
                peer_ip: "-",
                identity: Some(node.name.as_str()),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            }
            .log();
            return Err(anyhow::anyhow!("DELETE {url}: {e}"));
        }
    };
    let status = resp.status();
    RequestLogEntry {
        code: "F",
        direction: "<",
        status: status.as_u16(),
        method: "DELETE",
        path,
        host: &host,
        peer_ip: "-",
        identity: Some(node.name.as_str()),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
    .log();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("DELETE {url} → {status}: {body}");
    }
    Ok(())
}
