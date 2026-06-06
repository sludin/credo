use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use credo_lib::log::RequestLogEntry;
use crate::types::CorgiNodeConfig;

fn url_hostname(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .and_then(|host_port| host_port.split(':').next())
        .unwrap_or("-")
        .to_string()
}

pub type CorgiClientPool = HashMap<String, reqwest::Client>;

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

fn build_client(node: &CorgiNodeConfig) -> Result<reqwest::Client> {
    // During the bootstrap window the production cert hasn't been issued yet.
    // Use the bootstrap cert (shepherdRoot/bootstrap/) as a fallback until the
    // production cert appears in the corgi certstore live/ directory.
    let (cert_path, key_path) =
        if node.mtls.cert_path.exists() {
            (&node.mtls.cert_path, &node.mtls.key_path)
        } else if let (Some(bc), Some(bk)) =
            (&node.mtls.bootstrap_cert_path, &node.mtls.bootstrap_key_path)
        {
            (bc, bk)
        } else {
            (&node.mtls.cert_path, &node.mtls.key_path)
        };

    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("Reading corgi mTLS cert: {}", cert_path.display()))?;
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("Reading corgi mTLS key: {}", key_path.display()))?;

    // reqwest accepts cert + key PEM concatenated
    let mut identity_pem = cert_bytes;
    identity_pem.extend_from_slice(&key_bytes);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .context("Building mTLS client identity")?;

    let mut builder = reqwest::ClientBuilder::new()
        .identity(identity)
        .timeout(std::time::Duration::from_secs(30));

    if node.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Some(ca_path) = &node.mtls.ca_path {
        let ca_bytes = std::fs::read(ca_path)
            .with_context(|| format!("Reading corgi CA: {}", ca_path.display()))?;
        let ca = reqwest::Certificate::from_pem(&ca_bytes)
            .context("Parsing corgi CA certificate")?;
        builder = builder.add_root_certificate(ca);
    }

    builder.build().context("Building corgi HTTP client")
}

async fn get_or_create(pool: &Arc<RwLock<CorgiClientPool>>, node: &CorgiNodeConfig) -> Result<reqwest::Client> {
    {
        let r = pool.read().await;
        if let Some(client) = r.get(&node.name) {
            return Ok(client.clone());
        }
    }
    let client = build_client(node)?;
    pool.write().await.insert(node.name.clone(), client.clone());
    Ok(client)
}

/// Evict a cached client for `node_name` so the next request rebuilds it.
/// Call this after the production cert lands in the certstore so the client
/// switches from the bootstrap fallback to the production credential.
pub async fn evict(pool: &Arc<RwLock<CorgiClientPool>>, node_name: &str) {
    pool.write().await.remove(node_name);
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
    let resp = client.get(&url).send().await
        .with_context(|| format!("GET {url}"))?;
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
    }.log();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET {url} → {status}: {body}");
    }
    let body = resp.text().await.with_context(|| format!("Reading response from {url}"))?;
    tracing::debug!(url = %url, body = %body, "Corgi GET response body");
    serde_json::from_str::<T>(&body)
        .with_context(|| format!("Parsing response from {url}"))
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
    let resp = client.post(&url).json(body).send().await
        .with_context(|| format!("POST {url}"))?;
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
    }.log();
    let resp_body = resp.text().await.unwrap_or_default();
    tracing::debug!(url = %url, status = %status, body = %resp_body, "Corgi POST response body");
    if !status.is_success() {
        anyhow::bail!("POST {url} → {status}: {resp_body}");
    }
    serde_json::from_str::<T>(&resp_body)
        .with_context(|| format!("Parsing response from {url}"))
}
