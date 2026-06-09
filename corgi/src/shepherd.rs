use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;

use crate::config::CorgiConfig;
use crate::types::{AssignmentsResponse, ShepherdCertResponse};

/// Build a reqwest client configured for mTLS to Shepherd.
pub fn build_shepherd_client(config: &CorgiConfig) -> Result<Client> {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(15));

    // Load CA cert for server verification
    if let Some(ca_path) = &config.mtls.ca_path {
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("Reading Shepherd CA: {}", ca_path.display()))?;
        let ca_cert =
            reqwest::tls::Certificate::from_pem(&ca_pem).context("Parsing Shepherd CA cert")?;
        builder = builder.add_root_certificate(ca_cert);
    } else {
        // No CA configured — skip server cert verification (mirrors Node.js rejectUnauthorized: false)
        builder = builder.danger_accept_invalid_certs(true);
    }

    // Load client cert + key for mTLS authentication
    // reqwest::Identity::from_pem accepts a single PEM buffer with cert + key concatenated
    let mut combined = std::fs::read(&config.mtls.cert_path)
        .with_context(|| format!("Reading mTLS cert: {}", config.mtls.cert_path.display()))?;
    let key_pem = std::fs::read(&config.mtls.key_path)
        .with_context(|| format!("Reading mTLS key: {}", config.mtls.key_path.display()))?;
    combined.extend_from_slice(&key_pem);

    let identity = reqwest::Identity::from_pem(&combined).context("Building mTLS identity")?;
    builder = builder.identity(identity);

    Ok(builder.build().context("Building reqwest client")?)
}

pub struct ShepherdClient {
    client: Client,
    base_url: String,
}

impl ShepherdClient {
    pub fn new(config: &CorgiConfig) -> Result<Self> {
        let client = build_shepherd_client(config)?;
        Ok(Self {
            client,
            base_url: config.shepherd_url.trim_end_matches('/').to_string(),
        })
    }

    /// Construct from a pre-built (cached) reqwest client.  The `shepherd_url`
    /// is taken from the current config so it picks up SIGHUP changes.
    pub fn from_client(client: Client, shepherd_url: &str) -> Self {
        Self {
            client,
            base_url: shepherd_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn get_assignments(&self, corgi_id: &str) -> Result<AssignmentsResponse> {
        let url = format!("{}/agents/{}/assignments", self.base_url, corgi_id);
        tracing::debug!(url = %url, "Fetching assignments from Shepherd");

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("GET assignments")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Shepherd returned {} for assignments: {}",
                status,
                body.trim()
            ));
        }

        resp.json::<AssignmentsResponse>()
            .await
            .context("Parsing assignments response")
    }

    pub async fn get_cert(&self, corgi_id: &str, cert_name: &str) -> Result<ShepherdCertResponse> {
        let url = format!("{}/agents/{}/certs/{}", self.base_url, corgi_id, cert_name);
        tracing::debug!(url = %url, "Fetching cert material from Shepherd");

        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("GET cert")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Shepherd returned {} for cert {}: {}",
                status,
                cert_name,
                body.trim()
            ));
        }

        resp.json::<ShepherdCertResponse>()
            .await
            .context("Parsing cert response")
    }

    /// POST /agents/:id/renew/:name — submit a CSR for async re-issuance.
    /// Shepherd issues the cert from the provided CSR and pushes it to corgi
    /// via /flock/<name>/install when done.
    pub async fn request_renew(
        &self,
        corgi_id: &str,
        cert_name: &str,
        csr_pem: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/agents/{}/renew/{}",
            self.base_url,
            corgi_id,
            urlencoded(cert_name)
        );
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "csrPem": csr_pem }))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("POST renew")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Shepherd returned {} for renew {}: {}",
                status,
                cert_name,
                body.trim()
            ));
        }
        Ok(())
    }

    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/health", self.base_url);
        self.client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .context("Shepherd health check")?;
        Ok(())
    }
}

fn urlencoded(s: &str) -> String {
    s.replace('/', "%2F")
}
