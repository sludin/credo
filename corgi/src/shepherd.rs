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
        // No CA configured — skip server cert verification (mirrors Node.js rejectUnauthorized: false).
        // This disables MITM protection on every outbound call to Shepherd
        // (assignment pulls, cert-material fetches); log loudly so a missing
        // mtls.caPath in a real deployment doesn't go unnoticed.
        tracing::warn!(
            "mtls.caPath is not configured — TLS server certificate verification is DISABLED for all Shepherd connections. This is insecure outside of local development/testing."
        );
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

    builder.build().context("Building reqwest client")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthConfig, AuthMode, FilePolicyConfig, HttpChallengeConfig, MtlsConfig, ProxyAuthConfig,
        ShepherdSyncConfig, TlsConfig,
    };
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn test_config(dir: &TempDir, ca_path: Option<std::path::PathBuf>) -> CorgiConfig {
        let (cert_pem, key_pem, _fullchain_pem) = credo_test::cert_gen::generate_signed_cert(
            "corgi-test.credo.test",
            &["corgi-test.credo.test"],
            &[],
            30,
            dir.path(),
        )
        .unwrap();
        let cert_path = dir.path().join("mtls.pem");
        let key_path = dir.path().join("mtls.key");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

        CorgiConfig {
            node_id: "corgi-01".to_string(),
            common_name: "corgi-01.credo.test".to_string(),
            identity_uri: Some("vigil://credo/node/corgi-01".to_string()),
            shepherd_url: "http://127.0.0.1:0".to_string(),
            dns_override: HashMap::new(),
            tls: TlsConfig {
                cert_path: dir.path().join("tls.pem"),
                key_path: dir.path().join("tls.key"),
            },
            mtls: MtlsConfig {
                cert_path,
                key_path,
                ca_path,
            },
            cert_store_dir: dir.path().join("certstore"),
            flock: vec![],
            http_challenge: HttpChallengeConfig {
                enabled: false,
                port: 0,
                bind: "127.0.0.1".to_string(),
            },
            mtls_port: 0,
            bind: "127.0.0.1".to_string(),
            service_hooks: HashMap::new(),
            default_hooks: vec![],
            log_hook_output: false,
            log_level: credo_lib::LogLevel::Warn,
            logging: credo_lib::LoggingConfig::default(),
            auth: AuthConfig {
                mode: AuthMode::Mtls,
            },
            rbac_identities: vec![],
            proxy_auth: ProxyAuthConfig {
                client_cert_header: "X-Client-Cert".to_string(),
                client_fingerprint_header: "X-Client-Fingerprint".to_string(),
                client_subject_header: "X-Client-Subject".to_string(),
                client_san_uri_header: "X-Client-San-Uri".to_string(),
            },
            shepherd_sync: ShepherdSyncConfig {
                enabled: false,
                interval_seconds: 60,
                stale_warning_seconds: 300,
                assignments_cache_path: dir.path().join("assignments.json"),
            },
            monitor_interval_seconds: 900,
            config_path: dir.path().join("corgi.config.json"),
            accounts_path: dir.path().join("corgi.accounts.json"),
            chain_path: None,
            fullchain_path: None,
            csr_path: None,
            file_policy: FilePolicyConfig {
                owner: None,
                group: None,
                cert_mode: None,
                key_mode: None,
            },
        }
    }

    /// Regression test for a Medium finding: omitting mtls.caPath silently
    /// disabled TLS server-certificate verification for every outbound call
    /// to Shepherd, with no signal that anything was wrong. It must now log
    /// a loud warning every time this fallback is exercised.
    #[test]
    fn build_shepherd_client_warns_when_ca_path_unset() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir, None);

        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let result = build_shepherd_client(&config);

        drop(guard);
        assert!(result.is_ok(), "client build must still succeed");
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("TLS server certificate verification is DISABLED"),
            "expected a loud warning when mtls.caPath is unset, got: {logged}"
        );
    }

    /// When a CA is configured, no such warning should be logged.
    #[test]
    fn build_shepherd_client_no_warning_when_ca_path_set() {
        let dir = TempDir::new().unwrap();
        // Reuse the client cert itself as a stand-in CA file — its content
        // doesn't matter for this test, only that ca_path is Some(_).
        let ca_path = dir.path().join("mtls.pem");
        let config = test_config(&dir, Some(ca_path));

        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let result = build_shepherd_client(&config);

        drop(guard);
        assert!(result.is_ok());
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            !logged.contains("DISABLED"),
            "no warning expected when a CA is configured, got: {logged}"
        );
    }
}
