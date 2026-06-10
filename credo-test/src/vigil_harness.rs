/// Vigil test harness: spins up vigil's Axum router over plain HTTP on a random port.
///
/// The test instance uses the pre-committed test PKI fixtures and a temporary
/// directory for all state.  No TLS is used in tests — tests exercise the
/// application logic, not the TLS layer.
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::sync::oneshot;
use vigil::config::{CaConfig, IssuancePolicyConfig, TlsConfig, VigilConfig};

use crate::test_dir::{make_test_dir, TestDir};

pub struct TestVigil {
    /// Base URL of the running vigil instance (e.g., `http://127.0.0.1:12345`).
    pub url: String,
    /// Plain HTTP client for making requests to this instance.
    pub client: reqwest::Client,
    /// Output directory (temp or persistent depending on CREDO_TEST_KEEP_OUTPUT).
    pub dir: TestDir,
    /// Sending side of the shutdown channel — drop to stop the server.
    _shutdown: oneshot::Sender<()>,
}

impl TestVigil {
    /// Start vigil with no bootstrap secret (production-like mode).
    /// POST /bootstrap will return 404.
    pub async fn start() -> Result<Self> {
        Self::start_inner(None, None, true).await
    }

    /// Start vigil with a bootstrap secret in memory.
    /// POST /bootstrap will accept this exact secret string.
    pub async fn start_with_bootstrap(secret: impl Into<String>) -> Result<Self> {
        Self::start_inner(Some(secret.into()), None, true).await
    }

    /// Start vigil with a pre-injected admin `AuthUser` so authenticated routes
    /// (sign, revoke, OCSP, CRL, health, CA info) can be called without mTLS.
    /// Used by vigil integration tests.
    pub async fn start_authed() -> Result<Self> {
        Self::start_inner(None, Some(Self::test_admin()), true).await
    }

    /// Same as `start_authed` but with `allow_none_validation: false`.
    /// Use this to test that none-01 challenges are rejected.
    pub async fn start_authed_strict() -> Result<Self> {
        Self::start_inner(None, Some(Self::test_admin()), false).await
    }

    fn test_admin() -> vigil::auth::AuthUser {
        use vigil::auth::AuthUser;
        use vigil::types::VigilUser;
        let admin = VigilUser {
            id: "rbac:test-admin".to_string(),
            name: "Test Admin".to_string(),
            role: vigil::types::Role::Admin,
            active: true,
            public_key_pem: String::new(),
            public_key_fingerprint256: "test-fingerprint".to_string(),
        };
        AuthUser(admin)
    }

    async fn start_inner(
        bootstrap_secret: Option<String>,
        test_auth: Option<vigil::auth::AuthUser>,
        allow_none_validation: bool,
    ) -> Result<Self> {
        let dir = make_test_dir("vigil")?;
        let tmp = dir.path().to_path_buf();

        std::fs::create_dir_all(tmp.join("certs")).ok();

        let mut config = build_vigil_config(&tmp);
        config.allow_none_validation = allow_none_validation;

        vigil::storage::ensure_users_db(&config.users_db_path).context("ensure users db")?;
        vigil::storage::ensure_certs_db(&config.cert_db_path, &config.certs_dir)
            .context("ensure certs db")?;
        vigil::storage::ensure_acme_accounts_db(&config.acme_accounts_db_path)
            .context("ensure acme accounts db")?;

        let ca_metadata =
            vigil::ca::load_ca_metadata(&config).context("loading test CA metadata")?;

        let state = vigil::state::AppState::new(config, ca_metadata, bootstrap_secret);
        vigil::acme::restore_accounts(&state).await.ok();

        let base_router = vigil::routes::build_router(state);
        let router = if let Some(auth) = test_auth {
            base_router.layer(axum::Extension(auth))
        } else {
            base_router
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding vigil listener")?;
        let url = format!("http://{}", listener.local_addr()?);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("building reqwest client")?;

        Ok(TestVigil {
            url,
            client,
            dir,
            _shutdown: shutdown_tx,
        })
    }

    pub fn acme_directory_url(&self) -> String {
        format!("{}/acme/directory", self.url)
    }
    pub fn bootstrap_url(&self) -> String {
        format!("{}/bootstrap", self.url)
    }
    pub fn sign_url(&self) -> String {
        format!("{}/certificates/sign", self.url)
    }
}

pub fn build_vigil_config(tmp: &PathBuf) -> VigilConfig {
    use vigil::config::LogLevel;
    VigilConfig {
        port: 0,
        bind: "127.0.0.1".to_string(),
        ca_dir: tmp.join("ca"),
        ca_key_path: crate::fixtures::intermediate_ca_key(),
        ca_cert_path: crate::fixtures::intermediate_ca_pem(),
        ca_ecdsa_intermediate_key_path: crate::fixtures::intermediate_ca_key(),
        ca_ecdsa_intermediate_cert_path: crate::fixtures::intermediate_ca_pem(),
        ca: CaConfig {
            curve: "P-256".to_string(),
            cert_default_days: 365,
            crl_next_update_hours: 24,
            ocsp_max_age_seconds: 60,
        },
        users_db_path: tmp.join("users.json"),
        cert_db_path: tmp.join("certs.json"),
        acme_accounts_db_path: tmp.join("acme-accounts.json"),
        certs_dir: tmp.join("certs"),
        ct_log_path: tmp.join("ct.log"),
        common_name: "vigil.credo.test".to_string(),
        tls: TlsConfig {
            key_path: tmp.join("tls.key"),
            cert_path: tmp.join("tls.pem"),
            client_ca_path: crate::fixtures::catrust_pem(),
        },
        log_level: LogLevel::Warn,
        rbac_identities: vec![],
        issuance_policy: IssuancePolicyConfig {
            allowed_dns_suffixes: vec!["credo.test".to_string()],
            allow_subdomains: true,
            allow_bare_suffix: true,
            allowed_identity_uri_prefixes: vec!["vigil://credo/".to_string()],
            allow_ip_sans: false,
        },
        config_dir: tmp.clone(),
        allow_none_validation: true,
    }
}
