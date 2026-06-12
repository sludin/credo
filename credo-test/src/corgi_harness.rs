/// Corgi bootstrap harness: serves the bootstrap Axum handlers over plain HTTP.
///
/// In production the bootstrap server uses TLS (self-signed cert). Here we skip
/// TLS so tests can drive the handlers without certificate pinning. The token
/// field holds the random Bearer token the bootstrap endpoints require.
pub struct TestCorgiBootstrap {
    /// Base URL of the running bootstrap server (e.g., `http://127.0.0.1:12345`).
    pub url: String,
    /// The Bearer token accepted by all token-protected bootstrap endpoints.
    pub token: String,
    /// Plain HTTP client.
    pub client: reqwest::Client,
    /// Output directory (temp or persistent depending on CREDO_TEST_KEEP_OUTPUT).
    pub dir: TestDir,
    _shutdown: oneshot::Sender<()>,
    // Receiver fires when POST /bootstrap/finalize is called.
    done_rx: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl TestCorgiBootstrap {
    /// Start with an isolated certstore inside the harness tempdir.
    pub async fn start() -> Result<Self> {
        let dir = make_test_dir("corgi-bootstrap")?;
        let tmp = dir.path().to_path_buf();
        let cert_store = tmp.join("certstore");
        std::fs::create_dir_all(&cert_store).ok();
        Self::start_inner(dir, &tmp, cert_store).await
    }

    /// Start with a caller-supplied certstore, shared across multiple services.
    /// The harness still gets its own tempdir for non-certstore files (mtls certs, etc.).
    pub async fn start_with_cert_store(cert_store_dir: std::path::PathBuf) -> Result<Self> {
        let dir = make_test_dir("corgi-bootstrap")?;
        let tmp = dir.path().to_path_buf();
        std::fs::create_dir_all(&cert_store_dir).ok();
        Self::start_inner(dir, &tmp, cert_store_dir).await
    }

    async fn start_inner(
        dir: TestDir,
        tmp: &std::path::Path,
        cert_store_dir: std::path::PathBuf,
    ) -> Result<Self> {
        let config = std::sync::Arc::new(build_corgi_config(tmp, &cert_store_dir));
        let token = hex::encode({
            let mut b = [0u8; 16];
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| {
                    f.read_exact(&mut b)?;
                    Ok(b)
                })
                .unwrap_or_else(|_| {
                    b[0] = 42;
                    b
                })
        });

        let (router, done_rx) =
            corgi::bootstrap::build_bootstrap_router(config, std::sync::Arc::new(token.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
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
            .build()?;

        Ok(TestCorgiBootstrap {
            url,
            token,
            client,
            dir,
            _shutdown: shutdown_tx,
            done_rx: Some(done_rx),
        })
    }

    pub fn status_url(&self) -> String {
        format!("{}/bootstrap/status", self.url)
    }
    pub fn csr_url(&self) -> String {
        format!("{}/bootstrap/csr", self.url)
    }
    pub fn ca_url(&self) -> String {
        format!("{}/bootstrap/ca", self.url)
    }
    pub fn cert_url(&self) -> String {
        format!("{}/bootstrap/cert", self.url)
    }
    pub fn finalize_url(&self) -> String {
        format!("{}/bootstrap/finalize", self.url)
    }

    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Wait for POST /bootstrap/finalize to be called (with a timeout).
    pub async fn wait_for_finalize(&mut self) -> bool {
        if let Some(rx) = self.done_rx.take() {
            tokio::time::timeout(std::time::Duration::from_secs(5), rx)
                .await
                .is_ok()
        } else {
            false
        }
    }
}

use crate::test_dir::{make_test_dir, TestDir};
/// Corgi test harness: spins up corgi's control and challenge Axum routers
/// over plain HTTP on random ports.
use anyhow::Result;
use corgi::config::{
    AuthConfig, AuthMode, CorgiConfig, FilePolicyConfig, HttpChallengeConfig, LogLevel, MtlsConfig,
    ProxyAuthConfig, ShepherdSyncConfig, TlsConfig,
};
use corgi::state::AppState;
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::oneshot;

pub struct TestCorgi {
    /// Base URL of the mTLS control API (served over plain HTTP in tests).
    pub control_url: String,
    /// Base URL of the HTTP-01 challenge server.
    pub challenge_url: String,
    /// Plain HTTP client for making requests.
    pub client: reqwest::Client,
    /// Output directory (temp or persistent depending on CREDO_TEST_KEEP_OUTPUT).
    pub dir: TestDir,
    _shutdown_control: oneshot::Sender<()>,
    _shutdown_challenge: oneshot::Sender<()>,
}

impl TestCorgi {
    /// Start corgi with minimal config, empty flock, no auth bypass.
    pub async fn start() -> Result<Self> {
        Self::start_inner(false).await
    }

    /// Start corgi with a pre-injected Admin Role so authenticated control routes
    /// can be called without mTLS. Used by corgi integration tests.
    pub async fn start_authed() -> Result<Self> {
        Self::start_inner(true).await
    }

    async fn start_inner(inject_admin: bool) -> Result<Self> {
        let dir = make_test_dir("corgi")?;
        let tmp = dir.path().to_path_buf();
        let cert_store = tmp.join("certstore");

        let config = build_corgi_config(&tmp, &cert_store);
        let state = AppState::new(config)?;

        let base_control_router = corgi::server::build_control_router(state.clone());
        let control_router = if inject_admin {
            base_control_router.layer(axum::Extension(corgi::types::Role::Admin))
        } else {
            base_control_router
        };
        let challenge_router = corgi::server::build_challenge_router(state);

        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let control_addr = control_listener.local_addr()?;
        let control_url = format!("http://{}", control_addr);

        let challenge_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let challenge_addr = challenge_listener.local_addr()?;
        let challenge_url = format!("http://{}", challenge_addr);

        let (shutdown_control_tx, shutdown_control_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(control_listener, control_router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_control_rx.await;
                })
                .await
                .ok();
        });

        let (shutdown_challenge_tx, shutdown_challenge_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(challenge_listener, challenge_router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_challenge_rx.await;
                })
                .await
                .ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(TestCorgi {
            control_url,
            challenge_url,
            client,
            dir,
            _shutdown_control: shutdown_control_tx,
            _shutdown_challenge: shutdown_challenge_tx,
        })
    }

    pub fn control_health_url(&self) -> String {
        format!("{}/health", self.control_url)
    }
    pub fn challenge_health_url(&self) -> String {
        format!("{}/health", self.challenge_url)
    }
}

/// Build a corgi config.
/// `tmp`           — tempdir for non-certstore files (mtls certs, accounts, etc.)
/// `cert_store_dir` — where all certs live; mirrors production `corgiRoot/store`.
///                   May be shared across services in the full-stack bootstrap test.
pub const CORGI_COMMON_NAME: &str = "corgi-01.credo.test";

fn build_corgi_config(tmp: &Path, cert_store_dir: &Path) -> CorgiConfig {
    // Mirror the production layout: tls paths live inside certstore/live/<common_name>/
    // so install_to_archive creates all live/ symlinks in the correct directory.
    let live = cert_store_dir.join("live").join(CORGI_COMMON_NAME);
    CorgiConfig {
        node_id: "corgi-test-01".to_string(),
        common_name: CORGI_COMMON_NAME.to_string(),
        identity_uri: Some("vigil://credo/node/corgi-01".to_string()),
        shepherd_url: "http://127.0.0.1:0".to_string(),
        dns_override: HashMap::new(),
        tls: TlsConfig {
            cert_path: live.join("cert.pem"),
            key_path: live.join("privkey.pem"),
        },
        mtls: MtlsConfig {
            cert_path: tmp.join("mtls.pem"),
            key_path: tmp.join("mtls.key"),
            // bootstrap/ca writes the trust bundle here; must be inside the harness tempdir
            ca_path: Some(tmp.join("mtls-ca.pem")),
        },
        cert_store_dir: cert_store_dir.to_path_buf(),
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
        log_level: LogLevel::Warn,
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
            assignments_cache_path: tmp.join("assignments.json"),
        },
        config_path: tmp.join("corgi.config.json"),
        accounts_path: tmp.join("corgi.accounts.json"),
        chain_path: Some(live.join("chain.pem")),
        fullchain_path: Some(live.join("fullchain.pem")),
        csr_path: None,
        file_policy: FilePolicyConfig {
            owner: None,
            group: None,
            cert_mode: None,
            key_mode: None,
        },
        cert_hooks: HashMap::new(),
    }
}
