/// Shepherd test harness: spins up shepherd's agent and dashboard Axum routers
/// over plain HTTP on random ports.
use anyhow::{Context, Result};
use shepherd::config::{LogLevel, ShepherdConfig, TlsConfig};
use shepherd::state::AppState;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::oneshot;

use crate::test_dir::{make_test_dir, TestDir};

pub struct TestShepherd {
    /// Base URL of the agent (corgi-facing) API.
    pub agent_url: String,
    /// Base URL of the dashboard (admin-facing) API.
    pub dashboard_url: String,
    /// Plain HTTP client for making requests.
    pub client: reqwest::Client,
    /// JWT signing keys — use `shepherd::jwt::sign_jwt(&shepherd.jwt_keys, ...)` in tests.
    pub jwt_keys: std::sync::Arc<shepherd::jwt::JwtKeys>,
    /// Output directory (temp or persistent depending on CREDO_TEST_KEEP_OUTPUT).
    pub dir: TestDir,
    _shutdown_agent: oneshot::Sender<()>,
    _shutdown_dashboard: oneshot::Sender<()>,
}

impl TestShepherd {
    /// Start shepherd with no CAs, no corgis, no assignments, and no vigil connection.
    pub async fn start() -> Result<Self> {
        Self::start_inner(None, None).await
    }

    /// Start shepherd with pre-injected auth extensions so authenticated routes
    /// can be called without mTLS. Used by shepherd integration tests.
    ///
    /// - Agent (corgi) routes get a pre-built `CorgiNodeConfig` extension.
    /// - Dashboard routes get a pre-built `AuthenticatedUser` extension.
    pub async fn start_authed() -> Result<Self> {
        use shepherd::types::{AuthenticatedUser, CorgiMtlsConfig, CorgiNodeConfig, Role};

        let corgi_node = CorgiNodeConfig {
            name: "test-corgi-01".to_string(),
            url: "http://127.0.0.1:0".to_string(),
            identity_uri: Some("vigil://credo/node/corgi-01".to_string()),
            mtls: CorgiMtlsConfig {
                cert_path: std::path::PathBuf::from("/dev/null"),
                key_path:  std::path::PathBuf::from("/dev/null"),
                ca_path: None,
                bootstrap_cert_path: None,
                bootstrap_key_path:  None,
            },
            insecure_skip_verify: false,
        };

        let admin_user = AuthenticatedUser {
            identity_uri: "vigil://credo/service/shepherd".to_string(),
            role: Role::Admin,
            account_id: Some("test-admin".to_string()),
            account_name: Some("Test Admin".to_string()),
        };

        Self::start_inner(Some(corgi_node), Some(admin_user)).await
    }

    async fn start_inner(
        agent_auth: Option<shepherd::types::CorgiNodeConfig>,
        dashboard_auth: Option<shepherd::types::AuthenticatedUser>,
    ) -> Result<Self> {
        let dir = make_test_dir("shepherd")?;
        let tmp = dir.path().to_path_buf();

        let config = build_shepherd_config(&tmp);

        let jwt_keys = shepherd::jwt::load_or_generate(&config.jwt_signing_key_path)
            .context("JWT keys")?;
        let accounts = shepherd::accounts::load_accounts(&config.accounts_path)
            .context("accounts")?;
        let cas = shepherd::cas::load_cas(&config.ca_config_path)
            .context("CAs")?;

        let state = AppState::new(config, jwt_keys, accounts, cas, None, None, None);
        let jwt_keys_arc = state.jwt_keys.clone();

        let base_agent_router = shepherd::server::build_agent_router(state.clone());
        let agent_router = if let Some(node) = agent_auth {
            base_agent_router.layer(axum::Extension(node))
        } else {
            base_agent_router
        };

        let base_dashboard_router = shepherd::server::build_api_router(state);
        let dashboard_router = if let Some(user) = dashboard_auth {
            base_dashboard_router.layer(axum::Extension(user))
        } else {
            base_dashboard_router
        };

        let agent_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let agent_url = format!("http://{}", agent_listener.local_addr()?);

        let dashboard_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let dashboard_url = format!("http://{}", dashboard_listener.local_addr()?);

        let (shutdown_agent_tx, shutdown_agent_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(agent_listener, agent_router)
                .with_graceful_shutdown(async { let _ = shutdown_agent_rx.await; })
                .await.ok();
        });

        let (shutdown_dashboard_tx, shutdown_dashboard_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(dashboard_listener, dashboard_router)
                .with_graceful_shutdown(async { let _ = shutdown_dashboard_rx.await; })
                .await.ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(TestShepherd {
            agent_url,
            dashboard_url,
            client,
            jwt_keys: jwt_keys_arc,
            dir,
            _shutdown_agent: shutdown_agent_tx,
            _shutdown_dashboard: shutdown_dashboard_tx,
        })
    }

    pub fn agent_health_url(&self)     -> String { format!("{}/health", self.agent_url) }
    pub fn dashboard_health_url(&self) -> String { format!("{}/health", self.dashboard_url) }
}

fn build_shepherd_config(tmp: &PathBuf) -> ShepherdConfig {
    ShepherdConfig {
        config_path: tmp.join("shepherd.config.json"),
        base_dir: tmp.clone(),
        agent_port: 0,
        dashboard_port: 0,
        bind: "127.0.0.1".to_string(),
        tls: TlsConfig {
            cert_path: tmp.join("tls.pem"),
            key_path: tmp.join("tls.key"),
            client_ca_path: crate::fixtures::catrust_pem(),
            bootstrap_cert_path: None,
            bootstrap_key_path:  None,
        },
        jwt_signing_key_path: tmp.join("jwt.key"),
        corgis_config_path: tmp.join("shepherd.corgis.json"),
        assignments_config_path: tmp.join("shepherd.assignments.json"),
        ca_config_path: tmp.join("shepherd.ca.json"),
        accounts_path: tmp.join("shepherd.accounts.json"),
        cert_store_dir: tmp.join("certstore"),
        renew_before_days: 30.0,
        poll_interval_seconds: 60,
        corgi_health_check_interval_seconds: 30,
        renewal_jobs_dir: None,
        log_level: LogLevel::Warn,
        dns_override: HashMap::new(),
        common_name: None,
        identity_uri: None,
        vigil_url: None,
        shepherd_ca_path: None,
    }
}
