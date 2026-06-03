use anyhow::Result;
use axum::Router;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::config::VigilConfig;

// Shared TLS helpers and accept loop from credo-lib.
pub use credo_lib::tls::{bind_tcp, serve_tls};

pub fn build_server_tls(config: &VigilConfig) -> Result<Arc<rustls::ServerConfig>> {
    credo_lib::tls::build_server_tls(
        &config.tls.cert_path,
        &config.tls.key_path,
        Some(&config.tls.client_ca_path),
    )
}

pub async fn run(
    config: &VigilConfig,
    router: Router,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let listener = bind_tcp(&config.bind, config.port).await?;
    tracing::info!(addr = %format!("{}:{}", config.bind, config.port), "Vigil listening with mTLS");
    let acceptor = TlsAcceptor::from(tls_config);
    serve_tls(listener, acceptor, router).await;
    Ok(())
}
