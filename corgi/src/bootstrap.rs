use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use rand::Rng;
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

use crate::archive::set_permissions;
use crate::cert_ops::{
    fingerprint_display, generate_bootstrap_cert, generate_key_and_csr, install_certificate,
    pem_cert_to_der,
};
use crate::config::CorgiConfig;
use crate::server::bind_tcp;
use crate::types::{CsrRequest, InstallRequest};

// ---------------------------------------------------------------------------
// Bootstrap state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct BsState {
    config: Arc<CorgiConfig>,
    token: Arc<String>,
    done_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

// ---------------------------------------------------------------------------
// Constant-time token comparison
// ---------------------------------------------------------------------------

fn check_token(headers: &HeaderMap, expected_token: &str) -> bool {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", expected_token);

    if auth.len() != expected.len() {
        return false;
    }
    auth.as_bytes()
        .iter()
        .zip(expected.as_bytes().iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn unauthorized() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Unauthorized" })),
    )
}

// ---------------------------------------------------------------------------
// Bootstrap directory helpers
// ---------------------------------------------------------------------------

fn bootstrap_dir(config: &CorgiConfig) -> std::path::PathBuf {
    config
        .config_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("bootstrap")
}

// ---------------------------------------------------------------------------
// Bootstrap route handlers
// ---------------------------------------------------------------------------

async fn bs_status(State(state): State<BsState>) -> Json<Value> {
    Json(json!({
        "nodeId": state.config.node_id,
        "commonName": state.config.common_name,
        "mode": "bootstrap",
    }))
}

async fn bs_csr(
    State(state): State<BsState>,
    headers: HeaderMap,
) -> impl axum::response::IntoResponse {
    if !check_token(&headers, &state.token) {
        return unauthorized().into_response();
    }

    let bs_dir = bootstrap_dir(&state.config);
    if let Err(e) = std::fs::create_dir_all(&bs_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let mut entry = node_identity_entry(&state.config);
    entry.csr_path = Some(bs_dir.join("csr.pem"));
    let key_path = bs_dir.join("key.pem");
    let csr_req = CsrRequest::default();
    let config_identity_uri = state.config.identity_uri.as_deref();

    match generate_key_and_csr(&entry, &key_path, &csr_req, config_identity_uri) {
        Ok(csr_pem) => {
            tracing::info!(key_path = %key_path.display(), "Bootstrap: ECDSA key + CSR generated");
            (StatusCode::OK, Json(json!({ "csrPem": csr_pem }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn bs_ca(
    State(state): State<BsState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Map<String, Value>>,
) -> impl axum::response::IntoResponse {
    if !check_token(&headers, &state.token) {
        return unauthorized().into_response();
    }

    let ca_pem = match body.get("caPem").and_then(|v| v.as_str()).map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "caPem is required" })),
            )
                .into_response()
        }
    };

    // Write to the configured mtls.ca_path so it is available on normal-mode restart.
    let ca_path = match &state.config.mtls.ca_path {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "mtls.caPath is not configured" })),
            )
                .into_response()
        }
    };

    if let Some(parent) = ca_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    match std::fs::write(&ca_path, &ca_pem) {
        Ok(()) => {
            let _ = set_permissions(&ca_path, 0o644);
            tracing::info!(ca_path = %ca_path.display(), "Bootstrap: Shepherd CA installed");
            (StatusCode::OK, Json(json!({ "installed": true }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn bs_cert(
    State(state): State<BsState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Map<String, Value>>,
) -> impl axum::response::IntoResponse {
    if !check_token(&headers, &state.token) {
        return unauthorized().into_response();
    }

    let cert_pem = match body.get("certPem").and_then(|v| v.as_str()).map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "certPem is required" })),
            )
                .into_response()
        }
    };

    let bs_dir = bootstrap_dir(&state.config);
    let key_path = bs_dir.join("key.pem");
    if !key_path.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Private key not found. Call GET /bootstrap/csr first." })),
        )
            .into_response();
    }

    let key_pem = match std::fs::read_to_string(&key_path) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    let chain_pem = body
        .get("chainPem")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let fullchain_pem = body
        .get("fullchainPem")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}{}", cert_pem, chain_pem));

    let fingerprint = match pem_cert_to_der(&cert_pem) {
        Ok(der) => fingerprint_display(&der),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    let entry = node_identity_entry(&state.config);
    let req = InstallRequest {
        cert_pem: Some(cert_pem),
        chain_pem: if chain_pem.is_empty() {
            None
        } else {
            Some(chain_pem)
        },
        fullchain_pem: Some(fullchain_pem),
        key_pem: Some(key_pem),
        restart: None,
    };

    if let Err(e) = install_certificate(&entry, &state.config.cert_store_dir, &req) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    // Key is now safely in archive; remove the bootstrap staging copy.
    let _ = std::fs::remove_file(&key_path);

    tracing::info!(
        cert_store_dir = %state.config.cert_store_dir.display(),
        name = %entry.name,
        fingerprint256 = %fingerprint,
        "Bootstrap: cert installed to cert store"
    );
    (
        StatusCode::OK,
        Json(json!({
            "installed": true,
            "changed": true,
            "fingerprint256": fingerprint,
        })),
    )
        .into_response()
}

async fn bs_finalize(
    State(state): State<BsState>,
    headers: HeaderMap,
) -> impl axum::response::IntoResponse {
    if !check_token(&headers, &state.token) {
        return unauthorized().into_response();
    }

    tracing::info!("Bootstrap: finalize received");
    if let Some(tx) = state.done_tx.lock().await.take() {
        let _ = tx.send(());
    }

    (StatusCode::OK, Json(json!({ "done": true }))).into_response()
}

// ---------------------------------------------------------------------------
// Test-accessible router builder (no TLS wrapping)
// ---------------------------------------------------------------------------

/// Build the bootstrap Axum router with the given token, without TLS.
/// Returns the router and a receiver that fires when POST /bootstrap/finalize is called.
/// Used by integration tests to serve the bootstrap handlers over plain HTTP on a random port.
pub fn build_bootstrap_router(
    config: Arc<CorgiConfig>,
    token: Arc<String>,
) -> (Router, oneshot::Receiver<()>) {
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let state = BsState {
        config,
        token,
        done_tx: Arc::new(Mutex::new(Some(done_tx))),
    };
    let router = Router::new()
        .route("/bootstrap/status", get(bs_status))
        .route("/bootstrap/csr", get(bs_csr))
        .route("/bootstrap/ca", post(bs_ca))
        .route("/bootstrap/cert", post(bs_cert))
        .route("/bootstrap/finalize", post(bs_finalize))
        .with_state(state);
    (router, done_rx)
}

// ---------------------------------------------------------------------------
// Bootstrap server entry point
// ---------------------------------------------------------------------------

pub async fn run_bootstrap(config: Arc<CorgiConfig>) -> Result<()> {
    // Generate ephemeral self-signed cert for the bootstrap TLS server
    let (bs_cert_pem, bs_key_pem) =
        generate_bootstrap_cert(&config.common_name, config.identity_uri.as_deref())
            .context("Generating bootstrap cert")?;

    let der = pem_cert_to_der(&bs_cert_pem)?;
    // Use bare lowercase hex (no colons) so the bootstrap wizard can capture with a simple regex.
    // fingerprint_display is reserved for the colon format that the dashboard expects.
    let fingerprint = hex::encode(sha2::Sha256::digest(&der));
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut token_bytes);
    let token = hex::encode(token_bytes);

    println!();
    println!("  Node ID:               {}", config.node_id);
    println!("  Common name:           {}", config.common_name);
    println!("  Port:                  {}", config.mtls_port);
    println!();
    println!("  Corgi bootstrap fingerprint: {}", fingerprint);
    println!("  Corgi bootstrap token:       {}", token);
    println!();

    let tls_config = build_ephemeral_tls(&bs_cert_pem, &bs_key_pem)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let listener = bind_tcp(&config.bind, config.mtls_port)
        .await
        .context("Binding bootstrap port")?;

    tracing::info!(port = config.mtls_port, "Bootstrap HTTPS server listening");

    let (done_tx, done_rx) = oneshot::channel::<()>();

    let state = BsState {
        config,
        token: Arc::new(token),
        done_tx: Arc::new(Mutex::new(Some(done_tx))),
    };

    let router = Router::new()
        .route("/bootstrap/status", get(bs_status))
        .route("/bootstrap/csr", get(bs_csr))
        .route("/bootstrap/ca", post(bs_ca))
        .route("/bootstrap/cert", post(bs_cert))
        .route("/bootstrap/finalize", post(bs_finalize))
        .with_state(state);

    let accept_loop = async move {
        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "Bootstrap TCP accept error");
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let router = router.clone();

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, peer = %peer_addr, "Bootstrap TLS failed");
                        return;
                    }
                };

                let io = TokioIo::new(tls_stream);
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let router = router.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let req = hyper::Request::from_parts(parts, Body::new(body));
                            use tower::ServiceExt;
                            router
                                .oneshot(req)
                                .await
                                .map_err(|_| -> std::convert::Infallible { unreachable!() })
                        }
                    },
                );

                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    tracing::debug!(error = %e, "Bootstrap connection error");
                }
            });
        }
    };

    tokio::select! {
        _ = accept_loop => {},
        _ = done_rx => {
            tracing::info!("Bootstrap finalized — exiting bootstrap mode");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn node_identity_entry(config: &CorgiConfig) -> crate::config::FlockEntry {
    config
        .flock
        .iter()
        .find(|e| e.name == "node-identity" || e.name == config.common_name)
        .cloned()
        .unwrap_or_else(|| crate::config::FlockEntry {
            name: config.common_name.clone(),
            path: config.tls.cert_path.clone(),
            key_path: config.tls.key_path.clone(),
            chain_path: config.chain_path.clone(),
            fullchain_path: config.fullchain_path.clone(),
            csr_path: config.csr_path.clone(),
            domain: None,
            monitor: false,
            hooks: None,
            csr_subject: Some(crate::types::CsrSubjectWire {
                common_name: Some(config.common_name.clone()),
                country: None,
                state: None,
                locality: None,
                organization: None,
                organizational_unit: None,
                email_address: None,
            }),
            identity_uri: config.identity_uri.clone(),
            sans: vec![],
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
        })
}

fn build_ephemeral_tls(cert_pem: &str, key_pem: &str) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::ServerConfig;
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("Parsing bootstrap cert")?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
        .context("Parsing bootstrap key")?
        .ok_or_else(|| anyhow::anyhow!("No key found in bootstrap key PEM"))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Building bootstrap TLS config")?;
    Ok(Arc::new(config))
}
