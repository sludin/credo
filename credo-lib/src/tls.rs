/// Shared TLS server helpers.
///
/// Provides `PeerCertDer`, PEM loaders, `build_server_tls`, and `serve_tls`.
/// Each service calls `serve_tls` with its own pre-built axum Router.
use anyhow::{Context, Result};
use axum::body::Body;
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// Raw DER bytes of the client certificate from the TLS handshake.
/// Injected into request extensions by the TLS acceptor loop.
#[derive(Clone, Debug)]
pub struct PeerCertDer(pub Vec<u8>);

// ---------------------------------------------------------------------------
// PEM loaders
// ---------------------------------------------------------------------------

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Opening cert file: {}", path.display()))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Reading certs from: {}", path.display()))
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Opening key file: {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("Reading private key from: {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("No private key in: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Server TLS config
// ---------------------------------------------------------------------------

/// Build a rustls `ServerConfig` that requests (but does not require) a client cert.
/// `client_ca_path`: if `Some`, loads the CA bundle for client cert chain validation;
/// if `None`, allows any client cert (or none) — corgi uses this when no CA is configured.
pub fn build_server_tls(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key   = load_private_key(key_path)?;

    let client_verifier = match client_ca_path {
        Some(ca_path) => {
            let ca_file = std::fs::File::open(ca_path)
                .with_context(|| format!("Opening client CA: {}", ca_path.display()))?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut BufReader::new(ca_file)).flatten() {
                roots.add(cert).ok();
            }
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()
                .context("Building WebPKI client verifier")?
        }
        None => {
            rustls::server::WebPkiClientVerifier::builder(Arc::new(rustls::RootCertStore::empty()))
                .allow_unauthenticated()
                .build()
                .context("Building permissive client verifier")?
        }
    };

    Ok(Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .context("Building TLS server config")?,
    ))
}

// ---------------------------------------------------------------------------
// TCP bind helper
// ---------------------------------------------------------------------------

pub async fn bind_tcp(addr: &str, port: u16) -> Result<TcpListener> {
    let socket_addr: SocketAddr = format!("{}:{}", addr, port)
        .parse()
        .with_context(|| format!("Parsing bind address {}:{}", addr, port))?;
    TcpListener::bind(socket_addr)
        .await
        .with_context(|| format!("Binding to {}:{}", addr, port))
}

// ---------------------------------------------------------------------------
// mTLS HTTPS accept loop
// ---------------------------------------------------------------------------

/// Accept TLS connections, inject `PeerCertDer` into request extensions, serve
/// with the provided axum Router. Runs until the process exits.
pub async fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor, router: Router) {
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "TCP accept error");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let router   = router.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, peer = %peer_addr, "TLS handshake failed");
                    return;
                }
            };

            let peer_cert = tls_stream
                .get_ref().1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| PeerCertDer(c.as_ref().to_vec()));

            let io = TokioIo::new(tls_stream);

            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let router    = router.clone();
                let peer_cert = peer_cert.clone();
                async move {
                    let (mut parts, body) = req.into_parts();
                    if let Some(cert) = peer_cert {
                        parts.extensions.insert(cert);
                    }
                    parts.extensions.insert(peer_addr);
                    let req = hyper::Request::from_parts(parts, Body::new(body));
                    router
                        .oneshot(req)
                        .await
                        .map_err(|_| -> std::convert::Infallible { unreachable!() })
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!(error = %e, peer = %peer_addr, "Connection error");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Plain HTTP accept loop (ACME challenge listener — corgi)
// ---------------------------------------------------------------------------

pub async fn serve_http(listener: TcpListener, router: Router) {
    loop {
        let (tcp_stream, _peer_addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "TCP accept error on HTTP server");
                continue;
            }
        };

        let router = router.clone();
        tokio::spawn(async move {
            let io  = TokioIo::new(tcp_stream);
            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let router = router.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let req = hyper::Request::from_parts(parts, Body::new(body));
                    router
                        .oneshot(req)
                        .await
                        .map_err(|_| -> std::convert::Infallible { unreachable!() })
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!(error = %e, "HTTP connection error");
            }
        });
    }
}
