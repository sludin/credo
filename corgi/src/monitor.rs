use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use credo_lib::types::{MonitorConfig, MonitorResult, MonitorStatus};

use crate::cert_ops::fingerprint_display;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Give the service hook time to reload before the post-install check.
const POST_INSTALL_CHECK_DELAY: Duration = Duration::from_secs(5);
const SWEEP_JITTER_FRAC: f64 = 0.1;
/// Let the startup reconcile populate the flock before the first sweep.
const STARTUP_DELAY: Duration = Duration::from_secs(15);

/// Periodic endpoint-monitor sweep over all flock entries with monitor
/// config. Slow by design: this hunts config errors (a hook that didn't
/// reload, a vhost on an old cert), not uptime — installs additionally
/// trigger an immediate one-shot check.
pub async fn run_monitor_loop(state: crate::state::AppState) {
    tokio::time::sleep(STARTUP_DELAY).await;
    tracing::info!(
        interval_seconds = state.config.load().monitor_interval_seconds,
        "Starting endpoint monitor loop"
    );
    loop {
        monitor_sweep(&state).await;
        let interval = state.config.load().monitor_interval_seconds;
        tokio::time::sleep(credo_lib::timing::jittered_duration(
            interval,
            SWEEP_JITTER_FRAC,
        ))
        .await;
    }
}

async fn monitor_sweep(state: &crate::state::AppState) {
    let flock = state.flock.read().await.clone();
    for entry in flock.iter().filter(|e| e.monitor.is_some()) {
        check_one(state, entry).await;
    }
    // Drop results for certs that left the flock or lost their endpoint.
    let monitored: std::collections::HashSet<&String> = flock
        .iter()
        .filter(|e| e.monitor.is_some())
        .map(|e| &e.name)
        .collect();
    state
        .monitor_results
        .write()
        .await
        .retain(|name, _| monitored.contains(name));
}

/// Probe one flock entry's endpoint and record the result.
pub async fn check_one(state: &crate::state::AppState, entry: &crate::config::FlockEntry) {
    let Some(cfg) = &entry.monitor else {
        return;
    };
    let sni = entry.domain.as_deref().unwrap_or(&cfg.host);
    let expected = crate::cert_ops::read_cert_fingerprint(&entry.path);
    let probe = check_endpoint(cfg, sni)
        .await
        .map_err(|e| format!("{:#}", e));
    let result = evaluate_probe(expected.as_deref(), probe);
    match result.status {
        MonitorStatus::Ok => {
            tracing::debug!(cert = %entry.name, host = %cfg.host, port = cfg.port, "Endpoint monitor check ok");
        }
        _ => {
            tracing::warn!(
                cert = %entry.name,
                host = %cfg.host,
                port = cfg.port,
                status = ?result.status,
                error = result.error.as_deref().unwrap_or(""),
                "Endpoint monitor check not ok"
            );
        }
    }
    state
        .monitor_results
        .write()
        .await
        .insert(entry.name.clone(), result);
}

/// One-shot check shortly after a cert install: a hook that failed to reload
/// the service shows up as a mismatch within seconds instead of next sweep.
pub fn schedule_post_install_check(state: &crate::state::AppState, cert_name: String) {
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(POST_INSTALL_CHECK_DELAY).await;
        if let Some(entry) = crate::assignments::find_flock_entry(&state, &cert_name).await {
            check_one(&state, &entry).await;
        }
    });
}

/// TLS-handshake `host:port` and return the SHA-256 fingerprint of the leaf
/// certificate the endpoint serves. The chain is deliberately NOT verified:
/// an expired, self-signed, or wrong-CA cert is data for the mismatch check,
/// not a connection error. Unreachable means TCP or handshake failure only.
pub async fn check_endpoint(cfg: &MonitorConfig, sni: &str) -> anyhow::Result<String> {
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from(cfg.host.clone()))
        .with_context(|| format!("invalid server name '{}'", sni))?;

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let handshake = async {
        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connecting to {}", addr))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("TLS handshake with {}", addr))?;
        let (_, conn) = tls.get_ref();
        let leaf = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .with_context(|| format!("no peer certificate from {}", addr))?;
        Ok(fingerprint_display(leaf.as_ref()))
    };

    tokio::time::timeout(CONNECT_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            anyhow::anyhow!("timeout connecting to {} after {:?}", addr, CONNECT_TIMEOUT)
        })?
}

/// Map a probe outcome to a MonitorResult against the locally installed
/// cert's fingerprint (None = no cert installed locally).
pub fn evaluate_probe(
    expected_fingerprint: Option<&str>,
    probe: Result<String, String>,
) -> MonitorResult {
    let checked_at = Some(chrono::Utc::now().to_rfc3339());
    match probe {
        Ok(seen) => {
            let status = if expected_fingerprint == Some(seen.as_str()) {
                MonitorStatus::Ok
            } else {
                MonitorStatus::CertMismatch
            };
            MonitorResult {
                status,
                checked_at,
                seen_fingerprint: Some(seen),
                error: None,
            }
        }
        Err(e) => MonitorResult {
            status: MonitorStatus::Unreachable,
            checked_at,
            seen_fingerprint: None,
            error: Some(e),
        },
    }
}

/// The monitor result to report for a flock entry: unmonitored without an
/// endpoint config, pending until the first check lands, else the latest.
pub fn monitor_result_for(
    entry: &crate::config::FlockEntry,
    results: &std::collections::HashMap<String, MonitorResult>,
) -> MonitorResult {
    if entry.monitor.is_none() {
        return MonitorResult::unmonitored();
    }
    results
        .get(&entry.name)
        .cloned()
        .unwrap_or_else(MonitorResult::pending)
}

/// Accepts any server certificate so the handshake always completes and the
/// served leaf can be captured for fingerprint comparison. Only used by the
/// endpoint monitor — never for real client connections.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credo_lib::types::{MonitorConfig, MonitorProtocol, MonitorStatus};
    use std::sync::Arc;

    fn self_signed(names: Vec<String>) -> (String, String) {
        let cert = rcgen::Certificate::from_params(rcgen::CertificateParams::new(names)).unwrap();
        (
            cert.serialize_pem().unwrap(),
            cert.serialize_private_key_pem(),
        )
    }

    async fn spawn_tls_server(cert_pem: &str, key_pem: &str) -> std::net::SocketAddr {
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
            .unwrap()
            .unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acc.accept(stream).await {
                        use tokio::io::AsyncReadExt;
                        let _ = tls.read(&mut [0u8; 1]).await;
                    }
                });
            }
        });
        addr
    }

    fn monitor_cfg(addr: std::net::SocketAddr) -> MonitorConfig {
        MonitorConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            protocol: MonitorProtocol::Https,
        }
    }

    #[tokio::test]
    async fn check_endpoint_returns_served_leaf_fingerprint() {
        // Self-signed on purpose: the checker must capture the leaf without
        // verifying the chain — an untrusted cert is data, not an error.
        let (cert_pem, key_pem) = self_signed(vec!["localhost".into()]);
        let addr = spawn_tls_server(&cert_pem, &key_pem).await;

        let served = check_endpoint(&monitor_cfg(addr), "localhost")
            .await
            .unwrap();

        let der = crate::cert_ops::pem_cert_to_der(&cert_pem).unwrap();
        assert_eq!(served, crate::cert_ops::fingerprint_display(&der));
    }

    #[tokio::test]
    async fn check_endpoint_errors_on_closed_port() {
        // Bind then drop to obtain a port that is definitely closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = check_endpoint(&monitor_cfg(addr), "localhost").await;
        assert!(result.is_err());
    }

    #[test]
    fn monitor_result_for_reports_unmonitored_pending_or_latest() {
        use std::collections::HashMap;

        let mut entry = crate::config::FlockEntry {
            name: "api.example.com".into(),
            path: "/nonexistent/cert.pem".into(),
            key_path: "/nonexistent/key.pem".into(),
            chain_path: None,
            fullchain_path: None,
            csr_path: None,
            domain: None,
            monitor: None,
            hooks: None,
            csr_subject: None,
            identity_uri: None,
            sans: vec![],
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
        };
        let mut results: HashMap<String, MonitorResult> = HashMap::new();

        assert_eq!(
            monitor_result_for(&entry, &results).status,
            MonitorStatus::Unmonitored
        );

        entry.monitor = Some(MonitorConfig {
            host: "api.example.com".into(),
            port: 443,
            protocol: MonitorProtocol::Https,
        });
        assert_eq!(
            monitor_result_for(&entry, &results).status,
            MonitorStatus::Pending
        );

        results.insert(
            "api.example.com".into(),
            evaluate_probe(Some("AA:BB"), Ok("AA:BB".into())),
        );
        assert_eq!(
            monitor_result_for(&entry, &results).status,
            MonitorStatus::Ok
        );

        // Summaries carry the result on the wire for shepherd's flock probe.
        let summary = crate::cert_ops::to_flock_summary(&entry, &results);
        let v = serde_json::to_value(&summary).unwrap();
        assert_eq!(v["monitor"]["status"], "ok");
    }

    #[test]
    fn evaluate_probe_maps_results_to_statuses() {
        let ok = evaluate_probe(Some("AA:BB"), Ok("AA:BB".into()));
        assert_eq!(ok.status, MonitorStatus::Ok);
        assert_eq!(ok.seen_fingerprint.as_deref(), Some("AA:BB"));
        assert!(ok.checked_at.is_some());

        let mismatch = evaluate_probe(Some("AA:BB"), Ok("CC:DD".into()));
        assert_eq!(mismatch.status, MonitorStatus::CertMismatch);
        assert_eq!(mismatch.seen_fingerprint.as_deref(), Some("CC:DD"));

        // Endpoint serves a cert while corgi has none installed: that is a
        // mismatch, not an unknown — the endpoint disagrees with local state.
        let no_local = evaluate_probe(None, Ok("CC:DD".into()));
        assert_eq!(no_local.status, MonitorStatus::CertMismatch);

        let unreachable = evaluate_probe(Some("AA:BB"), Err("connect timeout".into()));
        assert_eq!(unreachable.status, MonitorStatus::Unreachable);
        assert_eq!(unreachable.error.as_deref(), Some("connect timeout"));
        assert!(unreachable.seen_fingerprint.is_none());
    }
}
