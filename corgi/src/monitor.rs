use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use credo_lib::types::{EndpointCheckResult, MonitorConfig, MonitorResult, MonitorStatus};

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

/// Probe every endpoint configured for one flock entry (a SAN cert may
/// configure several) and record the aggregated result.
pub async fn check_one(state: &crate::state::AppState, entry: &crate::config::FlockEntry) {
    let Some(configs) = &entry.monitor else {
        return;
    };
    let expected = crate::cert_ops::read_cert_fingerprint(&entry.path);

    let mut endpoints = Vec::with_capacity(configs.len());
    for cfg in configs {
        let sni = entry.domain.as_deref().unwrap_or(&cfg.host);
        let result = check_one_endpoint(cfg, sni, expected.as_deref()).await;
        match result.status {
            MonitorStatus::Ok => {
                tracing::debug!(
                    cert = %entry.name,
                    host = %result.host,
                    port = result.port,
                    sni = %result.sni,
                    resolved_addr = result.resolved_addr.as_deref().unwrap_or(""),
                    seen_fingerprint = result.seen_fingerprint.as_deref().unwrap_or(""),
                    "Endpoint monitor check ok"
                );
            }
            _ => {
                tracing::warn!(
                    cert = %entry.name,
                    host = %result.host,
                    port = result.port,
                    sni = %result.sni,
                    resolved_addr = result.resolved_addr.as_deref().unwrap_or(""),
                    seen_fingerprint = result.seen_fingerprint.as_deref().unwrap_or(""),
                    expected_fingerprint = expected.as_deref().unwrap_or(""),
                    status = ?result.status,
                    error = result.error.as_deref().unwrap_or(""),
                    "Endpoint monitor check not ok"
                );
            }
        }
        endpoints.push(result);
    }

    let result = aggregate_endpoints(endpoints);
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

/// Successful probe of one endpoint: what was actually dialed and served.
struct EndpointProbe {
    resolved_addr: SocketAddr,
    seen_fingerprint: String,
    /// `None` when the endpoint has no `ca_path` configured.
    chain_trusted: Option<bool>,
}

/// Resolve the address(es) to dial: `resolve_ip` pins a single address and
/// skips DNS entirely; otherwise resolve `host` and try each candidate in
/// turn, mirroring `TcpStream::connect`'s own multi-candidate fallback so
/// connect behavior is unchanged from before — just now observable.
async fn resolve_candidates(cfg: &MonitorConfig) -> anyhow::Result<Vec<SocketAddr>> {
    if let Some(ip) = cfg.resolve_ip {
        return Ok(vec![SocketAddr::new(ip, cfg.port)]);
    }
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let candidates: Vec<SocketAddr> = tokio::net::lookup_host(&addr)
        .await
        .with_context(|| format!("resolving {}", addr))?
        .collect();
    if candidates.is_empty() {
        anyhow::bail!("no addresses resolved for {}", addr);
    }
    Ok(candidates)
}

async fn connect_first(
    addrs: &[SocketAddr],
) -> anyhow::Result<(SocketAddr, tokio::net::TcpStream)> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok((*addr, stream)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "connecting to {:?}: {}",
        addrs,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no addresses resolved".into())
    ))
}

/// TLS-handshake an endpoint and return the SHA-256 fingerprint of the leaf
/// certificate it serves, plus what address was actually dialed and (if
/// `ca_path` is configured) whether the served chain verifies against it.
/// The chain is never required to verify for the handshake itself: an
/// expired, self-signed, or wrong-CA cert is data for the mismatch check,
/// not a connection error. `Unreachable` means TCP or handshake failure only.
async fn probe_endpoint(cfg: &MonitorConfig, sni: &str) -> anyhow::Result<EndpointProbe> {
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from(cfg.host.clone()))
        .with_context(|| format!("invalid server name '{}'", sni))?;

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let handshake = async {
        let candidates = resolve_candidates(cfg).await?;
        let (resolved_addr, tcp) = connect_first(&candidates).await?;
        let tls = connector
            .connect(server_name.clone(), tcp)
            .await
            .with_context(|| format!("TLS handshake with {}", resolved_addr))?;
        let (_, conn) = tls.get_ref();
        let certs = conn
            .peer_certificates()
            .with_context(|| format!("no peer certificates from {}", resolved_addr))?;
        let leaf = certs
            .first()
            .with_context(|| format!("no peer certificate from {}", resolved_addr))?;
        let seen_fingerprint = fingerprint_display(leaf.as_ref());
        let chain_trusted = cfg
            .ca_path
            .as_deref()
            .map(|ca_path| verify_chain_trusted(ca_path, &server_name, certs));
        Ok(EndpointProbe {
            resolved_addr,
            seen_fingerprint,
            chain_trusted,
        })
    };

    tokio::time::timeout(CONNECT_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "timeout connecting to {}:{} after {:?}",
                cfg.host,
                cfg.port,
                CONNECT_TIMEOUT
            )
        })?
}

/// Whether the served chain (leaf + any intermediates) verifies against the
/// CA bundle at `ca_path`. Best-effort and diagnostic only: any failure to
/// load or parse the CA bundle is reported as untrusted rather than erroring
/// the whole endpoint check, since a bad `ca_path` shouldn't turn an
/// otherwise-healthy fingerprint match into `Unreachable`.
fn verify_chain_trusted(
    ca_path: &str,
    server_name: &rustls::pki_types::ServerName<'_>,
    certs: &[rustls::pki_types::CertificateDer<'_>],
) -> bool {
    let Some((leaf, intermediates)) = certs.split_first() else {
        return false;
    };
    let Ok(roots) = load_root_store(ca_path) else {
        return false;
    };
    let Ok(verifier) = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build()
    else {
        return false;
    };
    use rustls::client::danger::ServerCertVerifier;
    verifier
        .verify_server_cert(
            leaf,
            intermediates,
            server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .is_ok()
}

fn load_root_store(ca_path: &str) -> anyhow::Result<rustls::RootCertStore> {
    let file =
        std::fs::File::open(ca_path).with_context(|| format!("opening CA bundle {}", ca_path))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(file)).flatten() {
        roots.add(cert).ok();
    }
    Ok(roots)
}

/// Probe one endpoint and map the outcome against the locally installed
/// cert's fingerprint (None = no cert installed locally) into a full
/// diagnostic record: what was dialed, what was seen, why it did or didn't
/// match.
pub async fn check_one_endpoint(
    cfg: &MonitorConfig,
    sni: &str,
    expected_fingerprint: Option<&str>,
) -> EndpointCheckResult {
    let probe = probe_endpoint(cfg, sni)
        .await
        .map_err(|e| format!("{:#}", e));
    match probe {
        Ok(p) => {
            let status = if expected_fingerprint == Some(p.seen_fingerprint.as_str()) {
                MonitorStatus::Ok
            } else {
                MonitorStatus::CertMismatch
            };
            EndpointCheckResult {
                host: cfg.host.clone(),
                port: cfg.port,
                sni: sni.to_string(),
                resolved_addr: Some(p.resolved_addr.to_string()),
                seen_fingerprint: Some(p.seen_fingerprint),
                chain_trusted: p.chain_trusted,
                status,
                error: None,
            }
        }
        Err(e) => EndpointCheckResult {
            host: cfg.host.clone(),
            port: cfg.port,
            sni: sni.to_string(),
            resolved_addr: None,
            seen_fingerprint: None,
            chain_trusted: None,
            status: MonitorStatus::Unreachable,
            error: Some(e),
        },
    }
}

/// Combine per-endpoint results into one overall status: `Ok` only if every
/// endpoint matched, `PartialSuccess` when some did and some didn't (a SAN
/// cert served from several hosts, one of which is stale or unreachable),
/// otherwise the pre-existing single-endpoint priority (a mismatch is more
/// informative than a bare connection failure) when none matched.
fn aggregate_endpoints(endpoints: Vec<EndpointCheckResult>) -> MonitorResult {
    let checked_at = Some(chrono::Utc::now().to_rfc3339());
    let ok_count = endpoints
        .iter()
        .filter(|e| e.status == MonitorStatus::Ok)
        .count();

    let status = if endpoints.is_empty() {
        MonitorStatus::Unreachable
    } else if ok_count == endpoints.len() {
        MonitorStatus::Ok
    } else if ok_count > 0 {
        MonitorStatus::PartialSuccess
    } else if endpoints
        .iter()
        .any(|e| e.status == MonitorStatus::CertMismatch)
    {
        MonitorStatus::CertMismatch
    } else {
        MonitorStatus::Unreachable
    };

    // Single endpoint: top-level fields mirror it exactly, unchanged from
    // before multi-endpoint support existed. Several endpoints: ambiguous
    // which fingerprint to surface at the top level, so leave it unset —
    // full detail lives in `endpoints`.
    let (seen_fingerprint, error) = match endpoints.as_slice() {
        [only] => (only.seen_fingerprint.clone(), only.error.clone()),
        _ => {
            let errors: Vec<String> = endpoints
                .iter()
                .filter_map(|e| e.error.as_ref().map(|err| format!("{}: {}", e.host, err)))
                .collect();
            (
                None,
                if errors.is_empty() {
                    None
                } else {
                    Some(errors.join("; "))
                },
            )
        }
    };

    MonitorResult {
        status,
        checked_at,
        seen_fingerprint,
        error,
        endpoints,
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

    /// A CA cert plus a leaf signed by it, for `ca_path` chain-trust tests.
    fn ca_and_signed_leaf(names: Vec<String>) -> (String, String, String) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new());
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "Test CA");
            dn
        };
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        let leaf_cert =
            rcgen::Certificate::from_params(rcgen::CertificateParams::new(names)).unwrap();
        let leaf_pem = leaf_cert.serialize_pem_with_signer(&ca_cert).unwrap();
        let leaf_key_pem = leaf_cert.serialize_private_key_pem();
        let ca_pem = ca_cert.serialize_pem().unwrap();

        (ca_pem, leaf_pem, leaf_key_pem)
    }

    fn write_temp_pem(pem: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        f
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
            ca_path: None,
            resolve_ip: None,
        }
    }

    #[tokio::test]
    async fn check_one_endpoint_returns_served_leaf_fingerprint_and_dialed_address() {
        // Self-signed on purpose: the checker must capture the leaf without
        // verifying the chain — an untrusted cert is data, not an error.
        let (cert_pem, key_pem) = self_signed(vec!["localhost".into()]);
        let addr = spawn_tls_server(&cert_pem, &key_pem).await;

        let der = crate::cert_ops::pem_cert_to_der(&cert_pem).unwrap();
        let expected = crate::cert_ops::fingerprint_display(&der);

        let result = check_one_endpoint(&monitor_cfg(addr), "localhost", Some(&expected)).await;

        assert_eq!(result.status, MonitorStatus::Ok);
        assert_eq!(result.seen_fingerprint.as_deref(), Some(expected.as_str()));
        assert_eq!(
            result.resolved_addr.as_deref(),
            Some(addr.to_string().as_str())
        );
        assert_eq!(result.sni, "localhost");
        assert!(result.chain_trusted.is_none(), "no ca_path configured");
    }

    #[tokio::test]
    async fn check_one_endpoint_errors_on_closed_port() {
        // Bind then drop to obtain a port that is definitely closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = check_one_endpoint(&monitor_cfg(addr), "localhost", None).await;
        assert_eq!(result.status, MonitorStatus::Unreachable);
        assert!(result.error.is_some());
        assert!(result.seen_fingerprint.is_none());
    }

    #[tokio::test]
    async fn check_one_endpoint_resolve_ip_override_bypasses_dns() {
        // Point `host` at a name that can never resolve; `resolve_ip` must
        // still let the connection through by skipping DNS entirely.
        let (cert_pem, key_pem) = self_signed(vec!["localhost".into()]);
        let addr = spawn_tls_server(&cert_pem, &key_pem).await;

        let mut cfg = monitor_cfg(addr);
        cfg.host = "this-name-does-not-resolve.invalid".to_string();
        cfg.resolve_ip = Some(addr.ip());

        let result = check_one_endpoint(&cfg, "localhost", None).await;
        assert_eq!(result.status, MonitorStatus::CertMismatch); // no expected fp given
        assert!(
            result.seen_fingerprint.is_some(),
            "handshake must succeed via the pinned IP"
        );
        assert_eq!(
            result.resolved_addr.as_deref(),
            Some(addr.to_string().as_str())
        );
    }

    #[tokio::test]
    async fn check_one_endpoint_ca_path_reports_chain_trust() {
        let (ca_pem, leaf_pem, leaf_key_pem) = ca_and_signed_leaf(vec!["localhost".into()]);
        let addr = spawn_tls_server(&leaf_pem, &leaf_key_pem).await;

        let ca_file = write_temp_pem(&ca_pem);
        let mut cfg = monitor_cfg(addr);
        cfg.ca_path = Some(ca_file.path().to_str().unwrap().to_string());
        let result = check_one_endpoint(&cfg, "localhost", None).await;
        assert_eq!(result.chain_trusted, Some(true));

        // An unrelated CA must not validate the same served chain.
        let (other_ca_pem, _, _) = ca_and_signed_leaf(vec!["localhost".into()]);
        let other_ca_file = write_temp_pem(&other_ca_pem);
        let mut cfg = monitor_cfg(addr);
        cfg.ca_path = Some(other_ca_file.path().to_str().unwrap().to_string());
        let result = check_one_endpoint(&cfg, "localhost", None).await;
        assert_eq!(result.chain_trusted, Some(false));
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

        entry.monitor = Some(vec![MonitorConfig {
            host: "api.example.com".into(),
            port: 443,
            protocol: MonitorProtocol::Https,
            ca_path: None,
            resolve_ip: None,
        }]);
        assert_eq!(
            monitor_result_for(&entry, &results).status,
            MonitorStatus::Pending
        );

        results.insert(
            "api.example.com".into(),
            aggregate_endpoints(vec![EndpointCheckResult {
                host: "api.example.com".into(),
                port: 443,
                sni: "api.example.com".into(),
                resolved_addr: Some("203.0.113.1:443".into()),
                seen_fingerprint: Some("AA:BB".into()),
                chain_trusted: None,
                status: MonitorStatus::Ok,
                error: None,
            }]),
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

    fn endpoint_result(
        status: MonitorStatus,
        seen: Option<&str>,
        error: Option<&str>,
    ) -> EndpointCheckResult {
        EndpointCheckResult {
            host: "api.example.com".into(),
            port: 443,
            sni: "api.example.com".into(),
            resolved_addr: Some("203.0.113.1:443".into()),
            seen_fingerprint: seen.map(str::to_string),
            chain_trusted: None,
            status,
            error: error.map(str::to_string),
        }
    }

    #[test]
    fn aggregate_endpoints_single_ok() {
        let result = aggregate_endpoints(vec![endpoint_result(
            MonitorStatus::Ok,
            Some("AA:BB"),
            None,
        )]);
        assert_eq!(result.status, MonitorStatus::Ok);
        assert_eq!(result.seen_fingerprint.as_deref(), Some("AA:BB"));
        assert!(result.checked_at.is_some());
        assert_eq!(result.endpoints.len(), 1);
    }

    #[test]
    fn aggregate_endpoints_single_mismatch() {
        let result = aggregate_endpoints(vec![endpoint_result(
            MonitorStatus::CertMismatch,
            Some("CC:DD"),
            None,
        )]);
        assert_eq!(result.status, MonitorStatus::CertMismatch);
        assert_eq!(result.seen_fingerprint.as_deref(), Some("CC:DD"));
    }

    #[test]
    fn aggregate_endpoints_single_unreachable() {
        let result = aggregate_endpoints(vec![endpoint_result(
            MonitorStatus::Unreachable,
            None,
            Some("connect timeout"),
        )]);
        assert_eq!(result.status, MonitorStatus::Unreachable);
        assert_eq!(result.error.as_deref(), Some("connect timeout"));
        assert!(result.seen_fingerprint.is_none());
    }

    #[test]
    fn aggregate_endpoints_all_ok_is_ok() {
        let result = aggregate_endpoints(vec![
            endpoint_result(MonitorStatus::Ok, Some("AA:BB"), None),
            endpoint_result(MonitorStatus::Ok, Some("AA:BB"), None),
        ]);
        assert_eq!(result.status, MonitorStatus::Ok);
        // Ambiguous across multiple endpoints — full detail lives in `endpoints`.
        assert!(result.seen_fingerprint.is_none());
        assert_eq!(result.endpoints.len(), 2);
    }

    #[test]
    fn aggregate_endpoints_mixed_is_partial_success() {
        let result = aggregate_endpoints(vec![
            endpoint_result(MonitorStatus::Ok, Some("AA:BB"), None),
            endpoint_result(MonitorStatus::CertMismatch, Some("CC:DD"), None),
        ]);
        assert_eq!(result.status, MonitorStatus::PartialSuccess);
    }

    #[test]
    fn aggregate_endpoints_none_ok_prefers_mismatch_over_unreachable() {
        let result = aggregate_endpoints(vec![
            endpoint_result(MonitorStatus::CertMismatch, Some("CC:DD"), None),
            endpoint_result(MonitorStatus::Unreachable, None, Some("timeout")),
        ]);
        assert_eq!(result.status, MonitorStatus::CertMismatch);
        let joined_error = result
            .error
            .expect("errors from unreachable endpoints are joined");
        assert!(joined_error.contains("timeout"));
    }

    #[test]
    fn aggregate_endpoints_all_unreachable() {
        let result = aggregate_endpoints(vec![
            endpoint_result(MonitorStatus::Unreachable, None, Some("timeout")),
            endpoint_result(MonitorStatus::Unreachable, None, Some("refused")),
        ]);
        assert_eq!(result.status, MonitorStatus::Unreachable);
    }
}
