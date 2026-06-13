use anyhow::{Context, Result};
use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder, Order, OrderStatus};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

use uuid::Uuid;

use crate::acme_client::AcmeAccountCache;
use crate::cert_store::persist_issued_material;
use crate::corgi_client::{corgi_delete, corgi_post, CorgiClientPool};
use crate::dns_providers::{create_provider, DnsProviderContext};
use crate::issuance_ledger::{canonical_sans, extract_registered_domain, IssuanceLedger};
use crate::renewal_jobs::{append_trace, update_phase, JobStore};
use crate::types::{AcmeCaConfig, CorgiNodeConfig, IssuanceEvent, ManagedAssignment, RenewalPhase};

// ---------------------------------------------------------------------------
// Public result type
// ---------------------------------------------------------------------------

pub struct IssuanceResult {
    pub cert_pem: String,
    pub chain_pem: String,
    pub fullchain_pem: String,
    pub fingerprint256: String,
    pub issued: bool,
    pub changed: bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Rate-limit error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RateLimitedError {
    pub retry_after: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Display for RateLimitedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rate limited until {}", self.retry_after)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn issue_cert(
    ca_config: &AcmeCaConfig,
    ca_name: &str,
    cert_name: &str,
    cert_store_dir: &std::path::Path,
    domains: &[String],
    csr_pem: &str,
    assignment: &ManagedAssignment,
    pool: &Arc<RwLock<CorgiClientPool>>,
    corgis: &[CorgiNodeConfig],
    account_cache: &AcmeAccountCache,
    ledger: &Arc<RwLock<IssuanceLedger>>,
    jobs: &JobStore,
    job_id: Uuid,
) -> Result<IssuanceResult> {
    if domains.is_empty() {
        anyhow::bail!("at least one domain is required for ACME issuance of '{cert_name}'");
    }

    // Check rate limits before making any ACME network call.
    let sans = canonical_sans(assignment);
    {
        let ledger_read = ledger.read().await;
        if let Some(retry_after) =
            ledger_read.rate_limit_check(&sans, ca_name, ca_config.rate_limits.as_ref())
        {
            return Err(anyhow::anyhow!(RateLimitedError { retry_after }));
        }
    }

    append_trace(jobs, job_id, "order-submitted", Some(ca_name), None, None).await;

    let csr_der = pem_to_csr_der(csr_pem)
        .ok_or_else(|| anyhow::anyhow!("Could not parse CSR PEM for '{cert_name}'"))?;

    let account = account_cache
        .get_or_create(ca_name, ca_config)
        .await
        .with_context(|| format!("Getting ACME account for CA '{ca_name}'"))?;

    let validation_method = resolve_validation_method(ca_config, assignment);
    let force_revalidate = assignment
        .validation
        .as_ref()
        .map(|v| v.force_revalidate)
        .unwrap_or(false);

    // Resolve the http challenge port from the assigned Corgi (if any).
    let http_challenge_port = assignment
        .corgi
        .as_deref()
        .and_then(|name| corgis.iter().find(|c| c.name == name))
        .and_then(|c| c.http_challenge_port);

    let cert_chain = run_issuance(
        &account,
        ca_config,
        ca_name,
        cert_name,
        domains,
        &csr_der,
        &validation_method,
        http_challenge_port,
        force_revalidate,
        assignment,
        pool,
        corgis,
        jobs,
        job_id,
    )
    .await
    .with_context(|| format!("ACME issuance for '{cert_name}' via CA '{ca_name}'"))?;

    let (cert_pem, chain_pem, fullchain_pem) = split_cert_chain(&cert_chain);
    let fingerprint = leaf_fingerprint(&cert_pem)?;

    let current_fp = crate::cert_store::read_cert_store_entry(cert_store_dir, cert_name)
        .and_then(|e| e.fingerprint256);
    let changed = current_fp.as_deref() != Some(&fingerprint);

    persist_issued_material(
        cert_store_dir,
        cert_name,
        &cert_pem,
        &chain_pem,
        &fullchain_pem,
        None,
    )
    .with_context(|| format!("Persisting cert material for '{cert_name}'"))?;

    tracing::info!(cert = %cert_name, ca = %ca_name, changed = %changed, fp = %fingerprint, "Cert issued and stored");

    // Record the issuance in the rate-limit ledger.
    let registered_domain = sans
        .iter()
        .find_map(|s| extract_registered_domain(s))
        .unwrap_or_else(|| sans.first().cloned().unwrap_or_default());
    let event = IssuanceEvent {
        cert_name: cert_name.to_string(),
        ca: ca_name.to_string(),
        registered_domain,
        sans,
        issued_at: chrono::Utc::now(),
        fingerprint256: fingerprint.clone(),
    };
    if let Err(e) = ledger.write().await.append(event) {
        tracing::warn!(cert = %cert_name, error = %e, "Failed to append to issuance ledger");
    }

    Ok(IssuanceResult {
        cert_pem,
        chain_pem,
        fullchain_pem,
        fingerprint256: fingerprint,
        issued: true,
        changed,
    })
}

// ---------------------------------------------------------------------------
// Core ACME flow
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_issuance(
    account: &instant_acme::Account,
    ca_config: &AcmeCaConfig,
    ca_name: &str,
    cert_name: &str,
    domains: &[String],
    csr_der: &[u8],
    validation_method: &str,
    http_challenge_port: Option<u16>,
    _force_revalidate: bool, // TODO: not yet implemented — bypass cert-age check and force ACME revalidation
    assignment: &ManagedAssignment,
    pool: &Arc<RwLock<CorgiClientPool>>,
    corgis: &[CorgiNodeConfig],
    jobs: &JobStore,
    job_id: Uuid,
) -> Result<String> {
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    tracing::info!(
        cert = %cert_name, ca = %ca_name,
        domains = ?domains, method = %validation_method,
        "Submitting ACME order"
    );

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
            validation_method: Some(validation_method),
            http_challenge_port,
        })
        .await
        .context("Creating ACME order")?;

    let authorizations = order
        .authorizations()
        .await
        .context("Fetching ACME authorizations")?;
    tracing::debug!(cert = %cert_name, count = authorizations.len(), "ACME authorizations loaded");

    update_phase(jobs, job_id, RenewalPhase::Validating).await;
    append_trace(
        jobs,
        job_id,
        "validating-domains",
        Some(&format!("{} domain(s)", authorizations.len())),
        None,
        None,
    )
    .await;

    // DNS cleanups deferred until after cert is issued
    #[allow(clippy::type_complexity)]
    let mut deferred_cleanups: Vec<
        Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>,
    > = vec![];

    for authz in &authorizations {
        let Identifier::Dns(domain) = &authz.identifier;

        match authz.status {
            AuthorizationStatus::Valid => {
                tracing::debug!(cert = %cert_name, domain = %domain, "Authorization already valid");
                continue;
            }
            AuthorizationStatus::Invalid => {
                let errors: Vec<String> = authz
                    .challenges
                    .iter()
                    .filter_map(|c| c.error.as_ref())
                    .map(fmt_problem)
                    .collect();
                if errors.is_empty() {
                    anyhow::bail!("ACME authorization is invalid for domain '{domain}'");
                } else {
                    anyhow::bail!(
                        "ACME authorization is invalid for domain '{domain}': {}",
                        errors.join("; ")
                    );
                }
            }
            _ => {}
        }

        let challenge = find_challenge(&authz.challenges, validation_method).ok_or_else(|| {
            anyhow::anyhow!("No '{validation_method}' challenge offered for '{domain}'")
        })?;

        tracing::info!(
            cert = %cert_name, domain = %domain, method = %validation_method,
            "Setting up ACME challenge"
        );

        match challenge.r#type {
            ChallengeType::Dns01 => {
                let key_auth = order.key_authorization(challenge);
                let dns_value = key_auth.dns_value();
                let record_name = format!(
                    "_acme-challenge.{}",
                    domain.trim_end_matches('.').trim_start_matches("*.")
                );

                let dns_validation = resolve_dns_validation_config(ca_config, assignment);
                let provider_name = dns_validation
                    .as_ref()
                    .and_then(|v| v.provider.as_deref())
                    .ok_or_else(|| anyhow::anyhow!(
                        "dns-01 for '{cert_name}/{domain}': missing validation.dns-01.provider in CA config"
                    ))?;
                let provider_config = dns_validation
                    .as_ref()
                    .and_then(|v| v.provider_config.as_ref())
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                let provider = create_provider(provider_name, &provider_config)
                    .with_context(|| format!("Creating DNS provider '{provider_name}'"))?;

                let ctx = DnsProviderContext {
                    record_name: record_name.clone(),
                    txt_value: dns_value.clone(),
                    identifier: domain.clone(),
                };

                tracing::info!(cert = %cert_name, domain = %domain, record = %record_name, "Creating DNS TXT record");
                provider
                    .create(&ctx)
                    .await
                    .with_context(|| format!("Creating DNS TXT for '{domain}'"))?;

                // Verify propagation at authoritative nameservers
                verify_dns_propagation(cert_name, domain, &record_name, &dns_value)
                    .await
                    .with_context(|| format!("DNS propagation check for '{domain}'"))?;
                tracing::info!(cert = %cert_name, domain = %domain, "DNS propagation verified");

                // Configurable additional delay
                let delay_secs = dns_validation
                    .as_ref()
                    .and_then(|v| v.propagation_delay_seconds)
                    .unwrap_or(0);
                if delay_secs > 0 {
                    sleep(Duration::from_secs(delay_secs)).await;
                }

                // Defer DNS cleanup until after cert issuance
                deferred_cleanups.push(Box::new(move || {
                    let cleanup_ctx = DnsProviderContext {
                        record_name: record_name.clone(),
                        txt_value: String::new(),
                        identifier: domain.clone(),
                    };
                    Box::pin(async move {
                        if let Err(e) = provider.cleanup(&cleanup_ctx).await {
                            tracing::warn!(error = %e, record = %cleanup_ctx.record_name, "DNS TXT cleanup failed");
                        }
                    })
                }));
            }

            ChallengeType::Http01 => {
                let key_auth = order.key_authorization(challenge);
                let token = &challenge.token;
                let corgi_name = assignment.corgi.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("http-01 for '{cert_name}' requires a corgi assignment")
                })?;
                let node = corgis
                    .iter()
                    .find(|c| c.name == corgi_name)
                    .ok_or_else(|| anyhow::anyhow!("Corgi '{corgi_name}' not found in config"))?;

                tracing::info!(cert = %cert_name, domain = %domain, corgi = %corgi_name, token = %token, "Publishing HTTP-01 challenge token to corgi");
                corgi_post::<serde_json::Value>(
                    pool,
                    node,
                    "/acme-challenges",
                    &serde_json::json!({
                        "token": token,
                        "response": key_auth.as_str(),
                        "domain": domain,
                    }),
                )
                .await
                .with_context(|| format!("Publishing HTTP-01 challenge for '{domain}'"))?;

                let cleanup_pool = pool.clone();
                let cleanup_node = node.clone();
                let cleanup_token = token.clone();
                deferred_cleanups.push(Box::new(move || {
                    Box::pin(async move {
                        let path = format!("/acme-challenges/{}", urlencoded(&cleanup_token));
                        // DELETE via corgi — best-effort
                        let _ = corgi_delete(&cleanup_pool, &cleanup_node, &path).await;
                    })
                }));
            }

            // none-01 or unknown — vigil validates immediately on challenge submission
            _ => {
                tracing::debug!(cert = %cert_name, domain = %domain, "Submitting none/unknown challenge (vigil-style)");
            }
        }

        order
            .set_challenge_ready(&challenge.url)
            .await
            .with_context(|| format!("Submitting challenge ready for '{domain}'"))?;
        append_trace(
            jobs,
            job_id,
            "challenge-ready",
            Some(validation_method),
            Some(domain),
            Some("waiting"),
        )
        .await;
    }

    // Poll order status until Ready (all authorizations valid)
    let order_state = wait_for_order_ready(cert_name, ca_name, &mut order).await?;
    update_phase(jobs, job_id, RenewalPhase::Finalizing).await;
    append_trace(jobs, job_id, "order-ready", None, None, Some("ok")).await;
    if order_state == OrderStatus::Invalid {
        let detail = order
            .state()
            .error
            .as_ref()
            .map(fmt_problem)
            .unwrap_or_else(|| "(no detail)".to_string());
        anyhow::bail!("ACME order became invalid for '{cert_name}': {detail}");
    }

    // Only finalize when the order is Ready. Valid means the CA has already
    // processed the CSR (e.g. a concurrent issuance beat us to it) and the
    // certificate is available to download — calling finalize again would
    // produce an "orderNotReady" / "already processing" rejection.
    if order_state == OrderStatus::Ready {
        tracing::info!(cert = %cert_name, ca = %ca_name, "Finalizing ACME order");
        order
            .finalize(csr_der)
            .await
            .context("Finalizing ACME order")?;
    } else {
        tracing::debug!(cert = %cert_name, ca = %ca_name, "Order already past Ready; skipping finalize");
    }

    // Get certificate (poll until available)
    let cert_chain = wait_for_certificate(cert_name, ca_name, &mut order).await?;
    append_trace(jobs, job_id, "certificate-issued", None, None, Some("ok")).await;

    // Run deferred cleanups
    for cleanup in deferred_cleanups {
        cleanup().await;
    }

    Ok(cert_chain)
}

// ---------------------------------------------------------------------------
// Polling helpers
// ---------------------------------------------------------------------------

async fn wait_for_order_ready(
    cert_name: &str,
    ca_name: &str,
    order: &mut Order,
) -> Result<OrderStatus> {
    for attempt in 1..=60u32 {
        sleep(Duration::from_secs(5)).await;
        let state = order.refresh().await.context("Refreshing order status")?;
        match state.status {
            OrderStatus::Ready | OrderStatus::Valid | OrderStatus::Invalid => {
                return Ok(state.status);
            }
            _ => {
                tracing::debug!(cert = %cert_name, ca = %ca_name, attempt = %attempt, "Waiting for order ready");
            }
        }
    }
    anyhow::bail!("Timeout waiting for ACME order to become ready for '{cert_name}'")
}

async fn wait_for_certificate(cert_name: &str, ca_name: &str, order: &mut Order) -> Result<String> {
    for attempt in 1..=30u32 {
        if let Some(cert) = order.certificate().await.context("Fetching certificate")? {
            return Ok(cert);
        }
        if order.state().status == OrderStatus::Invalid {
            let detail = order
                .state()
                .error
                .as_ref()
                .map(fmt_problem)
                .unwrap_or_else(|| "(no detail)".to_string());
            anyhow::bail!("ACME order invalid while waiting for cert: {detail}");
        }
        tracing::debug!(cert = %cert_name, ca = %ca_name, attempt = %attempt, "Waiting for certificate");
        sleep(Duration::from_secs(5)).await;
    }
    anyhow::bail!("Timeout waiting for certificate for '{cert_name}'")
}

// ---------------------------------------------------------------------------
// DNS propagation verification
// ---------------------------------------------------------------------------

async fn verify_dns_propagation(
    cert_name: &str,
    domain: &str,
    record_name: &str,
    expected_txt: &str,
) -> Result<()> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_tokio()
        .and_then(|b| b.build())
        .unwrap_or_else(|_| {
            let mut config = ResolverConfig::default();
            config.add_name_server(NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            )));
            config.add_name_server(NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(8, 8, 4, 4),
            )));
            TokioResolver::builder_with_config(
                config,
                hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
            )
            .build()
            .expect("DNS fallback resolver")
        });

    // Walk up labels to find authoritative NS
    let ns_names = resolve_authoritative_ns(&resolver, record_name).await;
    if ns_names.is_empty() {
        tracing::warn!(cert = %cert_name, domain = %domain, "No authoritative NS found; skipping DNS propagation check");
        return Ok(());
    }

    // Resolve NS IPs
    use hickory_resolver::proto::rr::RData;
    let mut ns_ips: Vec<std::net::IpAddr> = Vec::new();
    for ns in &ns_names {
        if let Ok(r) = resolver.ipv4_lookup(ns.as_str()).await {
            ns_ips.extend(r.answers().iter().filter_map(|rec| {
                if let RData::A(a) = &rec.data {
                    Some(std::net::IpAddr::V4(a.0))
                } else {
                    None
                }
            }));
        }
        if let Ok(r) = resolver.ipv6_lookup(ns.as_str()).await {
            ns_ips.extend(r.answers().iter().filter_map(|rec| {
                if let RData::AAAA(aaaa) = &rec.data {
                    Some(std::net::IpAddr::V6(aaaa.0))
                } else {
                    None
                }
            }));
        }
    }

    if ns_ips.is_empty() {
        tracing::warn!(cert = %cert_name, "Could not resolve NS IPs; skipping propagation check");
        return Ok(());
    }

    tracing::info!(cert = %cert_name, domain = %domain, record = %record_name, ns = ?ns_names, "Verifying DNS propagation");

    for attempt in 1..=100u32 {
        let mut all_ok = true;
        for &ip in &ns_ips {
            let ns_cfg =
                ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(ip)]);
            let ns_resolver = match TokioResolver::builder_with_config(
                ns_cfg,
                hickory_resolver::net::runtime::TokioRuntimeProvider::new(),
            )
            .build()
            {
                Ok(r) => r,
                Err(_) => {
                    all_ok = false;
                    continue;
                }
            };
            match ns_resolver.txt_lookup(record_name).await {
                Ok(records) => {
                    let found = records.answers().iter().any(|rec| {
                        if let RData::TXT(txt) = &rec.data {
                            txt.txt_data.iter().any(|d| {
                                std::str::from_utf8(d)
                                    .map(|s| s == expected_txt)
                                    .unwrap_or(false)
                            })
                        } else {
                            false
                        }
                    });
                    if !found {
                        all_ok = false;
                    }
                }
                Err(_) => {
                    all_ok = false;
                }
            }
        }
        if all_ok {
            tracing::info!(cert = %cert_name, domain = %domain, attempt = %attempt, "DNS TXT propagated");
            return Ok(());
        }
        tracing::debug!(cert = %cert_name, domain = %domain, attempt = %attempt, "Waiting for DNS propagation");
        sleep(Duration::from_secs(10)).await;
    }

    anyhow::bail!("DNS TXT '{expected_txt}' did not propagate for '{record_name}' within timeout")
}

async fn resolve_authoritative_ns(
    resolver: &hickory_resolver::TokioResolver,
    fqdn: &str,
) -> Vec<String> {
    use hickory_resolver::proto::rr::RData;
    let parts: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    for i in 0..parts.len().saturating_sub(1) {
        let zone = parts[i..].join(".");
        if let Ok(ns_lookup) = resolver.ns_lookup(zone.as_str()).await {
            let names: Vec<String> = ns_lookup
                .answers()
                .iter()
                .filter_map(|r| {
                    if let RData::NS(ns) = &r.data {
                        Some(ns.0.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            if !names.is_empty() {
                return names;
            }
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Certificate chain splitting
// ---------------------------------------------------------------------------

pub fn split_cert_chain(chain_pem: &str) -> (String, String, String) {
    let certs: Vec<&str> = chain_pem
        .split_inclusive("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .collect();

    if certs.is_empty() {
        return (chain_pem.to_string(), String::new(), chain_pem.to_string());
    }

    let leaf = certs[0].trim().to_string() + "\n";
    let chain: String = certs[1..]
        .iter()
        .map(|s| s.trim().to_string() + "\n")
        .collect();
    let fullchain = format!("{leaf}{chain}");
    (leaf, chain, fullchain)
}

pub fn leaf_fingerprint(cert_pem: &str) -> Result<String> {
    use rustls_pemfile::Item;
    use sha2::{Digest, Sha256};

    let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
    let der = rustls_pemfile::read_one(&mut reader)
        .ok()
        .flatten()
        .and_then(|item| match item {
            Item::X509Certificate(d) => Some(d.to_vec()),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("Could not parse cert PEM for fingerprint"))?;

    let hash = Sha256::digest(&der);
    let hex: Vec<String> = hash.iter().map(|b| format!("{b:02X}")).collect();
    Ok(hex.join(":"))
}

// ---------------------------------------------------------------------------
// Config resolution helpers
// ---------------------------------------------------------------------------

fn resolve_validation_method(config: &AcmeCaConfig, assignment: &ManagedAssignment) -> String {
    if let Some(method) = assignment
        .validation
        .as_ref()
        .and_then(|v| v.validation_type.as_deref())
    {
        if method != "auto" {
            return method.to_string();
        }
    }
    config.default_validation.clone()
}

struct DnsValidationConfig {
    provider: Option<String>,
    provider_config: Option<serde_json::Value>,
    propagation_delay_seconds: Option<u64>,
}

fn resolve_dns_validation_config(
    config: &AcmeCaConfig,
    assignment: &ManagedAssignment,
) -> Option<DnsValidationConfig> {
    let ca_defaults = config.validation.get("dns-01");

    let assignment_override = assignment
        .validation
        .as_ref()
        .and_then(|v| v.methods.as_ref())
        .and_then(|m| m.as_object())
        .and_then(|m| m.get("dns-01"));

    if ca_defaults.is_none() && assignment_override.is_none() {
        return None;
    }

    let provider = assignment_override
        .and_then(|o| {
            o.get("provider")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .or_else(|| ca_defaults.and_then(|d| d.provider.clone()));

    let provider_config = assignment_override
        .and_then(|o| o.get("providerConfig").cloned())
        .or_else(|| ca_defaults.and_then(|d| d.provider_config.clone()));

    let propagation_delay_seconds = assignment_override
        .and_then(|o| o.get("propagationDelaySeconds").and_then(|v| v.as_u64()))
        .or_else(|| ca_defaults.and_then(|d| d.propagation_delay_seconds));

    Some(DnsValidationConfig {
        provider,
        provider_config,
        propagation_delay_seconds,
    })
}

fn find_challenge<'a>(
    challenges: &'a [instant_acme::Challenge],
    method: &str,
) -> Option<&'a instant_acme::Challenge> {
    match method {
        "dns-01" => challenges.iter().find(|c| c.r#type == ChallengeType::Dns01),
        "http-01" => challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01),
        // none-01 or other vigil-style: skip unrecognised challenge types that
        // the server may include (e.g. dns-persist-01).
        _ => challenges
            .iter()
            .find(|c| c.r#type != ChallengeType::Unknown),
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn fmt_problem(p: &instant_acme::Problem) -> String {
    match (&p.r#type, &p.detail) {
        (Some(t), Some(d)) => format!("{t}: {d}"),
        (Some(t), None) => t.clone(),
        (None, Some(d)) => d.clone(),
        (None, None) => "(unknown ACME error)".to_string(),
    }
}

fn pem_to_csr_der(pem: &str) -> Option<Vec<u8>> {
    use rustls_pemfile::Item;
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::read_one(&mut reader)
        .ok()?
        .and_then(|item| match item {
            Item::Csr(der) => Some(der.to_vec()),
            _ => None,
        })
}

fn urlencoded(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn _issue_cert_accepts_job_store(
        ca_config: &AcmeCaConfig,
        ca_name: &str,
        cert_name: &str,
        cert_store_dir: &std::path::Path,
        domains: &[String],
        csr_pem: &str,
        assignment: &ManagedAssignment,
        pool: &Arc<RwLock<CorgiClientPool>>,
        corgis: &[CorgiNodeConfig],
        account_cache: &AcmeAccountCache,
        ledger: &Arc<RwLock<IssuanceLedger>>,
        jobs: &JobStore,
        job_id: Uuid,
    ) {
        let _ = issue_cert(
            ca_config,
            ca_name,
            cert_name,
            cert_store_dir,
            domains,
            csr_pem,
            assignment,
            pool,
            corgis,
            account_cache,
            ledger,
            jobs,
            job_id,
        );
    }
}
