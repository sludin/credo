use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tokio::time::Duration;

use crate::accounts::load_accounts;
use crate::assignments::{file_mtime, load_assignments};
use crate::cas::load_cas;
use crate::cert_store::read_cert_store_entry;
use crate::corgi_client::{corgi_get, corgi_post};
use crate::corgis::load_corgis;
use crate::issuance::issue_cert;
use crate::renewal_jobs::{complete_job, create_job, fail_job, update_phase};
use crate::state::AppState;
use crate::types::{
    CorgiFlockEntry, CorgiNodeConfig, CorgiNodeState, CorgiStatus, ManagedAssignment, RenewalPhase,
};

// ---------------------------------------------------------------------------
// Entry points (spawned as background tasks)
// ---------------------------------------------------------------------------

pub async fn run_health_check_loop(state: AppState) {
    loop {
        let secs = state.config.load().corgi_health_check_interval_seconds;
        tokio::time::sleep(Duration::from_secs(secs)).await;
        health_check_cycle(&state).await;
    }
}

pub async fn run_poll_loop(state: AppState) {
    loop {
        let secs = state.config.load().poll_interval_seconds;
        tokio::time::sleep(Duration::from_secs(secs)).await;
        poll_cycle(&state).await;
    }
}

// ---------------------------------------------------------------------------
// Health check cycle — lightweight /health ping
// ---------------------------------------------------------------------------

async fn health_check_cycle(state: &AppState) {
    maybe_reload_corgis(state).await;
    maybe_reload_accounts(state).await;
    maybe_reload_cas(state).await;
    let corgis = state.corgis.read().await.clone();
    for node in &corgis {
        ping_health(state, node).await;
    }
}

async fn ping_health(state: &AppState, node: &CorgiNodeConfig) {
    match corgi_get::<serde_json::Value>(&state.corgi_client_pool, node, "/health").await {
        Ok(_) => {
            let mut cs = state.corgi_state.write().await;
            let entry = cs
                .entry(node.name.clone())
                .or_insert_with(CorgiNodeState::new);
            entry.status = CorgiStatus::Reachable;
            entry.last_health_check = Some(Utc::now().timestamp());
            entry.error = None;
        }
        Err(e) => {
            tracing::warn!(corgi = %node.name, error = %e, "Corgi health check failed");
            let mut cs = state.corgi_state.write().await;
            let entry = cs
                .entry(node.name.clone())
                .or_insert_with(CorgiNodeState::new);
            entry.status = CorgiStatus::Unreachable;
            entry.error = Some(e.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Full poll cycle
// ---------------------------------------------------------------------------

async fn poll_cycle(state: &AppState) {
    maybe_reload_corgis(state).await;
    maybe_reload_assignments(state).await;
    maybe_reload_accounts(state).await;
    maybe_reload_cas(state).await;

    let corgis = state.corgis.read().await.clone();

    // Phase 1: poll /flock from all corgis
    for node in &corgis {
        poll_flock(state, node).await;
    }

    // Phase 2: fingerprint sync — tell corgis to refresh if their cert is stale
    for node in &corgis {
        fingerprint_sync_check(state, node).await;
    }

    // Phase 3: cert maintenance — renew if needed
    let assignments = state.assignments.read().await.clone();
    for node in &corgis {
        let node_assignments: Vec<ManagedAssignment> = assignments
            .iter()
            .filter(|a| a.corgi.as_deref() == Some(node.name.as_str()))
            .cloned()
            .collect();
        for assignment in node_assignments {
            if let Err(e) = cert_maintenance(state, node, &assignment).await {
                tracing::warn!(
                    corgi = %node.name,
                    cert = %assignment.cert_name,
                    error = %e,
                    "Cert maintenance error"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Flock poll
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FlockResponse {
    flock: Vec<FlockEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlockEntry {
    name: String,
    lifetime_days: Option<f64>,
    status: Option<String>,
    #[serde(default)]
    san_names: Vec<String>,
    fingerprint256: Option<String>,
    valid_to: Option<String>,
    domain: Option<String>,
    #[serde(default)]
    key_exists: bool,
}

async fn poll_flock(state: &AppState, node: &CorgiNodeConfig) {
    match corgi_get::<FlockResponse>(&state.corgi_client_pool, node, "/flock").await {
        Ok(resp) => {
            let flock: Vec<CorgiFlockEntry> = resp
                .flock
                .into_iter()
                .map(|e| CorgiFlockEntry {
                    name: e.name,
                    fingerprint256: e.fingerprint256,
                    valid_to: e.valid_to,
                    lifetime_days: e.lifetime_days.filter(|d| d.is_finite()),
                    status: e.status,
                    san_names: e.san_names,
                    key_exists: Some(e.key_exists),
                })
                .collect();
            let mut cs = state.corgi_state.write().await;
            let entry = cs
                .entry(node.name.clone())
                .or_insert_with(CorgiNodeState::new);
            entry.status = CorgiStatus::Reachable;
            entry.last_health_check = Some(Utc::now().timestamp());
            entry.flock = flock;
            entry.error = None;
        }
        Err(e) => {
            tracing::warn!(corgi = %node.name, error = %e, "Corgi flock poll failed");
            let mut cs = state.corgi_state.write().await;
            let entry = cs
                .entry(node.name.clone())
                .or_insert_with(CorgiNodeState::new);
            entry.status = CorgiStatus::Unreachable;
            entry.error = Some(e.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Fingerprint sync
// ---------------------------------------------------------------------------

async fn fingerprint_sync_check(state: &AppState, node: &CorgiNodeConfig) {
    let cs = state.corgi_state.read().await;
    let node_state = match cs.get(&node.name) {
        Some(s) if s.status == CorgiStatus::Reachable => s.clone(),
        _ => return,
    };
    drop(cs);

    let assignments = state.assignments.read().await;
    let config = state.config.load_full();
    let store_dir = &config.cert_store_dir;

    let needs_refresh = assignments
        .iter()
        .filter(|a| a.corgi.as_deref() == Some(node.name.as_str()))
        .any(|a| {
            let local_fp =
                read_cert_store_entry(store_dir, &a.cert_name).and_then(|e| e.fingerprint256);
            let Some(expected) = local_fp else {
                return false;
            };
            let corgi_fp = node_state
                .flock
                .iter()
                .find(|f| f.name == a.cert_name)
                .and_then(|f| f.fingerprint256.as_deref())
                .map(|s| s.to_uppercase());
            // Only refresh when corgi *has* the cert but it differs from shepherd's.
            // If corgi has no fingerprint (cert not yet installed) cert_maintenance owns
            // the initial issuance via the CSR path and will push with the key in place.
            // Triggering a pull sync before the CSR step installs the cert without a key.
            corgi_fp.is_some() && corgi_fp.as_deref() != Some(&expected)
        });
    drop(assignments);

    if needs_refresh {
        tracing::debug!(corgi = %node.name, "Requesting corgi assignment refresh");
        if let Err(e) = corgi_post::<serde_json::Value>(
            &state.corgi_client_pool,
            node,
            "/sync/assignments",
            &json!({}),
        )
        .await
        {
            tracing::warn!(corgi = %node.name, error = %e, "Failed to request corgi assignment refresh");
        }
    }
}

// ---------------------------------------------------------------------------
// Cert maintenance
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CsrResponse {
    csr_pem: String,
}

async fn cert_maintenance(
    state: &AppState,
    node: &CorgiNodeConfig,
    assignment: &ManagedAssignment,
) -> anyhow::Result<()> {
    // Only work on reachable corgis
    {
        let cs = state.corgi_state.read().await;
        if cs.get(&node.name).map(|s| &s.status) != Some(&CorgiStatus::Reachable) {
            return Ok(());
        }
    }

    let config = state.config.load_full();
    let store_dir = &config.cert_store_dir;
    let local_cert = read_cert_store_entry(store_dir, &assignment.cert_name);
    let renew_before: f64 = assignment
        .renew_before_days
        .map(|d| d as f64)
        .unwrap_or(config.renew_before_days);

    // Also renew when the cert exists in Shepherd's store but Corgi is missing the key.
    // This happens when the corgi sync installs a cert via pull (Shepherd has no key to
    // distribute) before cert_maintenance has had a chance to run the CSR→issue→push cycle.
    let corgi_missing_key = {
        let cs = state.corgi_state.read().await;
        cs.get(&node.name)
            .and_then(|s| s.flock.iter().find(|e| e.name == assignment.cert_name))
            .and_then(|e| e.key_exists)
            .map(|exists| !exists)
            .unwrap_or(false)
    };

    let needs_renewal = match &local_cert {
        None => true,
        Some(e) => e
            .expires_in_days
            .map(|d| d <= renew_before as i64)
            .unwrap_or(true),
    } || corgi_missing_key;

    if !needs_renewal {
        return Ok(());
    }

    // Don't start a second issuance if one is already in flight for this cert.
    {
        let jobs = state.renewal_jobs.read().await;
        if jobs
            .values()
            .any(|j| j.cert_name == assignment.cert_name && !j.phase.is_terminal())
        {
            tracing::debug!(
                cert = %assignment.cert_name,
                "Renewal already in progress; skipping poll-triggered renewal"
            );
            return Ok(());
        }
    }

    let renewal_reason = if local_cert.is_none() {
        "no cert in store"
    } else if corgi_missing_key {
        "corgi missing key"
    } else {
        "expiry threshold reached"
    };
    tracing::info!(
        corgi = %node.name,
        cert = %assignment.cert_name,
        reason = renewal_reason,
        expires_in_days = local_cert.as_ref().and_then(|e| e.expires_in_days).unwrap_or(0),
        threshold = renew_before,
        "Certificate needs renewal"
    );

    // Request CSR from corgi
    let csr_resp = corgi_post::<CsrResponse>(
        &state.corgi_client_pool,
        node,
        &format!("/flock/{}/csr", urlencoded(&assignment.cert_name)),
        &json!({ "keyAlgorithm": assignment.key_algorithm.as_deref().unwrap_or("rsa") }),
    )
    .await;

    let csr_pem = match csr_resp {
        Ok(r) => r.csr_pem,
        Err(e) => {
            tracing::warn!(
                corgi = %node.name,
                cert = %assignment.cert_name,
                error = %e,
                "Could not obtain CSR; skipping renewal until corgi is reachable"
            );
            return Ok(());
        }
    };

    // Build domain list
    let domains = build_domains(assignment);

    // Create a renewal job for tracking
    let job_id = create_job(
        &state.renewal_jobs,
        &assignment.cert_name,
        domains.clone(),
        &assignment.ca,
    )
    .await;

    update_phase(&state.renewal_jobs, job_id, RenewalPhase::SubmittingOrder).await;

    // Issue via ACME
    let ca_config = match state
        .cas
        .read()
        .await
        .get(&assignment.ca)
        .map(|ca| ca.config.clone())
    {
        Some(cfg) => cfg,
        None => {
            fail_job(
                &state.renewal_jobs,
                job_id,
                format!("CA '{}' not configured", assignment.ca),
            )
            .await;
            anyhow::bail!("CA '{}' not configured", assignment.ca);
        }
    };
    let corgis = state.corgis.read().await.clone();
    let result = issue_cert(
        &ca_config,
        &assignment.ca,
        &assignment.cert_name,
        store_dir,
        &domains,
        &csr_pem,
        assignment,
        &state.corgi_client_pool,
        &corgis,
        &state.acme_accounts,
    )
    .await;

    match result {
        Err(e) => {
            let msg = format!("{:#}", e);
            fail_job(&state.renewal_jobs, job_id, msg.clone()).await;
            anyhow::bail!("Renewal failed: {msg}");
        }
        Ok(issued) => {
            complete_job(&state.renewal_jobs, job_id, issued.fingerprint256.clone()).await;

            // Install on corgi
            if let Err(e) = corgi_post::<serde_json::Value>(
                &state.corgi_client_pool,
                node,
                &format!("/flock/{}/install", urlencoded(&assignment.cert_name)),
                &json!({
                    "certPem":      issued.cert_pem,
                    "chainPem":     issued.chain_pem,
                    "fullchainPem": issued.fullchain_pem,
                }),
            )
            .await
            {
                tracing::warn!(
                    corgi = %node.name,
                    cert = %assignment.cert_name,
                    error = %e,
                    "Cert issued but install on corgi failed; corgi will sync on next poll"
                );
            } else {
                tracing::info!(
                    corgi = %node.name,
                    cert = %assignment.cert_name,
                    fingerprint256 = %issued.fingerprint256,
                    "Renewed cert installed on corgi"
                );
                // The production cert is now in corgi's certstore.  Evict the cached
                // mTLS client so the next connection rebuilds from the production cert
                // instead of the bootstrap fallback.
                crate::corgi_client::evict(&state.corgi_client_pool, &node.name).await;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Hot-reload helpers
// ---------------------------------------------------------------------------

async fn maybe_reload_corgis(state: &AppState) {
    let path = state.config.load().corgis_config_path.clone();
    let new_mtime = file_mtime(&path);
    let needs = { *state.corgis_mtime.lock().unwrap() != new_mtime };
    if needs {
        match load_corgis(&path) {
            Ok(list) => {
                tracing::info!(count = list.len(), "Reloaded corgis config");
                *state.corgis.write().await = list;
                *state.corgis_mtime.lock().unwrap() = new_mtime;
            }
            Err(e) => tracing::warn!(error = %e, "Failed to reload corgis config"),
        }
    }
}

async fn maybe_reload_assignments(state: &AppState) {
    let path = state.config.load().assignments_config_path.clone();
    let new_mtime = file_mtime(&path);
    let needs = { *state.assignments_mtime.lock().unwrap() != new_mtime };
    if needs {
        match load_assignments(&path) {
            Ok(list) => {
                tracing::info!(count = list.len(), "Reloaded assignments config");
                *state.assignments.write().await = list;
                *state.assignments_mtime.lock().unwrap() = new_mtime;
            }
            Err(e) => tracing::warn!(error = %e, "Failed to reload assignments config"),
        }
    }
}

pub async fn maybe_reload_accounts(state: &AppState) {
    let path = state.config.load().accounts_path.clone();
    let new_mtime = file_mtime(&path);
    let needs = { *state.accounts_mtime.lock().unwrap() != new_mtime };
    if needs {
        match load_accounts(&path) {
            Ok(list) => {
                tracing::info!(count = list.len(), "Reloaded accounts");
                *state.accounts.write().await = list;
                *state.accounts_mtime.lock().unwrap() = new_mtime;
            }
            Err(e) => tracing::warn!(error = %e, "Failed to reload accounts"),
        }
    }
}

pub async fn maybe_reload_cas(state: &AppState) {
    let path = state.config.load().ca_config_path.clone();
    let new_mtime = file_mtime(&path);
    let needs = { *state.ca_mtime.lock().unwrap() != new_mtime };
    if needs {
        match load_cas(&path) {
            Ok(map) => {
                tracing::info!(count = map.len(), "Reloaded CA config");
                *state.cas.write().await = map;
                *state.ca_mtime.lock().unwrap() = new_mtime;
            }
            Err(e) => tracing::warn!(error = %e, "Failed to reload CA config"),
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn build_domains(assignment: &ManagedAssignment) -> Vec<String> {
    let mut domains = assignment.sans.clone();
    if let Some(d) = &assignment.domain {
        if !domains.contains(d) {
            domains.insert(0, d.clone());
        }
    }
    domains
}

fn urlencoded(s: &str) -> String {
    s.replace('/', "%2F")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ManagedAssignment;

    fn assignment(domain: Option<&str>, sans: &[&str]) -> ManagedAssignment {
        ManagedAssignment {
            cert_name: "test".into(),
            corgi: None,
            ca: "letsencrypt".into(),
            domain: domain.map(String::from),
            sans: sans.iter().map(|s| s.to_string()).collect(),
            renew_before_days: None,
            days: None,
            identity_uri: None,
            validation: None,
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
            key_algorithm: None,
        }
    }

    #[test]
    fn domain_only_returns_domain() {
        let a = assignment(Some("origin.ludin.org"), &[]);
        assert_eq!(build_domains(&a), vec!["origin.ludin.org"]);
    }

    #[test]
    fn sans_only_returns_sans() {
        let a = assignment(None, &["www.ludin.org", "api.ludin.org"]);
        assert_eq!(build_domains(&a), vec!["www.ludin.org", "api.ludin.org"]);
    }

    #[test]
    fn domain_and_sans_includes_domain_at_front() {
        // Regression: previously returned only sans, dropping the domain, which
        // caused Let's Encrypt to reject the CSR with an identifier mismatch.
        let a = assignment(Some("origin.ludin.org"), &["www.ludin.org"]);
        assert_eq!(build_domains(&a), vec!["origin.ludin.org", "www.ludin.org"]);
    }

    #[test]
    fn domain_already_in_sans_not_duplicated() {
        let a = assignment(
            Some("origin.ludin.org"),
            &["origin.ludin.org", "www.ludin.org"],
        );
        assert_eq!(build_domains(&a), vec!["origin.ludin.org", "www.ludin.org"]);
    }

    #[test]
    fn no_domain_no_sans_returns_empty() {
        let a = assignment(None, &[]);
        assert!(build_domains(&a).is_empty());
    }
}
