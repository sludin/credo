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
use crate::issuance::RateLimitedError;
use crate::renewal_jobs::{
    append_trace, complete_job, create_job, fail_job, rate_limit_job, update_phase,
};
use crate::state::AppState;
use crate::types::{
    CorgiFlockEntry, CorgiNodeConfig, CorgiNodeState, CorgiStatus, ManagedAssignment, RenewalPhase,
};

// ---------------------------------------------------------------------------
// Reconcile requests (queued by API mutation handlers)
// ---------------------------------------------------------------------------

/// Fraction of the reconcile interval used as random jitter so shepherds and
/// per-corgi work don't fire in lockstep at scale.
const RECONCILE_JITTER_FRAC: f64 = 0.1;
const RENEWAL_JITTER_FRAC: f64 = 0.05;
/// Max concurrent /flock probes per cycle.
const PROBE_CONCURRENCY: usize = 16;
/// A burst of API mutations coalesces into one targeted cycle.
const MUTATION_DEBOUNCE: Duration = Duration::from_secs(1);
/// One quick re-probe after a corgi drops offline, to filter transient blips
/// before the next full interval.
const UNREACHABLE_RETRY_DELAY: Duration = Duration::from_secs(60);

/// A request for an immediate reconcile of one or more corgis.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconcileRequest {
    /// Corgi names to reconcile; `None` means every configured corgi.
    pub corgis: Option<Vec<String>>,
    /// Desired state changed: also nudge the corgi to re-pull assignments and
    /// run cert maintenance so the change applies within seconds.
    pub maintenance: bool,
}

/// Queue an immediate reconcile. Fire-and-forget: if the loop is not running
/// (tests, shutdown) the request is simply dropped — the periodic sweep is
/// the guaranteed convergence path.
pub fn request_reconcile(state: &AppState, corgis: Option<Vec<String>>, maintenance: bool) {
    let _ = state.reconcile_tx.send(ReconcileRequest {
        corgis,
        maintenance,
    });
}

fn merge_requests(reqs: Vec<ReconcileRequest>) -> ReconcileRequest {
    let mut maintenance = false;
    let mut all = false;
    let mut names: Vec<String> = Vec::new();
    for r in reqs {
        maintenance |= r.maintenance;
        match r.corgis {
            None => all = true,
            Some(list) => {
                for n in list {
                    if !names.contains(&n) {
                        names.push(n);
                    }
                }
            }
        }
    }
    ReconcileRequest {
        corgis: if all { None } else { Some(names) },
        maintenance,
    }
}

// ---------------------------------------------------------------------------
// Entry points (spawned as background tasks)
// ---------------------------------------------------------------------------

/// Combined liveness + state reconcile loop. One /flock probe per corgi per
/// interval answers both "is it alive?" and "does it have what it should?".
/// Runs a full sweep immediately at startup, then on a jittered interval,
/// with queued `ReconcileRequest`s handled as they arrive.
pub async fn run_reconcile_loop(state: AppState) {
    let rx = state.reconcile_rx.lock().unwrap().take();
    let Some(mut rx) = rx else {
        tracing::error!("Reconcile loop started twice; refusing second instance");
        return;
    };

    reconcile_cycle(&state, None, false).await;

    loop {
        let interval = state.config.load().reconcile_interval_seconds;
        tokio::select! {
            _ = tokio::time::sleep(credo_lib::timing::jittered_duration(interval, RECONCILE_JITTER_FRAC)) => {
                reconcile_cycle(&state, None, false).await;
            }
            Some(first) = rx.recv() => {
                tokio::time::sleep(MUTATION_DEBOUNCE).await;
                let mut reqs = vec![first];
                while let Ok(r) = rx.try_recv() {
                    reqs.push(r);
                }
                let merged = merge_requests(reqs);
                reconcile_cycle(&state, merged.corgis, merged.maintenance).await;
            }
        }
    }
}

/// Periodic renewal sweep. Renewal is not time-critical (certs renew with
/// weeks remaining), so this runs on its own slow interval instead of every
/// reconcile cycle. Mutation-triggered cycles still run maintenance for the
/// affected corgis immediately.
pub async fn run_renewal_loop(state: AppState) {
    // Give the startup reconcile sweep time to establish reachability;
    // cert maintenance skips corgis that aren't known-reachable.
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
        renewal_cycle(&state).await;
        let interval = state.config.load().renewal_check_interval_seconds;
        tokio::time::sleep(credo_lib::timing::jittered_duration(
            interval,
            RENEWAL_JITTER_FRAC,
        ))
        .await;
    }
}

// ---------------------------------------------------------------------------
// Cycles
// ---------------------------------------------------------------------------

async fn reconcile_cycle(state: &AppState, targets: Option<Vec<String>>, maintenance: bool) {
    maybe_reload_corgis(state).await;
    maybe_reload_assignments(state).await;
    maybe_reload_accounts(state).await;
    maybe_reload_cas(state).await;

    let corgis: Vec<CorgiNodeConfig> = {
        let all = state.corgis.read().await;
        match &targets {
            None => all.clone(),
            Some(names) => all
                .iter()
                .filter(|c| names.contains(&c.name))
                .cloned()
                .collect(),
        }
    };

    // Phase 1: probe /flock concurrently — liveness + reported cert state.
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
    let mut probes = tokio::task::JoinSet::new();
    for node in corgis.clone() {
        let st = state.clone();
        let sem = sem.clone();
        probes.spawn(async move {
            let _permit = sem.acquire().await;
            let prev = st
                .corgi_state
                .read()
                .await
                .get(&node.name)
                .map(|s| s.status.clone());
            let now = poll_flock(&st, &node).await;
            (node.name, prev, now)
        });
    }
    let mut newly_unreachable = Vec::new();
    while let Some(res) = probes.join_next().await {
        if let Ok((name, prev, now)) = res {
            if prev == Some(CorgiStatus::Reachable) && now == CorgiStatus::Unreachable {
                newly_unreachable.push(name);
            }
        }
    }

    // Phase 2: assignment nudge (on desired-state change) + fingerprint sync.
    for node in &corgis {
        if maintenance {
            nudge_corgi_sync(state, node).await;
        }
        fingerprint_sync_check(state, node).await;
    }

    // Phase 3 (mutation-triggered only): run cert maintenance right away so a
    // new or changed assignment issues within seconds. The renewal loop owns
    // the periodic sweep.
    if maintenance {
        cert_maintenance_for(state, &corgis).await;
    }

    for name in newly_unreachable {
        let st = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(UNREACHABLE_RETRY_DELAY).await;
            request_reconcile(&st, Some(vec![name]), false);
        });
    }
}

async fn renewal_cycle(state: &AppState) {
    maybe_reload_corgis(state).await;
    maybe_reload_assignments(state).await;
    maybe_reload_accounts(state).await;
    maybe_reload_cas(state).await;
    let corgis = state.corgis.read().await.clone();
    cert_maintenance_for(state, &corgis).await;
}

async fn cert_maintenance_for(state: &AppState, corgis: &[CorgiNodeConfig]) {
    let assignments = state.assignments.read().await.clone();
    for node in corgis {
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

/// Ask the corgi to re-pull its assignments now. Data still flows via corgi's
/// pull; this is a data-free trigger. Failures are logged only — the periodic
/// sweep and corgi's own safety-net pull converge the state eventually.
async fn nudge_corgi_sync(state: &AppState, node: &CorgiNodeConfig) {
    {
        let cs = state.corgi_state.read().await;
        if cs.get(&node.name).map(|s| &s.status) != Some(&CorgiStatus::Reachable) {
            return;
        }
    }
    if let Err(e) = corgi_post::<serde_json::Value>(
        &state.corgi_client_pool,
        node,
        "/sync/assignments",
        &json!({}),
    )
    .await
    {
        tracing::warn!(corgi = %node.name, error = %e, "Failed to nudge corgi assignment sync");
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
    #[serde(default)]
    key_exists: bool,
    #[serde(default)]
    monitor: Option<credo_lib::types::MonitorResult>,
}

async fn poll_flock(state: &AppState, node: &CorgiNodeConfig) -> CorgiStatus {
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
                    monitor: e.monitor,
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
            CorgiStatus::Reachable
        }
        Err(e) => {
            tracing::warn!(corgi = %node.name, error = %e, "Corgi flock poll failed");
            let mut cs = state.corgi_state.write().await;
            let entry = cs
                .entry(node.name.clone())
                .or_insert_with(CorgiNodeState::new);
            entry.status = CorgiStatus::Unreachable;
            entry.error = Some(e.to_string());
            CorgiStatus::Unreachable
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

    // Don't start a second issuance if one is already in flight or rate-limited.
    {
        let jobs = state.renewal_jobs.read().await;
        let active = jobs
            .values()
            .find(|j| j.cert_name == assignment.cert_name && !j.phase.is_terminal());
        if let Some(job) = active {
            if job.phase == crate::types::RenewalPhase::RateLimited {
                if let Some(until) = job.rate_limited_until {
                    if until > Utc::now() {
                        tracing::info!(
                            cert = %assignment.cert_name,
                            until = %until,
                            "Cert is rate-limited; skipping until window reopens"
                        );
                        return Ok(());
                    }
                }
            } else {
                tracing::debug!(
                    cert = %assignment.cert_name,
                    "Renewal already in progress; skipping poll-triggered renewal"
                );
                return Ok(());
            }
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
            if let Some(path) = &state.renewal_jobs_history_path {
                crate::renewal_jobs::persist_terminal_jobs(&state.renewal_jobs, path).await;
            }
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
        &state.issuance_ledger,
        &state.renewal_jobs,
        job_id,
    )
    .await;

    match result {
        Err(e) => {
            // Detect rate-limit errors and defer rather than fail.
            if let Some(rl) = e.downcast_ref::<RateLimitedError>() {
                tracing::warn!(
                    cert = %assignment.cert_name,
                    until = %rl.retry_after,
                    "Issuance gated by rate limit; deferring"
                );
                rate_limit_job(&state.renewal_jobs, job_id, rl.retry_after).await;
                return Ok(());
            }
            let msg = format!("{:#}", e);
            fail_job(&state.renewal_jobs, job_id, msg.clone()).await;
            if let Some(path) = &state.renewal_jobs_history_path {
                crate::renewal_jobs::persist_terminal_jobs(&state.renewal_jobs, path).await;
            }
            anyhow::bail!("Renewal failed: {msg}");
        }
        Ok(issued) => {
            update_phase(&state.renewal_jobs, job_id, RenewalPhase::Installing).await;
            append_trace(
                &state.renewal_jobs,
                job_id,
                "installing-on-corgi",
                None,
                None,
                Some("in-progress"),
            )
            .await;

            if let Err(e) = crate::corgi_client::push_cert_install(
                &state.corgi_client_pool,
                node,
                &assignment.cert_name,
                &issued,
            )
            .await
            {
                tracing::warn!(
                    corgi = %node.name,
                    cert = %assignment.cert_name,
                    error = %e,
                    "Cert issued but install on corgi failed; corgi will sync on next poll"
                );
                append_trace(
                    &state.renewal_jobs,
                    job_id,
                    "install-failed",
                    Some(&e.to_string()),
                    None,
                    Some("warn"),
                )
                .await;
            } else {
                tracing::info!(
                    corgi = %node.name,
                    cert = %assignment.cert_name,
                    fingerprint256 = %issued.fingerprint256,
                    "Renewed cert installed on corgi"
                );
                append_trace(
                    &state.renewal_jobs,
                    job_id,
                    "installed-on-corgi",
                    None,
                    None,
                    Some("ok"),
                )
                .await;
                // The production cert is now in corgi's certstore.  Evict the cached
                // mTLS client so the next connection rebuilds from the production cert
                // instead of the bootstrap fallback.
                crate::corgi_client::evict(&state.corgi_client_pool, &node.name).await;
            }

            complete_job(&state.renewal_jobs, job_id, issued.fingerprint256.clone()).await;
            if let Some(path) = &state.renewal_jobs_history_path {
                crate::renewal_jobs::persist_terminal_jobs(&state.renewal_jobs, path).await;
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
            hooks: None,
            monitor: None,
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

    #[test]
    fn installing_phase_is_not_terminal() {
        assert!(!crate::types::RenewalPhase::Installing.is_terminal());
    }

    #[test]
    fn merge_requests_unions_targets_and_ors_maintenance() {
        let merged = merge_requests(vec![
            ReconcileRequest {
                corgis: Some(vec!["a".into()]),
                maintenance: false,
            },
            ReconcileRequest {
                corgis: Some(vec!["b".into(), "a".into()]),
                maintenance: true,
            },
        ]);
        let mut targets = merged.corgis.unwrap();
        targets.sort();
        assert_eq!(targets, vec!["a".to_string(), "b".to_string()]);
        assert!(merged.maintenance);
    }

    #[test]
    fn merge_requests_full_sweep_absorbs_targeted() {
        let merged = merge_requests(vec![
            ReconcileRequest {
                corgis: Some(vec!["a".into()]),
                maintenance: true,
            },
            ReconcileRequest {
                corgis: None,
                maintenance: false,
            },
        ]);
        assert!(
            merged.corgis.is_none(),
            "None target means poll every corgi"
        );
        assert!(merged.maintenance);
    }
}
