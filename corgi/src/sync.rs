use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::assignments::{load_assignments_cache, merge_assignments, save_assignments_cache};
use crate::cert_ops::{install_certificate, read_cert_fingerprint};
use crate::hooks::run_hooks;
use crate::shepherd::ShepherdClient;
use crate::state::AppState;
use crate::types::InstallRequest;

/// Perform a single reconciliation pass: pull assignments from Shepherd,
/// compare fingerprints, fetch and install changed certs, run hooks.
pub async fn reconcile_once(state: &AppState) -> anyhow::Result<()> {
    let config = &state.config;
    let client = ShepherdClient::new(config)?;

    let response = client.get_assignments(&config.node_id).await?;
    let assignments = response.assignments.clone();

    // Update last sync timestamp
    {
        let mut last_sync = state.last_sync_at.write().await;
        *last_sync = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
    }

    // Save to cache for fail-stale
    save_assignments_cache(config, &assignments);

    // Update stored assignments
    {
        let mut stored = state.assignments.write().await;
        *stored = assignments.clone();
    }

    // Merge assignments with config flock
    let active_flock = merge_assignments(&config.flock, &assignments, config);

    // Update active flock in state
    {
        let mut flock = state.flock.write().await;
        *flock = active_flock.clone();
    }

    // Reconcile each cert
    for assignment in &assignments {
        let entry = active_flock
            .iter()
            .find(|e| e.name == assignment.cert_name);

        let entry = match entry {
            Some(e) => e,
            None => {
                tracing::warn!(cert_name = %assignment.cert_name, "Assignment has no flock entry; skipping");
                continue;
            }
        };

        // Compare fingerprints
        let local_fp = read_cert_fingerprint(&entry.path);
        let shepherd_fp = assignment.fingerprint256.as_deref();

        let needs_install = match (local_fp.as_deref(), shepherd_fp) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(local), Some(remote)) => {
                // Normalize both sides: strip colons and lowercase so format
                // differences between sources ("FD:5A:..." vs "fd5a...") don't
                // cause spurious fetches.
                let norm = |s: &str| s.replace(':', "").to_lowercase();
                norm(local) != norm(remote)
            }
        };

        if !needs_install {
            tracing::debug!(cert_name = %assignment.cert_name, "Cert fingerprint matches; no install needed");
            continue;
        }

        tracing::info!(
            cert_name = %assignment.cert_name,
            local_fp = ?local_fp,
            shepherd_fp = ?shepherd_fp,
            "Fingerprint mismatch — fetching cert from Shepherd"
        );

        // Fetch cert material
        let cert_response = match client.get_cert(&config.node_id, &assignment.cert_name).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    cert_name = %assignment.cert_name,
                    error = %e,
                    "Failed to fetch cert from Shepherd"
                );
                continue;
            }
        };

        // Install
        let install_req = InstallRequest {
            cert_pem: cert_response.cert_pem,
            chain_pem: cert_response.chain_pem,
            fullchain_pem: cert_response.fullchain_pem,
            key_pem: cert_response.key_pem,
            restart: Some(assignment.restart.unwrap_or(true)),
        };

        match install_certificate(entry, &config.cert_store_dir, &install_req) {
            Ok(result) => {
                tracing::info!(
                    cert_name = %assignment.cert_name,
                    changed = result.changed,
                    fingerprint256 = %result.next_fingerprint,
                    "Cert installed successfully"
                );

                if result.changed {
                    let hook_results = run_hooks(entry, config).await;
                    for hr in &hook_results {
                        tracing::info!(
                            cert_name = %assignment.cert_name,
                            hook = %hr.hook,
                            command = %hr.command,
                            "Hook executed"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    cert_name = %assignment.cert_name,
                    error = %e,
                    "Failed to install cert"
                );
            }
        }
    }

    Ok(())
}

/// Run the periodic Shepherd sync loop. Calls `reconcile_once` on each tick.
/// On failure, logs and continues (fail-open with cached assignments).
pub async fn run_sync_loop(state: AppState) {
    let config = state.config.clone();
    if !config.shepherd_sync.enabled {
        tracing::info!("Shepherd sync disabled by config");
        return;
    }

    let interval_secs = config.shepherd_sync.interval_seconds;
    tracing::info!(interval_seconds = interval_secs, "Starting Shepherd sync loop");

    // Load from cache immediately before first sync
    if let Some(cached) = load_assignments_cache(&config) {
        let merged = merge_assignments(&config.flock, &cached, &config);
        let mut flock = state.flock.write().await;
        *flock = merged;
        let mut stored = state.assignments.write().await;
        *stored = cached;
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        match reconcile_once(&state).await {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Shepherd sync failed; continuing with cached state");

                // Warn if state is stale
                let last = *state.last_sync_at.read().await;
                if let Some(last_ts) = last {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let age = now.saturating_sub(last_ts);
                    if age > config.shepherd_sync.stale_warning_seconds {
                        tracing::warn!(
                            stale_seconds = age,
                            "Assignments cache is stale; Shepherd unreachable for {}s",
                            age
                        );
                    }
                }
            }
        }
    }
}
