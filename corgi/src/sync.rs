use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::pending_key_path;
use crate::assignments::{load_assignments_cache, merge_assignments, save_assignments_cache};
use crate::cert_ops::{
    cert_days_remaining, cert_pem_matches_key_file, generate_key_and_csr, install_certificate,
    read_cert_fingerprint,
};
use crate::hooks::run_hooks;
use crate::shepherd::ShepherdClient;
use crate::state::AppState;
use crate::types::{CsrRequest, InstallRequest};

/// Perform a single reconciliation pass: pull assignments from Shepherd,
/// compare fingerprints, fetch and install changed certs, run hooks.
pub async fn reconcile_once(state: &AppState) -> anyhow::Result<()> {
    let config = state.config.load_full();
    let http_client = state.shepherd_client.read().await.clone();
    let client = ShepherdClient::from_client(http_client, &config.shepherd_url);

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
    save_assignments_cache(&config, &assignments);

    // Update stored assignments
    {
        let mut stored = state.assignments.write().await;
        *stored = assignments.clone();
    }

    // Merge assignments with config flock
    let active_flock = merge_assignments(&config.flock, &assignments, &config);

    // Update active flock in state
    {
        let mut flock = state.flock.write().await;
        *flock = active_flock.clone();
    }

    // Reconcile each cert
    for assignment in &assignments {
        let entry = active_flock.iter().find(|e| e.name == assignment.cert_name);

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
            // No local cert: try to fetch regardless of whether Shepherd reports a
            // fingerprint. Shepherd may have issued the cert without propagating the
            // fingerprint back into the assignment record. A failed fetch is just a
            // warning — we skip and retry next cycle.
            (None, _) => true,
            // Have a local cert and Shepherd has no fingerprint: keep what we have
            // unless the cert is expiring soon (e.g. a bootstrap temp cert with 1-day
            // validity). Threshold of 30 days matches certbot's renewal window.
            (Some(_), None) => cert_days_remaining(&entry.path)
                .map(|days| days < 30)
                .unwrap_or(false),
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

        if local_fp.is_none() {
            tracing::info!(cert_name = %assignment.cert_name, "No local cert — fetching from Shepherd");
        } else {
            tracing::info!(
                cert_name = %assignment.cert_name,
                local_fp = ?local_fp,
                shepherd_fp = ?shepherd_fp,
                "Fingerprint mismatch — fetching cert from Shepherd"
            );
        }

        // Fetch cert material
        let cert_response = match client
            .get_cert(&config.node_id, &assignment.cert_name)
            .await
        {
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

        // Shepherd never stores private keys for CSR-issued certs, so key_pem is
        // almost always None here.
        //
        // A key is "properly archived" only when entry.key_path is a SYMLINK into
        // archive/.  A flat file at that path is a bootstrap temp key that belongs to
        // the bootstrap cert, not the cert shepherd is distributing now.  Generate a
        // new key whenever the key is absent or still a flat file.
        //
        // If a pending key already exists (written by a prior flock_csr call) a CSR is
        // in flight; proceed with the install so install_to_archive can pick it up.
        let key_is_archived = entry
            .key_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let pending = pending_key_path(&config.cert_store_dir, &assignment.cert_name);
        if cert_response.key_pem.is_none() && !key_is_archived && !pending.exists() {
            let csr_req = CsrRequest {
                sans: if assignment.sans.is_empty() {
                    None
                } else {
                    Some(assignment.sans.clone())
                },
                common_name: assignment.domain.clone(),
                identity_uri: assignment.identity_uri.clone(),
                csr_subject: assignment.csr_subject.clone(),
            };
            match generate_key_and_csr(entry, &pending, &csr_req, None) {
                Ok(csr_pem) => {
                    tracing::info!(
                        cert_name = %assignment.cert_name,
                        "No key on disk — generated key+CSR, requesting re-issue from Shepherd"
                    );
                    if let Err(e) = client
                        .request_renew(&config.node_id, &assignment.cert_name, &csr_pem)
                        .await
                    {
                        tracing::warn!(
                            cert_name = %assignment.cert_name,
                            error = %e,
                            "Re-issue request failed; will retry next sync cycle"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        cert_name = %assignment.cert_name,
                        error = %e,
                        "Failed to generate key+CSR for missing-key cert"
                    );
                }
            }
            continue;
        }

        // If a pending key is waiting to be archived and Shepherd didn't supply
        // the private key, verify the cert matches the pending key before
        // installing.  A mismatch means the new cert isn't ready yet — Shepherd
        // is still serving the old one.  Skip this cycle; install_to_archive
        // would otherwise link the pending (new) key to the old cert.
        if pending.exists() && cert_response.key_pem.is_none() {
            let cert_pem = cert_response
                .cert_pem
                .as_deref()
                .or(cert_response.fullchain_pem.as_deref());
            if let Some(pem) = cert_pem {
                if !cert_pem_matches_key_file(pem, &pending) {
                    tracing::warn!(
                        cert_name = %assignment.cert_name,
                        "Received cert does not match pending key; deferring install until new cert is issued"
                    );
                    continue;
                }
            }
        }

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
                    let hook_results = run_hooks(entry, &config).await;
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
    let config = state.config.load_full();
    if !config.shepherd_sync.enabled {
        tracing::info!("Shepherd sync disabled by config");
        return;
    }

    tracing::info!(
        interval_seconds = config.shepherd_sync.interval_seconds,
        "Starting Shepherd sync loop"
    );

    // Load from cache immediately before first sync
    if let Some(cached) = load_assignments_cache(&config) {
        let merged = merge_assignments(&config.flock, &cached, &config);
        let mut flock = state.flock.write().await;
        *flock = merged;
        let mut stored = state.assignments.write().await;
        *stored = cached;
    }

    let mut ticker =
        tokio::time::interval(Duration::from_secs(config.shepherd_sync.interval_seconds));
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
