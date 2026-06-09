use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{CorgiConfig, FlockEntry};
use crate::state::AppState;
use crate::types::{AssignmentsCacheFile, ManagedAssignment};

/// Merge Shepherd assignments into the flock entry list.
/// Shepherd assignments that match a config flock entry by cert_name override it.
/// Shepherd assignments with no matching config entry are appended as dynamic entries.
pub fn merge_assignments(
    config_flock: &[FlockEntry],
    assignments: &[ManagedAssignment],
    config: &CorgiConfig,
) -> Vec<FlockEntry> {
    // Use an ordered Vec of (name, entry) to preserve insertion order
    let mut ordered: Vec<(String, FlockEntry)> = config_flock
        .iter()
        .cloned()
        .map(|e| (e.name.clone(), e))
        .collect();

    for assignment in assignments {
        let name = &assignment.cert_name;

        // Find matching config entry for path defaults
        let config_entry = config_flock.iter().find(|e| &e.name == name);

        let (cert_path, key_path) = if let Some(existing) = config_entry {
            (existing.path.clone(), existing.key_path.clone())
        } else {
            let live = config.cert_store_dir.join("live").join(name);
            (live.join("fullchain.pem"), live.join("privkey.pem"))
        };

        let hooks = config
            .cert_hooks
            .get(name)
            .cloned()
            .unwrap_or_else(|| config.default_hooks.clone());

        let entry = FlockEntry {
            name: name.clone(),
            path: cert_path,
            key_path,
            chain_path: config_entry.and_then(|e| e.chain_path.clone()),
            fullchain_path: config_entry.and_then(|e| e.fullchain_path.clone()),
            csr_path: config_entry.and_then(|e| e.csr_path.clone()),
            domain: assignment.domain.clone(),
            monitor: assignment.monitor.unwrap_or(true),
            hooks,
            csr_subject: assignment.csr_subject.clone(),
            identity_uri: assignment.identity_uri.clone(),
            sans: assignment.sans.clone(),
            cert_mode: assignment
                .cert_mode
                .as_deref()
                .and_then(parse_mode)
                .or(config.file_policy.cert_mode),
            key_mode: assignment
                .key_mode
                .as_deref()
                .and_then(parse_mode)
                .or(config.file_policy.key_mode),
            cert_owner: assignment
                .cert_owner
                .clone()
                .or_else(|| config.file_policy.owner.clone()),
            cert_group: assignment
                .cert_group
                .clone()
                .or_else(|| config.file_policy.group.clone()),
            key_owner: assignment
                .key_owner
                .clone()
                .or_else(|| config.file_policy.owner.clone()),
            key_group: assignment
                .key_group
                .clone()
                .or_else(|| config.file_policy.group.clone()),
        };

        // Insert or replace
        if let Some(pos) = ordered.iter().position(|(n, _)| n == name) {
            ordered[pos] = (name.clone(), entry);
        } else {
            ordered.push((name.clone(), entry));
        }
    }

    ordered.into_iter().map(|(_, e)| e).collect()
}

fn parse_mode(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim_start_matches("0o").trim_start_matches('0'), 8).ok()
}

// ---------------------------------------------------------------------------
// Assignments cache (fail-stale)
// ---------------------------------------------------------------------------

pub fn load_assignments_cache(config: &CorgiConfig) -> Option<Vec<ManagedAssignment>> {
    let path = &config.shepherd_sync.assignments_cache_path;
    if !path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(path).ok()?;
    let cache: AssignmentsCacheFile = serde_json::from_str(&content).ok()?;

    tracing::info!(
        path = %path.display(),
        last_updated_at = %cache.last_updated_at,
        source = %cache.source,
        count = cache.assignments.len(),
        "Loaded assignments from cache"
    );

    // Warn if cache is stale
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&cache.last_updated_at) {
        let age_seconds = now.saturating_sub(dt.timestamp() as u64);
        if age_seconds > config.shepherd_sync.stale_warning_seconds {
            tracing::warn!(
                age_seconds,
                stale_threshold = config.shepherd_sync.stale_warning_seconds,
                "Assignments cache is stale"
            );
        }
    }

    Some(cache.assignments)
}

pub fn save_assignments_cache(config: &CorgiConfig, assignments: &[ManagedAssignment]) {
    let path = &config.shepherd_sync.assignments_cache_path;

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let cache = AssignmentsCacheFile {
        node_id: config.node_id.clone(),
        shepherd_url: config.shepherd_url.clone(),
        last_updated_at: chrono::Utc::now().to_rfc3339(),
        source: "shepherd".to_string(),
        assignments: assignments.to_vec(),
    };

    match serde_json::to_string_pretty(&cache) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, &json) {
                tracing::warn!(path = %path.display(), error = %e, "Failed to write assignments cache");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to serialize assignments cache");
        }
    }
}

// ---------------------------------------------------------------------------
// Active flock helpers
// ---------------------------------------------------------------------------

pub async fn find_flock_entry(state: &AppState, name: &str) -> Option<FlockEntry> {
    let flock = state.flock.read().await;
    flock.iter().find(|e| e.name == name).cloned()
}
