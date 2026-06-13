use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::types::{RenewalJob, RenewalPhase, TraceEntry};

pub type JobStore = Arc<RwLock<HashMap<Uuid, RenewalJob>>>;

pub async fn create_job(store: &JobStore, cert_name: &str, domains: Vec<String>, ca: &str) -> Uuid {
    let now = Utc::now().timestamp();
    let job = RenewalJob {
        id: Uuid::new_v4(),
        cert_name: cert_name.to_string(),
        ca: ca.to_string(),
        domains,
        phase: RenewalPhase::Queued,
        created_at: now,
        updated_at: now,
        error: None,
        fingerprint256: None,
        trace: vec![],
        rate_limited_until: None,
    };
    let id = job.id;
    store.write().await.insert(id, job);
    id
}

pub async fn update_phase(store: &JobStore, id: Uuid, phase: RenewalPhase) {
    let mut jobs = store.write().await;
    if let Some(job) = jobs.get_mut(&id) {
        job.phase = phase;
        job.updated_at = Utc::now().timestamp();
    }
}

pub async fn fail_job(store: &JobStore, id: Uuid, error: String) {
    let mut jobs = store.write().await;
    if let Some(job) = jobs.get_mut(&id) {
        job.phase = RenewalPhase::Failed;
        job.error = Some(error);
        job.updated_at = Utc::now().timestamp();
    }
}

pub async fn rate_limit_job(store: &JobStore, id: Uuid, retry_after: DateTime<Utc>) {
    let mut jobs = store.write().await;
    if let Some(job) = jobs.get_mut(&id) {
        job.phase = RenewalPhase::RateLimited;
        job.rate_limited_until = Some(retry_after);
        job.updated_at = Utc::now().timestamp();
    }
}

pub async fn complete_job(store: &JobStore, id: Uuid, fingerprint256: String) {
    let mut jobs = store.write().await;
    if let Some(job) = jobs.get_mut(&id) {
        job.phase = RenewalPhase::Completed;
        job.fingerprint256 = Some(fingerprint256);
        job.updated_at = Utc::now().timestamp();
    }
}

pub async fn append_trace(
    store: &JobStore,
    id: Uuid,
    step: &str,
    detail: Option<&str>,
    identifier: Option<&str>,
    status: Option<&str>,
) {
    let mut jobs = store.write().await;
    if let Some(job) = jobs.get_mut(&id) {
        job.trace.push(TraceEntry {
            at: chrono::Utc::now().to_rfc3339(),
            step: step.to_string(),
            detail: detail.map(str::to_string),
            identifier: identifier.map(str::to_string),
            status: status.map(str::to_string),
        });
    }
}

/// Load terminal jobs from a JSON file written by `persist_terminal_jobs`.
/// Missing file → empty map (first run). Corrupt file → warn and start empty.
pub fn load_terminal_jobs_sync(path: &Path) -> HashMap<Uuid, RenewalJob> {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<Vec<RenewalJob>>(&content) {
            Ok(jobs) => {
                tracing::info!(
                    path = %path.display(),
                    count = jobs.len(),
                    "Loaded renewal job history"
                );
                jobs.into_iter().map(|j| (j.id, j)).collect()
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e,
                    "Failed to parse renewal job history; starting empty");
                HashMap::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e,
                "Failed to read renewal job history; starting empty");
            HashMap::new()
        }
    }
}

/// Write all terminal jobs in the store to a JSON file.
/// Called after complete_job / fail_job so history survives shepherd restarts.
pub async fn persist_terminal_jobs(store: &JobStore, path: &Path) {
    let jobs = store.read().await;
    let terminal: Vec<&RenewalJob> = jobs
        .values()
        .filter(|j| j.phase.is_terminal())
        .collect();
    match serde_json::to_string_pretty(&terminal) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                tracing::warn!(path = %path.display(), error = %e,
                    "Failed to persist renewal job history");
            }
        }
        Err(e) => tracing::warn!(error = %e, "Failed to serialize renewal jobs"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn append_trace_adds_structured_entry() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));
        let id = create_job(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;

        append_trace(&store, id, "order-submitted", Some("vigil"), None, None).await;

        let jobs = store.read().await;
        let job = jobs.get(&id).unwrap();
        assert_eq!(job.trace.len(), 1);
        assert_eq!(job.trace[0].step, "order-submitted");
        assert_eq!(job.trace[0].detail.as_deref(), Some("vigil"));
        assert!(job.trace[0].identifier.is_none());
        chrono::DateTime::parse_from_rfc3339(&job.trace[0].at).unwrap();
    }

    #[tokio::test]
    async fn append_trace_with_identifier_and_status() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));
        let id = create_job(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;

        append_trace(
            &store,
            id,
            "dns-challenge",
            Some("TXT set"),
            Some("example.com"),
            Some("waiting"),
        )
        .await;

        let jobs = store.read().await;
        let entry = &jobs.get(&id).unwrap().trace[0];
        assert_eq!(entry.identifier.as_deref(), Some("example.com"));
        assert_eq!(entry.status.as_deref(), Some("waiting"));
    }

    #[tokio::test]
    async fn append_trace_noop_for_missing_job() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));
        append_trace(&store, uuid::Uuid::new_v4(), "step", None, None, None).await;
    }
}
