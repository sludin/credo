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

/// Result of `create_job_if_not_active`.
pub enum JobGate {
    /// No conflicting job existed; a new one was created and reserved.
    Created(Uuid),
    /// A non-terminal, non-rate-limited job already exists for this cert.
    AlreadyInProgress,
    /// A rate-limited job exists and its window hasn't reopened yet.
    StillRateLimited(DateTime<Utc>),
}

/// Atomically check for a conflicting job and create a new one under a
/// single write-lock acquisition, closing the check-then-act window between
/// "is a job already active?" and "create one" — without this, two callers
/// (e.g. the reconcile loop's mutation-triggered maintenance and the
/// periodic renewal sweep, which run as independent tasks) could both see
/// "no active job," both proceed to request a fresh CSR from Corgi, and
/// clobber Corgi's single pending-key file mid-flight, installing a
/// certificate against the wrong key.
///
/// Mirrors the same rate-limit-retry semantics `cert_maintenance` used to
/// implement via a separate read-then-later-create pair: a non-terminal job
/// blocks a new one *unless* it's specifically `RateLimited` and its window
/// has passed, in which case a new job is created alongside it.
pub async fn create_job_if_not_active(
    store: &JobStore,
    cert_name: &str,
    domains: Vec<String>,
    ca: &str,
) -> JobGate {
    let mut jobs = store.write().await;
    if let Some(job) = jobs
        .values()
        .find(|j| j.cert_name == cert_name && !j.phase.is_terminal())
    {
        if job.phase == RenewalPhase::RateLimited {
            if let Some(until) = job.rate_limited_until {
                if until > Utc::now() {
                    return JobGate::StillRateLimited(until);
                }
            }
        } else {
            return JobGate::AlreadyInProgress;
        }
    }

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
    jobs.insert(id, job);
    JobGate::Created(id)
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
    let terminal: Vec<&RenewalJob> = jobs.values().filter(|j| j.phase.is_terminal()).collect();
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

    #[tokio::test]
    async fn create_job_if_not_active_creates_when_none_exists() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));
        let gate = create_job_if_not_active(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        assert!(matches!(gate, JobGate::Created(_)));
    }

    /// Regression test for a Medium finding: two concurrent callers for the
    /// same cert must not both be told "no active job" — closing the window
    /// that let both proceed to request a CSR from Corgi and clobber its
    /// single pending-key file mid-flight.
    #[tokio::test]
    async fn create_job_if_not_active_rejects_second_concurrent_call() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));

        let first = create_job_if_not_active(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        assert!(matches!(first, JobGate::Created(_)));

        let second = create_job_if_not_active(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        assert!(
            matches!(second, JobGate::AlreadyInProgress),
            "a second call for the same cert while the first job is still active must be rejected"
        );

        // Only one job should ever have been created.
        assert_eq!(store.read().await.len(), 1);
    }

    #[tokio::test]
    async fn create_job_if_not_active_allows_retry_after_rate_limit_window_passes() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));
        let id = create_job(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        {
            let mut jobs = store.write().await;
            let job = jobs.get_mut(&id).unwrap();
            job.phase = RenewalPhase::RateLimited;
            job.rate_limited_until = Some(Utc::now() - chrono::Duration::seconds(1));
        }

        let gate = create_job_if_not_active(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        assert!(
            matches!(gate, JobGate::Created(_)),
            "a new job must be allowed once the rate-limit window has passed"
        );
    }

    #[tokio::test]
    async fn create_job_if_not_active_still_blocked_within_rate_limit_window() {
        let store: JobStore = Arc::new(RwLock::new(HashMap::new()));
        let id = create_job(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        let until = Utc::now() + chrono::Duration::seconds(60);
        {
            let mut jobs = store.write().await;
            let job = jobs.get_mut(&id).unwrap();
            job.phase = RenewalPhase::RateLimited;
            job.rate_limited_until = Some(until);
        }

        let gate = create_job_if_not_active(
            &store,
            "example.com",
            vec!["example.com".into()],
            "letsencrypt",
        )
        .await;
        match gate {
            JobGate::StillRateLimited(got) => assert_eq!(got, until),
            _ => panic!("expected StillRateLimited"),
        }
    }
}
