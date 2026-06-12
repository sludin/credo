use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::types::{RenewalJob, RenewalPhase};

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
