use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::json;

use crate::cert_store::read_cert_material;
use crate::corgi_client::corgi_post;
use crate::error::AppError;
use crate::issuance::issue_cert;
use crate::renewal_jobs::{complete_job, create_job, fail_job, update_phase};
use crate::state::AppState;
use crate::types::{CorgiNodeConfig, ManagedAssignment, RenewalPhase};

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "healthy", "service": "shepherd-corgi" }))
}

pub async fn get_assignments(
    State(state): State<AppState>,
    axum::Extension(node): axum::Extension<CorgiNodeConfig>,
    Path(corgi_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if node.name != corgi_id {
        return Err(AppError::Forbidden(format!(
            "Authenticated as '{}' but requested assignments for '{}'",
            node.name, corgi_id
        )));
    }

    let assignments = state.assignments.read().await;
    let filtered: Vec<_> = assignments
        .iter()
        .filter(|a| a.corgi.as_deref() == Some(&node.name))
        .collect();

    Ok(Json(json!({
        "corgiId": corgi_id,
        "assignments": filtered,
        "assignmentsCount": filtered.len(),
    })))
}

// ---------------------------------------------------------------------------
// GET /agents/:id/certs/:name
// Corgi calls this when it detects a fingerprint mismatch and needs fresh material.
// ---------------------------------------------------------------------------

pub async fn get_cert(
    State(state): State<AppState>,
    axum::Extension(_node): axum::Extension<CorgiNodeConfig>,
    Path((corgi_id, cert_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let assignments = state.assignments.read().await;
    let assignment = assignments
        .iter()
        .find(|a| a.corgi.as_deref() == Some(&corgi_id) && a.cert_name == cert_name)
        .ok_or_else(|| AppError::NotFound(format!("No assignment for {corgi_id}/{cert_name}")))?
        .clone();
    drop(assignments);

    let material =
        read_cert_material(&state.config.load().cert_store_dir, &cert_name).ok_or_else(|| {
            AppError::NotFound(format!(
                "No certificate material for {corgi_id}/{cert_name}"
            ))
        })?;

    Ok(Json(json!({
        "certName": cert_name,
        "ca": assignment.ca,
        "fingerprint256": material.fingerprint256,
        "expiresInDays": material.expires_in_days,
        "certPem": material.cert_pem,
        "chainPem": material.chain_pem,
        "fullchainPem": material.fullchain_pem,
        "keyPem": material.key_pem,
    })))
}

// ---------------------------------------------------------------------------
// POST /agents/:id/provision/:name
// Synchronous: get CSR → issue → install → respond.
// ---------------------------------------------------------------------------

pub async fn provision_cert(
    State(state): State<AppState>,
    axum::Extension(node): axum::Extension<CorgiNodeConfig>,
    Path((corgi_id, cert_name)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let assignments = state.assignments.read().await;
    let assignment = assignments
        .iter()
        .find(|a| a.corgi.as_deref() == Some(&corgi_id) && a.cert_name == cert_name)
        .ok_or_else(|| AppError::NotFound(format!("No assignment for {corgi_id}/{cert_name}")))?
        .clone();
    drop(assignments);

    let _current_fp = body
        .get("currentFingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();
    let key_algorithm = assignment.key_algorithm.as_deref().unwrap_or("rsa");

    let ca_config = state
        .cas
        .read()
        .await
        .get(&assignment.ca)
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("CA '{}' not configured", assignment.ca))
        })?
        .config
        .clone();

    // Get CSR from corgi
    #[derive(serde::Deserialize)]
    struct CsrResponse {
        #[serde(rename = "csrPem")]
        csr_pem: String,
    }
    let csr: CsrResponse = corgi_post(
        &state.corgi_client_pool,
        &node,
        &format!("/flock/{}/csr", urlencoded(&cert_name)),
        &json!({ "keyAlgorithm": key_algorithm }),
    )
    .await
    .map_err(AppError::Internal)?;

    let corgis = state.corgis.read().await.clone();
    let domains = build_domains(&assignment);
    let store_dir = state.config.load().cert_store_dir.clone();

    let job_id = create_job(
        &state.renewal_jobs,
        &cert_name,
        domains.clone(),
        &assignment.ca,
    )
    .await;
    update_phase(&state.renewal_jobs, job_id, RenewalPhase::SubmittingOrder).await;

    let result = issue_cert(
        &ca_config,
        &assignment.ca,
        &cert_name,
        &store_dir,
        &domains,
        &csr.csr_pem,
        &assignment,
        &state.corgi_client_pool,
        &corgis,
        &state.acme_accounts,
        &state.issuance_ledger,
        &state.renewal_jobs,
        job_id,
    )
    .await
    .map_err(|e| {
        let msg = format!("{e:#}");
        let store = state.renewal_jobs.clone();
        tokio::spawn(async move { fail_job(&store, job_id, msg).await });
        AppError::Internal(e)
    })?;
    complete_job(&state.renewal_jobs, job_id, result.fingerprint256.clone()).await;

    // Install on corgi
    if result.changed {
        if let Err(e) = corgi_post::<serde_json::Value>(
            &state.corgi_client_pool,
            &node,
            &format!("/flock/{}/install", urlencoded(&cert_name)),
            &json!({
                "certPem":      result.cert_pem,
                "chainPem":     result.chain_pem,
                "fullchainPem": result.fullchain_pem,
            }),
        )
        .await
        {
            tracing::warn!(corgi = %corgi_id, cert = %cert_name, error = %e,
                "Cert issued but install failed; corgi will sync on next poll");
        } else {
            crate::corgi_client::evict(&state.corgi_client_pool, &node.name).await;
        }
    }

    Ok(Json(json!({
        "issued": result.issued,
        "changed": result.changed,
        "fingerprint256": result.fingerprint256,
        "certPem": if result.changed { Some(&result.cert_pem) } else { None },
        "ca": assignment.ca,
    })))
}

// ---------------------------------------------------------------------------
// POST /agents/:id/renew/:name
// Async: start renewal job, return 202 immediately.
// ---------------------------------------------------------------------------

pub async fn renew_cert(
    State(state): State<AppState>,
    axum::Extension(node): axum::Extension<CorgiNodeConfig>,
    Path((corgi_id, cert_name)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let assignments = state.assignments.read().await;
    let assignment = assignments
        .iter()
        .find(|a| a.corgi.as_deref() == Some(&corgi_id) && a.cert_name == cert_name)
        .ok_or_else(|| AppError::NotFound(format!("No assignment for {corgi_id}/{cert_name}")))?
        .clone();
    drop(assignments);

    let csr_pem = body
        .get("csrPem")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if csr_pem.trim().is_empty() {
        return Err(AppError::BadRequest("csrPem is required".to_string()));
    }
    let _current_fp = body
        .get("currentFingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();

    // Return existing active job if present
    {
        let jobs = state.renewal_jobs.read().await;
        if let Some(job) = jobs
            .values()
            .find(|j| j.cert_name == cert_name && !j.phase.is_terminal())
        {
            let id = job.id.to_string();
            let phase = format!("{:?}", job.phase).to_lowercase();
            return Ok((
                axum::http::StatusCode::ACCEPTED,
                Json(json!({
                    "jobId": id, "status": "pending", "certName": cert_name, "phase": phase,
                })),
            ));
        }
    }

    let ca_config = state
        .cas
        .read()
        .await
        .get(&assignment.ca)
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("CA '{}' not configured", assignment.ca))
        })?
        .config
        .clone();
    let domains = build_domains(&assignment);
    let job_id = create_job(
        &state.renewal_jobs,
        &cert_name,
        domains.clone(),
        &assignment.ca,
    )
    .await;

    // Spawn async renewal
    let state2 = state.clone();
    let node2 = node.clone();
    let cert_name2 = cert_name.clone();
    let assignment2 = assignment.clone();
    tokio::spawn(async move {
        update_phase(&state2.renewal_jobs, job_id, RenewalPhase::SubmittingOrder).await;
        let corgis = state2.corgis.read().await.clone();
        let store_dir2 = state2.config.load().cert_store_dir.clone();
        match issue_cert(
            &ca_config,
            &assignment2.ca,
            &cert_name2,
            &store_dir2,
            &domains,
            &csr_pem,
            &assignment2,
            &state2.corgi_client_pool,
            &corgis,
            &state2.acme_accounts,
            &state2.issuance_ledger,
            &state2.renewal_jobs,
            job_id,
        )
        .await
        {
            Ok(result) => {
                complete_job(&state2.renewal_jobs, job_id, result.fingerprint256.clone()).await;
                if result.changed {
                    let ok = corgi_post::<serde_json::Value>(
                        &state2.corgi_client_pool,
                        &node2,
                        &format!("/flock/{}/install", urlencoded(&cert_name2)),
                        &json!({
                            "certPem":      result.cert_pem,
                            "chainPem":     result.chain_pem,
                            "fullchainPem": result.fullchain_pem,
                        }),
                    )
                    .await;
                    if ok.is_ok() {
                        crate::corgi_client::evict(&state2.corgi_client_pool, &node2.name).await;
                    }
                }
            }
            Err(e) => {
                fail_job(&state2.renewal_jobs, job_id, e.to_string()).await;
                tracing::warn!(corgi = %corgi_id, cert = %cert_name2, error = %format!("{e:#}"), "Renewal failed");
            }
        }
    });

    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({
            "jobId": job_id.to_string(),
            "status": "pending",
            "certName": cert_name,
            "phase": "queued",
        })),
    ))
}

// ---------------------------------------------------------------------------
// GET /agents/:id/renew/:name/status
// ---------------------------------------------------------------------------

pub async fn renew_status(
    State(state): State<AppState>,
    axum::Extension(_node): axum::Extension<CorgiNodeConfig>,
    Path((corgi_id, cert_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let assignments = state.assignments.read().await;
    let _assignment = assignments
        .iter()
        .find(|a| a.corgi.as_deref() == Some(&corgi_id) && a.cert_name == cert_name)
        .ok_or_else(|| AppError::NotFound(format!("No assignment for {corgi_id}/{cert_name}")))?;
    drop(assignments);

    let jobs = state.renewal_jobs.read().await;

    // Active job first
    if let Some(job) = jobs
        .values()
        .find(|j| j.cert_name == cert_name && !j.phase.is_terminal())
    {
        return Ok(Json(renewal_job_response(job)));
    }
    // Last completed/failed job
    let last = jobs
        .values()
        .filter(|j| j.cert_name == cert_name)
        .max_by_key(|j| j.updated_at);
    match last {
        Some(job) => Ok(Json(renewal_job_response(job))),
        None => Err(AppError::NotFound(format!(
            "No renewal job for {cert_name}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn renewal_job_response(job: &crate::types::RenewalJob) -> serde_json::Value {
    let status = if job.phase == RenewalPhase::Completed {
        "completed"
    } else if job.phase.is_terminal() {
        "failed"
    } else {
        "pending"
    };
    json!({
        "jobId": job.id,
        "status": status,
        "certName": job.cert_name,
        "ca": job.ca,
        "phase": format!("{:?}", job.phase).to_lowercase(),
        "startedAt": job.created_at,
        "updatedAt": job.updated_at,
        "error": job.error,
        "fingerprint256": job.fingerprint256,
    })
}

pub fn build_domains(assignment: &ManagedAssignment) -> Vec<String> {
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
