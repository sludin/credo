use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::assignments::find_flock_entry;
use crate::auth::check_min_role;
use crate::cert_ops::{
    generate_csr_with_keypair, install_certificate,
    is_ecdsa_key, load_key_pem, read_cert_status, to_flock_summary,
};
use crate::error::AppError;
use crate::hooks::run_hooks;
use crate::state::AppState;
use crate::sync::reconcile_once;
use crate::types::{ChallengeRecord, CsrRequest, InstallRequest, Role};

// ---------------------------------------------------------------------------
// Challenge app routes (plain HTTP — no auth required)
// ---------------------------------------------------------------------------

pub async fn challenge_health() -> Json<Value> {
    Json(json!({ "status": "healthy", "service": "corgi-http-challenge" }))
}

pub async fn challenge_get(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let challenges = state.challenges.read().await;
    match challenges.get(&token) {
        Some(record) => (
            StatusCode::OK,
            [("content-type", "text/plain")],
            record.response.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Control API routes (mTLS — auth via middleware-injected Role extension)
// ---------------------------------------------------------------------------

pub async fn control_health(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Readonly)?;
    let flock_size = state.flock.read().await.len();
    Ok(Json(json!({
        "status": "healthy",
        "service": "corgi",
        "nodeId": state.config.node_id,
        "shepherdUrl": state.config.shepherd_url,
        "flockSize": flock_size,
    })))
}

pub async fn flock_list(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Readonly)?;
    let flock = state.flock.read().await;
    let summaries: Vec<_> = flock.iter().map(to_flock_summary).collect();
    Ok(Json(json!({ "flock": summaries })))
}

pub async fn flock_get(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Readonly)?;
    let entry = find_flock_entry(&state, &name)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Certificate '{}' not found", name)))?;
    Ok(Json(json!({ "certificate": read_cert_status(&entry) })))
}

pub async fn flock_csr(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(name): Path<String>,
    body: Option<Json<CsrRequest>>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Admin)?;
    let entry = find_flock_entry(&state, &name)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Certificate '{}' not found", name)))?;

    let csr_req = body.map(|b| b.0).unwrap_or_default();
    // Node-level identityUri is for the node's own auth cert (used with Shepherd).
    // It must not bleed into domain certificate CSRs (e.g. Let's Encrypt won't accept URI SANs).
    // Per-cert identity can be set via FlockEntry.identity_uri or the CSR request body.
    let config_identity_uri: Option<&str> = None;

    tracing::info!(cert_name = %name, phase = "csr", "Renewal started");

    let csr_pem = if !entry.key_path.exists() || !is_ecdsa_key(&entry.key_path) {
        tracing::info!(cert_name = %name, "Generating new ECDSA key before CSR");
        crate::cert_ops::generate_key_and_csr(&entry, &csr_req, config_identity_uri)
            .map_err(|e| AppError::BadRequest(e.to_string()))?
    } else {
        let key_pem = load_key_pem(&entry.key_path)
            .map_err(anyhow::Error::from)?;
        let key_pair = rcgen::KeyPair::from_pem(&key_pem)
            .map_err(|e| AppError::BadRequest(format!("Loading key: {}", e)))?;
        generate_csr_with_keypair(&entry, &csr_req, config_identity_uri, key_pair)
            .map_err(|e| AppError::BadRequest(e.to_string()))?
    };

    tracing::info!(cert_name = %name, phase = "csr-ready", "CSR generated");
    Ok(Json(json!({ "name": name, "csrPem": csr_pem })))
}

pub async fn flock_install(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(name): Path<String>,
    Json(body): Json<InstallRequest>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Admin)?;
    let entry = find_flock_entry(&state, &name)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Certificate '{}' not found", name)))?;

    tracing::info!(cert_name = %name, phase = "install-start", "Install request received");

    let result = install_certificate(&entry, &state.config.cert_store_dir, &body)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let should_restart = result.changed && body.restart.unwrap_or(true);
    let hook_results: Vec<Value> = if should_restart {
        run_hooks(&entry, &state.config)
            .await
            .iter()
            .map(|hr| json!({ "hook": hr.hook, "command": hr.command, "stdout": hr.stdout, "stderr": hr.stderr }))
            .collect()
    } else {
        vec![]
    };

    tracing::info!(
        cert_name = %name, phase = "install",
        changed = result.changed, fingerprint256 = %result.next_fingerprint,
        "Renewal finished successfully"
    );

    Ok(Json(json!({
        "installed": true,
        "changed": result.changed,
        "previousFingerprint": result.previous_fingerprint,
        "fingerprint256": result.next_fingerprint,
        "certificate": read_cert_status(&entry),
        "restartResults": hook_results,
    })))
}

pub async fn flock_restart(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Admin)?;
    let entry = find_flock_entry(&state, &name)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Certificate '{}' not found", name)))?;

    let results: Vec<Value> = run_hooks(&entry, &state.config)
        .await
        .iter()
        .map(|hr| json!({ "hook": hr.hook, "command": hr.command, "stdout": hr.stdout, "stderr": hr.stderr }))
        .collect();

    Ok(Json(json!({ "restarted": true, "results": results })))
}

pub async fn sync_assignments(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Admin)?;
    reconcile_once(&state)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(Json(json!({ "refreshed": true, "source": "shepherd-command" })))
}

pub async fn acme_challenge_create(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Json(body): Json<serde_json::Map<String, Value>>,
) -> Result<impl IntoResponse, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Admin)?;

    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::BadRequest("token is required".to_string()))?
        .to_string();

    let response = body
        .get("response")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::BadRequest("response is required".to_string()))?
        .to_string();

    let domain = body.get("domain").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string());
    let file_path = body.get("filePath").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string());

    if let Some(ref fp) = file_path {
        let path = std::path::Path::new(fp);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("Creating challenge dir: {}", e))?;
        }
        std::fs::write(path, format!("{}\n", response))
            .map_err(|e| anyhow::anyhow!("Writing challenge file: {}", e))?;
    }

    let record = ChallengeRecord {
        token: token.clone(),
        response,
        domain,
        file_path,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    state.challenges.write().await.insert(token, record.clone());
    Ok((StatusCode::CREATED, Json(json!({ "challenge": record }))))
}

pub async fn acme_challenge_delete(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(token): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_min_role(role.as_ref().map(|e| &e.0), &Role::Admin)?;
    let mut challenges = state.challenges.write().await;
    let existing = challenges.remove(&token);
    if let Some(ref record) = existing {
        if let Some(ref fp) = record.file_path {
            let _ = std::fs::remove_file(fp);
        }
    }
    Ok(Json(json!({ "removed": existing.is_some() })))
}
