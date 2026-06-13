use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Json},
    routing::{get, head, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{auth_middleware, AuthUser};
use crate::bootstrap::handle_bootstrap;
use crate::error::AppError;
use crate::pki_wire::{
    build_ocsp_error_response, build_ocsp_response_from_request, build_signed_crl_der,
    build_signed_crl_pem,
};
use crate::revocation::{generate_crl, get_ocsp_status_by_cert_id, get_ocsp_status_by_serial};
use crate::state::AppState;
use crate::storage;

// ---------------------------------------------------------------------------
// Route assembly
// ---------------------------------------------------------------------------

pub fn build_router(state: AppState) -> Router {
    // ACME routes — mTLS required; auth_middleware sets AuthUser for JWS handlers
    // Directory and nonce are unauthenticated entry points; all others require a
    // valid client cert matching rbacIdentities.
    let acme_public = Router::new()
        .route("/acme/directory", get(crate::acme::directory))
        .route(
            "/acme/new-nonce",
            head(crate::acme::new_nonce_head).get(crate::acme::new_nonce_get),
        )
        .layer(middleware::from_fn(|req, next| {
            credo_lib::log::log_request("V", req, next)
        }))
        .with_state(state.clone());

    let acme_protected = Router::new()
        .route("/acme/new-account", post(crate::acme::new_account))
        .route("/acme/account/:id", post(crate::acme::get_account))
        .route("/acme/new-order", post(crate::acme::new_order))
        .route("/acme/order/:id", post(crate::acme::get_order))
        .route(
            "/acme/order/:id/finalize",
            post(crate::acme::finalize_order),
        )
        .route("/acme/authz/:id", post(crate::acme::get_authz))
        .route("/acme/challenge/:id", post(crate::acme::respond_challenge))
        .route("/acme/cert/:id", post(crate::acme::download_cert))
        .route("/acme/revoke-cert", post(crate::acme::revoke_cert))
        .route("/acme/key-change", post(crate::acme::key_change))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(|req, next| {
            credo_lib::log::log_request("V", req, next)
        }))
        .with_state(state.clone());

    // Bootstrap (no mTLS, ephemeral)
    let bootstrap = Router::new()
        .route("/bootstrap", post(handle_bootstrap))
        .layer(middleware::from_fn(|req, next| {
            credo_lib::log::log_request("V", req, next)
        }))
        .with_state(state.clone());

    // mTLS-protected routes
    let protected = Router::new()
        .route("/health", get(health))
        .route("/ca", get(ca_info))
        .route("/ocsp/:id", get(ocsp_by_id))
        .route("/ocsp", get(ocsp_by_serial))
        .route("/ocsp", post(ocsp_der))
        .route("/crl", get(crl_json))
        .route("/crl.der", get(crl_der))
        .route("/crl.pem", get(crl_pem))
        .route("/certificates/sign", post(sign_certificate))
        .route("/certificates/:id", get(get_certificate))
        .route("/certificates/:id/revoke", post(revoke_certificate))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(|req, next| {
            credo_lib::log::log_request("V", req, next)
        }))
        .with_state(state.clone());

    Router::new()
        .merge(acme_public)
        .merge(acme_protected)
        .merge(bootstrap)
        .merge(protected)
}

// ---------------------------------------------------------------------------
// mTLS route handlers
// ---------------------------------------------------------------------------

async fn health(
    State(state): State<AppState>,
    axum::Extension(AuthUser(_auth_user)): axum::Extension<AuthUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    let config = state.config();
    let (total, revoked, active) = storage::certificate_stats(&config.cert_db_path)?;
    let users = storage::list_users(&config.users_db_path)?.len();
    let ca = state.ca_metadata();

    Ok(Json(json!({
        "status": "healthy",
        "service": "vigil",
        "users": { "total": users },
        "certificates": { "total": total, "revoked": revoked, "active": active },
        "ca": {
            "initialized": true,
            "fingerprint256": ca.fingerprint256,
            "validTo": ca.valid_to,
        }
    })))
}

async fn ca_info(
    State(state): State<AppState>,
    axum::Extension(AuthUser(_auth_user)): axum::Extension<AuthUser>,
) -> Json<serde_json::Value> {
    Json(json!({ "rootCA": state.ca_metadata() }))
}

#[derive(Deserialize)]
struct SerialQuery {
    #[serde(rename = "serialNumber")]
    serial_number: Option<String>,
}

async fn ocsp_by_id(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let config = state.config();
    let ocsp =
        get_ocsp_status_by_cert_id(&config.cert_db_path, &id, config.ca.ocsp_max_age_seconds)?;
    let _ = crate::ctlog::append_ct_log(
        &config.ct_log_path,
        "certificate.ocsp.checked",
        &auth_user.id,
        json!({ "certificateId": id, "status": ocsp.status }),
    );
    Ok(Json(json!({ "ocsp": ocsp })))
}

async fn ocsp_by_serial(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    Query(q): Query<SerialQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let serial = q
        .serial_number
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("serialNumber query parameter is required.".to_string())
        })?;
    let config = state.config();
    let ocsp = get_ocsp_status_by_serial(
        &config.cert_db_path,
        &serial,
        config.ca.ocsp_max_age_seconds,
    )?;
    let _ = crate::ctlog::append_ct_log(
        &config.ct_log_path,
        "certificate.ocsp.checked",
        &auth_user.id,
        json!({ "serialNumber": serial, "status": ocsp.status }),
    );
    Ok(Json(json!({ "ocsp": ocsp })))
}

async fn ocsp_der(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    body: Bytes,
) -> impl IntoResponse {
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            [("Content-Type", "application/ocsp-response")],
            build_ocsp_error_response(1),
        )
            .into_response();
    }
    let config = state.config();
    match build_ocsp_response_from_request(&body, config.ca.ocsp_max_age_seconds, &config) {
        Ok(resp) => {
            let _ = crate::ctlog::append_ct_log(
                &config.ct_log_path,
                "certificate.ocsp.der.checked",
                &auth_user.id,
                json!({ "requestBytes": body.len(), "responseBytes": resp.len() }),
            );
            (
                StatusCode::OK,
                [("Content-Type", "application/ocsp-response")],
                resp,
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("DER OCSP request failed: {}", e);
            (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "application/ocsp-response")],
                build_ocsp_error_response(1),
            )
                .into_response()
        }
    }
}

async fn crl_json(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    let config = state.config();
    let crl = generate_crl(
        &config.cert_db_path,
        state.ca_metadata(),
        config.ca.crl_next_update_hours,
    )?;
    let _ = crate::ctlog::append_ct_log(
        &config.ct_log_path,
        "certificate.crl.downloaded",
        &auth_user.id,
        json!({ "revokedCount": crl.revoked_certificates.len() }),
    );
    Ok(Json(json!({ "crl": crl })))
}

async fn crl_der(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    let config = state.config();
    match build_signed_crl_der(
        state.ca_metadata(),
        config.ca.crl_next_update_hours,
        &config,
    ) {
        Ok(der) => {
            let _ = crate::ctlog::append_ct_log(
                &config.ct_log_path,
                "certificate.crl.der.downloaded",
                &auth_user.id,
                json!({ "byteLength": der.len() }),
            );
            (
                StatusCode::OK,
                [
                    ("Content-Type", "application/pkix-crl"),
                    ("Content-Disposition", "inline; filename=\"vigil.crl\""),
                ],
                der,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn crl_pem(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    let config = state.config();
    match build_signed_crl_pem(
        state.ca_metadata(),
        config.ca.crl_next_update_hours,
        &config,
    ) {
        Ok(pem) => {
            let _ = crate::ctlog::append_ct_log(
                &config.ct_log_path,
                "certificate.crl.pem.downloaded",
                &auth_user.id,
                json!({ "byteLength": pem.len() }),
            );
            (
                StatusCode::OK,
                [
                    ("Content-Type", "application/x-pem-file"),
                    ("Content-Disposition", "inline; filename=\"vigil.crl.pem\""),
                ],
                pem,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct SignRequest {
    #[serde(rename = "csrPem")]
    csr_pem: Option<String>,
    days: Option<f64>,
    sans: Option<Vec<String>>,
}

async fn sign_certificate(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    Json(body): Json<SignRequest>,
) -> Result<impl IntoResponse, AppError> {
    let csr_pem = body
        .csr_pem
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("csrPem is required.".to_string()))?;

    let days = body
        .days
        .map(|d| d as u32)
        .unwrap_or(state.config().ca.cert_default_days);
    if days == 0 {
        return Err(AppError::BadRequest(
            "days must be a positive number.".to_string(),
        ));
    }

    let extra_sans: Vec<String> = body
        .sans
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect();

    crate::issuance_policy::validate_issuance_policy(
        &csr_pem,
        &extra_sans,
        &state.config().issuance_policy,
    )
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let signed = crate::ca::sign_csr(
        &csr_pem,
        days,
        if extra_sans.is_empty() {
            None
        } else {
            Some(&extra_sans)
        },
        &state.config(),
    )
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let config = state.config();
    let record = crate::types::CertificateRecord {
        id: signed.id.clone(),
        serial_number: signed.serial_number.clone(),
        subject: signed.subject.clone(),
        fingerprint256: signed.fingerprint256.clone(),
        valid_from: signed.valid_from.clone(),
        valid_to: signed.valid_to.clone(),
        cert_path: String::new(),
        issued_at: chrono::Utc::now().to_rfc3339(),
        issued_by: auth_user.id.clone(),
        owner_vigil_user_id: auth_user.id.clone(),
        issuing_acme_account_id: None,
        revoked: false,
        revoked_at: None,
        revoked_by: None,
        revoked_by_vigil_user_id: None,
        revoked_by_acme_account_id: None,
        revoked_via: None,
        revoke_reason: None,
    };

    let stored = storage::issue_certificate_record(
        &config.cert_db_path,
        &config.certs_dir,
        record,
        &signed.fullchain_pem,
    )?;

    let _ = crate::ctlog::append_ct_log(
        &config.ct_log_path,
        "certificate.signed",
        &auth_user.id,
        json!({ "certificateId": stored.id, "serialNumber": stored.serial_number, "subject": stored.subject, "validTo": stored.valid_to }),
    );
    tracing::info!(user_id = %auth_user.id, cert_id = %stored.id, serial = %stored.serial_number, "Certificate signed");

    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "certificate": { "certPem": signed.fullchain_pem, "id": stored.id, "serialNumber": stored.serial_number, "subject": stored.subject, "validFrom": stored.valid_from, "validTo": stored.valid_to, "fingerprint256": stored.fingerprint256, "issuedAt": stored.issued_at, "issuedBy": stored.issued_by, "ownerVigilUserId": stored.owner_vigil_user_id, "revoked": false } }),
        ),
    ))
}

async fn get_certificate(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let config = state.config();
    let record = storage::get_certificate_record(&config.cert_db_path, &id)?
        .ok_or_else(|| AppError::NotFound("Certificate not found.".to_string()))?;
    let cert_pem = storage::read_certificate_pem(&record.cert_path)
        .ok_or_else(|| AppError::NotFound("Certificate file is missing.".to_string()))?;

    let _ = crate::ctlog::append_ct_log(
        &config.ct_log_path,
        "certificate.downloaded",
        &auth_user.id,
        json!({ "certificateId": id }),
    );
    Ok(Json(
        json!({ "certificate": { "certPem": cert_pem, "id": record.id, "serialNumber": record.serial_number, "subject": record.subject, "revoked": record.revoked } }),
    ))
}

#[derive(serde::Deserialize)]
struct RevokeRequest {
    reason: Option<String>,
}

async fn revoke_certificate(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let config = state.config();
    let existing = storage::get_certificate_record(&config.cert_db_path, &id)?
        .ok_or_else(|| AppError::NotFound("Certificate not found.".to_string()))?;

    use crate::types::Role;
    if auth_user.role != Role::Admin {
        let owner = existing.owner_vigil_user_id.as_str();
        if owner != auth_user.id && existing.issued_by != auth_user.id {
            return Err(AppError::Forbidden(
                "Certificate does not belong to authenticated user.".to_string(),
            ));
        }
    }

    let reason = body
        .reason
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unspecified".to_string());
    let updated = storage::revoke_certificate(
        &config.cert_db_path,
        &id,
        &auth_user.id,
        &reason,
        Some(auth_user.id.clone()),
        None,
        Some("api-user".to_string()),
    )?
    .ok_or_else(|| AppError::NotFound("Certificate not found.".to_string()))?;

    let _ = crate::ctlog::append_ct_log(
        &config.ct_log_path,
        "certificate.revoked",
        &auth_user.id,
        json!({ "certificateId": id, "reason": reason }),
    );
    tracing::info!(user_id = %auth_user.id, cert_id = %id, reason = %reason, "Certificate revoked");
    Ok(Json(json!({ "certificate": updated })))
}
