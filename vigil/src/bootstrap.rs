/// One-shot POST /bootstrap endpoint.
///
/// When vigil starts in bootstrap mode it holds a random secret hex string.
/// Shepherd posts { secret, csr, sans? } — on correct secret, signs the CSR
/// and returns { cert, chain }. The endpoint deactivates after first use.
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::ca::sign_csr;
use crate::error::AppError;
use crate::issuance_policy::validate_issuance_policy;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct BootstrapRequest {
    pub secret: String,
    pub csr: String,
    pub sans: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct BootstrapResponse {
    pub cert: String,
    pub chain: String,
}

pub async fn handle_bootstrap(
    State(state): State<AppState>,
    Json(body): Json<BootstrapRequest>,
) -> Result<Json<BootstrapResponse>, AppError> {
    let mut secret_guard = state.inner.bootstrap_secret.lock().await;

    let expected = match &*secret_guard {
        None => {
            return Err(AppError::NotFound("Bootstrap endpoint is not available.".to_string()));
        }
        Some(s) => s.clone(),
    };

    // Timing-safe comparison
    let provided = hex::decode(body.secret.trim()).unwrap_or_default();
    let expected_bytes = hex::decode(&expected).unwrap_or_default();
    let equal: bool = subtle::ConstantTimeEq::ct_eq(provided.as_slice(), expected_bytes.as_slice()).into();

    if !equal {
        tracing::warn!("Bootstrap: attempt rejected — invalid secret");
        return Err(AppError::Forbidden("Invalid secret.".to_string()));
    }

    let csr_pem = body.csr.trim().to_string();
    let extra_sans: Vec<String> = body
        .sans
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    validate_issuance_policy(&csr_pem, &extra_sans, &state.config().issuance_policy)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let signed = sign_csr(&csr_pem, 1, if extra_sans.is_empty() { None } else { Some(&extra_sans) }, state.config())
        .map_err(|e| AppError::Internal(e))?;

    // Deactivate after first successful use
    *secret_guard = None;
    tracing::info!("Bootstrap: enrolled. Endpoint closed.");

    Ok(Json(BootstrapResponse {
        cert: signed.cert_pem,
        chain: signed.chain_pem,
    }))
}
