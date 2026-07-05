/// Bootstrap API endpoints served on the dashboard port.
/// Authenticated by the one-time in-memory admin token (not JWT).
/// All Vigil and Corgi interactions happen here so the CLI stays a thin HTTP client.
use anyhow::Context;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Token check (constant-time)
// ---------------------------------------------------------------------------

fn check_bootstrap_token(headers: &HeaderMap, state: &AppState) -> bool {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let guard = state.bootstrap_admin_token.lock().unwrap();
    let Some(expected) = guard.as_ref() else {
        return false;
    };
    let expected_full = format!("Bearer {}", expected);
    if auth.len() != expected_full.len() {
        return false;
    }
    auth.as_bytes()
        .iter()
        .zip(expected_full.as_bytes().iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn unauthorized() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "Unauthorized" })),
    )
}

fn vigil_unavailable() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "Vigil client not available" })),
    )
}

// ---------------------------------------------------------------------------
// POST /bootstrap/admin-cert
// ---------------------------------------------------------------------------
// Body:    { "csrPem": "...", "days": 365 }
// Returns: { "certPem": "..." }
//
// The CLI generates the key+CSR locally (the key is the admin's private credential
// and never leaves the CLI process). The server signs the CSR via Vigil.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCertRequest {
    pub csr_pem: String,
    pub days: Option<u32>,
    pub identity_uri: String,
    pub name: Option<String>,
}

pub async fn bootstrap_admin_cert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AdminCertRequest>,
) -> impl IntoResponse {
    if !check_bootstrap_token(&headers, &state) {
        return unauthorized().into_response();
    }
    let vc = state.vigil_client.read().await.clone();
    let Some(client) = vc else {
        return vigil_unavailable().into_response();
    };
    let config = state.config.load_full();
    let Some(vigil_url) = config.vigil_url.as_deref() else {
        return vigil_unavailable().into_response();
    };

    let cert_pem =
        match sign_csr_via_vigil(&client, vigil_url, &body.csr_pem, body.days.unwrap_or(365)).await
        {
            Ok(pem) => pem,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response()
            }
        };

    let name = body
        .name
        .clone()
        .unwrap_or_else(|| derive_name_from_uri(&body.identity_uri));
    let account = crate::types::Account {
        id: Uuid::new_v4().to_string(),
        name: name.clone(),
        display_name: name,
        role: credo_lib::types::Role::Admin,
        active: true,
        identities: vec![body.identity_uri.clone()],
        notes: String::new(),
        created_at: Some(chrono::Utc::now()),
    };

    {
        let mut accounts = state.accounts.write().await;
        accounts.push(account);
        if let Err(e) =
            crate::accounts::save_accounts(&state.config.load().accounts_path, &accounts)
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to persist account: {e}") })),
            )
                .into_response();
        }
    }

    tracing::info!(identity_uri = %body.identity_uri, "Bootstrap admin account registered");

    (
        StatusCode::OK,
        Json(serde_json::json!({ "certPem": cert_pem })),
    )
        .into_response()
}

fn derive_name_from_uri(uri: &str) -> String {
    uri.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("admin")
        .to_string()
}

// ---------------------------------------------------------------------------
// POST /bootstrap/corgi
// ---------------------------------------------------------------------------
// Body:    { "name", "token", "fingerprint", "identityUri", "corgiUrl" }
// Returns: { "enrolled": true }
//
// The server handles the full enrollment sequence:
//   1. Fetch CSR from corgi (fingerprint-pinned TLS, bearer token)
//   2. Sign CSR via Vigil (mTLS, already in vigil_client)
//   3. Push CA + cert to corgi, then finalize

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapCorgiRequest {
    pub name: String,
    pub token: String,
    pub fingerprint: String,
    pub identity_uri: String,
    pub corgi_url: String,
    /// CA name to use for the corgi's own cert assignment (default: "vigil").
    #[serde(default)]
    pub ca: Option<String>,
}

pub async fn bootstrap_corgi(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BootstrapCorgiRequest>,
) -> impl IntoResponse {
    if !check_bootstrap_token(&headers, &state) {
        return unauthorized().into_response();
    }
    let vc = state.vigil_client.read().await.clone();
    let Some(vigil_client) = vc else {
        return vigil_unavailable().into_response();
    };
    let config = state.config.load_full();
    let Some(vigil_url) = config.vigil_url.as_deref() else {
        return vigil_unavailable().into_response();
    };

    match enroll_corgi(&state, &vigil_client, vigil_url, &body).await {
        Ok(()) => {
            tracing::info!(name = %body.name, identity_uri = %body.identity_uri, "Corgi enrolled");
            (
                StatusCode::OK,
                Json(serde_json::json!({ "enrolled": true })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(name = %body.name, error = %e, "Corgi enrollment failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

pub async fn enroll_corgi(
    state: &AppState,
    vigil_client: &reqwest::Client,
    vigil_url: &str,
    req: &BootstrapCorgiRequest,
) -> anyhow::Result<()> {
    let corgi_client = build_corgi_bootstrap_client(&req.fingerprint)
        .context("Building corgi bootstrap client")?;

    let csr_resp: serde_json::Value = corgi_client
        .get(format!("{}/bootstrap/csr", req.corgi_url))
        .header("Authorization", format!("Bearer {}", req.token))
        .send()
        .await
        .context("GET /bootstrap/csr from corgi")?
        .json()
        .await
        .context("Parsing corgi CSR response")?;
    let csr_pem = csr_resp["csrPem"].as_str().ok_or_else(|| {
        if let Some(e) = csr_resp["error"].as_str() {
            anyhow::anyhow!("Corgi /bootstrap/csr failed: {}", e)
        } else {
            anyhow::anyhow!("Missing csrPem in corgi response: {}", csr_resp)
        }
    })?;
    let http_challenge_port: Option<u16> = csr_resp["httpChallengePort"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok());
    let common_name: Option<String> = csr_resp["commonName"].as_str().map(str::to_string);

    let fullchain_pem = sign_csr_via_vigil(vigil_client, vigil_url, csr_pem, 365)
        .await
        .context("Signing corgi CSR via Vigil")?;
    let (leaf_pem, chain_pem, _) = crate::issuance::split_cert_chain(&fullchain_pem);

    let config = state.config.load_full();
    let ca_path = config
        .shepherd_ca_path
        .as_ref()
        .unwrap_or(&config.tls.client_ca_path);
    let ca_pem = std::fs::read_to_string(ca_path)
        .with_context(|| format!("Reading CA bundle: {}", ca_path.display()))?;

    require_corgi_success(
        "POST /bootstrap/ca",
        corgi_client
            .post(format!("{}/bootstrap/ca", req.corgi_url))
            .header("Authorization", format!("Bearer {}", req.token))
            .json(&serde_json::json!({ "caPem": ca_pem }))
            .send()
            .await
            .context("POST /bootstrap/ca")?,
    )
    .await?;

    require_corgi_success(
        "POST /bootstrap/cert",
        corgi_client
            .post(format!("{}/bootstrap/cert", req.corgi_url))
            .header("Authorization", format!("Bearer {}", req.token))
            .json(&serde_json::json!({
                "certPem":      leaf_pem,
                "chainPem":     chain_pem,
                "fullchainPem": fullchain_pem,
            }))
            .send()
            .await
            .context("POST /bootstrap/cert")?,
    )
    .await?;

    require_corgi_success(
        "POST /bootstrap/finalize",
        corgi_client
            .post(format!("{}/bootstrap/finalize", req.corgi_url))
            .header("Authorization", format!("Bearer {}", req.token))
            .send()
            .await
            .context("POST /bootstrap/finalize")?,
    )
    .await?;

    // Persist the enrolled corgi and refresh in-memory state so shepherd picks it up immediately.
    let corgis_path = state.config.load().corgis_config_path.clone();
    crate::corgis::save_corgi_entry(
        &corgis_path,
        &req.name,
        &req.corgi_url,
        Some(&req.identity_uri),
        http_challenge_port,
    )
    .context("Saving corgi to corgis config")?;
    match crate::corgis::load_corgis(&corgis_path) {
        Ok(updated) => {
            tracing::info!(
                name = %req.name,
                count = updated.len(),
                "Corgi registered in corgis config"
            );
            *state.corgis.write().await = updated;
        }
        Err(e) => {
            tracing::warn!(error = %e, "Enrolled corgi saved but failed to reload corgis state");
        }
    }

    // Add an assignment for the corgi's own cert so shepherd manages it going forward.
    if let Some(cn) = common_name {
        let ca = req.ca.as_deref().unwrap_or("vigil").to_string();
        let new_assignment = crate::types::ManagedAssignment {
            cert_name: cn.clone(),
            corgi: Some(req.name.clone()),
            ca,
            domain: Some(cn.clone()),
            sans: vec![cn.clone()],
            identity_uri: Some(req.identity_uri.clone()),
            validation: Some(crate::types::AssignmentValidation {
                validation_type: Some("http-01".to_string()),
                force_revalidate: false,
                methods: None,
            }),
            renew_before_days: None,
            days: None,
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
            key_algorithm: None,
            hooks: None,
        };
        let assignments_path = state.config.load().assignments_config_path.clone();
        let mut assignments = crate::assignments::load_assignments(&assignments_path)
            .context("Loading assignments for corgi cert registration")?;
        assignments.retain(|a| a.cert_name != cn);
        assignments.push(new_assignment);
        crate::assignments::save_assignments(&assignments_path, &assignments)
            .context("Saving corgi cert assignment")?;
        tracing::info!(
            cert_name = %cn,
            corgi = %req.name,
            "Corgi cert assignment registered"
        );
        *state.assignments.write().await = assignments;
    } else {
        tracing::warn!(
            name = %req.name,
            "Corgi CSR response missing commonName — cert assignment not created automatically"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers (moved from main.rs)
// ---------------------------------------------------------------------------

async fn require_corgi_success(label: &str, resp: reqwest::Response) -> anyhow::Result<()> {
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    anyhow::bail!("Corgi {} returned {}: {}", label, status, body)
}

pub(crate) async fn sign_csr_via_vigil(
    client: &reqwest::Client,
    vigil_url: &str,
    csr_pem: &str,
    days: u32,
) -> anyhow::Result<String> {
    let resp = client
        .post(format!("{}/certificates/sign", vigil_url))
        .json(&serde_json::json!({ "csrPem": csr_pem, "days": days }))
        .send()
        .await
        .context("POST /certificates/sign")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Vigil sign returned {}: {}", status, body);
    }
    let body: serde_json::Value = resp.json().await.context("Parsing vigil sign response")?;
    body["certificate"]["certPem"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Missing certificate.certPem in vigil sign response"))
}

fn build_corgi_bootstrap_client(expected_fingerprint: &str) -> anyhow::Result<reqwest::Client> {
    let normalized = expected_fingerprint.replace(':', "").to_lowercase();
    let verifier = std::sync::Arc::new(FingerprintVerifier {
        expected_hex: normalized,
    });
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    reqwest::ClientBuilder::new()
        .use_preconfigured_tls(tls)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Building corgi bootstrap client with fingerprint verifier")
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected_hex: String,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest;
        let actual = hex::encode(sha2::Sha256::digest(end_entity.as_ref()));
        if actual == self.expected_hex {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Bootstrap fingerprint mismatch: expected {}, got {}",
                self.expected_hex, actual
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
