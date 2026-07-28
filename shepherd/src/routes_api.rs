use axum::extract::{Path, Query, State};
use axum::response::Json;
use chrono::Utc;
use serde_json::json;

use axum::http::header;
use axum::response::IntoResponse;

use crate::assignments::{file_mtime, load_assignments, save_assignments};
use crate::auth::check_min_role;
use crate::cert_store;
use crate::corgi_client::{corgi_get_hooks, corgi_post};
use crate::corgis::load_corgis;
use crate::error::AppError;
use crate::issuance::issue_cert;
use crate::jwt::{jwks_response, sign_jwt};
use crate::renewal_jobs::{append_trace, complete_job, create_job, fail_job, update_phase};
use crate::routes_corgi::build_domains;
use crate::state::AppState;
use crate::types::{AuthenticatedUser, RenewalPhase, Role};

// ---------------------------------------------------------------------------
// Public routes (no auth required)
// ---------------------------------------------------------------------------

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "healthy", "service": "shepherd" }))
}

// ---------------------------------------------------------------------------
// Flock state (dashboard view of all corgis + their runtime status)
// ---------------------------------------------------------------------------

pub async fn flock_list(State(state): State<AppState>) -> Json<serde_json::Value> {
    let corgis = state.corgis.read().await;
    let cs = state.corgi_state.read().await;
    let entries: Vec<_> = corgis.iter().map(|node| {
        let s = cs.get(&node.name);
        json!({
            "name": node.name,
            "url": node.url,
            "status": s.map(|s| format!("{:?}", s.status).to_lowercase()).unwrap_or_else(|| "unknown".into()),
            "lastPolledAt": s.and_then(|s| s.last_health_check),
            "flock": s.map(|s| &s.flock).cloned().unwrap_or_default(),
            "error": s.and_then(|s| s.error.as_deref()),
        })
    }).collect();
    Json(json!({ "corgis": entries }))
}

pub async fn flock_get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let corgis = state.corgis.read().await;
    let node = corgis
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| AppError::NotFound(format!("Corgi '{name}' not found")))?;
    let node_name = node.name.clone();
    let node_url = node.url.clone();
    drop(corgis);
    let cs = state.corgi_state.read().await;
    let s = cs.get(&node_name);
    let status = s
        .map(|s| format!("{:?}", s.status).to_lowercase())
        .unwrap_or_else(|| "unknown".into());
    let last_polled = s.and_then(|s| s.last_health_check);
    let flock = s.map(|s| s.flock.clone()).unwrap_or_default();
    let error = s.and_then(|s| s.error.clone());
    Ok(Json(json!({
        "corgi": {
            "name": node_name,
            "url": node_url,
            "status": status,
            "lastPolledAt": last_polled,
            "flock": flock,
            "error": error,
        }
    })))
}

pub async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(jwks_response(&state.jwt_keys))
}

pub async fn token(
    State(state): State<AppState>,
    maybe_peer: Option<axum::Extension<credo_lib::PeerCertDer>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Bootstrap override: SHEPHERD_BOOTSTRAP_ADMIN_TOKEN env var bypasses cert validation
    if let Ok(bootstrap_token) = std::env::var("SHEPHERD_BOOTSTRAP_ADMIN_TOKEN") {
        if let Some(provided) = body.get("bootstrapToken").and_then(|v| v.as_str()) {
            if provided == bootstrap_token {
                let role = Role::Admin;
                let identity_uri = "vigil://credo/bootstrap/admin";
                let access = sign_jwt(&state.jwt_keys, identity_uri, &role, None)
                    .map_err(AppError::Internal)?;
                let expires_at = Utc::now().timestamp() + 86400;
                let refresh = state
                    .refresh_tokens
                    .issue_token(identity_uri, &role, None, expires_at)
                    .await;
                return Ok(Json(json!({
                    "accessToken": access,
                    "refreshToken": refresh,
                })));
            }
        }
    }

    // PoP token exchange
    let pop = body
        .get("pop")
        .ok_or_else(|| AppError::BadRequest("Missing pop field".to_string()))?;

    let cert_pem = pop
        .get("cert")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing pop.cert".to_string()))?;
    let identity_uri = pop
        .get("identityUri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing pop.identityUri".to_string()))?;
    let issued_at_str = pop
        .get("issuedAt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing pop.issuedAt".to_string()))?;
    let challenge = pop
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing pop.challenge".to_string()))?;
    let signature_b64 = pop
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing pop.signature".to_string()))?;

    // Freshness: reject PoPs older than 5 minutes
    let issued_at = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .map_err(|_| AppError::BadRequest("Invalid issuedAt format".to_string()))?;
    if (Utc::now() - issued_at.with_timezone(&Utc)).num_minutes() > 5 {
        return Err(AppError::Unauthorized("PoP token has expired".to_string()));
    }

    // Parse cert DER
    let cert_der = pop_pem_to_der(cert_pem)
        .ok_or_else(|| AppError::BadRequest("Could not parse pop.cert".to_string()))?;

    // Fast path: if client presented the same cert via TLS, the handshake already
    // proved key possession and CA validity — skip crypto verification.
    let tls_match = maybe_peer
        .and_then(|ext| credo_lib::auth::identity_from_der(&ext.0 .0).ok())
        .zip(credo_lib::auth::identity_from_der(&cert_der).ok())
        .map(|(peer, pop_id)| peer.fingerprint256 == pop_id.fingerprint256)
        .unwrap_or(false);

    if !tls_match {
        // No matching TLS cert — verify CA chain then verify PoP signature
        verify_pop_cert(cert_pem, &state.config.load().tls.client_ca_path).map_err(|e| {
            AppError::Unauthorized(format!("Certificate not signed by configured CA: {e}"))
        })?;

        verify_pop_signature(
            &cert_der,
            challenge,
            identity_uri,
            issued_at_str,
            signature_b64,
        )
        .map_err(|e| AppError::Unauthorized(format!("PoP signature verification failed: {e}")))?;
    }

    // Verify the cert has a vigil:// URI SAN matching identityUri
    let pop_identity = credo_lib::auth::identity_from_der(&cert_der)
        .map_err(|_| AppError::BadRequest("Could not parse cert identity".to_string()))?;

    let cert_uri = pop_identity
        .san_uris
        .iter()
        .find(|u| u.starts_with("vigil://"))
        .ok_or_else(|| AppError::Unauthorized("Certificate has no vigil:// URI SAN".to_string()))?;
    if cert_uri != identity_uri {
        return Err(AppError::Unauthorized(
            "pop.identityUri does not match certificate URI SAN".to_string(),
        ));
    }

    // Look up the account by identity URI.
    let accounts = state.accounts.read().await;
    let account = accounts
        .iter()
        .find(|a| a.active && a.identities.contains(&identity_uri.to_string()))
        .ok_or_else(|| AppError::Unauthorized(format!(
            "Identity '{}' not found in any active Shepherd account. \
             Add this URI to the identities[] array of the matching account in shepherd.accounts.json.",
            identity_uri
        )))?
        .clone();
    drop(accounts);

    // Cert expiry drives the refresh token TTL
    let (_, x509) = x509_parser::parse_x509_certificate(&cert_der)
        .map_err(|_| AppError::BadRequest("Could not parse cert".to_string()))?;
    let cert_not_after = x509.validity().not_after.timestamp();

    let access_token = sign_jwt(
        &state.jwt_keys,
        identity_uri,
        &account.role,
        Some(&account.name),
    )
    .map_err(AppError::Internal)?;
    let refresh_token = state
        .refresh_tokens
        .issue_token(
            identity_uri,
            &account.role,
            Some(&account.name),
            cert_not_after,
        )
        .await;
    let expires_at = chrono::DateTime::from_timestamp(cert_not_after, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    Ok(Json(json!({
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at,
    })))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = body
        .get("refreshToken")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing refreshToken field".to_string()))?;

    let entry = state
        .refresh_tokens
        .validate_token(token)
        .await
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired refresh token".to_string()))?;

    // Use the current account role rather than the role baked in at issuance,
    // so that role changes in shepherd.accounts.json take effect at the next refresh.
    let current_role = {
        let accounts = state.accounts.read().await;
        accounts
            .iter()
            .find(|a| a.active && a.identities.iter().any(|id| id == &entry.identity_uri))
            .map(|a| a.role.clone())
            .unwrap_or_else(|| Role::from_str(&entry.role))
    };
    let role = current_role;
    let access = sign_jwt(
        &state.jwt_keys,
        &entry.identity_uri,
        &role,
        entry.account_name.as_deref(),
    )
    .map_err(AppError::Internal)?;

    // Revoke old, issue new — preserve the original cert-based expiry so the
    // refresh token lives for the lifetime of the enrollment cert, not just 24h.
    state.refresh_tokens.revoke_token(token).await;
    let expires_at = entry.expires_at;
    let new_refresh = state
        .refresh_tokens
        .issue_token(
            &entry.identity_uri,
            &role,
            entry.account_name.as_deref(),
            expires_at,
        )
        .await;

    let expires_at_str = chrono::DateTime::from_timestamp(expires_at, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    Ok(Json(json!({
        "accessToken": access,
        "refreshToken": new_refresh,
        "expiresAt": expires_at_str,
    })))
}

// ---------------------------------------------------------------------------
// Corgi hook discovery (proxies to corgi's GET /hooks)
// ---------------------------------------------------------------------------

pub async fn get_corgi_hooks(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(corgi_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let corgis = state.corgis.read().await;
    let node = corgis
        .iter()
        .find(|c| c.name == corgi_id)
        .ok_or_else(|| AppError::NotFound(format!("Corgi '{corgi_id}' not found")))?
        .clone();
    drop(corgis);
    let resp = corgi_get_hooks(&state.corgi_client_pool, &state.hooks_cache, &node)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({
        "corgiId": corgi_id,
        "availableHooks": resp.available_hooks,
        "defaultHooks": resp.default_hooks,
    })))
}

// ---------------------------------------------------------------------------
// Authenticated routes (readonly+)
// ---------------------------------------------------------------------------

pub async fn get_assignments(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let assignments = state.assignments.read().await;
    Ok(Json(json!({ "assignments": *assignments })))
}

pub async fn get_certstore(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let config = state.config.load_full();
    let store_dir = &config.cert_store_dir;
    let names = cert_store::list_cert_store_entries(store_dir);
    let entries: Vec<_> = names
        .iter()
        .filter_map(|n| cert_store::read_cert_store_entry(store_dir, n))
        .collect();
    Ok(Json(
        json!({ "certStoreDir": store_dir, "entries": entries }),
    ))
}

pub async fn get_certstore_entry(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let entry = cert_store::read_cert_store_entry(&state.config.load().cert_store_dir, &name)
        .ok_or_else(|| AppError::NotFound(format!("Cert '{name}' not found")))?;
    Ok(Json(json!({ "entry": entry })))
}

pub async fn get_certstore_pem(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    if !cert_store::is_safe_cert_name(&name) {
        return Err(AppError::BadRequest("Invalid certificate name".to_string()));
    }
    let path = state
        .config
        .load()
        .cert_store_dir
        .join("live")
        .join(&name)
        .join("cert.pem");
    let pem = std::fs::read_to_string(&path)
        .map_err(|_| AppError::NotFound(format!("Certificate file not found for '{name}'")))?;
    Ok(([(header::CONTENT_TYPE, "text/plain")], pem))
}

pub async fn get_certstore_fullchain(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    if !cert_store::is_safe_cert_name(&name) {
        return Err(AppError::BadRequest("Invalid certificate name".to_string()));
    }
    let path = state
        .config
        .load()
        .cert_store_dir
        .join("live")
        .join(&name)
        .join("fullchain.pem");
    let pem = std::fs::read_to_string(&path)
        .map_err(|_| AppError::NotFound(format!("Fullchain file not found for '{name}'")))?;
    Ok(([(header::CONTENT_TYPE, "text/plain")], pem))
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RenewalJobsQuery {
    /// "true" filters to non-terminal jobs; absent or any other value = no filter.
    pub active: Option<String>,
    pub cert_name: Option<String>,
}

pub async fn get_renewal_jobs(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Query(params): Query<RenewalJobsQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let jobs = state.renewal_jobs.read().await;
    let jobs_list: Vec<_> = jobs
        .values()
        .filter(|j| {
            if params.active.as_deref() == Some("true") && j.phase.is_terminal() {
                return false;
            }
            if let Some(ref name) = params.cert_name {
                if &j.cert_name != name {
                    return false;
                }
            }
            true
        })
        .collect();
    Ok(Json(json!({ "jobs": jobs_list })))
}

pub async fn get_renewal_job(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let job_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid job ID".to_string()))?;
    let jobs = state.renewal_jobs.read().await;
    let job = jobs
        .get(&job_id)
        .ok_or_else(|| AppError::NotFound(format!("Renewal job '{id}' not found")))?;
    Ok(Json(serde_json::to_value(job).unwrap()))
}

pub async fn get_last_renewal_job(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(cert_name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let jobs = state.renewal_jobs.read().await;
    let last = jobs
        .values()
        .filter(|j| j.cert_name == cert_name && j.phase.is_terminal())
        .max_by_key(|j| j.updated_at)
        .cloned();
    drop(jobs);
    match last {
        Some(job) => Ok(Json(json!({ "job": job }))),
        None => Err(AppError::NotFound(format!(
            "No completed job found for '{cert_name}'"
        ))),
    }
}

pub async fn get_rate_limits(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let ledger = state.issuance_ledger.read().await;
    let assignments = state.assignments.read().await;
    let cas = state.cas.read().await;
    let ca_limits: std::collections::HashMap<String, crate::types::CaRateLimits> = cas
        .iter()
        .filter_map(|(name, ca)| ca.config.rate_limits.clone().map(|rl| (name.clone(), rl)))
        .collect();
    let domain_quotas = ledger.domain_quotas(&ca_limits);
    let identifier_set_quotas = ledger.identifier_set_quotas(&assignments, &ca_limits);
    Ok(Json(json!({
        "domainQuotas": domain_quotas,
        "identifierSetQuotas": identifier_set_quotas,
    })))
}

pub async fn list_accounts(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let accounts = state.accounts.read().await;
    Ok(Json(json!({ "accounts": *accounts })))
}

pub async fn get_me(
    State(_state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    Ok(Json(json!({
        "identityUri": user.identity_uri,
        "role": format!("{:?}", user.role).to_lowercase(),
        "accountId": user.account_id,
        "accountName": user.account_name,
    })))
}

pub async fn get_account(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let accounts = state.accounts.read().await;
    let account = accounts
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| AppError::NotFound(format!("Account '{id}' not found")))?;
    Ok(Json(serde_json::to_value(account).unwrap()))
}

pub async fn get_cas(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let cas_guard = state.cas.read().await;
    let cas: Vec<_> = cas_guard
        .values()
        .map(|ca| {
            json!({
                "name": ca.name,
                "protocol": ca.protocol,
                "provider": ca.provider,
                "directoryUrl": ca.config.directory_url,
                "supportedValidations": ca.config.supported_validations,
                "defaultValidation": ca.config.default_validation,
            })
        })
        .collect();
    Ok(Json(json!({ "cas": cas })))
}

/// Query parameters for `GET /admin/logs`. Reuses the field set of
/// `credo_lib::log_query::LogQueryParams` directly rather than
/// `#[serde(flatten)]`-ing it: axum's `Query` extractor uses
/// `serde_urlencoded`, which doesn't support flatten reliably. `target`
/// selects the log source: `"shepherd"` (default), `"vigil"`, or
/// `"corgi:<name>"`. `follow` requests a live-tailing SSE stream instead
/// of a historical JSON array.
#[derive(Debug, serde::Deserialize, Default)]
pub struct AdminLogsQuery {
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub last: Option<String>,
    pub level: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
    /// Live-tail via Server-Sent Events instead of a historical JSON array.
    #[serde(default)]
    pub follow: bool,
}

impl AdminLogsQuery {
    /// Converts to `LogQueryParams` for a direct, in-process call into
    /// `credo_lib::log_query` - used for `target=shepherd`. `follow` is
    /// passed through as-is; `respond_to_log_query` branches on it
    /// internally to decide between a historical read and a live tail.
    fn to_log_query_params(&self) -> credo_lib::log_query::LogQueryParams {
        credo_lib::log_query::LogQueryParams {
            since: self.since.clone(),
            until: self.until.clone(),
            last: self.last.clone(),
            level: self.level.clone(),
            q: self.q.clone(),
            limit: self.limit,
            follow: self.follow,
        }
    }

    /// Key/value pairs to forward to a proxied service's own `/logs`
    /// endpoint - everything except `target`, which is shepherd-only and
    /// never forwarded. Includes `follow=true` when set, so a proxied
    /// `target=vigil`/`target=corgi:<name>` request can ask that service's
    /// own `/logs` for a live tail too.
    fn forward_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(v) = &self.since {
            pairs.push(("since", v.clone()));
        }
        if let Some(v) = &self.until {
            pairs.push(("until", v.clone()));
        }
        if let Some(v) = &self.last {
            pairs.push(("last", v.clone()));
        }
        if let Some(v) = &self.level {
            pairs.push(("level", v.clone()));
        }
        if let Some(v) = &self.q {
            pairs.push(("q", v.clone()));
        }
        if let Some(v) = self.limit {
            pairs.push(("limit", v.to_string()));
        }
        if self.follow {
            pairs.push(("follow", "true".to_string()));
        }
        pairs
    }
}

/// Builds a `?key=value&...` query string (percent-encoded via `url`'s
/// query-pair builder, re-exported as `reqwest::Url`) from `pairs`, or an
/// empty string if `pairs` is empty.
fn build_query_string(pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let mut url =
        reqwest::Url::parse("http://placeholder.invalid/").expect("static URL must parse");
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in pairs {
            qp.append_pair(k, v);
        }
    }
    format!("?{}", url.query().unwrap_or_default())
}

/// Converts a successful upstream `follow=true` SSE response into an axum
/// streaming Response, proxying the bytes through verbatim - not re-parsed
/// into new SSE `Event`s. Only the innermost service's own `/logs` handler
/// (`credo_lib::log_query::follow_logs`) should ever construct real SSE
/// events; every proxy hop after that just forwards bytes, avoiding
/// framing bugs. Headers match exactly what axum's own `Sse` type sets on
/// success (`Content-Type: text/event-stream`, `Cache-Control: no-cache` -
/// verified against the pinned axum 0.7.9 source, not guessed).
///
/// Returns `AppError::Internal` if the upstream response itself is an
/// error (e.g. that service's own logging is disabled) - the specific
/// upstream status/message isn't preserved through the proxy for now, the
/// same known, already-accepted limitation as the non-follow proxy
/// branches in `get_logs`.
async fn stream_upstream_logs_response(
    upstream: reqwest::Response,
) -> Result<axum::response::Response, AppError> {
    if !upstream.status().is_success() {
        let status = upstream.status();
        let body = upstream.text().await.unwrap_or_default();
        return Err(AppError::Internal(anyhow::anyhow!(
            "upstream /logs?follow=true failed ({status}): {body}"
        )));
    }
    let body = axum::body::Body::from_stream(upstream.bytes_stream());
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .body(body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("building streaming response: {e}")))
}

/// Historical log retrieval, aggregated across services. `target=shepherd`
/// (default) serves this shepherd's own logs; `target=vigil` and
/// `target=corgi:<name>` proxy to that service's own `/logs` endpoint using
/// the existing outbound clients (`state.vigil_client`, `state.corgi_client_pool`)
/// already used for `/ca`, `/health`, and hook fetches. `?follow=true`
/// requests a live-tailing SSE stream instead, proxied through verbatim
/// from whichever service actually produced it.
pub async fn get_logs(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Query(query): Query<AdminLogsQuery>,
) -> Result<axum::response::Response, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;

    let target = query.target.as_deref().unwrap_or("shepherd");

    if target == "shepherd" {
        let params = query.to_log_query_params();
        return credo_lib::log_query::respond_to_log_query(&state.logging_handle, &params).await;
    }

    if target == "vigil" {
        let config = state.config.load_full();
        let url = config
            .vigil_url
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Vigil not configured".to_string()))?;
        let client = state
            .vigil_client
            .read()
            .await
            .clone()
            .ok_or_else(|| AppError::BadRequest("Vigil client unavailable".to_string()))?;

        if query.follow {
            // Reusing corgi_client's timeout constant here too - it's just
            // a shared "effectively unbounded for a live tail" value, not
            // corgi-specific.
            let upstream = client
                .get(format!("{}/logs", url.trim_end_matches('/')))
                .query(&query.forward_pairs())
                .timeout(std::time::Duration::from_secs(
                    crate::corgi_client::FOLLOW_TIMEOUT_SECS,
                ))
                .send()
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?;
            return stream_upstream_logs_response(upstream).await;
        }

        let body: Vec<String> = client
            .get(format!("{}/logs", url.trim_end_matches('/')))
            .query(&query.forward_pairs())
            .send()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!("Vigil response parse error: {}", e))
            })?;
        return Ok(Json(body).into_response());
    }

    if let Some(name) = target.strip_prefix("corgi:") {
        let corgis = state.corgis.read().await;
        let node = corgis
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| AppError::NotFound(format!("Corgi '{name}' not found")))?
            .clone();
        drop(corgis);
        let path = format!("/logs{}", build_query_string(&query.forward_pairs()));

        if query.follow {
            let upstream =
                crate::corgi_client::corgi_get_stream(&state.corgi_client_pool, &node, &path)
                    .await
                    .map_err(AppError::Internal)?;
            return stream_upstream_logs_response(upstream).await;
        }

        let body: Vec<String> =
            crate::corgi_client::corgi_get(&state.corgi_client_pool, &node, &path)
                .await
                .map_err(AppError::Internal)?;
        return Ok(Json(body).into_response());
    }

    Err(AppError::BadRequest(format!("unknown target '{target}'")))
}

pub async fn get_vigil_ca(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let config = state.config.load_full();
    let url = config
        .vigil_url
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Vigil not configured".to_string()))?;
    let client = state
        .vigil_client
        .read()
        .await
        .clone()
        .ok_or_else(|| AppError::BadRequest("Vigil client unavailable".to_string()))?;
    let body: serde_json::Value = client
        .get(format!("{}/ca", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil response parse error: {}", e)))?;
    Ok(Json(body))
}

pub async fn get_vigil_status(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let config = state.config.load_full();
    let url = config
        .vigil_url
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Vigil not configured".to_string()))?;
    let client = state
        .vigil_client
        .read()
        .await
        .clone()
        .ok_or_else(|| AppError::BadRequest("Vigil client unavailable".to_string()))?;
    let body: serde_json::Value = client
        .get(format!("{}/health", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil request failed: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil response parse error: {}", e)))?;
    Ok(Json(body))
}

pub async fn config_summary(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Readonly)?;
    let config = state.config.load_full();
    let cas_guard = state.cas.read().await;
    let cas: Vec<_> = cas_guard
        .values()
        .map(|ca| {
            json!({
                "name": ca.name,
                "protocol": ca.protocol,
                "provider": ca.provider,
                "defaultValidation": ca.config.default_validation,
            })
        })
        .collect();
    Ok(Json(json!({
        "agentPort": config.agent_port,
        "dashboardPort": config.dashboard_port,
        "bind": config.bind,
        "certStoreDir": config.cert_store_dir,
        "renewBeforeDays": config.renew_before_days,
        "reconcileIntervalSeconds": config.reconcile_interval_seconds,
        "renewalCheckIntervalSeconds": config.renewal_check_interval_seconds,
        "cas": cas,
    })))
}

// ---------------------------------------------------------------------------
// Admin-only routes
// ---------------------------------------------------------------------------

pub async fn trigger_renew(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(cert_name): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let body = body.map(|b| b.0).unwrap_or_default();
    admin_provision_or_renew(&state, &cert_name, &body).await
}

pub async fn trigger_provision(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(cert_name): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let body = body.map(|b| b.0).unwrap_or_default();
    admin_provision_or_renew(&state, &cert_name, &body).await
}

async fn admin_provision_or_renew(
    state: &AppState,
    cert_name: &str,
    body: &serde_json::Value,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let assignments = state.assignments.read().await;
    let assignment = assignments
        .iter()
        .find(|a| a.cert_name == cert_name || a.domain.as_deref() == Some(cert_name))
        .ok_or_else(|| AppError::NotFound(format!("No assignment for '{cert_name}'")))?
        .clone();
    drop(assignments);

    let corgi_name = assignment
        .corgi
        .as_deref()
        .ok_or_else(|| AppError::BadRequest(format!("Assignment '{cert_name}' has no corgi")))?;

    let corgis = state.corgis.read().await.clone();
    let node = corgis
        .iter()
        .find(|c| c.name == corgi_name)
        .ok_or_else(|| AppError::NotFound(format!("Corgi '{corgi_name}' not in config")))?
        .clone();

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

    let key_algorithm = body
        .get("keyAlgorithm")
        .and_then(|v| v.as_str())
        .or(assignment.key_algorithm.as_deref())
        .unwrap_or("rsa");

    // Get CSR from corgi
    #[derive(serde::Deserialize)]
    struct CsrResponse {
        #[serde(rename = "csrPem")]
        csr_pem: String,
    }
    let csr: CsrResponse = corgi_post(
        &state.corgi_client_pool,
        &node,
        &format!("/flock/{}/csr", urlencoded(cert_name)),
        &json!({ "keyAlgorithm": key_algorithm }),
    )
    .await
    .map_err(AppError::Internal)?;

    let domains = build_domains(&assignment);
    let job_id = create_job(
        &state.renewal_jobs,
        &assignment.cert_name,
        domains.clone(),
        &assignment.ca,
    )
    .await;

    let state2 = state.clone();
    let node2 = node.clone();
    let assignment2 = assignment.clone();
    let cert_name2 = assignment.cert_name.clone();
    tokio::spawn(async move {
        update_phase(&state2.renewal_jobs, job_id, RenewalPhase::SubmittingOrder).await;
        let corgis = state2.corgis.read().await.clone();
        match issue_cert(
            &ca_config,
            &assignment2.ca,
            &cert_name2,
            &state2.config.load().cert_store_dir,
            &domains,
            &csr.csr_pem,
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
                update_phase(&state2.renewal_jobs, job_id, RenewalPhase::Installing).await;
                append_trace(
                    &state2.renewal_jobs,
                    job_id,
                    "installing-on-corgi",
                    None,
                    None,
                    Some("in-progress"),
                )
                .await;

                if result.changed {
                    match crate::corgi_client::push_cert_install(
                        &state2.corgi_client_pool,
                        &node2,
                        &cert_name2,
                        &result,
                    )
                    .await
                    {
                        Ok(_) => {
                            append_trace(
                                &state2.renewal_jobs,
                                job_id,
                                "installed-on-corgi",
                                None,
                                None,
                                Some("ok"),
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!(cert = %cert_name2, error = %e,
                                "Admin-triggered renewal: corgi install failed (non-fatal)");
                            append_trace(
                                &state2.renewal_jobs,
                                job_id,
                                "install-failed",
                                Some(&e.to_string()),
                                None,
                                Some("warn"),
                            )
                            .await;
                        }
                    }
                }

                complete_job(&state2.renewal_jobs, job_id, result.fingerprint256.clone()).await;
                if let Some(path) = &state2.renewal_jobs_history_path {
                    crate::renewal_jobs::persist_terminal_jobs(&state2.renewal_jobs, path).await;
                }
            }
            Err(e) => {
                fail_job(&state2.renewal_jobs, job_id, e.to_string()).await;
                if let Some(path) = &state2.renewal_jobs_history_path {
                    crate::renewal_jobs::persist_terminal_jobs(&state2.renewal_jobs, path).await;
                }
                tracing::warn!(cert = %cert_name2, error = %e, "Admin-triggered renewal failed");
            }
        }
    });

    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({
            "jobId": job_id.to_string(),
            "status": "pending",
            "certName": assignment.cert_name,
        })),
    ))
}

pub async fn cancel_renewal_job(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let job_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid job ID".to_string()))?;
    let mut jobs = state.renewal_jobs.write().await;
    if jobs.remove(&job_id).is_some() {
        Ok(Json(json!({ "cancelled": true })))
    } else {
        Err(AppError::NotFound(format!("Renewal job '{id}' not found")))
    }
}

pub async fn create_account(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let account: crate::types::Account = serde_json::from_value(body)
        .map_err(|e| AppError::BadRequest(format!("Invalid account: {e}")))?;
    let mut accounts = state.accounts.write().await;
    accounts.push(account.clone());
    drop(accounts);
    let all = state.accounts.read().await;
    crate::accounts::save_accounts(&state.config.load().accounts_path, &all)
        .map_err(AppError::Internal)?;
    Ok(Json(serde_json::to_value(&account).unwrap()))
}

pub async fn update_account(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let mut accounts = state.accounts.write().await;
    let account = accounts
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| AppError::NotFound(format!("Account '{id}' not found")))?;
    if let Some(v) = body.get("displayName").and_then(|v| v.as_str()) {
        account.display_name = v.to_string();
    }
    if let Some(v) = body.get("role").and_then(|v| v.as_str()) {
        account.role = Role::try_from_str(v).ok_or_else(|| {
            AppError::BadRequest(format!(
                "Invalid role '{v}'; expected admin, operator, or readonly"
            ))
        })?;
    }
    if let Some(v) = body.get("active").and_then(|v| v.as_bool()) {
        account.active = v;
    }
    if let Some(v) = body.get("notes").and_then(|v| v.as_str()) {
        account.notes = v.to_string();
    }
    if let Some(ids) = body.get("identities").and_then(|v| v.as_array()) {
        account.identities = ids
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    let updated = account.clone();
    drop(accounts);
    let all = state.accounts.read().await;
    crate::accounts::save_accounts(&state.config.load().accounts_path, &all)
        .map_err(AppError::Internal)?;
    Ok(Json(serde_json::to_value(&updated).unwrap()))
}

pub async fn delete_account(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let mut accounts = state.accounts.write().await;
    let before = accounts.len();
    accounts.retain(|a| a.id != id);
    if accounts.len() == before {
        return Err(AppError::NotFound(format!("Account '{id}' not found")));
    }
    drop(accounts);
    let all = state.accounts.read().await;
    crate::accounts::save_accounts(&state.config.load().accounts_path, &all)
        .map_err(AppError::Internal)?;
    Ok(Json(json!({ "deleted": true })))
}

pub async fn reload_corgis(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let path = state.config.load().corgis_config_path.clone();
    let list = load_corgis(&path).map_err(AppError::Internal)?;
    let count = list.len();
    *state.corgis.write().await = list;
    *state.corgis_mtime.lock().unwrap() = file_mtime(&path);
    crate::poll::request_reconcile(&state, None, false);
    Ok(Json(
        json!({ "reloaded": true, "corgis": count, "corgisConfigPath": path }),
    ))
}

/// Validate the assignment's monitor endpoint(s): non-empty host and
/// non-zero port on every entry (a SAN cert may configure several).
fn validate_assignment_monitor(
    assignment: &crate::types::ManagedAssignment,
) -> Result<(), AppError> {
    let Some(endpoints) = &assignment.monitor else {
        return Ok(());
    };
    for monitor in endpoints {
        if monitor.host.trim().is_empty() {
            return Err(AppError::BadRequest(
                "monitor.host must be a non-empty hostname or IP".into(),
            ));
        }
        if monitor.port == 0 {
            return Err(AppError::BadRequest("monitor.port must be non-zero".into()));
        }
    }
    Ok(())
}

async fn validate_assignment_hooks(
    state: &AppState,
    assignment: &crate::types::ManagedAssignment,
) -> Result<(), AppError> {
    let hooks = match assignment.hooks.as_deref() {
        None | Some([]) => return Ok(()),
        Some(h) => h,
    };
    let corgi_name = match assignment.corgi.as_deref() {
        Some(n) => n.to_string(),
        None => return Ok(()),
    };
    let corgis = state.corgis.read().await;
    let node = match corgis.iter().find(|c| c.name == corgi_name) {
        Some(n) => n.clone(),
        None => return Ok(()), // corgi not configured yet; skip validation
    };
    drop(corgis);
    let available = corgi_get_hooks(&state.corgi_client_pool, &state.hooks_cache, &node)
        .await
        .map_err(|e| {
            AppError::BadRequest(format!(
                "Cannot reach corgi '{corgi_name}' to validate hooks: {e}"
            ))
        })?;
    for hook in hooks {
        let name = hook.name();
        if !available.available_hooks.iter().any(|h| h == name) {
            return Err(AppError::BadRequest(format!(
                "Hook '{name}' is not available on corgi '{corgi_name}'. Available: {:?}",
                available.available_hooks
            )));
        }
    }
    Ok(())
}

pub async fn create_assignment(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let mut assignment: crate::types::ManagedAssignment = serde_json::from_value(body)
        .map_err(|e| AppError::BadRequest(format!("Invalid assignment: {e}")))?;
    if assignment.cert_name.is_empty() {
        assignment.cert_name = assignment.domain.clone().unwrap_or_default();
    }
    if assignment.cert_name.is_empty() {
        return Err(AppError::BadRequest(
            "Assignment must have certName or domain".into(),
        ));
    }
    validate_assignment_monitor(&assignment)?;
    validate_assignment_hooks(&state, &assignment).await?;
    let mut assignments = state.assignments.write().await;
    if assignments
        .iter()
        .any(|a| a.cert_name == assignment.cert_name)
    {
        return Err(AppError::BadRequest(format!(
            "Assignment '{}' already exists",
            assignment.cert_name
        )));
    }
    assignments.push(assignment.clone());
    let path = state.config.load().assignments_config_path.clone();
    save_assignments(&path, &assignments).map_err(AppError::Internal)?;
    *state.assignments_mtime.lock().unwrap() = file_mtime(&path);
    if let Some(corgi) = assignment.corgi.clone() {
        crate::poll::request_reconcile(&state, Some(vec![corgi]), true);
    }
    Ok(Json(serde_json::to_value(&assignment).unwrap()))
}

pub async fn update_assignment(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(cert_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    // Replace the whole record with the incoming body, preserving cert_name
    let mut updated: crate::types::ManagedAssignment = serde_json::from_value(body)
        .map_err(|e| AppError::BadRequest(format!("Invalid assignment: {e}")))?;
    updated.cert_name = cert_name.clone();
    validate_assignment_monitor(&updated)?;
    validate_assignment_hooks(&state, &updated).await?;
    let mut assignments = state.assignments.write().await;
    let assignment = assignments
        .iter_mut()
        .find(|a| a.cert_name == cert_name)
        .ok_or_else(|| AppError::NotFound(format!("No assignment for '{cert_name}'")))?;
    let previous_corgi = assignment.corgi.clone();
    *assignment = updated.clone();
    let path = state.config.load().assignments_config_path.clone();
    save_assignments(&path, &assignments).map_err(AppError::Internal)?;
    *state.assignments_mtime.lock().unwrap() = file_mtime(&path);
    // Reconcile both the new corgi and (if reassigned) the one that lost it.
    let mut affected: Vec<String> = updated.corgi.clone().into_iter().collect();
    if let Some(prev) = previous_corgi {
        if !affected.contains(&prev) {
            affected.push(prev);
        }
    }
    if !affected.is_empty() {
        crate::poll::request_reconcile(&state, Some(affected), true);
    }
    Ok(Json(serde_json::to_value(&updated).unwrap()))
}

pub async fn delete_assignment(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Path(cert_name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let mut assignments = state.assignments.write().await;
    let before = assignments.len();
    let removed_corgi = assignments
        .iter()
        .find(|a| a.cert_name == cert_name)
        .and_then(|a| a.corgi.clone());
    assignments.retain(|a| a.cert_name != cert_name);
    if assignments.len() == before {
        return Err(AppError::NotFound(format!(
            "No assignment for '{cert_name}'"
        )));
    }
    let path = state.config.load().assignments_config_path.clone();
    save_assignments(&path, &assignments).map_err(AppError::Internal)?;
    *state.assignments_mtime.lock().unwrap() = file_mtime(&path);
    if let Some(corgi) = removed_corgi {
        crate::poll::request_reconcile(&state, Some(vec![corgi]), true);
    }
    Ok(Json(json!({ "deleted": true })))
}

pub async fn reload_assignments(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let path = state.config.load().assignments_config_path.clone();
    let list = load_assignments(&path).map_err(AppError::Internal)?;
    let count = list.len();
    *state.assignments.write().await = list;
    *state.assignments_mtime.lock().unwrap() = file_mtime(&path);
    crate::poll::request_reconcile(&state, None, true);
    Ok(Json(
        json!({ "reloaded": true, "assignments": count, "assignmentsConfigPath": path }),
    ))
}

pub async fn reload_accounts(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let path = state.config.load().accounts_path.clone();
    let list = crate::accounts::load_accounts(&path).map_err(AppError::Internal)?;
    let count = list.len();
    *state.accounts.write().await = list;
    *state.accounts_mtime.lock().unwrap() = file_mtime(&path);
    Ok(Json(
        json!({ "reloaded": true, "accounts": count, "accountsPath": path }),
    ))
}

pub async fn reload_cas(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let path = state.config.load().ca_config_path.clone();
    let map = crate::cas::load_cas(&path).map_err(AppError::Internal)?;
    let count = map.len();
    *state.cas.write().await = map;
    *state.ca_mtime.lock().unwrap() = file_mtime(&path);
    Ok(Json(
        json!({ "reloaded": true, "cas": count, "caConfigPath": path }),
    ))
}

fn urlencoded(s: &str) -> String {
    s.replace('/', "%2F")
}

// ---------------------------------------------------------------------------
// PoP token helpers
// ---------------------------------------------------------------------------

fn pop_pem_to_der(pem: &str) -> Option<Vec<u8>> {
    use rustls_pemfile::Item;
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::read_one(&mut rd)
        .ok()?
        .and_then(|item| match item {
            Item::X509Certificate(d) => Some(d.to_vec()),
            _ => None,
        })
}

/// Verify that the leaf cert (first in `chain_pem`) chains to a cert in `ca_path`.
/// Intermediates embedded in `chain_pem` are trusted as signers if they are
/// themselves anchored in the CA bundle, mirroring how browsers handle cert chains.
fn verify_pop_cert(chain_pem: &str, ca_path: &std::path::Path) -> anyhow::Result<()> {
    use x509_parser::prelude::*;

    let ca_pem = std::fs::read_to_string(ca_path)
        .with_context(|| format!("Reading client CA: {}", ca_path.display()))?;

    // Collect all DERs from the CA bundle as the initial trusted set.
    let mut trusted: Vec<Vec<u8>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(ca_pem.as_bytes()))
            .flatten()
            .map(|d| d.to_vec())
            .collect();

    // Collect all certs from the submitted chain (leaf first, then intermediates).
    let chain_ders: Vec<Vec<u8>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(chain_pem.as_bytes()))
            .flatten()
            .map(|d| d.to_vec())
            .collect();

    if chain_ders.is_empty() {
        anyhow::bail!("pop.cert contains no parseable certificates");
    }

    let is_signed_by = |cert_der: &[u8], issuer_der: &[u8]| -> bool {
        let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
            return false;
        };
        let Ok((_, issuer)) = X509Certificate::from_der(issuer_der) else {
            return false;
        };
        cert.verify_signature(Some(issuer.public_key())).is_ok()
    };

    // Promote any chain-provided intermediate that is anchored by a currently
    // trusted cert. Repeat until stable (handles arbitrary ordering and depth).
    let mut changed = true;
    while changed {
        changed = false;
        for candidate in &chain_ders[1..] {
            if !trusted.contains(candidate) && trusted.iter().any(|t| is_signed_by(candidate, t)) {
                trusted.push(candidate.clone());
                changed = true;
            }
        }
    }

    // Check the leaf against the expanded trusted pool.
    let leaf = &chain_ders[0];
    if trusted.iter().any(|t| is_signed_by(leaf, t)) {
        return Ok(());
    }

    anyhow::bail!("Certificate not signed by any cert in client CA bundle")
}

use anyhow::Context as AnyhowContext;

// ---------------------------------------------------------------------------
// Identity cert issuance (POST /admin/identity-cert)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCertRequest {
    csr_pem: String,
    #[serde(default = "default_identity_cert_days")]
    days: u32,
}

fn default_identity_cert_days() -> u32 {
    365
}

pub async fn issue_identity_cert(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(body): Json<IdentityCertRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;

    csr_has_no_dns_sans(&body.csr_pem)
        .map_err(|e| AppError::BadRequest(format!("CSR rejected: {e}")))?;

    let config = state.config.load_full();
    let vigil_url = config
        .vigil_url
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Vigil not configured".to_string()))?
        .to_string();
    let client = state
        .vigil_client
        .read()
        .await
        .clone()
        .ok_or_else(|| AppError::BadRequest("Vigil client unavailable".to_string()))?;

    let cert_pem =
        crate::routes_bootstrap::sign_csr_via_vigil(&client, &vigil_url, &body.csr_pem, body.days)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Vigil signing failed: {e}")))?;

    tracing::info!(
        issued_by = %user.identity_uri,
        "Identity cert issued via /admin/identity-cert"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({ "certPem": cert_pem })),
    ))
}

// ---------------------------------------------------------------------------
// POST /admin/enroll-corgi
// ---------------------------------------------------------------------------
// Authenticate with mTLS admin cert (or JWT); enrolls a corgi the same way
// the bootstrap endpoint does, but available outside the bootstrap window.

pub async fn enroll_corgi_admin(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(body): Json<crate::routes_bootstrap::BootstrapCorgiRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_min_role(Some(&user.role), &Role::Admin)?;
    let vc = state.vigil_client.read().await.clone();
    let vigil_client =
        vc.ok_or_else(|| AppError::Internal(anyhow::anyhow!("Vigil client not available")))?;
    let config = state.config.load_full();
    let vigil_url = config
        .vigil_url
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("vigilUrl not configured")))?
        .to_string();
    crate::routes_bootstrap::enroll_corgi(&state, &vigil_client, &vigil_url, &body)
        .await
        .map_err(AppError::Internal)?;
    tracing::info!(
        name = %body.name,
        identity_uri = %body.identity_uri,
        issued_by = %user.identity_uri,
        "Corgi enrolled via admin endpoint"
    );
    Ok(Json(json!({ "enrolled": true })))
}

/// Reject CSRs that contain any DNS SAN. Identity certs must use URI SANs only.
fn csr_has_no_dns_sans(csr_pem: &str) -> anyhow::Result<()> {
    use rustls_pemfile::Item;
    use x509_parser::prelude::*;

    let der = {
        let mut rd = std::io::BufReader::new(csr_pem.as_bytes());
        rustls_pemfile::read_one(&mut rd)
            .context("Reading CSR PEM")?
            .and_then(|item| match item {
                Item::Csr(d) => Some(d.to_vec()),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("No CSR found in PEM input"))?
    };

    let (_, csr) = X509CertificationRequest::from_der(&der)
        .map_err(|e| anyhow::anyhow!("Could not parse CSR DER: {e:?}"))?;

    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    if matches!(name, GeneralName::DNSName(_)) {
                        anyhow::bail!(
                            "identity certs must not contain DNS SANs; \
                             use URI SANs (e.g. vigil://credo/admin/<name>) instead"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RenewalPhase;

    #[test]
    fn renewal_jobs_query_active_excludes_terminal() {
        assert!(RenewalPhase::Completed.is_terminal());
        assert!(RenewalPhase::Failed.is_terminal());
        assert!(RenewalPhase::Cancelled.is_terminal());
        assert!(!RenewalPhase::Validating.is_terminal());
        assert!(!RenewalPhase::RateLimited.is_terminal());
        assert!(!RenewalPhase::Installing.is_terminal());
    }

    #[test]
    fn renewal_jobs_query_struct_has_cert_name() {
        let q = RenewalJobsQuery {
            active: Some("true".into()),
            cert_name: Some("foo.com".into()),
        };
        assert_eq!(q.cert_name.as_deref(), Some("foo.com"));
        assert_eq!(q.active.as_deref(), Some("true"));
    }

    #[test]
    fn admin_logs_query_converts_to_log_query_params_with_follow_false() {
        let query = AdminLogsQuery {
            target: Some("shepherd".to_string()),
            since: Some("2024-01-15T09:00:00Z".to_string()),
            until: Some("2024-01-15T10:00:00Z".to_string()),
            last: Some("5m".to_string()),
            level: Some("warn".to_string()),
            q: Some("corgi".to_string()),
            limit: Some(100),
            follow: false,
        };
        let params = query.to_log_query_params();
        assert_eq!(params.since, Some("2024-01-15T09:00:00Z".to_string()));
        assert_eq!(params.until, Some("2024-01-15T10:00:00Z".to_string()));
        assert_eq!(params.last, Some("5m".to_string()));
        assert_eq!(params.level, Some("warn".to_string()));
        assert_eq!(params.q, Some("corgi".to_string()));
        assert_eq!(params.limit, Some(100));
        assert!(!params.follow);
    }

    #[test]
    fn admin_logs_query_forward_pairs_only_includes_set_fields() {
        let query = AdminLogsQuery {
            target: Some("vigil".to_string()),
            level: Some("warn".to_string()),
            limit: Some(50),
            follow: false,
            ..Default::default()
        };
        let pairs = query.forward_pairs();
        assert_eq!(
            pairs,
            vec![("level", "warn".to_string()), ("limit", "50".to_string())]
        );
    }

    #[test]
    fn admin_logs_query_forward_pairs_empty_when_nothing_set() {
        let query = AdminLogsQuery::default();
        assert!(query.forward_pairs().is_empty());
    }

    #[test]
    fn admin_logs_query_forward_pairs_includes_follow_when_true() {
        let query = AdminLogsQuery {
            follow: true,
            ..Default::default()
        };
        assert_eq!(query.forward_pairs(), vec![("follow", "true".to_string())]);
    }

    #[test]
    fn admin_logs_query_forward_pairs_omits_follow_when_false() {
        let query = AdminLogsQuery::default();
        assert!(query.forward_pairs().is_empty());
    }

    #[test]
    fn admin_logs_query_to_log_query_params_passes_through_follow() {
        let query = AdminLogsQuery {
            follow: true,
            ..Default::default()
        };
        assert!(query.to_log_query_params().follow);
    }

    #[tokio::test]
    async fn stream_upstream_logs_response_passes_sse_bytes_through_verbatim() {
        // Minimal mock server standing in for a real corgi/vigil
        // /logs?follow=true SSE endpoint - proves the byte-passthrough and
        // header-setting logic in isolation, without needing the corgi
        // client pool's mTLS machinery or a full TestCorgi/TestVigil
        // harness (no composable cross-service harness pattern exists in
        // this codebase - confirmed before writing this plan).
        let app = axum::Router::new().route(
            "/logs",
            axum::routing::get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    "data: {\"line\":\"hello\",\"source\":\"mock\"}\n\n",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = reqwest::Client::new();
        let upstream = client
            .get(format!("http://{addr}/logs"))
            .send()
            .await
            .expect("request");

        let response = stream_upstream_logs_response(upstream)
            .await
            .expect("stream response");
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .expect("content-type header"),
            "text/event-stream"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .expect("cache-control header"),
            "no-cache"
        );

        use http_body_util::BodyExt;
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(
            body_bytes.as_ref(),
            b"data: {\"line\":\"hello\",\"source\":\"mock\"}\n\n".as_slice()
        );
    }

    #[tokio::test]
    async fn stream_upstream_logs_response_maps_upstream_error_to_internal() {
        let app = axum::Router::new().route(
            "/logs",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "file logging is not enabled",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = reqwest::Client::new();
        let upstream = client
            .get(format!("http://{addr}/logs"))
            .send()
            .await
            .expect("request");

        let result = stream_upstream_logs_response(upstream).await;
        assert!(result.is_err(), "non-2xx upstream must map to an error");
    }

    #[test]
    fn build_query_string_empty_pairs_returns_empty_string() {
        assert_eq!(build_query_string(&[]), "");
    }

    #[test]
    fn build_query_string_round_trips_values_with_special_characters() {
        let pairs = vec![
            ("q", "hello world & more".to_string()),
            ("level", "warn".to_string()),
        ];
        let qs = build_query_string(&pairs);
        assert!(qs.starts_with('?'), "expected a leading '?', got {qs:?}");
        // Round-trip through a real URL parse rather than asserting an exact
        // percent-encoding scheme, since the specific encoding (e.g. spaces
        // as '+' vs '%20') is an implementation detail of the `url` crate.
        let url = reqwest::Url::parse(&format!("http://x.invalid/{qs}")).expect("parse url");
        let collected: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(
            collected,
            vec![
                ("q".to_string(), "hello world & more".to_string()),
                ("level".to_string(), "warn".to_string()),
            ]
        );
    }
}

/// Verify the PoP signature:
///   message = hex_decode(challenge) || identityUri_bytes || issuedAt_bytes
///   sig     = base64url(DER-encoded ECDSA or PKCS1v15 SHA-256 signature)
fn verify_pop_signature(
    cert_der: &[u8],
    challenge_hex: &str,
    identity_uri: &str,
    issued_at: &str,
    signature_b64: &str,
) -> anyhow::Result<()> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use x509_parser::prelude::*;

    let challenge_bytes = hex::decode(challenge_hex).context("Decoding PoP challenge hex")?;
    let mut message = challenge_bytes;
    message.extend_from_slice(identity_uri.as_bytes());
    message.extend_from_slice(issued_at.as_bytes());

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(signature_b64))
        .context("Decoding PoP signature base64")?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("Parsing cert DER: {e:?}"))?;
    let spki = cert.public_key();
    let pk_data = spki.subject_public_key.data.as_ref();

    // EC P-256 (all Vigil-issued certs are P-256)
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk =
        VerifyingKey::from_sec1_bytes(pk_data).context("Parsing EC P-256 public key from cert")?;
    let sig = Signature::from_der(&sig_bytes).context("Parsing DER-encoded PoP signature")?;
    vk.verify(&message, &sig)
        .context("EC P-256 PoP signature mismatch")
}
