use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

pub use credo_lib::auth::check_min_role;
use credo_lib::auth::identity_from_der;

use crate::error::AppError;
use crate::jwt::verify_jwt;
use crate::log_middleware::LogIdentity;
use crate::state::AppState;
use crate::types::{AuthenticatedUser, CorgiNodeConfig, Role};

// ---------------------------------------------------------------------------
// Corgi agent auth middleware (agent port)
//
// Auth chain (identity-only, no fingerprint fallbacks):
//   1. Extract PeerCertDer → parse URI SANs
//   2. Match URI SAN against corgis[].identityUri → inject CorgiNodeConfig
//   3. Reject if no match
// ---------------------------------------------------------------------------

pub async fn corgi_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Test bypass: if a CorgiNodeConfig is already injected (e.g. via test layer), use it.
    if req.extensions().get::<CorgiNodeConfig>().is_some() {
        return Ok(next.run(req).await);
    }

    let cert_der = req
        .extensions()
        .get::<credo_lib::PeerCertDer>()
        .map(|p| p.0.clone())
        .ok_or_else(|| AppError::Unauthorized("mTLS client certificate required".to_string()))?;

    let identity = identity_from_der(&cert_der)
        .map_err(|e| AppError::Unauthorized(format!("Invalid client certificate: {e}")))?;

    // URI SAN must match a configured corgi's identityUri
    let corgis = state.corgis.read().await;
    let matched: Option<CorgiNodeConfig> = corgis
        .iter()
        .find(|c| {
            c.identity_uri
                .as_ref()
                .map(|uri| identity.san_uris.iter().any(|s| s == uri))
                .unwrap_or(false)
        })
        .cloned();
    drop(corgis);

    let node = matched.ok_or_else(|| {
        AppError::Unauthorized(format!(
            "Client certificate URI SAN not recognized as a configured corgi \
             (SANs: {:?})",
            identity.san_uris
        ))
    })?;

    req.extensions_mut().insert(node.clone());
    let mut response = next.run(req).await;
    response
        .extensions_mut()
        .insert(LogIdentity(node.name.clone()));
    Ok(response)
}

// ---------------------------------------------------------------------------
// Admin/dashboard API auth middleware (dashboard port)
//
// Auth chain (identity-only, no fingerprint fallbacks):
//   1. Authorization: Bearer <token> → verify JWT → inject AuthenticatedUser
//   2. PeerCertDer → parse URI SANs → match accounts[].identities → inject AuthenticatedUser
//   3. Reject if nothing matches
// ---------------------------------------------------------------------------

pub async fn api_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Test bypass: if an AuthenticatedUser is already injected (e.g. via test layer), use it.
    if req.extensions().get::<AuthenticatedUser>().is_some() {
        return Ok(next.run(req).await);
    }

    // --- Step 1: Try JWT Bearer token ---
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(value) = auth_header.to_str() {
            if let Some(token) = value.strip_prefix("Bearer ") {
                let keys = &state.jwt_keys;
                let claims = verify_jwt(keys, token)
                    .map_err(|_| AppError::Unauthorized("Invalid or expired JWT".to_string()))?;

                let role = Role::from_str(&claims.role);
                let user = AuthenticatedUser {
                    identity_uri: claims.sub,
                    role,
                    account_id: None,
                    account_name: claims.account,
                };
                req.extensions_mut().insert(user);
                return Ok(next.run(req).await);
            }
        }
    }

    // --- Step 2: Try mTLS client certificate with URI SAN matching ---
    let cert_der = req
        .extensions()
        .get::<credo_lib::PeerCertDer>()
        .map(|p| p.0.clone())
        .ok_or_else(|| {
            AppError::Unauthorized(
                "Authentication required: provide a JWT Bearer token or mTLS client certificate"
                    .to_string(),
            )
        })?;

    let identity = identity_from_der(&cert_der)
        .map_err(|e| AppError::Unauthorized(format!("Invalid client certificate: {e}")))?;

    let accounts = state.accounts.read().await;
    let matched_account = accounts
        .iter()
        .find(|a| a.active && a.identities.iter().any(|id| identity.san_uris.contains(id)));

    let user = if let Some(account) = matched_account {
        AuthenticatedUser {
            identity_uri: identity.san_uris.first().cloned().unwrap_or_default(),
            role: account.role.clone(),
            account_id: Some(account.id.clone()),
            account_name: Some(account.name.clone()),
        }
    } else {
        drop(accounts);
        return Err(AppError::Unauthorized(format!(
            "Client certificate URI SANs not recognized (SANs: {:?}). \
             Add an account with a matching identity in shepherd.accounts.json.",
            identity.san_uris
        )));
    };

    let identity = user
        .account_name
        .clone()
        .or_else(|| user.account_id.clone())
        .unwrap_or_else(|| user.identity_uri.clone());
    req.extensions_mut().insert(user);
    let mut response = next.run(req).await;
    response.extensions_mut().insert(LogIdentity(identity));
    Ok(response)
}
