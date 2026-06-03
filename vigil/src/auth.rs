use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

use crate::error::AppError;
use crate::log_middleware::LogIdentity;
use crate::state::AppState;
use crate::types::VigilUser;

// Re-export shared helpers so existing call sites still compile.
pub use credo_lib::tls::PeerCertDer;

// ---------------------------------------------------------------------------
// Axum extension type set by vigil's mTLS auth middleware
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AuthUser(pub VigilUser);

// ---------------------------------------------------------------------------
// mTLS auth middleware (vigil requires mTLS — no proxy-header fallback)
// ---------------------------------------------------------------------------

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let peer_cert = req.extensions().get::<PeerCertDer>().map(|p| p.0.clone());

    let Some(der) = peer_cert else {
        return Err(AppError::Unauthorized(
            "A valid client certificate is required.".to_string(),
        ));
    };

    let identity = credo_lib::auth::identity_from_der(&der).map_err(|e| {
        AppError::Unauthorized(format!("Invalid client certificate: {}", e))
    })?;

    let config = state.config();
    let matched = config
        .rbac_identities
        .iter()
        .find(|entry| identity.san_uris.contains(&entry.uri));

    let Some(rbac) = matched else {
        return Err(AppError::Unauthorized(format!(
            "Client certificate URI not in rbacIdentities. presented={:?}",
            identity.san_uris
        )));
    };

    let auth_user = VigilUser {
        id: format!("rbac:{}", rbac.name.as_deref().unwrap_or(&rbac.uri)),
        name: rbac.name.clone().unwrap_or_else(|| rbac.uri.clone()),
        role: rbac.role.clone(),
        active: true,
        public_key_pem: String::new(),
        public_key_fingerprint256: identity.fingerprint256,
    };

    let name = auth_user.name.clone();
    req.extensions_mut().insert(AuthUser(auth_user));
    let mut response = next.run(req).await;
    response.extensions_mut().insert(LogIdentity(name));
    Ok(response)
}
