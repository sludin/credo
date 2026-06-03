use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use crate::config::{AuthMode, CorgiConfig};
use crate::error::AppError;
use crate::log_middleware::LogIdentity;
use crate::server::PeerCertDer;
use crate::types::{ClientIdentity, Role};

// Re-export shared helpers so existing call sites still compile.
pub use credo_lib::auth::{
    check_min_role, identity_from_der,
};

// ---------------------------------------------------------------------------
// RBAC role resolution
// ---------------------------------------------------------------------------

pub fn resolve_role(identity: &ClientIdentity, config: &CorgiConfig) -> Option<Role> {
    for rbac in &config.rbac_identities {
        for uri in &identity.san_uris {
            if uri == &rbac.uri {
                return Some(rbac.role.clone());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// axum middleware
// ---------------------------------------------------------------------------

/// Extracts client identity from TLS peer cert or proxy headers, then stores
/// the identity and resolved role in request extensions.
pub async fn auth_middleware(
    State(state): State<crate::state::AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let config = &state.config;

    let identity = match config.auth.mode {
        AuthMode::Mtls => extract_mtls_identity(&req)?,
        AuthMode::ProxyHeaders => extract_proxy_identity(&req, config)?,
    };

    let identity_name = if identity.is_anonymous() {
        None
    } else {
        Some(identity.display_name().to_string())
    };
    let role = resolve_role(&identity, config);
    req.extensions_mut().insert(identity);
    if let Some(r) = role {
        req.extensions_mut().insert(r);
    }
    let mut response = next.run(req).await;
    if let Some(name) = identity_name {
        response.extensions_mut().insert(LogIdentity(name));
    }
    Ok(response)
}

fn extract_mtls_identity(req: &Request) -> Result<ClientIdentity, AppError> {
    let cert_der = req
        .extensions()
        .get::<PeerCertDer>()
        .map(|p| p.0.clone());

    match cert_der {
        Some(der) => identity_from_der(&der).map_err(|e| {
            AppError::Unauthorized(format!("Failed to parse client cert: {}", e))
        }),
        None => Err(AppError::Unauthorized(
            "mTLS client certificate required".to_string(),
        )),
    }
}

fn extract_proxy_identity(
    req: &Request,
    config: &CorgiConfig,
) -> Result<ClientIdentity, AppError> {
    let cert_raw = req
        .headers()
        .get(&config.proxy_auth.client_cert_header)
        .and_then(|v| v.to_str().ok());

    if let Some(raw) = cert_raw {
        if let Some(identity) = credo_lib::auth::identity_from_header(raw) {
            return Ok(identity);
        }
    }

    // No cert header or unparseable — return empty identity so role check rejects
    Ok(ClientIdentity {
        fingerprint256: String::new(),
        subject: String::new(),
        san_uris: vec![],
        san_dns: vec![],
    })
}

