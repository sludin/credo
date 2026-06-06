use anyhow::{Context, Result};
use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::{Router, extract::Request, response::IntoResponse, http::StatusCode};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use credo_lib::tls::{bind_tcp, serve_tls};

use crate::auth::{api_auth_middleware, corgi_auth_middleware};
use crate::config::ShepherdConfig;
use crate::log_middleware::{agent_log_middleware, api_log_middleware};
use crate::routes_api as api;
use crate::routes_bootstrap as bootstrap;
use crate::routes_corgi as corgi;
use crate::state::AppState;

pub fn build_server_tls(config: &ShepherdConfig) -> Result<Arc<rustls::ServerConfig>> {
    credo_lib::tls::build_server_tls(
        &config.tls.cert_path,
        &config.tls.key_path,
        Some(&config.tls.client_ca_path),
    )
}

pub fn build_agent_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(corgi::health))
        .route("/agents/:id/assignments",       get(corgi::get_assignments))
        .route("/agents/:id/certs/:name",       get(corgi::get_cert))
        .route("/agents/:id/provision/:name",   post(corgi::provision_cert))
        .route("/agents/:id/renew/:name",       post(corgi::renew_cert))
        .route("/agents/:id/renew/:name/status", get(corgi::renew_status))
        .layer(middleware::from_fn_with_state(state.clone(), corgi_auth_middleware))
        .layer(middleware::from_fn(agent_log_middleware))
        .with_state(state)
}

pub fn build_api_router(state: AppState) -> Router {
    // Public routes (no auth middleware)
    let public = Router::new()
        .route("/health",          get(api::health))
        .route("/auth/jwks",       get(api::jwks))
        .route("/auth/token",      post(api::token))
        .route("/auth/refresh",    post(api::refresh_token))
        .route("/flock",           get(api::flock_list))
        .route("/flock/:name",     get(api::flock_get));

    // Authenticated routes
    let authenticated = Router::new()
        .route("/admin/assignments",                get(api::get_assignments))
        .route("/admin/certstore",                  get(api::get_certstore))
        .route("/admin/certstore/:name",            get(api::get_certstore_entry))
        .route("/admin/certstore/:name/pem",        get(api::get_certstore_pem))
        .route("/admin/certstore/:name/fullchain",  get(api::get_certstore_fullchain))
        .route("/admin/renewal-jobs",               get(api::get_renewal_jobs))
        .route("/admin/renewal-jobs/:id",           get(api::get_renewal_job))
        .route("/admin/renewal-jobs/last/:name",    get(api::get_last_renewal_job))
        .route("/admin/cas",                        get(api::get_cas))
        .route("/admin/vigil/ca",                   get(api::get_vigil_ca))
        .route("/admin/vigil/status",               get(api::get_vigil_status))
        .route("/admin/config-summary",             get(api::config_summary))
        .route("/accounts",                         get(api::list_accounts))
        .route("/accounts/me",                      get(api::get_me))
        .route("/accounts/:id",                     get(api::get_account))
        // Admin-only
        .route("/admin/renew/:name",                post(api::trigger_renew))
        .route("/admin/provision/:name",            post(api::trigger_provision))
        .route("/admin/renewal-jobs/:id",           delete(api::cancel_renewal_job))
        .route("/accounts",                         post(api::create_account))
        .route("/accounts/:id",                     put(api::update_account))
        .route("/accounts/:id",                     delete(api::delete_account))
        .route("/admin/reload-corgis",              post(api::reload_corgis))
        .route("/admin/reload-assignments",         post(api::reload_assignments))
        .layer(middleware::from_fn_with_state(state.clone(), api_auth_middleware));

    // Bootstrap routes — authenticated by one-time token, not JWT
    let bootstrap_routes = Router::new()
        .route("/bootstrap/admin-cert", post(bootstrap::bootstrap_admin_cert))
        .route("/bootstrap/corgi",      post(bootstrap::bootstrap_corgi));

    public.merge(authenticated).merge(bootstrap_routes)
        .fallback(api_fallback)
        .layer(middleware::from_fn(api_log_middleware))
        .with_state(state)
}

async fn api_fallback(req: Request) -> impl IntoResponse {
    tracing::warn!(
        method = %req.method(),
        path   = %req.uri().path(),
        "API router: no route matched (fallback hit)"
    );
    StatusCode::NOT_FOUND
}

pub async fn run(state: AppState, tls_config: Arc<rustls::ServerConfig>) -> Result<()> {
    let config = state.config.clone();

    let agent_listener = bind_tcp(&config.bind, config.agent_port)
        .await
        .with_context(|| format!("Binding agent server on {}:{}", config.bind, config.agent_port))?;

    let api_listener = bind_tcp(&config.bind, config.dashboard_port)
        .await
        .with_context(|| format!("Binding dashboard API on {}:{}", config.bind, config.dashboard_port))?;

    tracing::info!(
        addr = %format!("{}:{}", config.bind, config.agent_port),
        "Agent (corgi) API listening"
    );
    tracing::info!(
        addr = %format!("{}:{}", config.bind, config.dashboard_port),
        "Dashboard API listening"
    );

    let agent_router = build_agent_router(state.clone());
    tracing::info!(port = config.agent_port, "Agent router built (code=C)");
    let api_router   = build_api_router(state);
    tracing::info!(port = config.dashboard_port, "API router built (code=S, has /flock)");

    let agent_acceptor = TlsAcceptor::from(tls_config.clone());
    let api_acceptor   = TlsAcceptor::from(tls_config);

    tokio::join!(
        serve_tls(agent_listener, agent_acceptor, agent_router),
        serve_tls(api_listener, api_acceptor, api_router),
    );

    Ok(())
}
