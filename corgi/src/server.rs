use anyhow::Result;
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use std::sync::Arc;

use crate::auth::auth_middleware;
use crate::routes;
use crate::state::AppState;

// Shared TLS helpers and accept loops from credo-lib.
pub use credo_lib::tls::{bind_tcp, serve_http, serve_tls, PeerCertDer};

pub fn build_server_tls(config: &crate::config::CorgiConfig) -> Result<Arc<rustls::ServerConfig>> {
    credo_lib::tls::build_server_tls(
        &config.tls.cert_path,
        &config.tls.key_path,
        config.mtls.ca_path.as_deref(),
    )
}

// ---------------------------------------------------------------------------
// Router construction (corgi-specific routes)
// ---------------------------------------------------------------------------

pub fn build_challenge_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(routes::challenge_health))
        .route(
            "/.well-known/acme-challenge/test",
            get(routes::challenge_test),
        )
        .route(
            "/.well-known/acme-challenge/:token",
            get(routes::challenge_get),
        )
        .layer(middleware::from_fn(|req, next| {
            credo_lib::log::log_request("C", req, next)
        }))
        .with_state(state)
}

pub fn build_control_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(routes::control_health))
        .route("/hooks", get(routes::hooks_list))
        .route("/flock", get(routes::flock_list))
        .route("/flock/:name", get(routes::flock_get))
        .route("/flock/:name/csr", post(routes::flock_csr))
        .route("/flock/:name/install", post(routes::flock_install))
        .route("/flock/:name/restart", post(routes::flock_restart))
        .route("/sync/assignments", post(routes::sync_assignments))
        .route("/acme-challenges", post(routes::acme_challenge_create))
        .route(
            "/acme-challenges/:token",
            delete(routes::acme_challenge_delete),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(|req, next| {
            credo_lib::log::log_request("C", req, next)
        }))
        .with_state(state)
}
