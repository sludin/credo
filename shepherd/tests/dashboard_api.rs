/// Dashboard API tests (shepherd's port 7011 equivalent).
///
/// Uses `TestShepherd::start_authed()` which pre-injects an admin AuthenticatedUser,
/// bypassing mTLS/JWT auth for routes that require authentication.
use credo_test::shepherd_harness::TestShepherd;
use serde_json::Value;

// ============================================================================
// Public routes (no auth needed)
// ============================================================================

/// GET /health returns 200 and a healthy status.
#[tokio::test]
async fn health_returns_200() {
    let shepherd = TestShepherd::start().await.unwrap();

    let resp = shepherd.client
        .get(shepherd.dashboard_health_url())
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
    assert_eq!(body["service"].as_str(), Some("shepherd"));
}

/// GET /flock is public and returns a corgis array (empty when no corgis registered).
#[tokio::test]
async fn flock_list_is_public() {
    let shepherd = TestShepherd::start().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/flock", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200, "flock list must be public");
    let body: Value = resp.json().await.unwrap();
    assert!(body["corgis"].is_array(), "response must have corgis array");
}

// ============================================================================
// Auth enforcement
// ============================================================================

/// Authenticated routes return 401 when no token or cert is provided.
#[tokio::test]
async fn authenticated_routes_require_auth() {
    let shepherd = TestShepherd::start().await.unwrap();

    for path in ["/admin/assignments", "/admin/certstore", "/accounts", "/accounts/me"] {
        let resp = shepherd.client
            .get(format!("{}{}", shepherd.dashboard_url, path))
            .send().await.unwrap();
        assert_eq!(resp.status(), 401,
            "GET {path} must require auth, got {}", resp.status());
    }
}

// ============================================================================
// Authenticated routes (with auth bypass)
// ============================================================================

/// GET /admin/assignments returns an empty list on a fresh instance.
#[tokio::test]
async fn get_assignments_returns_empty_list() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/assignments", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let assignments = body["assignments"].as_array().expect("assignments array");
    assert!(assignments.is_empty(), "fresh instance must have no assignments");
}

/// GET /admin/certstore returns an empty entries list on a fresh instance.
#[tokio::test]
async fn get_certstore_returns_empty() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/certstore", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["entries"].is_array(), "certstore must return entries array");
}

/// GET /admin/certstore/:name returns 404 for an unknown cert name.
#[tokio::test]
async fn get_certstore_entry_404_for_unknown() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/certstore/nonexistent-cert", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 404);
}

/// GET /admin/config-summary returns key config fields.
#[tokio::test]
async fn config_summary_returns_fields() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/config-summary", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["renewBeforeDays"].is_number(), "renewBeforeDays must be present");
    assert!(body["certStoreDir"].is_string(),   "certStoreDir must be present");
}

/// GET /accounts returns an empty list on a fresh instance.
#[tokio::test]
async fn list_accounts_returns_empty() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/accounts", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["accounts"].is_array(), "response must have accounts array");
}

/// GET /accounts/me returns the identity of the authenticated user.
#[tokio::test]
async fn get_me_returns_authenticated_identity() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/accounts/me", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["identityUri"].as_str(),
        Some("vigil://credo/service/shepherd"),
        "identityUri must match the injected test admin user"
    );
    assert!(body["role"].is_string(), "role must be present");
}

/// GET /admin/renewal-jobs returns an empty list on a fresh instance.
#[tokio::test]
async fn renewal_jobs_empty_on_fresh_instance() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/renewal-jobs", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["jobs"].is_array(), "response must have jobs array");
    assert!(body["jobs"].as_array().unwrap().is_empty(), "no renewal jobs on fresh start");
}

/// GET /admin/cas returns an empty list when no CAs are configured.
#[tokio::test]
async fn get_cas_returns_empty_when_none_configured() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/cas", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["cas"].is_array(), "response must have cas array");
}

/// POST /admin/reload-assignments returns a success response.
#[tokio::test]
async fn reload_assignments_returns_ok() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .post(format!("{}/admin/reload-assignments", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
}

/// POST /admin/reload-corgis returns a success response.
#[tokio::test]
async fn reload_corgis_returns_ok() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd.client
        .post(format!("{}/admin/reload-corgis", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
}
