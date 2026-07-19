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

    let resp = shepherd
        .client
        .get(shepherd.dashboard_health_url())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
    assert_eq!(body["service"].as_str(), Some("shepherd"));
}

/// GET /flock is public and returns a corgis array (empty when no corgis registered).
#[tokio::test]
async fn flock_list_is_public() {
    let shepherd = TestShepherd::start().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/flock", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

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

    for path in [
        "/admin/assignments",
        "/admin/certstore",
        "/accounts",
        "/accounts/me",
    ] {
        let resp = shepherd
            .client
            .get(format!("{}{}", shepherd.dashboard_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "GET {path} must require auth, got {}",
            resp.status()
        );
    }
}

// ============================================================================
// Authenticated routes (with auth bypass)
// ============================================================================

/// GET /admin/assignments returns an empty list on a fresh instance.
#[tokio::test]
async fn get_assignments_returns_empty_list() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/assignments", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let assignments = body["assignments"].as_array().expect("assignments array");
    assert!(
        assignments.is_empty(),
        "fresh instance must have no assignments"
    );
}

/// GET /admin/certstore returns an empty entries list on a fresh instance.
#[tokio::test]
async fn get_certstore_returns_empty() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/certstore", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["entries"].is_array(),
        "certstore must return entries array"
    );
}

/// GET /admin/certstore/:name returns 404 for an unknown cert name.
#[tokio::test]
async fn get_certstore_entry_404_for_unknown() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/certstore/nonexistent-cert",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

/// GET /admin/config-summary returns key config fields.
#[tokio::test]
async fn config_summary_returns_fields() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/config-summary", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["renewBeforeDays"].is_number(),
        "renewBeforeDays must be present"
    );
    assert!(
        body["certStoreDir"].is_string(),
        "certStoreDir must be present"
    );
}

/// GET /accounts returns an empty list on a fresh instance.
#[tokio::test]
async fn list_accounts_returns_empty() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/accounts", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["accounts"].is_array(),
        "response must have accounts array"
    );
}

/// GET /accounts/me returns the identity of the authenticated user.
#[tokio::test]
async fn get_me_returns_authenticated_identity() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/accounts/me", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

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

    let resp = shepherd
        .client
        .get(format!("{}/admin/renewal-jobs", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["jobs"].is_array(), "response must have jobs array");
    assert!(
        body["jobs"].as_array().unwrap().is_empty(),
        "no renewal jobs on fresh start"
    );
}

/// GET /admin/cas returns an empty list when no CAs are configured.
#[tokio::test]
async fn get_cas_returns_empty_when_none_configured() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/cas", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["cas"].is_array(), "response must have cas array");
}

/// POST /admin/reload-assignments returns a success response.
#[tokio::test]
async fn reload_assignments_returns_ok() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .post(format!(
            "{}/admin/reload-assignments",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

/// POST /admin/reload-corgis returns a success response.
#[tokio::test]
async fn reload_corgis_returns_ok() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .post(format!("{}/admin/reload-corgis", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

// ============================================================================
// Reconcile triggering on assignment mutations
// ============================================================================

/// Creating an assignment queues a targeted, maintenance-enabled reconcile
/// request for the assignment's corgi so changes apply within seconds
/// instead of waiting for the next periodic sweep.
#[tokio::test]
async fn create_assignment_queues_targeted_reconcile() {
    let shepherd = TestShepherd::start_authed().await.unwrap();
    let mut rx = shepherd
        .state
        .reconcile_rx
        .lock()
        .unwrap()
        .take()
        .expect("harness leaves the reconcile receiver in place");

    let resp = shepherd
        .client
        .post(format!("{}/admin/assignments", shepherd.dashboard_url))
        .json(&serde_json::json!({
            "certName": "reconcile-test",
            "domain": "reconcile-test.example.com",
            "ca": "letsencrypt",
            "corgi": "corgi-1"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let req = rx
        .try_recv()
        .expect("mutation must queue a reconcile request");
    assert_eq!(req.corgis, Some(vec!["corgi-1".to_string()]));
    assert!(req.maintenance);
}

/// Deleting an assignment queues a reconcile for the corgi that held it.
#[tokio::test]
async fn delete_assignment_queues_targeted_reconcile() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .post(format!("{}/admin/assignments", shepherd.dashboard_url))
        .json(&serde_json::json!({
            "certName": "reconcile-del",
            "domain": "reconcile-del.example.com",
            "ca": "letsencrypt",
            "corgi": "corgi-2"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Take the receiver after create so we only observe the delete's request.
    let mut rx = shepherd
        .state
        .reconcile_rx
        .lock()
        .unwrap()
        .take()
        .expect("harness leaves the reconcile receiver in place");
    while rx.try_recv().is_ok() {}

    let resp = shepherd
        .client
        .delete(format!(
            "{}/admin/assignments/reconcile-del",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let req = rx
        .try_recv()
        .expect("delete must queue a reconcile request");
    assert_eq!(req.corgis, Some(vec!["corgi-2".to_string()]));
}

/// A monitor block on a new assignment is validated, defaulted, and echoed.
#[tokio::test]
async fn create_assignment_round_trips_monitor_block() {
    let shepherd = TestShepherd::start_authed().await.unwrap();
    let resp = shepherd
        .client
        .post(format!("{}/admin/assignments", shepherd.dashboard_url))
        .json(&serde_json::json!({
            "certName": "monitored-cert",
            "domain": "monitored.example.com",
            "ca": "letsencrypt",
            "monitor": { "host": "monitored.example.com" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["monitor"]["host"], "monitored.example.com");
    assert_eq!(body["monitor"]["port"], 443);
    assert_eq!(body["monitor"]["protocol"], "https");
}

/// A monitor block with a blank host is a config error, not silence later.
#[tokio::test]
async fn create_assignment_rejects_blank_monitor_host() {
    let shepherd = TestShepherd::start_authed().await.unwrap();
    let resp = shepherd
        .client
        .post(format!("{}/admin/assignments", shepherd.dashboard_url))
        .json(&serde_json::json!({
            "certName": "bad-monitor",
            "ca": "letsencrypt",
            "monitor": { "host": "   " }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
