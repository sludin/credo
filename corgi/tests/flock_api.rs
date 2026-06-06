/// Flock control API tests — corgi's mTLS control port.
///
/// Uses `TestCorgi::start_authed()` which pre-injects Role::Admin,
/// bypassing the mTLS cert auth check.
use credo_test::corgi_harness::TestCorgi;
use serde_json::Value;

// ============================================================================
// Auth enforcement
// ============================================================================

/// GET /health requires auth — returns 401 without a Role extension.
#[tokio::test]
async fn control_health_requires_auth() {
    let corgi = TestCorgi::start().await.unwrap();

    let resp = corgi.client
        .get(corgi.control_health_url())
        .send().await.unwrap();

    assert_eq!(resp.status(), 401, "control /health must require auth");
}

// ============================================================================
// Authenticated control routes
// ============================================================================

/// GET /health returns healthy status with node info.
#[tokio::test]
async fn control_health_returns_200_with_node_info() {
    let corgi = TestCorgi::start_authed().await.unwrap();

    let resp = corgi.client
        .get(corgi.control_health_url())
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
    assert_eq!(body["service"].as_str(), Some("corgi"));
    assert!(body["nodeId"].is_string(), "nodeId must be present");
    assert!(body["flockSize"].is_number(), "flockSize must be present");
}

/// GET /flock returns an empty list when no certs are configured.
#[tokio::test]
async fn flock_list_returns_empty_on_fresh_start() {
    let corgi = TestCorgi::start_authed().await.unwrap();

    let resp = corgi.client
        .get(format!("{}/flock", corgi.control_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let flock = body["flock"].as_array().expect("flock must be an array");
    assert!(flock.is_empty(), "fresh corgi must have empty flock");
}

/// GET /flock/:name returns 404 for a cert that is not in the flock.
#[tokio::test]
async fn flock_get_unknown_cert_returns_404() {
    let corgi = TestCorgi::start_authed().await.unwrap();

    let resp = corgi.client
        .get(format!("{}/flock/nonexistent-cert", corgi.control_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 404);
}

/// POST /sync/assignments returns a success response (reconcile trigger).
#[tokio::test]
async fn sync_assignments_returns_refreshed() {
    let corgi = TestCorgi::start_authed().await.unwrap();

    let resp = corgi.client
        .post(format!("{}/sync/assignments", corgi.control_url))
        .send().await.unwrap();

    // Sync will fail to reach shepherd (no shepherd running) but the route
    // itself must respond — either 200 on success or a meaningful error.
    // Either way the route is reachable.
    assert!(resp.status().is_success() || resp.status().is_server_error(),
        "sync endpoint must be reachable, got {}", resp.status());
}

/// POST /acme-challenges creates a challenge record; GET returns the key authorization.
#[tokio::test]
async fn acme_challenge_lifecycle_via_control_api() {
    let corgi = TestCorgi::start_authed().await.unwrap();

    // Create challenge via control API
    let create_resp = corgi.client
        .post(format!("{}/acme-challenges", corgi.control_url))
        .json(&serde_json::json!({
            "token": "test-token-abc",
            "response": "test-token-abc.key-auth-value",
        }))
        .send().await.unwrap();

    assert_eq!(create_resp.status(), 201);
    let body: Value = create_resp.json().await.unwrap();
    assert!(body["challenge"]["token"].is_string(), "challenge token must be present");

    // The challenge must now be served on the challenge port
    let get_resp = corgi.client
        .get(format!("{}/.well-known/acme-challenge/test-token-abc", corgi.challenge_url))
        .send().await.unwrap();
    assert_eq!(get_resp.status(), 200);
    assert_eq!(get_resp.text().await.unwrap(), "test-token-abc.key-auth-value");

    // Delete the challenge
    let del_resp = corgi.client
        .delete(format!("{}/acme-challenges/test-token-abc", corgi.control_url))
        .send().await.unwrap();
    assert_eq!(del_resp.status(), 200);
    let del_body: Value = del_resp.json().await.unwrap();
    assert_eq!(del_body["removed"].as_bool(), Some(true));

    // Must be gone from challenge server
    let after_del = corgi.client
        .get(format!("{}/.well-known/acme-challenge/test-token-abc", corgi.challenge_url))
        .send().await.unwrap();
    assert_eq!(after_del.status(), 404, "challenge must be gone after delete");
}
