use credo_test::{corgi_harness::TestCorgi, shepherd_harness::TestShepherd, vigil_harness::TestVigil};

/// Smoke test: start all three services, verify unauthenticated health/directory
/// endpoints return 200. This confirms the test harness itself is working.
#[tokio::test]
async fn full_stack_health() {
    let vigil = TestVigil::start().await.expect("vigil start");
    let shepherd = TestShepherd::start().await.expect("shepherd start");
    let corgi = TestCorgi::start().await.expect("corgi start");

    // Vigil: /acme/directory is unauthenticated
    let resp = vigil.client
        .get(vigil.acme_directory_url())
        .send()
        .await
        .expect("vigil GET /acme/directory");
    assert_eq!(resp.status(), 200, "vigil /acme/directory should return 200");

    // Shepherd dashboard: /health is public
    let resp = shepherd.client
        .get(shepherd.dashboard_health_url())
        .send()
        .await
        .expect("shepherd GET /health");
    assert_eq!(resp.status(), 200, "shepherd /health should return 200");

    // Shepherd agent /health requires a client cert — 401 is the expected
    // unauthenticated response, which confirms the route is wired up.
    let resp = shepherd.client
        .get(shepherd.agent_health_url())
        .send()
        .await
        .expect("shepherd agent GET /health");
    assert_eq!(resp.status(), 401, "shepherd agent /health should reject unauthenticated request");

    // Corgi challenge server: /health is public
    let resp = corgi.client
        .get(corgi.challenge_health_url())
        .send()
        .await
        .expect("corgi challenge GET /health");
    assert_eq!(resp.status(), 200, "corgi challenge /health should return 200");
}

/// Vigil ACME directory contains the expected RFC 8555 fields.
#[tokio::test]
async fn vigil_acme_directory_shape() {
    let vigil = TestVigil::start().await.expect("vigil start");

    let resp = vigil.client
        .get(vigil.acme_directory_url())
        .send()
        .await
        .expect("GET /acme/directory");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");

    assert!(body["newAccount"].is_string(), "directory must have newAccount URL");
    assert!(body["newOrder"].is_string(),   "directory must have newOrder URL");
    assert!(body["newNonce"].is_string(),   "directory must have newNonce URL");
}
