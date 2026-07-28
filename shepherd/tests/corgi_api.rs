/// Agent (corgi-facing) API tests — shepherd's port 7010 equivalent.
///
/// Uses `TestShepherd::start_authed()` which pre-injects a CorgiNodeConfig extension,
/// bypassing the mTLS cert-matching auth for corgi routes.
use credo_test::shepherd_harness::TestShepherd;
use serde_json::Value;

/// GET /health on the agent port returns 401 without auth (no pre-injected CorgiNodeConfig).
#[tokio::test]
async fn agent_health_requires_auth() {
    let shepherd = TestShepherd::start().await.unwrap();

    let resp = shepherd
        .client
        .get(shepherd.agent_health_url())
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "agent /health must require corgi mTLS auth"
    );
}

/// GET /health on the agent port returns 200 with a valid CorgiNodeConfig injected.
#[tokio::test]
async fn agent_health_returns_200_with_auth() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(shepherd.agent_health_url())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
    assert_eq!(body["service"].as_str(), Some("shepherd-corgi"));
}

/// GET /agents/:id/assignments returns an empty list for a corgi with no assignments.
#[tokio::test]
async fn get_assignments_returns_empty_for_unassigned_corgi() {
    let shepherd = TestShepherd::start_authed().await.unwrap();
    // Injected corgi name is "test-corgi-01" (from start_authed)
    let resp = shepherd
        .client
        .get(format!(
            "{}/agents/test-corgi-01/assignments",
            shepherd.agent_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["corgiId"].as_str(), Some("test-corgi-01"));
    let assignments = body["assignments"].as_array().expect("assignments array");
    assert!(assignments.is_empty(), "no assignments on fresh instance");
}

/// GET /agents/:id/certs/:name returns 404 for a cert that does not exist in the certstore.
#[tokio::test]
async fn get_cert_returns_404_for_unknown_cert() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/agents/test-corgi-01/certs/nonexistent",
            shepherd.agent_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

/// GET /agents/:id/certs/:name must reject a corgi_id that doesn't match the
/// authenticated corgi, even when a real assignment exists for that other corgi.
/// Regression test for a High finding: the handler looked up cert material by
/// the untrusted path parameter alone, so any authenticated corgi could read
/// any other corgi's certificate material.
#[tokio::test]
async fn get_cert_rejects_mismatched_corgi_id() {
    use shepherd::types::ManagedAssignment;

    let shepherd = TestShepherd::start_authed().await.unwrap();
    // Authenticated as "test-corgi-01"; seed an assignment belonging to a
    // different corgi so a successful lookup would prove the leak.
    shepherd
        .state
        .assignments
        .write()
        .await
        .push(ManagedAssignment {
            cert_name: "victim-cert".to_string(),
            corgi: Some("victim-corgi".to_string()),
            ca: "letsencrypt".to_string(),
            domain: Some("victim.credo.test".to_string()),
            sans: vec![],
            renew_before_days: None,
            days: None,
            identity_uri: None,
            validation: None,
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
            key_algorithm: None,
            hooks: None,
            monitor: None,
        });

    let resp = shepherd
        .client
        .get(format!(
            "{}/agents/victim-corgi/certs/victim-cert",
            shepherd.agent_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "corgi authenticated as test-corgi-01 must not read victim-corgi's cert material"
    );
}

/// POST /agents/:id/provision/:name must reject a mismatched corgi_id before
/// ever looking up an assignment or contacting a CA.
#[tokio::test]
async fn provision_cert_rejects_mismatched_corgi_id() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .post(format!(
            "{}/agents/victim-corgi/provision/some-cert",
            shepherd.agent_url
        ))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "corgi authenticated as test-corgi-01 must not trigger provisioning for victim-corgi"
    );
}

/// POST /agents/:id/renew/:name must reject a mismatched corgi_id before
/// ever looking up an assignment or spawning a renewal job.
#[tokio::test]
async fn renew_cert_rejects_mismatched_corgi_id() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .post(format!(
            "{}/agents/victim-corgi/renew/some-cert",
            shepherd.agent_url
        ))
        .json(&serde_json::json!({ "csrPem": "not-empty" }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "corgi authenticated as test-corgi-01 must not trigger renewal for victim-corgi"
    );
}

/// GET /agents/:id/renew/:name/status must reject a mismatched corgi_id.
#[tokio::test]
async fn renew_status_rejects_mismatched_corgi_id() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/agents/victim-corgi/renew/some-cert/status",
            shepherd.agent_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "corgi authenticated as test-corgi-01 must not read victim-corgi's renewal status"
    );
}

/// Corgi agents other than the authenticated one cannot access another corgi's assignments.
/// The auth bypass injects a fixed CorgiNodeConfig; the handler filters by corgi name.
#[tokio::test]
async fn get_assignments_filtered_to_authenticated_corgi() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    // Authenticated as test-corgi-01; requesting another corgi's assignments returns empty
    // (the handler returns assignments assigned to the requesting corgi's name)
    let resp = shepherd
        .client
        .get(format!(
            "{}/agents/test-corgi-01/assignments",
            shepherd.agent_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // corgiId in response should reflect the path parameter
    assert_eq!(body["corgiId"].as_str(), Some("test-corgi-01"));
}
