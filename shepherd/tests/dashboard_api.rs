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

/// Regression test for a Medium finding: axum's `Path<String>` extractor
/// percent-decodes the *entire* captured segment (including `%2F`) after
/// route matching has already treated it as one opaque segment — so a name
/// containing percent-encoded `..%2F` sequences reintroduces a literal `..`
/// path component right before it's joined into a filesystem path, letting
/// an authenticated readonly account read files outside the certstore tree.
#[tokio::test]
async fn get_certstore_pem_rejects_path_traversal() {
    let shepherd = TestShepherd::start_authed().await.unwrap();
    let cert_store_dir = shepherd.state.config.load().cert_store_dir.clone();

    // The traversal only resolves through a `live/` dir that actually exists
    // (the OS must be able to walk into it before backing out via `..`) — any
    // real instance with at least one issued cert has this directory.
    std::fs::create_dir_all(cert_store_dir.join("live")).unwrap();

    // A file just outside the certstore dir that traversal would reach:
    // cert_store_dir/live/<name>/cert.pem with name="../../marker" resolves
    // to <tmp>/marker/cert.pem (certstore/live -> certstore -> tmp -> marker).
    let marker_dir = shepherd.dir.path().join("marker");
    std::fs::create_dir_all(&marker_dir).unwrap();
    std::fs::write(marker_dir.join("cert.pem"), "SECRET OUTSIDE CERTSTORE").unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/certstore/..%2f..%2fmarker/pem",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_ne!(
        resp.status(),
        200,
        "traversal must not succeed in reading a file outside the certstore"
    );
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("SECRET OUTSIDE CERTSTORE"),
        "response must never contain the out-of-tree file's contents"
    );
}

/// Same traversal guard, for GET /admin/certstore/:name (the entry-metadata
/// endpoint, which goes through cert_store::read_cert_store_entry).
#[tokio::test]
async fn get_certstore_entry_rejects_path_traversal() {
    let shepherd = TestShepherd::start_authed().await.unwrap();
    let cert_store_dir = shepherd.state.config.load().cert_store_dir.clone();
    std::fs::create_dir_all(cert_store_dir.join("live")).unwrap();

    // Must be a real, parseable cert — read_cert_store_entry parses the PEM
    // as X.509 and returns None on failure, which would mask a traversal
    // "success" as an unrelated parse failure and make this test meaningless.
    let (cert_pem, _key_pem, _fullchain_pem) = credo_test::cert_gen::generate_signed_cert(
        "marker2.credo.test",
        &["marker2.credo.test"],
        &[],
        30,
        shepherd.dir.path(),
    )
    .unwrap();
    let marker_dir = shepherd.dir.path().join("marker2");
    std::fs::create_dir_all(&marker_dir).unwrap();
    std::fs::write(marker_dir.join("cert.pem"), &cert_pem).unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/certstore/..%2f..%2fmarker2",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "traversal attempt must be treated as not-found, not resolved"
    );
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

/// PUT /accounts/:id with an unrecognized role must be rejected, not
/// silently escalate the account to Admin. Regression test for a Medium
/// finding: Role::from_str used to default any unrecognized string to Admin.
#[tokio::test]
async fn update_account_rejects_invalid_role() {
    use shepherd::types::{Account, Role};

    let shepherd = TestShepherd::start_authed().await.unwrap();
    let account = Account {
        id: "acct-1".to_string(),
        name: "bob".to_string(),
        display_name: "Bob".to_string(),
        role: Role::Readonly,
        active: true,
        identities: vec!["vigil://credo/user/bob".to_string()],
        notes: String::new(),
        created_at: None,
    };
    shepherd.state.accounts.write().await.push(account);

    let resp = shepherd
        .client
        .put(format!("{}/accounts/acct-1", shepherd.dashboard_url))
        .json(&serde_json::json!({ "role": "admni" }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "an unrecognized role must be rejected, not silently applied"
    );

    let accounts = shepherd.state.accounts.read().await;
    let bob = accounts.iter().find(|a| a.id == "acct-1").unwrap();
    assert_eq!(
        bob.role,
        Role::Readonly,
        "the account's role must be unchanged after a rejected update"
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

/// POST /admin/monitor-check/:name returns 404 when there's no assignment
/// for the cert.
#[tokio::test]
async fn monitor_check_unknown_cert_returns_404() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .post(format!(
            "{}/admin/monitor-check/nonexistent-cert",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"].as_str(),
        Some("No assignment for 'nonexistent-cert'"),
        "must be the assignment-lookup 404, not an unmatched-route fallback"
    );
}

/// GET /admin/archived-cert/:certName/:ordinal/fullchain returns 404 when
/// there's no assignment for the cert.
#[tokio::test]
async fn archived_cert_fullchain_unknown_cert_returns_404() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/archived-cert/nonexistent-cert/001/fullchain",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"].as_str(),
        Some("No assignment for 'nonexistent-cert'"),
        "must be the assignment-lookup 404, not an unmatched-route fallback"
    );
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

// ============================================================================
// POST /auth/refresh
// ============================================================================

fn make_test_account(
    identity_uri: &str,
    role: shepherd::types::Role,
    active: bool,
) -> shepherd::types::Account {
    shepherd::types::Account {
        id: "refresh-test-account".to_string(),
        name: "refresh-test".to_string(),
        display_name: "Refresh Test".to_string(),
        role,
        active,
        identities: vec![identity_uri.to_string()],
        notes: String::new(),
        created_at: None,
    }
}

/// A refresh token for an active account is honored, and a fresh access token
/// plus rotated refresh token are returned.
#[tokio::test]
async fn refresh_succeeds_for_active_account() {
    let shepherd = TestShepherd::start().await.unwrap();
    let identity_uri = "vigil://credo/user/refresh-test";

    shepherd
        .state
        .accounts
        .write()
        .await
        .push(make_test_account(
            identity_uri,
            shepherd::types::Role::Operator,
            true,
        ));

    let expires_at = chrono::Utc::now().timestamp() + 3600;
    let token = shepherd
        .state
        .refresh_tokens
        .issue_token(
            identity_uri,
            &shepherd::types::Role::Operator,
            None,
            expires_at,
        )
        .await;

    let resp = shepherd
        .client
        .post(format!("{}/auth/refresh", shepherd.dashboard_url))
        .json(&serde_json::json!({ "refreshToken": token }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["accessToken"].as_str().is_some());
    assert!(body["refreshToken"].as_str().is_some());
}

/// Regression test for a High finding: a refresh token for an account that has
/// since been deactivated must be rejected, not silently honored using the
/// role cached in the token at issuance time. Deactivating an account must
/// actually stop it from refreshing its own session.
#[tokio::test]
async fn refresh_rejected_for_deactivated_account() {
    let shepherd = TestShepherd::start().await.unwrap();
    let identity_uri = "vigil://credo/user/refresh-test-deactivated";

    // Account is inactive from the start — equivalent to having been
    // deactivated after the refresh token was issued.
    shepherd
        .state
        .accounts
        .write()
        .await
        .push(make_test_account(
            identity_uri,
            shepherd::types::Role::Admin,
            false,
        ));

    let expires_at = chrono::Utc::now().timestamp() + 3600;
    let token = shepherd
        .state
        .refresh_tokens
        .issue_token(
            identity_uri,
            &shepherd::types::Role::Admin,
            None,
            expires_at,
        )
        .await;

    let resp = shepherd
        .client
        .post(format!("{}/auth/refresh", shepherd.dashboard_url))
        .json(&serde_json::json!({ "refreshToken": token.clone() }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "refresh must be rejected for a deactivated account"
    );

    // The rejected token must also be revoked — not just refused this once.
    let resp2 = shepherd
        .client
        .post(format!("{}/auth/refresh", shepherd.dashboard_url))
        .json(&serde_json::json!({ "refreshToken": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        401,
        "a refresh token rejected for inactivity must be revoked, not just skipped once"
    );
}

/// A refresh token for an identity with no matching account at all (e.g. the
/// account was deleted outright, not just deactivated) must also be rejected.
#[tokio::test]
async fn refresh_rejected_when_account_no_longer_exists() {
    let shepherd = TestShepherd::start().await.unwrap();
    let identity_uri = "vigil://credo/user/refresh-test-deleted";

    // No account is ever added for this identity.
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    let token = shepherd
        .state
        .refresh_tokens
        .issue_token(
            identity_uri,
            &shepherd::types::Role::Admin,
            None,
            expires_at,
        )
        .await;

    let resp = shepherd
        .client
        .post(format!("{}/auth/refresh", shepherd.dashboard_url))
        .json(&serde_json::json!({ "refreshToken": token }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "refresh must be rejected when no account exists for the token's identity"
    );
}
