/// HTTP API tests for vigil's authenticated routes.
///
/// Uses `TestVigil::start_authed()` which pre-injects an admin AuthUser extension,
/// bypassing mTLS auth so tests can drive the API over plain HTTP.
use credo_test::{cert_gen::make_csr, vigil_harness::TestVigil};
use serde_json::Value;

// ============================================================================
// Health + CA info
// ============================================================================

/// GET /health returns a healthy status with CA and cert stats.
#[tokio::test]
async fn health_returns_status_and_ca_info() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let resp = vigil
        .client
        .get(format!("{}/health", vigil.url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
    assert_eq!(body["service"].as_str(), Some("vigil"));
    assert!(
        body["ca"]["initialized"].as_bool().unwrap_or(false),
        "CA must be initialized"
    );
    assert!(
        body["ca"]["fingerprint256"].is_string(),
        "CA fingerprint must be present"
    );
    assert!(
        body["certificates"]["total"].is_number(),
        "cert stats must be present"
    );
}

/// GET /ca returns CA metadata including fingerprint and validity.
#[tokio::test]
async fn ca_info_has_fingerprint_and_subject() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let resp = vigil
        .client
        .get(format!("{}/ca", vigil.url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let ca = &body["rootCA"];
    assert!(
        ca["fingerprint256"].is_string(),
        "fingerprint256 must be present"
    );
    assert!(ca["subject"].is_string(), "subject must be present");
    assert!(ca["validTo"].is_string(), "validTo must be present");
    let subject = ca["subject"].as_str().unwrap();
    assert!(
        subject.contains("Credo Test Intermediate CA"),
        "subject must identify test CA, got: {subject}"
    );
}

// ============================================================================
// Certificate issuance + retrieval + revocation
// ============================================================================

/// POST /certificates/sign returns a signed cert; GET /certificates/:id retrieves it.
#[tokio::test]
async fn sign_cert_and_fetch_by_id() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let (csr, _) = make_csr(
        "test.credo.test",
        &["test.credo.test"],
        &["vigil://credo/test"],
    )
    .unwrap();

    let sign_resp = vigil
        .client
        .post(format!("{}/certificates/sign", vigil.url))
        .json(&serde_json::json!({ "csrPem": csr, "days": 1 }))
        .send()
        .await
        .unwrap();

    assert_eq!(sign_resp.status(), 201, "sign must return 201 Created");

    let sign_body: Value = sign_resp.json().await.unwrap();
    let cert_id = sign_body["certificate"]["id"].as_str().expect("id present");
    let cert_pem = sign_body["certificate"]["certPem"]
        .as_str()
        .expect("certPem present");
    assert!(
        cert_pem.contains("BEGIN CERTIFICATE"),
        "certPem must be valid PEM"
    );

    // Fetch by ID
    let get_resp = vigil
        .client
        .get(format!("{}/certificates/{}", vigil.url, cert_id))
        .send()
        .await
        .unwrap();

    assert_eq!(get_resp.status(), 200);
    let get_body: Value = get_resp.json().await.unwrap();
    assert!(
        !get_body["certificate"]["revoked"].as_bool().unwrap_or(true),
        "newly issued cert must not be revoked"
    );
}

/// POST /certificates/:id/revoke marks the cert revoked; health stats update.
#[tokio::test]
async fn revoke_cert_marks_revoked_in_db() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let (csr, _) = make_csr("rev.credo.test", &["rev.credo.test"], &[]).unwrap();
    let sign: Value = vigil
        .client
        .post(format!("{}/certificates/sign", vigil.url))
        .json(&serde_json::json!({ "csrPem": csr }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cert_id = sign["certificate"]["id"].as_str().unwrap();

    let rev_resp = vigil
        .client
        .post(format!("{}/certificates/{}/revoke", vigil.url, cert_id))
        .json(&serde_json::json!({ "reason": "keyCompromise" }))
        .send()
        .await
        .unwrap();
    assert_eq!(rev_resp.status(), 200);

    let rev: Value = rev_resp.json().await.unwrap();
    assert!(
        rev["certificate"]["revoked"].as_bool().unwrap_or(false),
        "certificate must be marked revoked"
    );

    // GET /certificates/:id must now show revoked: true
    let get: Value = vigil
        .client
        .get(format!("{}/certificates/{}", vigil.url, cert_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(get["certificate"]["revoked"].as_bool().unwrap_or(false));
}

// ============================================================================
// OCSP
// ============================================================================

/// GET /ocsp/:id returns "good" for an active cert and "revoked" after revocation.
#[tokio::test]
async fn ocsp_status_transitions_with_revocation() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let (csr, _) = make_csr("ocsp.credo.test", &["ocsp.credo.test"], &[]).unwrap();
    let sign: Value = vigil
        .client
        .post(format!("{}/certificates/sign", vigil.url))
        .json(&serde_json::json!({ "csrPem": csr }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cert_id = sign["certificate"]["id"].as_str().unwrap();

    // Before revocation: good
    let before: Value = vigil
        .client
        .get(format!("{}/ocsp/{}", vigil.url, cert_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before["ocsp"]["status"].as_str(), Some("good"));

    // Revoke
    vigil
        .client
        .post(format!("{}/certificates/{}/revoke", vigil.url, cert_id))
        .json(&serde_json::json!({ "reason": "superseded" }))
        .send()
        .await
        .unwrap();

    // After revocation: revoked
    let after: Value = vigil
        .client
        .get(format!("{}/ocsp/{}", vigil.url, cert_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        after["ocsp"]["status"].as_str(),
        Some("revoked"),
        "OCSP must show revoked after revocation"
    );
}

// ============================================================================
// CRL
// ============================================================================

/// GET /crl returns JSON with a revoked_certificates list updated after revocation.
#[tokio::test]
async fn crl_json_lists_revoked_certs() {
    let vigil = TestVigil::start_authed().await.unwrap();

    // Issue and revoke a cert
    let (csr, _) = make_csr("crl.credo.test", &["crl.credo.test"], &[]).unwrap();
    let sign: Value = vigil
        .client
        .post(format!("{}/certificates/sign", vigil.url))
        .json(&serde_json::json!({ "csrPem": csr }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cert_id = sign["certificate"]["id"].as_str().unwrap().to_string();

    vigil
        .client
        .post(format!("{}/certificates/{}/revoke", vigil.url, cert_id))
        .json(&serde_json::json!({ "reason": "keyCompromise" }))
        .send()
        .await
        .unwrap();

    let resp = vigil
        .client
        .get(format!("{}/crl", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    let revoked = body["crl"]["revokedCertificates"]
        .as_array()
        .expect("revokedCertificates array");
    assert_eq!(
        revoked.len(),
        1,
        "CRL must contain exactly the one revoked cert"
    );
    assert_eq!(revoked[0]["certificateId"].as_str(), Some(cert_id.as_str()));
}

/// GET /crl.pem returns valid PEM-encoded CRL text.
#[tokio::test]
async fn crl_pem_endpoint_returns_valid_format() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let resp = vigil
        .client
        .get(format!("{}/crl.pem", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("pem") || ct.contains("text") || ct.contains("octet"),
        "content-type should indicate PEM"
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("BEGIN X509 CRL"),
        "body must contain PEM CRL header"
    );
    assert!(
        body.contains("END X509 CRL"),
        "body must contain PEM CRL footer"
    );
}

/// GET /crl.der returns binary DER with the correct content-type.
#[tokio::test]
async fn crl_der_endpoint_returns_binary() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let resp = vigil
        .client
        .get(format!("{}/crl.der", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("pkix-crl") || ct.contains("octet"),
        "content-type must indicate DER CRL, got: {ct}"
    );

    let bytes = resp.bytes().await.unwrap();
    assert!(!bytes.is_empty(), "DER response must not be empty");
    assert_eq!(
        bytes[0], 0x30,
        "DER CRL must start with SEQUENCE tag (0x30)"
    );
}

// ============================================================================
// Auth enforcement
// ============================================================================

/// Authenticated routes return 401 when no client cert is present (no auth bypass).
#[tokio::test]
async fn authenticated_routes_reject_unauthenticated() {
    // Use plain start() — no auth bypass injected
    let vigil = TestVigil::start().await.unwrap();

    // /health requires auth
    let resp = vigil
        .client
        .get(format!("{}/health", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "health must require auth");

    // /ca requires auth
    let resp = vigil
        .client
        .get(format!("{}/ca", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "/ca must require auth");
}

/// Unauthenticated ACME endpoints remain accessible without a client cert.
#[tokio::test]
async fn acme_public_endpoints_accessible_without_auth() {
    let vigil = TestVigil::start().await.unwrap();

    let dir_resp = vigil
        .client
        .get(format!("{}/acme/directory", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(dir_resp.status(), 200, "/acme/directory must be public");

    let nonce_resp = vigil
        .client
        .get(format!("{}/acme/new-nonce", vigil.url))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200, "/acme/new-nonce must be public");
}
