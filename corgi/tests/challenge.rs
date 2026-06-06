/// HTTP-01 challenge server tests — the plain-HTTP port corgi uses for ACME validation.
/// No auth required on the challenge server (it's the public ACME validation endpoint).
use credo_test::corgi_harness::TestCorgi;

/// GET /health on the challenge server always returns 200 with no auth.
#[tokio::test]
async fn challenge_health_is_public() {
    let corgi = TestCorgi::start().await.unwrap();

    let resp = corgi.client
        .get(corgi.challenge_health_url())
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
}

/// GET /.well-known/acme-challenge/:token returns 404 when no challenge exists for that token.
#[tokio::test]
async fn challenge_404_for_unknown_token() {
    let corgi = TestCorgi::start().await.unwrap();

    let resp = corgi.client
        .get(format!("{}/.well-known/acme-challenge/unknown-token", corgi.challenge_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 404, "unknown challenge token must return 404");
}

/// A challenge stored via the control API is immediately served on the challenge port.
/// Validates the in-memory state is shared between control and challenge routers.
#[tokio::test]
async fn challenge_served_after_insert_via_state() {
    // Use start_authed so we can POST to the control API
    let corgi = TestCorgi::start_authed().await.unwrap();

    let token = "acme-token-xyz";
    let key_auth = format!("{token}.ABCDEFG1234567890");

    // Insert via control API
    let insert = corgi.client
        .post(format!("{}/acme-challenges", corgi.control_url))
        .json(&serde_json::json!({ "token": token, "response": key_auth }))
        .send().await.unwrap();
    assert_eq!(insert.status(), 201);

    // Must be served on challenge port with correct key authorization
    let resp = corgi.client
        .get(format!("{}/.well-known/acme-challenge/{token}", corgi.challenge_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let content_type = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("text/plain"), "challenge response must be text/plain");
    assert_eq!(resp.text().await.unwrap(), key_auth,
        "response body must be the key authorization string");
}

/// Challenge response has text/plain content-type (required by RFC 8555 §8.3).
#[tokio::test]
async fn challenge_response_is_text_plain() {
    let corgi = TestCorgi::start_authed().await.unwrap();

    corgi.client
        .post(format!("{}/acme-challenges", corgi.control_url))
        .json(&serde_json::json!({ "token": "ct-tok", "response": "ct-tok.keyauth" }))
        .send().await.unwrap();

    let resp = corgi.client
        .get(format!("{}/.well-known/acme-challenge/ct-tok", corgi.challenge_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/plain"), "content-type must be text/plain, got: {ct}");
}
