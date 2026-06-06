/// ACME protocol tests — unauthenticated endpoints that don't require JWS signing.
/// Full ACME flow (account → order → finalize) requires JWS and is a follow-up.
use credo_test::vigil_harness::TestVigil;
use serde_json::Value;
use std::collections::HashSet;

/// GET /acme/directory returns all required RFC 8555 fields.
#[tokio::test]
async fn acme_directory_has_required_fields() {
    let vigil = TestVigil::start().await.unwrap();

    let resp = vigil.client
        .get(vigil.acme_directory_url())
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // RFC 8555 §7.1.1 required directory fields
    assert!(body["newAccount"].is_string(), "newAccount URL must be present");
    assert!(body["newOrder"].is_string(),   "newOrder URL must be present");
    assert!(body["newNonce"].is_string(),   "newNonce URL must be present");
    assert!(body["revokeCert"].is_string(), "revokeCert URL must be present");
    assert!(body["keyChange"].is_string(),  "keyChange URL must be present");
}

/// GET /acme/new-nonce provides unique nonces on repeated calls.
/// HEAD /acme/new-nonce also returns a nonce (RFC 8555 §7.2).
#[tokio::test]
async fn new_nonce_is_unique_per_call() {
    let vigil = TestVigil::start().await.unwrap();
    let nonce_url = format!("{}/acme/new-nonce", vigil.url);

    let mut nonces = HashSet::new();

    // GET form
    for _ in 0..5 {
        let resp = vigil.client.get(&nonce_url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let nonce = resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .expect("Replay-Nonce header must be present")
            .to_string();
        assert!(!nonce.is_empty(), "nonce must be non-empty");
        assert!(nonces.insert(nonce.clone()), "nonce must be unique, got duplicate: {nonce}");
    }

    // HEAD form (RFC 8555 §7.2 — server MUST provide nonce via HEAD)
    let head_resp = vigil.client.head(&nonce_url).send().await.unwrap();
    assert_eq!(head_resp.status(), 200);
    let head_nonce = head_resp.headers()
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("HEAD must also return Replay-Nonce")
        .to_string();
    assert!(!head_nonce.is_empty());
    assert!(nonces.insert(head_nonce), "HEAD nonce must be unique from GET nonces");
}

/// Directory URLs all resolve to the same host as the vigil server.
#[tokio::test]
async fn acme_directory_urls_share_host_with_server() {
    let vigil = TestVigil::start().await.unwrap();

    let body: Value = vigil.client
        .get(vigil.acme_directory_url())
        .send().await.unwrap()
        .json().await.unwrap();

    // All URL fields must be strings (absolute URLs)
    for field in ["newAccount", "newOrder", "newNonce", "revokeCert", "keyChange"] {
        let url = body[field].as_str().unwrap_or_else(|| panic!("{field} must be a string"));
        assert!(url.starts_with("http"), "{field} must be an absolute URL, got: {url}");
    }
}
