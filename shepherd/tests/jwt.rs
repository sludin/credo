/// JWT tests — key generation, signing, verification, and JWKS endpoint.
use shepherd::jwt::{load_or_generate, sign_jwt, verify_jwt};
use shepherd::types::Role;
use tempfile::TempDir;

fn tmp_keys() -> shepherd::jwt::JwtKeys {
    let dir = TempDir::new().unwrap();
    load_or_generate(&dir.path().join("jwt.key")).unwrap()
}

/// `load_or_generate` creates a new key file when none exists, then reloads it correctly.
#[test]
fn load_or_generate_creates_and_reloads() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("jwt.key");

    assert!(!path.exists(), "key file must not exist before first call");
    load_or_generate(&path).unwrap();
    assert!(path.exists(), "key file must be created after first call");

    // Second call must succeed (reload existing key)
    load_or_generate(&path).unwrap();
}

/// A token signed by the encoding key is verified correctly by the decoding key.
#[test]
fn sign_and_verify_round_trip() {
    let keys = tmp_keys();
    let token = sign_jwt(&keys, "vigil://credo/test", &Role::Admin, Some("test-account")).unwrap();

    let claims = verify_jwt(&keys, &token).unwrap();
    assert_eq!(claims.sub, "vigil://credo/test");
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.account.as_deref(), Some("test-account"));
}

/// A tampered or garbage token is rejected by `verify_jwt`.
#[test]
fn verify_rejects_garbage_token() {
    let keys = tmp_keys();
    let result = verify_jwt(&keys, "not-a-jwt");
    assert!(result.is_err(), "garbage token must not verify");
}

/// A token signed with a DIFFERENT key is rejected.
#[test]
fn verify_rejects_wrong_key() {
    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();
    let keys1 = load_or_generate(&dir1.path().join("k1.key")).unwrap();
    let keys2 = load_or_generate(&dir2.path().join("k2.key")).unwrap();

    let token = sign_jwt(&keys1, "vigil://credo/test", &Role::Readonly, None).unwrap();
    let result = verify_jwt(&keys2, &token);
    assert!(result.is_err(), "token from different key must be rejected");
}

/// The JWKS endpoint returns a JSON object with a `keys` array containing at least one key.
#[tokio::test]
async fn jwks_endpoint_returns_keys() {
    let shepherd = credo_test::shepherd_harness::TestShepherd::start().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/auth/jwks", shepherd.dashboard_url))
        .send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let keys = body["keys"].as_array().expect("keys must be an array");
    assert!(!keys.is_empty(), "JWKS must contain at least one key");
    // Must be EC key (ES256)
    let kty = keys[0]["kty"].as_str().unwrap_or("");
    assert_eq!(kty, "EC", "JWKS key must be EC type");
}

/// The dashboard API accepts a valid JWT Bearer token on authenticated routes.
#[tokio::test]
async fn jwt_bearer_token_grants_access() {
    let shepherd = credo_test::shepherd_harness::TestShepherd::start().await.unwrap();

    let token = sign_jwt(
        &shepherd.jwt_keys,
        "vigil://credo/service/test",
        &Role::Admin,
        Some("test-admin"),
    ).unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/assignments", shepherd.dashboard_url))
        .header("Authorization", format!("Bearer {}", token))
        .send().await.unwrap();

    // 200 means auth succeeded (empty assignments list is fine)
    assert_eq!(resp.status(), 200, "valid JWT must grant access to authenticated route");
}

/// An expired or invalid JWT is rejected with 401.
#[tokio::test]
async fn invalid_jwt_returns_401() {
    let shepherd = credo_test::shepherd_harness::TestShepherd::start().await.unwrap();

    let resp = shepherd.client
        .get(format!("{}/admin/assignments", shepherd.dashboard_url))
        .header("Authorization", "Bearer not-a-valid-jwt")
        .send().await.unwrap();

    assert_eq!(resp.status(), 401, "invalid JWT must return 401");
}
