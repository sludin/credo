/// ACME full-flow integration tests — account, order, authz, challenge validation.
///
/// Uses a P-256 JWS signing helper (`AcmeTestClient`) to drive the ACME API over
/// plain HTTP through the test-auth bypass in the vigil harness.
use axum::{extract::Path, routing::get, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use credo_test::vigil_harness::TestVigil;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

// ---------------------------------------------------------------------------
// JWS signing helper
// ---------------------------------------------------------------------------

struct AcmeTestClient {
    key: SigningKey,
    account_url: Option<String>,
    http: reqwest::Client,
    base: String,
}

impl AcmeTestClient {
    fn new(base: &str) -> Self {
        Self {
            key: SigningKey::random(&mut OsRng),
            account_url: None,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            base: base.to_string(),
        }
    }

    /// Convert an https:// URL from vigil's responses to http:// for the plain-HTTP test server.
    fn norm(url: &str) -> String {
        if let Some(rest) = url.strip_prefix("https://") {
            format!("http://{}", rest)
        } else {
            url.to_string()
        }
    }

    fn public_jwk(&self) -> Value {
        let pt = self.key.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(pt.x().unwrap()),
            "y": B64.encode(pt.y().unwrap()),
        })
    }

    /// Computes the RFC 7638 JWK thumbprint for this key.
    fn jwk_thumbprint(&self) -> String {
        let pt = self.key.verifying_key().to_encoded_point(false);
        let x = B64.encode(pt.x().unwrap());
        let y = B64.encode(pt.y().unwrap());
        // RFC 7638: canonical JSON with lexicographically sorted member names
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);
        B64.encode(Sha256::digest(canonical.as_bytes()))
    }

    async fn nonce(&self) -> String {
        self.http
            .get(format!("{}/acme/new-nonce", self.base))
            .send()
            .await
            .unwrap()
            .headers()["replay-nonce"]
            .to_str()
            .unwrap()
            .to_string()
    }

    fn sign(&self, protected_b64: &str, payload_b64: &str) -> String {
        use p256::ecdsa::signature::Signer;
        let msg = format!("{}.{}", protected_b64, payload_b64);
        let sig: p256::ecdsa::Signature = self.key.sign(msg.as_bytes());
        B64.encode(sig.to_bytes())
    }

    fn build_jws(&self, protected: Value, payload: Value) -> Value {
        let ph = B64.encode(protected.to_string().as_bytes());
        let pl = B64.encode(payload.to_string().as_bytes());
        let sig = self.sign(&ph, &pl);
        json!({"protected": ph, "payload": pl, "signature": sig})
    }

    fn jws_with_jwk(&self, nonce: &str, url: &str, payload: Value) -> Value {
        self.build_jws(
            json!({"alg": "ES256", "jwk": self.public_jwk(), "nonce": nonce, "url": url}),
            payload,
        )
    }

    fn jws_with_kid(&self, nonce: &str, url: &str, payload: Value) -> Value {
        let kid = self.account_url.as_deref().expect("call register() first");
        self.build_jws(
            json!({"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}),
            payload,
        )
    }

    async fn register(&mut self) {
        let url = format!("{}/acme/new-account", self.base);
        let nonce = self.nonce().await;
        let body = self.jws_with_jwk(&nonce, &url, json!({"contact": ["mailto:test@credo.test"]}));
        let resp = self.http.post(&url).json(&body).send().await.unwrap();
        assert_eq!(resp.status(), 201, "new-account must return 201");
        let loc = resp.headers()["location"].to_str().unwrap().to_string();
        self.account_url = Some(Self::norm(&loc));
    }

    async fn new_order(&self, domain: &str, validation_method: Option<&str>) -> Value {
        let url = format!("{}/acme/new-order", self.base);
        let nonce = self.nonce().await;
        let mut payload = json!({"identifiers": [{"type": "dns", "value": domain}]});
        if let Some(m) = validation_method {
            payload["validationMethod"] = json!(m);
        }
        let body = self.jws_with_kid(&nonce, &url, payload);
        let resp = self.http.post(&url).json(&body).send().await.unwrap();
        assert_eq!(resp.status(), 201, "new-order must return 201");
        resp.json().await.unwrap()
    }

    async fn try_new_order(
        &self,
        domain: &str,
        validation_method: Option<&str>,
    ) -> reqwest::Response {
        let url = format!("{}/acme/new-order", self.base);
        let nonce = self.nonce().await;
        let mut payload = json!({"identifiers": [{"type": "dns", "value": domain}]});
        if let Some(m) = validation_method {
            payload["validationMethod"] = json!(m);
        }
        let body = self.jws_with_kid(&nonce, &url, payload);
        self.http.post(&url).json(&body).send().await.unwrap()
    }

    async fn get_authz(&self, authz_url: &str) -> Value {
        let url = Self::norm(authz_url);
        let nonce = self.nonce().await;
        let body = self.jws_with_kid(&nonce, &url, json!({}));
        let resp = self.http.post(&url).json(&body).send().await.unwrap();
        assert_eq!(resp.status(), 200, "get-authz must return 200");
        resp.json().await.unwrap()
    }

    /// Finds the first challenge of `challenge_type` and returns (url, token).
    fn find_challenge(authz: &Value, challenge_type: &str) -> (String, String) {
        authz["challenges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some(challenge_type))
            .map(|c| {
                (
                    c["url"].as_str().unwrap().to_string(),
                    c["token"].as_str().unwrap().to_string(),
                )
            })
            .unwrap_or_else(|| panic!("no {challenge_type} challenge found in authz"))
    }

    async fn respond_challenge(&self, challenge_url: &str) -> reqwest::Response {
        let url = Self::norm(challenge_url);
        let nonce = self.nonce().await;
        let body = self.jws_with_kid(&nonce, &url, json!({}));
        self.http.post(&url).json(&body).send().await.unwrap()
    }

    /// Poll the authz URL every 50 ms until status is "valid" or "invalid", or timeout.
    async fn poll_authz_until_terminal(&self, authz_url: &str, timeout_ms: u64) -> Value {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let authz = self.get_authz(authz_url).await;
            match authz["status"].as_str().unwrap_or("pending") {
                "valid" | "invalid" => return authz,
                _ => {}
            }
            assert!(
                Instant::now() < deadline,
                "authz did not reach terminal status within {timeout_ms}ms"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Challenge mock server
// ---------------------------------------------------------------------------

/// Start an HTTP server on a random port serving `/.well-known/acme-challenge/:tok`.
/// The returned `Arc<Mutex<...>>` can be updated with `(token, key_auth)` before
/// calling respond_challenge so the token lookup succeeds.
async fn start_challenge_server() -> (
    u16,
    Arc<Mutex<Option<(String, String)>>>,
    oneshot::Sender<()>,
) {
    let challenge: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = oneshot::channel::<()>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let c = challenge.clone();
    let router = Router::new().route(
        "/.well-known/acme-challenge/:tok",
        get(move |Path(tok): Path<String>| {
            let c = c.clone();
            async move {
                let lock = c.lock().unwrap();
                match lock.as_ref() {
                    Some((t, body)) if *t == tok => (axum::http::StatusCode::OK, body.clone()),
                    _ => (axum::http::StatusCode::NOT_FOUND, String::new()),
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    (port, challenge, tx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// none-01 (explicit) is rejected at new-order time when allowNoneValidation is false.
/// Absent validationMethod is a malformed request regardless of allowNoneValidation.
#[tokio::test]
async fn none_01_rejected_when_allow_none_validation_false() {
    let vigil = TestVigil::start_authed_strict().await.unwrap();
    let mut client = AcmeTestClient::new(&vigil.url);

    client.register().await;

    // Absent validationMethod is always a malformed request — callers must specify a method.
    let resp = client.try_new_order("test.credo.test", None).await;
    assert_eq!(
        resp.status(),
        400,
        "absent validationMethod must return 400"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["type"].as_str().unwrap_or("").contains("malformed"),
        "error type must be malformed, got: {}",
        body["type"]
    );

    // Explicit none-01 must be rejected with unauthorized when allowNoneValidation is false.
    let resp = client
        .try_new_order("test.credo.test", Some("none-01"))
        .await;
    assert_eq!(resp.status(), 400, "explicit none-01 must be rejected");
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["type"].as_str().unwrap_or("").contains("unauthorized"),
        "error type must be unauthorized for explicit none-01, got: {}",
        body["type"]
    );
}

/// none-01 (explicit) is accepted when allowNoneValidation is true.
#[tokio::test]
async fn none_01_accepted_when_allow_none_validation_true() {
    let vigil = TestVigil::start_authed().await.unwrap();
    let mut client = AcmeTestClient::new(&vigil.url);

    client.register().await;
    let order = client.new_order("test.credo.test", Some("none-01")).await;
    let authz_url = order["authorizations"][0].as_str().unwrap();
    let authz = client.get_authz(authz_url).await;
    let (chall_url, _token) = AcmeTestClient::find_challenge(&authz, "http-01");

    let resp = client.respond_challenge(&chall_url).await;
    assert_eq!(
        resp.status(),
        200,
        "none-01 challenge must be accepted when allowNoneValidation is true"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"].as_str(),
        Some("valid"),
        "challenge status must be valid"
    );
}

/// http-01 challenge is accepted when the mock server serves the correct key authorization.
#[tokio::test]
async fn http_01_correct_key_auth_validates() {
    let vigil = TestVigil::start_authed().await.unwrap();
    let mut client = AcmeTestClient::new(&vigil.url);

    client.register().await;

    // Start the mock challenge server before creating the order so we know the port.
    let (port, challenge, _server) = start_challenge_server().await;
    let domain = format!("127.0.0.1:{}", port);

    let order = client.new_order(&domain, Some("http-01")).await;
    let authz_url = order["authorizations"][0].as_str().unwrap();
    let authz = client.get_authz(authz_url).await;
    let (chall_url, token) = AcmeTestClient::find_challenge(&authz, "http-01");

    // Set up the mock server with the correct key authorization.
    let key_auth = format!("{}.{}", token, client.jwk_thumbprint());
    *challenge.lock().unwrap() = Some((token, key_auth));

    let resp = client.respond_challenge(&chall_url).await;
    assert_eq!(resp.status(), 200, "respond_challenge must return 200");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"].as_str(),
        Some("processing"),
        "challenge must be processing after respond_challenge"
    );

    // Background task validates immediately; poll authz until it becomes valid.
    let authz = client.poll_authz_until_terminal(authz_url, 5000).await;
    assert_eq!(
        authz["status"].as_str(),
        Some("valid"),
        "authz must be valid after successful http-01 validation"
    );
}

/// http-01 challenge is rejected when the mock server serves the wrong key authorization.
#[tokio::test]
async fn http_01_wrong_key_auth_rejected() {
    let vigil = TestVigil::start_authed().await.unwrap();
    let mut client = AcmeTestClient::new(&vigil.url);

    client.register().await;

    let (port, challenge, _server) = start_challenge_server().await;
    let domain = format!("127.0.0.1:{}", port);

    let order = client.new_order(&domain, Some("http-01")).await;
    let authz_url = order["authorizations"][0].as_str().unwrap();
    let authz = client.get_authz(authz_url).await;
    let (chall_url, token) = AcmeTestClient::find_challenge(&authz, "http-01");

    // Serve an incorrect key authorization — correct token path but wrong body.
    *challenge.lock().unwrap() = Some((token, "wrong-key-auth".to_string()));

    let resp = client.respond_challenge(&chall_url).await;
    assert_eq!(resp.status(), 200, "respond_challenge must return 200");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"].as_str(),
        Some("processing"),
        "challenge must be processing after respond_challenge"
    );

    // Background task retries and exhausts attempts; poll authz until it becomes invalid.
    let authz = client.poll_authz_until_terminal(authz_url, 5000).await;
    assert_eq!(
        authz["status"].as_str(),
        Some("invalid"),
        "authz must be invalid after failed http-01 validation"
    );
}
