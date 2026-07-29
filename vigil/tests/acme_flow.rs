/// ACME full-flow integration tests — account, order, authz, challenge validation.
///
/// Uses a P-256 JWS signing helper (`AcmeTestClient`) to drive the ACME API over
/// plain HTTP through the test-auth bypass in the vigil harness.
use axum::{extract::Path, routing::get, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use credo_test::vigil_harness::TestVigil;
use p256::ecdsa::SigningKey;
use pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// Build a CSR (DER) with SAN entries for each of `sans`, signed by `key`. The
/// first entry also becomes the CSR's CommonName. `key` becomes the
/// certificate's own keypair — distinct from whatever ACME account key drives
/// the request; callers that need to prove possession of the cert's key
/// (e.g. jwk-path revoke) hang onto `key` after calling this.
fn build_csr_der(sans: &[&str], key: &SigningKey) -> Vec<u8> {
    let key_pem = key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .expect("encode CSR key to PKCS8 PEM");
    let key_pair = rcgen::KeyPair::from_pem(&key_pem).expect("load rcgen keypair from PEM");
    let mut params =
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    params.key_pair = Some(key_pair);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, sans[0]);
    let cert = rcgen::Certificate::from_params(params).expect("build CSR params");
    cert.serialize_request_der().expect("serialize CSR DER")
}

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

    /// Convert an http:// test URL back to https:// for use in JWS protected headers.
    /// vigil's extract_host_scheme always returns "https", so the JWS url field must match.
    fn jws_url(url: &str) -> String {
        if let Some(rest) = url.strip_prefix("http://") {
            format!("https://{}", rest)
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
        let body = self.jws_with_jwk(
            &nonce,
            &Self::jws_url(&url),
            json!({"contact": ["mailto:test@credo.test"]}),
        );
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
        let body = self.jws_with_kid(&nonce, &Self::jws_url(&url), payload);
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
        let body = self.jws_with_kid(&nonce, &Self::jws_url(&url), payload);
        self.http.post(&url).json(&body).send().await.unwrap()
    }

    async fn get_authz(&self, authz_url: &str) -> Value {
        let url = Self::norm(authz_url);
        let nonce = self.nonce().await;
        // authz_url is the https:// URL from vigil's response; use it as-is in the JWS.
        let jws_url = if authz_url.starts_with("https://") {
            authz_url.to_string()
        } else {
            Self::jws_url(&url)
        };
        let body = self.jws_with_kid(&nonce, &jws_url, json!({}));
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
        // challenge_url is the https:// URL from vigil's response; use it as-is in the JWS.
        let jws_url = if challenge_url.starts_with("https://") {
            challenge_url.to_string()
        } else {
            Self::jws_url(&url)
        };
        let body = self.jws_with_kid(&nonce, &jws_url, json!({}));
        self.http.post(&url).json(&body).send().await.unwrap()
    }

    async fn finalize(&self, finalize_url: &str, csr_der: &[u8]) -> Value {
        let url = Self::norm(finalize_url);
        let nonce = self.nonce().await;
        let jws_url = if finalize_url.starts_with("https://") {
            finalize_url.to_string()
        } else {
            Self::jws_url(&url)
        };
        let payload = json!({"csr": B64.encode(csr_der)});
        let body = self.jws_with_kid(&nonce, &jws_url, payload);
        let resp = self.http.post(&url).json(&body).send().await.unwrap();
        assert_eq!(resp.status(), 200, "finalize must return 200");
        resp.json().await.unwrap()
    }

    /// POST /acme/revoke-cert signed via the jwk (certificate-key) path, using
    /// this client's own key rather than an account kid.
    async fn revoke_via_jwk(&self, cert_id: &str) -> reqwest::Response {
        let url = format!("{}/acme/revoke-cert", self.base);
        let nonce = self.nonce().await;
        let body = self.jws_with_jwk(
            &nonce,
            &Self::jws_url(&url),
            json!({"certificateId": cert_id}),
        );
        self.http.post(&url).json(&body).send().await.unwrap()
    }

    /// Poll the authz URL every 50 ms until status is "valid" or "invalid", or timeout.
    /// POST the order's finalize URL with `csr_der` and return the raw response
    /// (status not asserted here — callers may expect a rejection).
    async fn finalize_raw(&self, finalize_url: &str, csr_der: &[u8]) -> reqwest::Response {
        let url = Self::norm(finalize_url);
        let nonce = self.nonce().await;
        let jws_url = if finalize_url.starts_with("https://") {
            finalize_url.to_string()
        } else {
            Self::jws_url(&url)
        };
        let payload = json!({"csr": B64.encode(csr_der)});
        let body = self.jws_with_kid(&nonce, &jws_url, payload);
        self.http.post(&url).json(&body).send().await.unwrap()
    }

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

/// finalize must reject a CSR that embeds a domain the order never validated.
/// Regression test for the fix to a High finding where `sign_csr` unioned the
/// CSR's own SANs with the order's validated identifiers instead of requiring
/// the CSR's SANs to be a subset of them, letting a client smuggle an
/// unchallenged domain into the issued certificate.
#[tokio::test]
async fn finalize_rejects_csr_san_outside_validated_order() {
    let vigil = TestVigil::start_authed().await.unwrap();
    let mut client = AcmeTestClient::new(&vigil.url);
    client.register().await;

    let validated_domain = "finalize-test.credo.test";
    let smuggled_domain = "unvalidated-finalize-test.credo.test";

    let order = client.new_order(validated_domain, Some("none-01")).await;
    let authz_url = order["authorizations"][0].as_str().unwrap();
    let authz = client.get_authz(authz_url).await;
    let (chall_url, _token) = AcmeTestClient::find_challenge(&authz, "http-01");
    let resp = client.respond_challenge(&chall_url).await;
    assert_eq!(
        resp.status(),
        200,
        "none-01 challenge response must return 200"
    );

    let finalize_url = order["finalize"].as_str().unwrap();

    // A CSR naming only the validated domain must still succeed.
    let clean_key = SigningKey::random(&mut OsRng);
    let clean_csr = build_csr_der(&[validated_domain], &clean_key);
    let resp = client.finalize_raw(finalize_url, &clean_csr).await;
    assert_eq!(
        resp.status(),
        200,
        "finalize with a CSR matching the validated order must succeed"
    );

    // A second order/CSR that also embeds a domain never subjected to any
    // challenge in this order must be rejected, not silently included.
    let order2 = client.new_order(validated_domain, Some("none-01")).await;
    let authz_url2 = order2["authorizations"][0].as_str().unwrap();
    let authz2 = client.get_authz(authz_url2).await;
    let (chall_url2, _token2) = AcmeTestClient::find_challenge(&authz2, "http-01");
    let resp = client.respond_challenge(&chall_url2).await;
    assert_eq!(resp.status(), 200);

    let finalize_url2 = order2["finalize"].as_str().unwrap();
    let smuggling_key = SigningKey::random(&mut OsRng);
    let smuggling_csr = build_csr_der(&[validated_domain, smuggled_domain], &smuggling_key);
    let resp = client.finalize_raw(finalize_url2, &smuggling_csr).await;
    assert_eq!(
        resp.status(),
        400,
        "finalize must reject a CSR containing a domain outside the validated order"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["type"].as_str().unwrap_or("").contains("badCSR"),
        "error type must be badCSR, got: {}",
        body["type"]
    );
}

/// RFC 8555 §7.6 proof-of-possession: revoke-cert's jwk (certificate-key) path must
/// require the JWK to be the certificate's own key, not just any valid keypair.
/// Regression test for the fix to a Critical finding where any mTLS-authenticated
/// ACME client could revoke any certificate in the fleet via a throwaway keypair.
#[tokio::test]
async fn revoke_cert_via_jwk_requires_matching_key() {
    let vigil = TestVigil::start_authed().await.unwrap();
    let mut client = AcmeTestClient::new(&vigil.url);
    client.register().await;

    // Issue a certificate for a domain. The CSR is signed by `cert_key`, which is
    // the certificate's own keypair — distinct from `client`'s ACME account key.
    let domain = "revoke-test.credo.test";
    let cert_key = SigningKey::random(&mut OsRng);
    let order = client.new_order(domain, Some("none-01")).await;
    let authz_url = order["authorizations"][0].as_str().unwrap();
    let authz = client.get_authz(authz_url).await;
    let (chall_url, _token) = AcmeTestClient::find_challenge(&authz, "http-01");
    let resp = client.respond_challenge(&chall_url).await;
    assert_eq!(
        resp.status(),
        200,
        "none-01 challenge response must return 200"
    );

    let finalize_url = order["finalize"].as_str().unwrap();
    let csr_der = build_csr_der(&[domain], &cert_key);
    let finalized = client.finalize(finalize_url, &csr_der).await;
    assert_eq!(
        finalized["status"].as_str(),
        Some("valid"),
        "order must be valid immediately after finalize"
    );
    let cert_id = finalized["certificate"]
        .as_str()
        .expect("finalize response must include a certificate URL")
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    // An attacker holding an unrelated keypair (never registered as an account,
    // never involved in issuing this cert) must NOT be able to revoke it via the
    // jwk path just by signing a request with their own throwaway key.
    let mut attacker = AcmeTestClient::new(&vigil.url);
    attacker.key = SigningKey::random(&mut OsRng);
    let resp = attacker.revoke_via_jwk(&cert_id).await;
    assert_eq!(
        resp.status(),
        403,
        "revoke-cert via jwk with a non-matching key must be rejected"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["type"].as_str().unwrap_or("").contains("unauthorized"),
        "error type must be unauthorized, got: {}",
        body["type"]
    );

    // The actual holder of the certificate's private key CAN revoke it via the
    // jwk path, with no account kid at all — this is the legitimate use of §7.6.
    let mut owner = AcmeTestClient::new(&vigil.url);
    owner.key = cert_key;
    let resp = owner.revoke_via_jwk(&cert_id).await;
    assert_eq!(
        resp.status(),
        200,
        "revoke-cert via jwk with the matching certificate key must succeed"
    );
}
