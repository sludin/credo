/// Phase 2 bootstrap tests.
///
/// Vigil bootstrap: the one-shot POST /bootstrap endpoint that Shepherd calls
/// to get its identity cert signed during the 5-step ceremony.
///
/// Corgi bootstrap: the ephemeral server that Shepherd calls to enroll a Corgi
/// node (GET /bootstrap/csr, POST /bootstrap/ca, POST /bootstrap/cert,
/// POST /bootstrap/finalize).
use credo_test::{
    cert_gen,
    corgi_harness::{TestCorgiBootstrap, CORGI_COMMON_NAME},
    vigil_harness::TestVigil,
};
use serde_json::Value;

// ============================================================================
// Vigil bootstrap tests
// ============================================================================

/// POST /bootstrap returns 404 when vigil started without a bootstrap secret.
#[tokio::test]
async fn vigil_bootstrap_endpoint_inactive_by_default() {
    let vigil = TestVigil::start().await.unwrap();
    let (csr_pem, _) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let resp = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({
            "secret": "deadbeefdeadbeef",
            "csr": csr_pem,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "bootstrap endpoint should be inactive without a secret"
    );
}

/// POST /bootstrap with the correct secret signs the CSR and returns cert+chain.
#[tokio::test]
async fn vigil_bootstrap_success() {
    let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let resp = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({
            "secret": secret,
            "csr": csr_pem,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "correct secret should succeed");

    let body: Value = resp.json().await.unwrap();
    let cert = body["cert"].as_str().expect("cert field must be present");
    let chain = body["chain"].as_str().expect("chain field must be present");

    assert!(cert.contains("BEGIN CERTIFICATE"), "cert must be PEM");
    assert!(chain.contains("BEGIN CERTIFICATE"), "chain must be PEM");
}

/// POST /bootstrap with a wrong secret returns 403 and does not close the endpoint.
#[tokio::test]
async fn vigil_bootstrap_wrong_secret_returns_403() {
    let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let resp = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({
            "secret": "0000000000000000000000000000000000000000000000000000000000000000",
            "csr": csr_pem,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403, "wrong secret must return 403");
}

/// After a wrong-secret rejection the endpoint stays open and accepts the correct secret.
#[tokio::test]
async fn vigil_bootstrap_wrong_secret_stays_open() {
    let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    // Wrong secret — should not close the endpoint
    let r1 = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": "wrong", "csr": csr_pem }))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 403);

    // Correct secret — should still work
    let r2 = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": secret, "csr": csr_pem }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        200,
        "correct secret must still work after wrong-secret attempt"
    );
}

/// POST /bootstrap closes the endpoint after one successful call.
/// A second call (with the same correct secret) must return 404.
#[tokio::test]
async fn vigil_bootstrap_endpoint_closes_after_success() {
    let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let body = serde_json::json!({ "secret": secret, "csr": csr_pem });

    let r1 = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200, "first call must succeed");

    let r2 = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        404,
        "second call must get 404 — endpoint closed"
    );
}

/// POST /bootstrap with a CSR that violates issuance policy returns 400.
/// Test config allows only .credo.test DNS names; this CSR uses .evil.com.
#[tokio::test]
async fn vigil_bootstrap_policy_violation_returns_400() {
    let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _) =
        cert_gen::make_csr("attacker.evil.com", &["attacker.evil.com"], &[]).unwrap();

    let resp = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": secret, "csr": csr_pem }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "policy-violating CSR must return 400");
}

/// The cert returned by /bootstrap is signed by the test intermediate CA.
#[tokio::test]
async fn vigil_bootstrap_cert_is_signed_by_test_ca() {
    let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let resp = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": secret, "csr": csr_pem }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let cert_pem = body["cert"].as_str().unwrap();

    // Parse the leaf cert and check the issuer matches the test intermediate CA subject.
    let der = pem_to_der(cert_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let issuer = cert.issuer().to_string();
    assert!(
        issuer.contains("Credo Test Intermediate CA"),
        "issued cert must have test intermediate CA as issuer, got: {issuer}"
    );
}

// ============================================================================
// Corgi bootstrap tests
// ============================================================================

/// GET /bootstrap/status returns node info without requiring a token.
#[tokio::test]
async fn corgi_bootstrap_status_no_token_required() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let resp = bs.client.get(bs.status_url()).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["mode"].as_str(), Some("bootstrap"));
    assert!(body["nodeId"].is_string(), "nodeId must be present");
    assert!(body["commonName"].is_string(), "commonName must be present");
}

/// GET /bootstrap/csr without an Authorization header returns 401.
#[tokio::test]
async fn corgi_bootstrap_csr_requires_token() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let resp = bs.client.get(bs.csr_url()).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

/// GET /bootstrap/csr with a wrong token returns 401.
#[tokio::test]
async fn corgi_bootstrap_csr_bad_token() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let resp = bs
        .client
        .get(bs.csr_url())
        .header("Authorization", "Bearer wrongtoken")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// GET /bootstrap/csr with the correct token generates and returns a CSR.
#[tokio::test]
async fn corgi_bootstrap_csr_success() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let resp = bs
        .client
        .get(bs.csr_url())
        .header("Authorization", bs.auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    let csr = body["csrPem"].as_str().expect("csrPem must be present");
    assert!(
        csr.contains("CERTIFICATE REQUEST"),
        "response must contain a CSR PEM"
    );
}

/// POST /bootstrap/ca without a token returns 401.
#[tokio::test]
async fn corgi_bootstrap_ca_requires_token() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let catrust = std::fs::read_to_string(credo_test::fixtures::catrust_pem()).unwrap();
    let resp = bs
        .client
        .post(bs.ca_url())
        .json(&serde_json::json!({ "caPem": catrust }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// POST /bootstrap/ca with a valid caPem installs the CA and returns installed:true.
#[tokio::test]
async fn corgi_bootstrap_ca_installs_ca() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let catrust = std::fs::read_to_string(credo_test::fixtures::catrust_pem()).unwrap();
    let resp = bs
        .client
        .post(bs.ca_url())
        .header("Authorization", bs.auth_header())
        .json(&serde_json::json!({ "caPem": catrust }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["installed"].as_bool(), Some(true));

    // Verify the CA file was actually written to the config's mtls.ca_path
    let ca_path = bs.dir.path().join("mtls-ca.pem");
    assert!(ca_path.exists(), "CA file must exist after bootstrap/ca");
}

/// POST /bootstrap/cert before /bootstrap/csr (no key on disk) returns 400.
#[tokio::test]
async fn corgi_bootstrap_cert_without_csr_first_returns_400() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let (cert_pem, _, _) = cert_gen::generate_signed_cert(
        "corgi-01.credo.test",
        &["corgi-01.credo.test"],
        &["vigil://credo/node/corgi-01"],
        1,
        bs.dir.path(),
    )
    .unwrap();

    let resp = bs
        .client
        .post(bs.cert_url())
        .header("Authorization", bs.auth_header())
        .json(&serde_json::json!({ "certPem": cert_pem }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "cert install without prior CSR/key must fail"
    );
}

/// POST /bootstrap/finalize without a token returns 401.
#[tokio::test]
async fn corgi_bootstrap_finalize_requires_token() {
    let bs = TestCorgiBootstrap::start().await.unwrap();

    let resp = bs.client.post(bs.finalize_url()).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

/// POST /bootstrap/finalize with the correct token returns done:true.
#[tokio::test]
async fn corgi_bootstrap_finalize_returns_done() {
    let mut bs = TestCorgiBootstrap::start().await.unwrap();

    let resp = bs
        .client
        .post(bs.finalize_url())
        .header("Authorization", bs.auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["done"].as_bool(), Some(true));

    // The done channel should have fired
    assert!(
        bs.wait_for_finalize().await,
        "done channel must fire after finalize"
    );
}

/// Full corgi bootstrap sequence: csr → ca → cert → finalize.
/// Exercises all four handlers in the correct order, verifies each step,
/// and asserts the production-like certstore structure afterward.
#[tokio::test]
async fn corgi_bootstrap_full_sequence() {
    let mut bs = TestCorgiBootstrap::start().await.unwrap();
    let tmp = bs.dir.path().to_path_buf();

    // Step 1: GET /bootstrap/csr — generates key on disk, returns CSR PEM
    let csr_resp: Value = bs
        .client
        .get(bs.csr_url())
        .header("Authorization", bs.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csr_pem = csr_resp["csrPem"].as_str().expect("csrPem present");

    // Sign the CSR with the test intermediate CA (direct call, no vigil server needed)
    let signed = cert_gen::sign_csr_with_test_ca(csr_pem, 1, &tmp).unwrap();

    // Step 2: POST /bootstrap/ca — install the trust bundle
    let catrust = std::fs::read_to_string(credo_test::fixtures::catrust_pem()).unwrap();
    let ca_resp: Value = bs
        .client
        .post(bs.ca_url())
        .header("Authorization", bs.auth_header())
        .json(&serde_json::json!({ "caPem": catrust }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ca_resp["installed"].as_bool(),
        Some(true),
        "CA install must succeed"
    );

    // Step 3: POST /bootstrap/cert — install the signed certificate with all three fields
    let cert_resp = bs
        .client
        .post(bs.cert_url())
        .header("Authorization", bs.auth_header())
        .json(&serde_json::json!({
            "certPem":      signed.cert_pem,
            "chainPem":     signed.chain_pem,
            "fullchainPem": signed.fullchain_pem,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(cert_resp.status(), 200, "cert install must succeed");

    let cert_body: Value = cert_resp.json().await.unwrap();
    assert_eq!(cert_body["installed"].as_bool(), Some(true));
    assert!(
        cert_body["fingerprint256"].is_string(),
        "fingerprint256 must be returned"
    );

    // Step 4: POST /bootstrap/finalize — signal enrollment complete
    let fin_resp: Value = bs
        .client
        .post(bs.finalize_url())
        .header("Authorization", bs.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fin_resp["done"].as_bool(), Some(true));

    assert!(bs.wait_for_finalize().await, "done channel must fire");

    // === Certstore structure assertions ===
    // Archive and live directories use the node's common name, not "node-identity".
    // certstore/archive/<common_name>/cert-001.pem      (regular file)
    // certstore/archive/<common_name>/chain-001.pem
    // certstore/archive/<common_name>/fullchain-001.pem
    // certstore/archive/<common_name>/privkey-001.pem
    // certstore/live/<common_name>/cert.pem             (symlink → archive)
    // certstore/live/<common_name>/chain.pem            (symlink → archive)
    // certstore/live/<common_name>/fullchain.pem        (symlink → archive)
    // certstore/live/<common_name>/privkey.pem          (symlink → archive)
    let certstore = tmp.join("certstore");
    let archive = certstore.join("archive").join(CORGI_COMMON_NAME);
    let live = certstore.join("live").join(CORGI_COMMON_NAME);

    assert!(
        archive.join("cert-001.pem").is_file(),
        "cert archive must exist as regular file"
    );
    assert!(
        archive.join("chain-001.pem").is_file(),
        "chain archive must exist as regular file"
    );
    assert!(
        archive.join("fullchain-001.pem").is_file(),
        "fullchain archive must exist as regular file"
    );
    assert!(
        archive.join("privkey-001.pem").is_file(),
        "key archive must exist as regular file"
    );

    assert!(
        live.join("cert.pem").is_symlink(),
        "live/cert.pem must be a symlink"
    );
    assert!(
        live.join("chain.pem").is_symlink(),
        "live/chain.pem must be a symlink"
    );
    assert!(
        live.join("fullchain.pem").is_symlink(),
        "live/fullchain.pem must be a symlink"
    );
    assert!(
        live.join("privkey.pem").is_symlink(),
        "live/privkey.pem must be a symlink"
    );

    // The live cert symlink must resolve to a valid PEM certificate signed by the test CA.
    let live_cert_pem = std::fs::read_to_string(live.join("cert.pem"))
        .expect("live/cert.pem must be readable through symlink");
    assert!(
        live_cert_pem.contains("BEGIN CERTIFICATE"),
        "live cert must be valid PEM"
    );

    let issuer = cert_issuer(&live_cert_pem);
    assert!(
        issuer.contains("Credo Test Intermediate CA"),
        "live cert must be signed by test intermediate CA, got: {issuer}"
    );
}

// ============================================================================
// Shepherd bootstrap tests
// ============================================================================

/// Shepherd enrolls itself via vigil's one-shot bootstrap endpoint.
/// This mirrors `cmd_bootstrap_server_start` in shepherd/src/main.rs.
#[tokio::test]
async fn shepherd_gets_cert_from_vigil_bootstrap() {
    let secret = "ccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb";
    let vigil = TestVigil::start_with_bootstrap(secret).await.unwrap();

    let (csr_pem, _key_pem) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let resp = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": secret, "csr": csr_pem }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "shepherd must get cert from vigil bootstrap"
    );

    let body: Value = resp.json().await.unwrap();
    let cert_pem = body["cert"].as_str().expect("cert field present");
    let chain_pem = body["chain"].as_str().expect("chain field present");

    assert!(
        cert_pem.contains("BEGIN CERTIFICATE"),
        "cert must be valid PEM"
    );
    assert!(
        chain_pem.contains("BEGIN CERTIFICATE"),
        "chain must be valid PEM"
    );

    // Cert must be signed by the test intermediate CA
    let issuer = cert_issuer(cert_pem);
    assert!(
        issuer.contains("Credo Test Intermediate CA"),
        "shepherd cert must be signed by test CA, got: {issuer}"
    );

    // Cert must carry the shepherd identity URI SAN
    assert!(
        cert_has_uri_san(cert_pem, "vigil://credo/service/shepherd"),
        "shepherd cert must have identity URI SAN vigil://credo/service/shepherd"
    );

    // Vigil bootstrap closes after one successful use
    let closed = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": secret, "csr": csr_pem }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        closed.status(),
        404,
        "vigil bootstrap must be closed after shepherd enrolled"
    );
}

/// Full 5-step bootstrap ceremony: vigil → shepherd → corgi.
///
/// Mirrors the production bootstrap wizard exactly:
///   - All three services' certs live in ONE shared certstore (corgi's store).
///   - Shepherd writes its cert directly to `certstore/live/shepherd.credo.test/`
///     (a flat file write, same as cmd_bootstrap_server_start in shepherd/src/main.rs).
///   - Corgi's bootstrap cert goes to `certstore/live/<common_name>/` via install_to_archive.
///   - vigil.credo.test/ does NOT appear here — it requires assignment sync (Phase 5).
///
/// After this test, with CREDO_TEST_KEEP_OUTPUT=1, you should see:
///   certstore/
///     archive/<common_name>/cert-001.pem  chain-001.pem  fullchain-001.pem  privkey-001.pem
///     live/
///       <common_name>/    cert.pem(→)  chain.pem(→)  fullchain.pem(→)  privkey.pem(→)   [corgi, symlinks]
///       shepherd.credo.test/  fullchain.pem  privkey.pem                                  [shepherd, regular files]
#[tokio::test]
async fn full_stack_bootstrap_ceremony() {
    // Shared certstore for all services — mirrors corgiRoot/store in production.
    // Using make_test_dir so CREDO_TEST_KEEP_OUTPUT=1 persists it for inspection.
    let certstore_dir = credo_test::test_dir::make_test_dir("certstore").unwrap();
    let certstore = certstore_dir.path().to_path_buf();
    std::fs::create_dir_all(&certstore).unwrap();

    let vigil_secret = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";
    let vigil = TestVigil::start_with_bootstrap(vigil_secret).await.unwrap();

    // === Phase 1: Shepherd enrolls — gets its identity cert from vigil ===
    // Mirrors cmd_bootstrap_server_start in shepherd/src/main.rs:
    //   generate key+CSR → POST /bootstrap → write cert+key to tls.certPath / tls.keyPath
    let (shepherd_csr, shepherd_key) = cert_gen::make_csr(
        "shepherd.credo.test",
        &["shepherd.credo.test"],
        &["vigil://credo/service/shepherd"],
    )
    .unwrap();

    let shepherd_resp: Value = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": vigil_secret, "csr": shepherd_csr }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let shepherd_cert = shepherd_resp["cert"].as_str().expect("shepherd cert field");
    let shepherd_chain = shepherd_resp["chain"].as_str().unwrap_or("");
    let shepherd_fullchain = format!("{}{}", shepherd_cert, shepherd_chain);

    assert!(
        shepherd_cert.contains("BEGIN CERTIFICATE"),
        "shepherd cert must be PEM"
    );
    assert!(
        cert_has_uri_san(shepherd_cert, "vigil://credo/service/shepherd"),
        "shepherd cert must carry its identity URI SAN"
    );

    // Write shepherd's cert to the shared certstore — same flat-write that
    // cmd_bootstrap_server_start does when config.tls.cert_path = corgiStore/shepherd.hostname/...
    let shepherd_live = certstore.join("live/shepherd.credo.test");
    std::fs::create_dir_all(&shepherd_live).unwrap();
    std::fs::write(shepherd_live.join("fullchain.pem"), &shepherd_fullchain).unwrap();
    std::fs::write(shepherd_live.join("privkey.pem"), &shepherd_key).unwrap();

    // Vigil bootstrap is now closed (one-shot).
    let closed_check = vigil
        .client
        .post(vigil.bootstrap_url())
        .json(&serde_json::json!({ "secret": vigil_secret, "csr": shepherd_csr }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        closed_check.status(),
        404,
        "vigil bootstrap must close after shepherd enrolled"
    );

    // === Phase 2: Corgi starts in bootstrap mode using the shared certstore ===
    let mut corgi = TestCorgiBootstrap::start_with_cert_store(certstore.clone())
        .await
        .unwrap();
    let signing_tmp = corgi.dir.path().to_path_buf();

    // === Phase 3: Shepherd coordinates corgi enrollment ===

    // 3a: Fetch corgi's CSR
    let csr_body: Value = corgi
        .client
        .get(corgi.csr_url())
        .header("Authorization", corgi.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let corgi_csr = csr_body["csrPem"].as_str().expect("csrPem");

    // 3b: Sign CSR (shepherd calls vigil's /certificates/sign in production;
    //     in tests we call the same underlying vigil::ca::sign_csr directly)
    let signed = cert_gen::sign_csr_with_test_ca(corgi_csr, 1, &signing_tmp).unwrap();

    // 3c: Push trust bundle to corgi
    let catrust = std::fs::read_to_string(credo_test::fixtures::catrust_pem()).unwrap();
    let ca_resp: Value = corgi
        .client
        .post(corgi.ca_url())
        .header("Authorization", corgi.auth_header())
        .json(&serde_json::json!({ "caPem": catrust }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ca_resp["installed"].as_bool(),
        Some(true),
        "CA install must succeed"
    );

    // 3d: Install signed cert on corgi — send cert, chain, and fullchain separately
    let cert_resp: Value = corgi
        .client
        .post(corgi.cert_url())
        .header("Authorization", corgi.auth_header())
        .json(&serde_json::json!({
            "certPem":      signed.cert_pem,
            "chainPem":     signed.chain_pem,
            "fullchainPem": signed.fullchain_pem,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cert_resp["installed"].as_bool(),
        Some(true),
        "corgi cert install must succeed"
    );

    // 3e: Finalize
    let fin: Value = corgi
        .client
        .post(corgi.finalize_url())
        .header("Authorization", corgi.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fin["done"].as_bool(), Some(true));
    assert!(corgi.wait_for_finalize().await, "done channel must fire");

    // === Verify shared certstore — production bootstrap state ===

    // Shepherd's entry: regular files (direct write by cmd_bootstrap_server_start)
    assert!(
        shepherd_live.join("fullchain.pem").is_file(),
        "shepherd fullchain must be a regular file (direct write)"
    );
    assert!(
        shepherd_live.join("privkey.pem").is_file(),
        "shepherd privkey must be a regular file (direct write)"
    );

    let shepherd_cert_on_disk =
        std::fs::read_to_string(shepherd_live.join("fullchain.pem")).unwrap();
    assert!(
        cert_issuer(&shepherd_cert_on_disk).contains("Credo Test Intermediate CA"),
        "shepherd cert must be signed by test CA"
    );

    // Corgi's entry: archive + live symlinks, all in the common_name directory (not "node-identity")
    let archive = certstore.join("archive").join(CORGI_COMMON_NAME);
    let live = certstore.join("live").join(CORGI_COMMON_NAME);

    assert!(
        archive.join("cert-001.pem").is_file(),
        "corgi cert archive must exist"
    );
    assert!(
        archive.join("chain-001.pem").is_file(),
        "corgi chain archive must exist"
    );
    assert!(
        archive.join("fullchain-001.pem").is_file(),
        "corgi fullchain archive must exist"
    );
    assert!(
        archive.join("privkey-001.pem").is_file(),
        "corgi key archive must exist"
    );

    assert!(
        live.join("cert.pem").is_symlink(),
        "live/cert.pem must be a symlink"
    );
    assert!(
        live.join("chain.pem").is_symlink(),
        "live/chain.pem must be a symlink"
    );
    assert!(
        live.join("fullchain.pem").is_symlink(),
        "live/fullchain.pem must be a symlink"
    );
    assert!(
        live.join("privkey.pem").is_symlink(),
        "live/privkey.pem must be a symlink"
    );

    let corgi_live_cert = std::fs::read_to_string(live.join("cert.pem")).unwrap();
    let issuer = cert_issuer(&corgi_live_cert);
    assert!(
        issuer.contains("Credo Test Intermediate CA"),
        "corgi cert must be signed by test CA, got: {issuer}"
    );
    assert!(
        cert_has_uri_san(&corgi_live_cert, "vigil://credo/node/corgi-01"),
        "corgi cert must carry node identity URI SAN"
    );

    // vigil.credo.test/ intentionally absent — it appears only after assignment sync (Phase 5).
    assert!(
        !certstore.join("live/vigil.credo.test").exists(),
        "vigil cert must not exist yet — appears only after assignment sync"
    );
}

// ============================================================================
// Regression tests for specific bugs
// ============================================================================

/// Bug: bootstrap cert was installed under `live/node-identity/` instead of
/// `live/<common_name>/`. After the fix, cert.pem must appear in the same
/// directory as fullchain.pem and privkey.pem, all named after the common name.
#[tokio::test]
async fn bootstrap_cert_live_dir_uses_common_name_not_node_identity() {
    let bs = TestCorgiBootstrap::start().await.unwrap();
    let certstore = bs.dir.path().join("certstore");

    // Generate key + CSR
    let csr_resp: Value = bs
        .client
        .get(bs.csr_url())
        .header("Authorization", bs.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csr_pem = csr_resp["csrPem"].as_str().unwrap();

    let signed = cert_gen::sign_csr_with_test_ca(csr_pem, 1, bs.dir.path()).unwrap();

    bs.client
        .post(bs.cert_url())
        .header("Authorization", bs.auth_header())
        .json(&serde_json::json!({
            "certPem":      signed.cert_pem,
            "chainPem":     signed.chain_pem,
            "fullchainPem": signed.fullchain_pem,
        }))
        .send()
        .await
        .unwrap();

    let live_common = certstore.join("live").join(CORGI_COMMON_NAME);
    let live_node_id = certstore.join("live/node-identity");

    // The correct directory must contain all three live symlinks
    assert!(
        live_common.join("cert.pem").exists(),
        "cert.pem must be in live/<common_name>/, not node-identity/"
    );
    assert!(
        live_common.join("fullchain.pem").exists(),
        "fullchain.pem must be in live/<common_name>/"
    );
    assert!(
        live_common.join("privkey.pem").exists(),
        "privkey.pem must be in live/<common_name>/"
    );

    // The old node-identity directory must not be created
    assert!(
        !live_node_id.exists(),
        "live/node-identity/ must not be created — archive uses common_name"
    );
}

/// Bug: when chainPem was omitted from the bootstrap cert request, no chain.pem
/// was written to archive or live. After the fix, a complete POST /bootstrap/cert
/// request (cert + chain + fullchain) produces all four archive files and four
/// live symlinks including chain.pem.
#[tokio::test]
async fn bootstrap_cert_creates_chain_archive_and_symlink() {
    let bs = TestCorgiBootstrap::start().await.unwrap();
    let certstore = bs.dir.path().join("certstore");

    let csr_resp: Value = bs
        .client
        .get(bs.csr_url())
        .header("Authorization", bs.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csr_pem = csr_resp["csrPem"].as_str().unwrap();

    let signed = cert_gen::sign_csr_with_test_ca(csr_pem, 1, bs.dir.path()).unwrap();
    assert!(
        !signed.chain_pem.is_empty(),
        "test CA must produce a non-empty chain"
    );

    let resp: Value = bs
        .client
        .post(bs.cert_url())
        .header("Authorization", bs.auth_header())
        .json(&serde_json::json!({
            "certPem":      signed.cert_pem,
            "chainPem":     signed.chain_pem,
            "fullchainPem": signed.fullchain_pem,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["installed"].as_bool(), Some(true));

    let archive = certstore.join("archive").join(CORGI_COMMON_NAME);
    let live = certstore.join("live").join(CORGI_COMMON_NAME);

    assert!(
        archive.join("chain-001.pem").is_file(),
        "chain-001.pem must exist in archive when chainPem is provided"
    );
    assert!(
        live.join("chain.pem").is_symlink(),
        "live/chain.pem must be a symlink into the archive"
    );

    // Symlink must resolve and contain valid PEM
    let chain_content = std::fs::read_to_string(live.join("chain.pem"))
        .expect("live/chain.pem must be readable through symlink");
    assert!(
        chain_content.contains("BEGIN CERTIFICATE"),
        "chain.pem must contain at least one PEM certificate"
    );
}

/// Bug: when a local cert existed but Shepherd had no fingerprint, the sync loop
/// unconditionally skipped renewal — even for bootstrap temp certs expiring in 1 day.
/// After the fix, a cert expiring in < 30 days is detected as near-expiry.
#[test]
fn cert_days_remaining_flags_near_expiry_bootstrap_cert() {
    use corgi::cert_ops::cert_days_remaining;
    use rcgen::{Certificate, CertificateParams, SanType};
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let cert_path = dir.path().join("temp.pem");

    // Build a 1-day cert — same validity as a bootstrap temp cert
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName("bootstrap.credo.test".to_string())];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(1);
    let cert = Certificate::from_params(params).unwrap();
    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();

    let days = cert_days_remaining(&cert_path).expect("must read 1-day cert");
    assert!(
        days < 30,
        "1-day cert must be flagged as near-expiry (got {days} days remaining)"
    );
    assert!(days >= 0, "cert must not be reported as already expired");

    // Also verify a long-lived cert is not flagged
    let long_path = dir.path().join("long.pem");
    let mut params2 = CertificateParams::default();
    params2.subject_alt_names = vec![SanType::DnsName("long.credo.test".to_string())];
    params2.not_before = now;
    params2.not_after = now + time::Duration::days(365);
    let cert2 = Certificate::from_params(params2).unwrap();
    std::fs::write(&long_path, cert2.serialize_pem().unwrap()).unwrap();

    let long_days = cert_days_remaining(&long_path).expect("must read 365-day cert");
    assert!(
        long_days >= 30,
        "365-day cert must not be flagged as near-expiry (got {long_days} days remaining)"
    );
}

// ============================================================================
// Helpers
// ============================================================================

fn pem_to_der(pem: &str) -> Vec<u8> {
    pem::parse(pem).expect("valid PEM").into_contents()
}

fn cert_issuer(cert_pem: &str) -> String {
    let der = pem_to_der(cert_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    cert.issuer().to_string()
}

fn cert_has_uri_san(cert_pem: &str, expected_uri: &str) -> bool {
    use x509_parser::extensions::GeneralName;
    let der = pem_to_der(cert_pem);
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) else {
        return false;
    };
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .any(|n| matches!(n, GeneralName::URI(u) if *u == expected_uri))
        })
        .unwrap_or(false)
}
