/// ACME protocol endpoints (RFC 8555).
///
/// Supports: directory, new-nonce, new-account, account, new-order, order,
/// authz, challenge, finalize, cert, revoke-cert, key-change (stub).
///
/// Validation method: none-01 (internal, auto-valid), http-01, dns-01.
/// JWS algorithm: RS256, RS384, RS512 (RSA) and ES256 (EC P-256).
///
/// TODO(resilience): orders/authzs/challenges/nonces are in-memory only.
/// See docs/vigil-rs-port-plan.md for the SQLite persistence plan.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::ca::sign_csr;
use crate::error::acme_error_body;
use crate::issuance_policy::validate_issuance_policy;
use crate::state::AppState;
use crate::storage;
use crate::types::{
    AcmeAccountRecord, AcmeAuthz, AcmeChallenge, AcmeIdentifier, AcmeOrder, AcmeRsaJwk,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn acme_error(status: StatusCode, type_slug: &str, detail: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/problem+json".parse().unwrap());
    (status, headers, Json(acme_error_body(type_slug, detail))).into_response()
}

fn random_token() -> String {
    let bytes: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    B64.encode(&bytes)
}

fn new_nonce_value() -> String {
    let bytes: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    B64.encode(&bytes)
}

fn base36(n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let chars: Vec<char> = "0123456789abcdefghijklmnopqrstuvwxyz".chars().collect();
    let mut result = Vec::new();
    let mut val = n;
    while val > 0 {
        result.push(chars[(val % 36) as usize]);
        val /= 36;
    }
    result.iter().rev().collect()
}

fn account_counter_from_id(id: &str) -> u64 {
    id.strip_prefix("acct-")
        .and_then(|s| u64::from_str_radix(s, 36).ok())
        .unwrap_or(0)
}

fn base_url(host: &str, scheme: &str) -> String {
    format!("{}://{}", scheme, host)
}

fn absolute(host: &str, scheme: &str, path: &str) -> String {
    format!("{}{}", base_url(host, scheme), path)
}

fn extract_host_scheme(headers: &HeaderMap) -> (&'static str, String) {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    ("https", host)
}

// ---------------------------------------------------------------------------
// JWS validation
// ---------------------------------------------------------------------------

struct JwsBody {
    protected_b64: String,
    payload_b64: String,
    signature_b64: String,
}

struct JwsContext {
    protected_header: Value,
    payload: Value,
    account_id: Option<String>,
    account: Option<AcmeAccountRecord>,
    jwk: Option<AcmeRsaJwk>,
    jwk_thumbprint: Option<String>,
}

fn parse_jws_body(body: &Value) -> Option<JwsBody> {
    Some(JwsBody {
        protected_b64: body.get("protected")?.as_str()?.to_string(),
        payload_b64: body.get("payload")?.as_str()?.to_string(),
        signature_b64: body.get("signature")?.as_str()?.to_string(),
    })
}

fn rsa_jwk_thumbprint(jwk: &AcmeRsaJwk) -> String {
    let canonical = format!(r#"{{"e":"{}","kty":"{}","n":"{}"}}"#, jwk.e, jwk.kty, jwk.n);
    use sha2::{Digest, Sha256};
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

fn ec_jwk_thumbprint(jwk: &AcmeRsaJwk) -> String {
    // RFC 7638 canonical form: lexicographically sorted keys
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    use sha2::{Digest, Sha256};
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

fn jwk_thumbprint(jwk: &AcmeRsaJwk) -> String {
    if jwk.kty == "EC" {
        ec_jwk_thumbprint(jwk)
    } else {
        rsa_jwk_thumbprint(jwk)
    }
}

fn verify_ec_jws(protected_b64: &str, payload_b64: &str, sig_b64: &str, jwk: &AcmeRsaJwk) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{EncodedPoint, PublicKey};

    let x_bytes = match B64.decode(&jwk.x) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let y_bytes = match B64.decode(&jwk.y) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match B64.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let point = EncodedPoint::from_affine_coordinates(
        generic_array_from_slice(&x_bytes),
        generic_array_from_slice(&y_bytes),
        false,
    );
    let pk = match PublicKey::from_encoded_point(&point).into_option() {
        Some(k) => k,
        None => return false,
    };
    let vk = VerifyingKey::from(&pk);
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let msg = format!("{}.{}", protected_b64, payload_b64);
    vk.verify(msg.as_bytes(), &sig).is_ok()
}

#[allow(deprecated)]
fn generic_array_from_slice(bytes: &[u8]) -> &p256::FieldBytes {
    p256::FieldBytes::from_slice(bytes)
}

fn verify_rsa_jws(
    protected_b64: &str,
    payload_b64: &str,
    sig_b64: &str,
    jwk: &AcmeRsaJwk,
    alg: &str,
) -> bool {
    use rsa::signature::Verifier;
    use rsa::BigUint;

    let n_bytes = match B64.decode(&jwk.n) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let e_bytes = match B64.decode(&jwk.e) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match B64.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let msg = format!("{}.{}", protected_b64, payload_b64);

    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);
    let pub_key = match rsa::RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };

    match alg {
        "RS256" => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pub_key);
            let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(msg.as_bytes(), &sig).is_ok()
        }
        "RS384" => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(pub_key);
            let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(msg.as_bytes(), &sig).is_ok()
        }
        "RS512" => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(pub_key);
            let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(msg.as_bytes(), &sig).is_ok()
        }
        _ => false,
    }
}

async fn validate_jws(
    state: &AppState,
    _headers: &HeaderMap, // TODO: needed for RFC 8555 §6.4 url validation
    body: &Value,
    require_kid: bool,
    require_jwk: bool,
    auth_user_id: Option<&str>,
) -> Result<JwsContext, Response> {
    let jws = parse_jws_body(body).ok_or_else(|| {
        acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "request body must be JWS with protected/payload/signature",
        )
    })?;

    let protected_json = B64
        .decode(&jws.protected_b64)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .ok_or_else(|| {
            acme_error(
                StatusCode::BAD_REQUEST,
                "malformed",
                "invalid protected header",
            )
        })?;

    // Consume nonce
    let nonce = protected_json
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    {
        let mut nonces = state.inner.nonces.lock().await;
        if nonce.is_empty() || !nonces.remove(&nonce) {
            let mut headers_out = HeaderMap::new();
            let new_nonce = new_nonce_value();
            nonces.insert(new_nonce.clone());
            headers_out.insert("Replay-Nonce", new_nonce.parse().unwrap());
            return Err((
                StatusCode::BAD_REQUEST,
                headers_out,
                Json(acme_error_body(
                    "badNonce",
                    "missing or invalid replay nonce",
                )),
            )
                .into_response());
        }
    }

    // TODO: validate JWS url matches request URL (RFC 8555 §6.4)
    // The protected.url field must exactly match the request URL being processed.
    // This requires plumbing the actual request URI through to validate_jws().

    let alg = protected_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if alg.is_empty() {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "protected alg is required",
        ));
    }

    let has_kid = protected_json
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let has_jwk = protected_json.get("jwk").is_some();

    if !has_kid && !has_jwk {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "protected header must include kid or jwk",
        ));
    }
    if has_kid && has_jwk {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "protected header must contain either kid or jwk, not both",
        ));
    }
    if require_kid && !has_kid {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "protected kid is required",
        ));
    }
    if require_jwk && !has_jwk {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "protected jwk is required",
        ));
    }

    let payload: Value = if jws.payload_b64.is_empty() {
        json!({})
    } else {
        B64.decode(&jws.payload_b64)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .ok_or_else(|| {
                acme_error(StatusCode::BAD_REQUEST, "malformed", "invalid JWS payload")
            })?
    };

    if has_jwk {
        let jwk_val = &protected_json["jwk"];
        let kty = jwk_val.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let jwk = AcmeRsaJwk {
            kty: kty.to_string(),
            n: jwk_val
                .get("n")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            e: jwk_val
                .get("e")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            crv: jwk_val
                .get("crv")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            x: jwk_val
                .get("x")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            y: jwk_val
                .get("y")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        };
        let valid = match kty {
            "RSA" => {
                if jwk.n.is_empty() || jwk.e.is_empty() {
                    return Err(acme_error(
                        StatusCode::BAD_REQUEST,
                        "badPublicKey",
                        "RSA JWK missing n or e",
                    ));
                }
                verify_rsa_jws(
                    &jws.protected_b64,
                    &jws.payload_b64,
                    &jws.signature_b64,
                    &jwk,
                    alg,
                )
            }
            "EC" => {
                if jwk.x.is_empty() || jwk.y.is_empty() {
                    return Err(acme_error(
                        StatusCode::BAD_REQUEST,
                        "badPublicKey",
                        "EC JWK missing x or y",
                    ));
                }
                verify_ec_jws(
                    &jws.protected_b64,
                    &jws.payload_b64,
                    &jws.signature_b64,
                    &jwk,
                )
            }
            _ => {
                return Err(acme_error(
                    StatusCode::BAD_REQUEST,
                    "badPublicKey",
                    "unsupported JWK kty; expected RSA or EC",
                ))
            }
        };
        if !valid {
            return Err(acme_error(
                StatusCode::BAD_REQUEST,
                "badSignatureAlgorithm",
                "invalid JWS signature or unsupported algorithm",
            ));
        }
        let thumbprint = jwk_thumbprint(&jwk);
        return Ok(JwsContext {
            protected_header: protected_json,
            payload,
            account_id: None,
            account: None,
            jwk: Some(jwk),
            jwk_thumbprint: Some(thumbprint),
        });
    }

    // kid path
    let kid = protected_json
        .get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let account_id = kid.rsplit('/').next().unwrap_or("").to_string();
    if account_id.is_empty() {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "invalid kid",
        ));
    }

    let account = {
        let accounts = state.inner.acme_accounts.read().await;
        accounts.get(&account_id).cloned()
    };
    let Some(account) = account else {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "accountDoesNotExist",
            "account does not exist",
        ));
    };

    if let Some(uid) = auth_user_id {
        if account.vigil_user_id != uid {
            return Err(acme_error(
                StatusCode::FORBIDDEN,
                "unauthorized",
                "acme account is bound to a different vigil user",
            ));
        }
    }

    let sig_valid = if account.public_jwk.kty == "EC" {
        verify_ec_jws(
            &jws.protected_b64,
            &jws.payload_b64,
            &jws.signature_b64,
            &account.public_jwk,
        )
    } else {
        verify_rsa_jws(
            &jws.protected_b64,
            &jws.payload_b64,
            &jws.signature_b64,
            &account.public_jwk,
            alg,
        )
    };
    if !sig_valid {
        return Err(acme_error(
            StatusCode::BAD_REQUEST,
            "badSignatureAlgorithm",
            "invalid JWS signature or unsupported algorithm",
        ));
    }

    Ok(JwsContext {
        protected_header: protected_json,
        payload,
        account_id: Some(account_id),
        account: Some(account),
        jwk: None,
        jwk_thumbprint: None,
    })
}

// ---------------------------------------------------------------------------
// Nonce injection middleware helper
// ---------------------------------------------------------------------------

async fn inject_nonce(state: &AppState, headers_out: &mut HeaderMap) {
    let nonce = new_nonce_value();
    let mut nonces = state.inner.nonces.lock().await;
    nonces.insert(nonce.clone());
    headers_out.insert("Replay-Nonce", nonce.parse().unwrap());
    headers_out.insert("Cache-Control", "no-store".parse().unwrap());
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

pub async fn directory(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let (scheme, host) = extract_host_scheme(&headers);
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;
    let body = json!({
        "newNonce":   absolute(&host, scheme, "/acme/new-nonce"),
        "newAccount": absolute(&host, scheme, "/acme/new-account"),
        "newOrder":   absolute(&host, scheme, "/acme/new-order"),
        "revokeCert": absolute(&host, scheme, "/acme/revoke-cert"),
        "keyChange":  absolute(&host, scheme, "/acme/key-change"),
        "meta": {
            "termsOfService": "https://credo.local/tos",
            "website":        "https://credo.local",
        }
    });
    (resp_headers, Json(body))
}

pub async fn new_nonce_head(State(state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    inject_nonce(&state, &mut headers).await;
    (StatusCode::OK, headers)
}

pub async fn new_nonce_get(State(state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    inject_nonce(&state, &mut headers).await;
    (StatusCode::OK, headers)
}

pub async fn new_account(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut resp_headers = HeaderMap::new();

    let jws = match validate_jws(&state, &headers, &body, false, true, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    inject_nonce(&state, &mut resp_headers).await;

    let thumbprint = jws.jwk_thumbprint.as_deref().unwrap_or("").to_string();
    let payload = &jws.payload;

    // Check if account exists by thumbprint
    let existing = {
        let accounts = state.inner.acme_accounts.read().await;
        accounts
            .values()
            .find(|a| a.jwk_thumbprint == thumbprint)
            .cloned()
    };

    let (scheme, host) = extract_host_scheme(&headers);

    if let Some(mut existing) = existing {
        if existing.vigil_user_id.is_empty() {
            existing.vigil_user_id = auth_user.id.clone();
            let mut accounts = state.inner.acme_accounts.write().await;
            accounts.insert(existing.id.clone(), existing.clone());
            drop(accounts);
            let _ = save_accounts(&state).await;
        }
        if existing.vigil_user_id != auth_user.id {
            return acme_error(
                StatusCode::FORBIDDEN,
                "unauthorized",
                "account key is already bound to a different vigil user",
            );
        }
        let loc = absolute(&host, scheme, &format!("/acme/account/{}", existing.id));
        resp_headers.insert("Location", loc.parse().unwrap());
        return (
            StatusCode::OK,
            resp_headers,
            Json(json!({
                "status": existing.status,
                "contact": existing.contact,
                "orders": absolute(&host, scheme, &format!("/acme/account/{}/orders", existing.id)),
            })),
        )
            .into_response();
    }

    if payload
        .get("onlyReturnExisting")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return acme_error(
            StatusCode::BAD_REQUEST,
            "accountDoesNotExist",
            "account does not exist for provided key",
        );
    }

    let id = {
        let mut counter = state.inner.acme_id_counter.lock().await;
        *counter += 1;
        format!("acct-{}", base36(*counter))
    };

    let contact: Vec<String> = payload
        .get("contact")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let account = AcmeAccountRecord {
        id: id.clone(),
        status: "valid".to_string(),
        vigil_user_id: auth_user.id.clone(),
        contact,
        orders: vec![],
        jwk_thumbprint: thumbprint,
        public_jwk: jws.jwk.unwrap(),
    };

    {
        let mut accounts = state.inner.acme_accounts.write().await;
        accounts.insert(id.clone(), account);
    }
    let _ = save_accounts(&state).await;

    let loc = absolute(&host, scheme, &format!("/acme/account/{}", id));
    resp_headers.insert("Location", loc.parse().unwrap());
    let accounts = state.inner.acme_accounts.read().await;
    let acc = accounts.get(&id).unwrap();
    (
        StatusCode::CREATED,
        resp_headers,
        Json(json!({
            "status": acc.status,
            "contact": acc.contact,
            "orders": absolute(&host, scheme, &format!("/acme/account/{}/orders", id)),
        })),
    )
        .into_response()
}

pub async fn get_account(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    if jws.account_id.as_deref() != Some(&id) {
        return acme_error(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "kid does not match requested account",
        );
    }
    let account = match jws.account {
        Some(a) => a,
        None => {
            return acme_error(
                StatusCode::BAD_REQUEST,
                "accountDoesNotExist",
                "account not found",
            )
        }
    };
    let (scheme, host) = extract_host_scheme(&headers);
    let loc = absolute(&host, scheme, &format!("/acme/account/{}", account.id));
    resp_headers.insert("Location", loc.parse().unwrap());
    (
        resp_headers,
        Json(json!({
            "status": account.status,
            "contact": account.contact,
            "orders": absolute(&host, scheme, &format!("/acme/account/{}/orders", id)),
        })),
    )
        .into_response()
}

pub async fn new_order(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    let account_id = jws.account_id.unwrap();
    let payload = &jws.payload;

    let identifiers: Vec<AcmeIdentifier> = payload
        .get("identifiers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|id| {
                    let t = id.get("type")?.as_str()?;
                    let v = id.get("value")?.as_str()?;
                    if t == "dns" && !v.trim().is_empty() {
                        Some(AcmeIdentifier {
                            id_type: "dns".to_string(),
                            value: v.trim().to_string(),
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if identifiers.is_empty() {
        return acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "identifiers must include at least one dns entry",
        );
    }

    let requested_method = payload
        .get("validationMethod")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let config = state.config();
    let validation_method = match requested_method.as_str() {
        "http-01" => "http-01",
        "dns-01" => "dns-01",
        "none-01" => {
            if !config.allow_none_validation {
                return acme_error(
                    StatusCode::BAD_REQUEST,
                    "unauthorized",
                    "none-01 validation is not permitted",
                );
            }
            "none-01"
        }
        "" => {
            return acme_error(
                StatusCode::BAD_REQUEST,
                "malformed",
                "validationMethod is required; expected http-01, dns-01, or none-01",
            );
        }
        _ => {
            return acme_error(
                StatusCode::BAD_REQUEST,
                "malformed",
                "unsupported validationMethod; expected http-01, dns-01, or none-01",
            );
        }
    };

    let http_challenge_port = payload
        .get("httpChallengePort")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(80);
    if !config
        .allowed_http_challenge_ports
        .contains(&http_challenge_port)
    {
        return acme_error(
            StatusCode::BAD_REQUEST,
            "unauthorized",
            "httpChallengePort is not in allowedHttpChallengePorts",
        );
    }

    let order_id = {
        let mut counter = state.inner.acme_id_counter.lock().await;
        *counter += 1;
        format!("order-{}", base36(*counter))
    };

    let (scheme, host) = extract_host_scheme(&headers);

    let mut authz_ids = Vec::new();
    for identifier in &identifiers {
        let authz_id = {
            let mut counter = state.inner.acme_id_counter.lock().await;
            *counter += 1;
            format!("authz-{}", base36(*counter))
        };
        let chall_id = {
            let mut counter = state.inner.acme_id_counter.lock().await;
            *counter += 1;
            format!("chall-{}", base36(*counter))
        };

        let (chall_status, authz_status) = if validation_method == "none-01" {
            ("valid", "valid")
        } else {
            ("pending", "pending")
        };

        let token = random_token();
        let thumbprint = jws
            .account
            .as_ref()
            .map(|a| a.jwk_thumbprint.as_str())
            .unwrap_or("");
        let key_authorization = if validation_method != "none-01" && !thumbprint.is_empty() {
            format!("{}.{}", token, thumbprint)
        } else {
            String::new()
        };

        let challenge = AcmeChallenge {
            id: chall_id.clone(),
            authz_id: authz_id.clone(),
            order_id: order_id.clone(),
            // none-01 is an internal auto-validate signal; report http-01 so
            // standard ACME clients (e.g. instant-acme) can deserialize the type.
            challenge_type: if validation_method == "none-01" {
                "http-01"
            } else {
                validation_method
            }
            .to_string(),
            validation_method: validation_method.to_string(),
            status: chall_status.to_string(),
            token,
            key_authorization,
            http_challenge_port,
        };

        let authz = AcmeAuthz {
            id: authz_id.clone(),
            order_id: order_id.clone(),
            identifier: identifier.clone(),
            status: authz_status.to_string(),
            challenge_ids: vec![chall_id.clone()],
        };

        let mut challenges = state.inner.acme_challenges.write().await;
        challenges.insert(chall_id, challenge);
        drop(challenges);
        let mut authzs = state.inner.acme_authzs.write().await;
        authzs.insert(authz_id.clone(), authz);
        authz_ids.push(authz_id);
    }

    let status = if validation_method == "none-01" {
        "ready"
    } else {
        "pending"
    };
    let order = AcmeOrder {
        id: order_id.clone(),
        account_id: account_id.clone(),
        status: status.to_string(),
        expires: (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        identifiers: identifiers.clone(),
        authz_ids: authz_ids.clone(),
        finalize_path: format!("/acme/order/{}/finalize", order_id),
        certificate_path: None,
    };

    {
        let mut orders = state.inner.acme_orders.write().await;
        orders.insert(order_id.clone(), order.clone());
    }
    {
        let mut accounts = state.inner.acme_accounts.write().await;
        if let Some(acc) = accounts.get_mut(&account_id) {
            acc.orders.push(order_id.clone());
        }
    }
    let _ = save_accounts(&state).await;

    let loc = absolute(&host, scheme, &format!("/acme/order/{}", order_id));
    resp_headers.insert("Location", loc.parse().unwrap());
    (
        StatusCode::CREATED,
        resp_headers,
        Json(order_response(&order, &host, scheme)),
    )
        .into_response()
}

pub async fn get_order(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    let orders = state.inner.acme_orders.read().await;
    let Some(order) = orders.get(&id) else {
        return acme_error(StatusCode::NOT_FOUND, "malformed", "order not found");
    };
    if jws.account_id.as_deref() != Some(&order.account_id) {
        return acme_error(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "order does not belong to account",
        );
    }
    let (scheme, host) = extract_host_scheme(&headers);
    let loc = absolute(&host, scheme, &format!("/acme/order/{}", id));
    resp_headers.insert("Location", loc.parse().unwrap());
    (resp_headers, Json(order_response(order, &host, scheme))).into_response()
}

pub async fn get_authz(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    let authzs = state.inner.acme_authzs.read().await;
    let Some(authz) = authzs.get(&id) else {
        return acme_error(
            StatusCode::NOT_FOUND,
            "malformed",
            "authorization not found",
        );
    };
    let order_id = authz.order_id.clone();
    let authz = authz.clone();
    drop(authzs);

    let orders = state.inner.acme_orders.read().await;
    if orders.get(&order_id).map(|o| o.account_id.as_str())
        != Some(jws.account_id.as_deref().unwrap_or(""))
    {
        return acme_error(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "authorization does not belong to account",
        );
    }
    drop(orders);

    let (scheme, host) = extract_host_scheme(&headers);
    let challenges = state.inner.acme_challenges.read().await;
    let chall_list: Vec<Value> = authz
        .challenge_ids
        .iter()
        .filter_map(|cid| {
            challenges.get(cid).map(|c| {
                json!({
                    "type": c.challenge_type,
                    "status": c.status,
                    "url": absolute(&host, scheme, &format!("/acme/challenge/{}", c.id)),
                    "token": c.token,
                })
            })
        })
        .collect();

    (
        resp_headers,
        Json(json!({
            "status": authz.status,
            "identifier": { "type": authz.identifier.id_type, "value": authz.identifier.value },
            "challenges": chall_list,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Challenge validation
// ---------------------------------------------------------------------------

async fn validate_http_01(domain: &str, token: &str, expected_key_auth: &str, port: u16) -> bool {
    let url = if port == 80 {
        format!("http://{}/.well-known/acme-challenge/{}", domain, token)
    } else {
        format!(
            "http://{}:{}/.well-known/acme-challenge/{}",
            domain, port, token
        )
    };
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(domain = %domain, error = %e, "http-01: failed to build HTTP client");
            return false;
        }
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(body) => {
                let ok = body.trim() == expected_key_auth.trim();
                if !ok {
                    tracing::warn!(domain = %domain, "http-01: key authorization mismatch");
                }
                ok
            }
            Err(e) => {
                tracing::warn!(domain = %domain, error = %e, "http-01: failed to read response body");
                false
            }
        },
        Ok(resp) => {
            tracing::warn!(domain = %domain, status = %resp.status(), "http-01: unexpected HTTP status");
            false
        }
        Err(e) => {
            tracing::warn!(domain = %domain, error = %e, "http-01: HTTP fetch failed");
            false
        }
    }
}

/// Resolve the authoritative NS IPs for a domain by walking up the label hierarchy.
/// Uses the recursive resolver (for NS record lookup and NS hostname → IP resolution).
async fn find_authoritative_ns_ips(
    domain: &str,
    resolver: &hickory_resolver::TokioResolver,
) -> Vec<std::net::IpAddr> {
    use hickory_resolver::proto::rr::RData;

    let domain_clean = domain.trim_end_matches('.');
    let labels: Vec<&str> = domain_clean.split('.').collect();

    // Walk from the full domain up to the 2nd-level domain (don't query TLD nameservers).
    for start in 0..labels.len().saturating_sub(1) {
        let zone = format!("{}.", labels[start..].join("."));
        let Ok(ns_lookup) = resolver.ns_lookup(&zone).await else {
            continue;
        };
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for rec in ns_lookup.answers() {
            if let RData::NS(ns_name) = &rec.data {
                let host = ns_name.to_string();
                if let Ok(ip_lookup) = resolver.lookup_ip(host.trim_end_matches('.')).await {
                    ips.extend(ip_lookup.iter());
                }
            }
        }
        if !ips.is_empty() {
            tracing::debug!(domain = %domain, zone = %zone, ns_count = %ips.len(),
                           "dns-01: found authoritative NS");
            return ips;
        }
    }
    Vec::new()
}

/// Query a TXT record directly from a specific nameserver IP, bypassing the recursive resolver cache.
async fn query_txt_from_ns(ns_ip: std::net::IpAddr, lookup_name: &str, expected: &str) -> bool {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::proto::rr::RData;

    let mut config = ResolverConfig::default();
    config.add_name_server(NameServerConfig::udp_and_tcp(ns_ip));
    let auth_resolver = match hickory_resolver::TokioResolver::builder_with_config(
        config,
        hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(ns_ip = %ns_ip, error = %e, "dns-01: failed to build NS resolver");
            return false;
        }
    };

    match auth_resolver.txt_lookup(lookup_name).await {
        Ok(records) => records.answers().iter().any(|rec| {
            if let RData::TXT(txt) = &rec.data {
                txt.txt_data.iter().any(|d| {
                    std::str::from_utf8(d)
                        .map(|s| s.trim() == expected)
                        .unwrap_or(false)
                })
            } else {
                false
            }
        }),
        Err(e) => {
            tracing::debug!(ns_ip = %ns_ip, lookup = %lookup_name, error = %e,
                           "dns-01: TXT lookup from authoritative NS failed");
            false
        }
    }
}

/// Validate a dns-01 challenge by querying the authoritative nameservers directly,
/// bypassing any recursive resolver cache.
async fn validate_dns_01(
    domain: &str,
    key_auth: &str,
    resolver: &hickory_resolver::TokioResolver,
) -> bool {
    use sha2::{Digest, Sha256};

    let expected = B64.encode(Sha256::digest(key_auth.as_bytes()));
    let lookup_name = format!("_acme-challenge.{}.", domain.trim_end_matches('.'));

    let ns_ips = find_authoritative_ns_ips(domain, resolver).await;
    if ns_ips.is_empty() {
        tracing::warn!(domain = %domain, "dns-01: could not find authoritative NS");
        return false;
    }

    for ns_ip in ns_ips {
        if query_txt_from_ns(ns_ip, &lookup_name, &expected).await {
            return true;
        }
    }

    tracing::warn!(domain = %domain, "dns-01: TXT record not found on any authoritative NS");
    false
}

pub async fn respond_challenge(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    // Snapshot challenge without marking valid yet
    let (challenge_snap, authz_id, order_id) = {
        let challenges = state.inner.acme_challenges.read().await;
        let Some(chall) = challenges.get(&id) else {
            return acme_error(StatusCode::NOT_FOUND, "malformed", "challenge not found");
        };
        (
            chall.clone(),
            chall.authz_id.clone(),
            chall.order_id.clone(),
        )
    };

    // Check ownership
    {
        let orders = state.inner.acme_orders.read().await;
        if orders.get(&order_id).map(|o| o.account_id.as_str())
            != Some(jws.account_id.as_deref().unwrap_or(""))
        {
            return acme_error(
                StatusCode::FORBIDDEN,
                "unauthorized",
                "challenge does not belong to account",
            );
        }
    }

    // Look up domain from authz
    let domain = {
        let authzs = state.inner.acme_authzs.read().await;
        authzs
            .get(&authz_id)
            .map(|a| a.identifier.value.clone())
            .unwrap_or_default()
    };

    let (scheme, host) = extract_host_scheme(&headers);
    let challenge_url = absolute(
        &host,
        scheme,
        &format!("/acme/challenge/{}", challenge_snap.id),
    );

    // none-01 is a server-side decision — validate synchronously and return immediately.
    if challenge_snap.validation_method == "none-01" {
        if !state.config().allow_none_validation {
            return acme_error(
                StatusCode::FORBIDDEN,
                "unauthorized",
                "none-01 validation is not permitted",
            );
        }
        mark_challenge_valid(&state, &id, &authz_id, &order_id).await;
        return (
            resp_headers,
            Json(json!({
                "type": challenge_snap.challenge_type,
                "status": "valid",
                "url": challenge_url,
                "token": challenge_snap.token,
            })),
        )
            .into_response();
    }

    // For http-01 and dns-01: if already resolved, return current status immediately.
    {
        let challenges = state.inner.acme_challenges.read().await;
        if let Some(c) = challenges.get(&id) {
            if c.status == "valid" || c.status == "invalid" || c.status == "processing" {
                return (
                    resp_headers,
                    Json(json!({
                        "type": challenge_snap.challenge_type,
                        "status": c.status,
                        "url": challenge_url,
                        "token": challenge_snap.token,
                    })),
                )
                    .into_response();
            }
        }
    }

    // Mark as processing and spawn background validation task.
    {
        let mut challenges = state.inner.acme_challenges.write().await;
        if let Some(c) = challenges.get_mut(&id) {
            c.status = "processing".to_string();
        }
    }

    let config = state.config();
    let check_count = config.challenge_check_count;
    let check_interval = std::time::Duration::from_secs(config.challenge_check_interval_secs);
    drop(config);

    tokio::spawn(validate_challenge_background(
        state,
        id.clone(),
        domain,
        challenge_snap.clone(),
        authz_id,
        order_id,
        check_count,
        check_interval,
    ));

    (
        resp_headers,
        Json(json!({
            "type": challenge_snap.challenge_type,
            "status": "processing",
            "url": challenge_url,
            "token": challenge_snap.token,
        })),
    )
        .into_response()
}

pub async fn finalize_order(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    let order = {
        let orders = state.inner.acme_orders.read().await;
        let Some(o) = orders.get(&id) else {
            return acme_error(StatusCode::NOT_FOUND, "malformed", "order not found");
        };
        if jws.account_id.as_deref() != Some(&o.account_id) {
            return acme_error(
                StatusCode::FORBIDDEN,
                "unauthorized",
                "order does not belong to account",
            );
        }
        if o.status != "ready" && o.status != "valid" {
            return acme_error(
                StatusCode::BAD_REQUEST,
                "orderNotReady",
                "order is not ready for finalize",
            );
        }
        o.clone()
    };

    let csr_b64 = jws
        .payload
        .get("csr")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if csr_b64.is_empty() {
        return acme_error(StatusCode::BAD_REQUEST, "malformed", "csr is required");
    }

    let days = jws
        .payload
        .get("days")
        .and_then(|v| v.as_u64())
        .unwrap_or(state.config().ca.cert_default_days as u64) as u32;
    let sans: Vec<String> = order
        .identifiers
        .iter()
        .map(|id| id.value.clone())
        .collect();

    let csr_der = match B64.decode(csr_b64) {
        Ok(b) => b,
        Err(_) => return acme_error(StatusCode::BAD_REQUEST, "badCSR", "invalid CSR base64url"),
    };
    let csr_pem = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &csr_der)
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    );

    if let Err(e) = validate_issuance_policy(&csr_pem, &sans, &state.config().issuance_policy) {
        return acme_error(StatusCode::BAD_REQUEST, "badCSR", &e.to_string());
    }

    let signed = match sign_csr(&csr_pem, days, Some(&sans), &state.config()) {
        Ok(s) => s,
        Err(e) => return acme_error(StatusCode::BAD_REQUEST, "badCSR", &e.to_string()),
    };

    let config = state.config();
    let owner_user_id = {
        let accounts = state.inner.acme_accounts.read().await;
        accounts
            .get(&order.account_id)
            .map(|a| a.vigil_user_id.clone())
            .unwrap_or_else(|| "unknown".to_string())
    };

    let record = crate::types::CertificateRecord {
        id: signed.id.clone(),
        serial_number: signed.serial_number.clone(),
        subject: signed.subject.clone(),
        fingerprint256: signed.fingerprint256.clone(),
        valid_from: signed.valid_from.clone(),
        valid_to: signed.valid_to.clone(),
        cert_path: String::new(),
        issued_at: chrono::Utc::now().to_rfc3339(),
        issued_by: format!("acme:{}", order.account_id),
        owner_vigil_user_id: owner_user_id,
        issuing_acme_account_id: Some(order.account_id.clone()),
        revoked: false,
        revoked_at: None,
        revoked_by: None,
        revoked_by_vigil_user_id: None,
        revoked_by_acme_account_id: None,
        revoked_via: None,
        revoke_reason: None,
    };

    if let Err(e) = storage::issue_certificate_record(
        &config.cert_db_path,
        &config.certs_dir,
        record,
        &signed.fullchain_pem,
    ) {
        tracing::error!("Failed to persist certificate: {}", e);
        return acme_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "badCSR",
            "failed to store certificate",
        );
    }

    let cert_path = format!("/acme/cert/{}", signed.id);
    {
        let mut orders = state.inner.acme_orders.write().await;
        if let Some(o) = orders.get_mut(&id) {
            o.status = "valid".to_string();
            o.certificate_path = Some(cert_path.clone());
        }
    }

    let (scheme, host) = extract_host_scheme(&headers);
    let loc = absolute(&host, scheme, &format!("/acme/order/{}", id));
    resp_headers.insert("Location", loc.parse().unwrap());
    let orders = state.inner.acme_orders.read().await;
    let order = orders.get(&id).unwrap();
    (resp_headers, Json(order_response(order, &host, scheme))).into_response()
}

pub async fn download_cert(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    let config = state.config();
    let record = match storage::get_certificate_record(&config.cert_db_path, &id) {
        Ok(Some(r)) => r,
        _ => return acme_error(StatusCode::NOT_FOUND, "malformed", "certificate not found"),
    };

    let owning_order = {
        let cert_path = format!("/acme/cert/{}", id);
        let orders = state.inner.acme_orders.read().await;
        orders
            .values()
            .find(|o| o.certificate_path.as_deref() == Some(&cert_path))
            .cloned()
    };

    let Some(owning_order) = owning_order else {
        return acme_error(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "certificate does not belong to account",
        );
    };
    if Some(&owning_order.account_id) != jws.account_id.as_ref() {
        return acme_error(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "certificate does not belong to account",
        );
    }

    let cert_pem = match storage::read_certificate_pem(&record.cert_path) {
        Some(p) => p,
        None => {
            return acme_error(
                StatusCode::NOT_FOUND,
                "malformed",
                "certificate PEM missing",
            )
        }
    };

    resp_headers.insert(
        "Content-Type",
        "application/pem-certificate-chain".parse().unwrap(),
    );
    (resp_headers, cert_pem).into_response()
}

pub async fn revoke_cert(
    State(state): State<AppState>,
    axum::Extension(AuthUser(_auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let jws = match validate_jws(&state, &headers, &body, false, false, None).await {
        Ok(j) => j,
        Err(e) => return e,
    };
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;

    let config = state.config();
    let payload = &jws.payload;

    // Resolve certificate by certificateId or certificate DER
    let cert_id = payload
        .get("certificateId")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string());
    let cert_der_b64 = payload
        .get("certificate")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let record = if let Some(ref cid) = cert_id {
        storage::get_certificate_record(&config.cert_db_path, cid)
            .ok()
            .flatten()
    } else if let Some(ref b64) = cert_der_b64 {
        let der = match B64.decode(b64) {
            Ok(b) => b,
            Err(_) => {
                return acme_error(
                    StatusCode::BAD_REQUEST,
                    "malformed",
                    "invalid certificate base64url",
                )
            }
        };
        if let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) {
            let serial = cert.serial.to_str_radix(16);
            storage::find_certificate_by_serial(&config.cert_db_path, &serial)
                .ok()
                .flatten()
        } else {
            None
        }
    } else {
        None
    };

    let Some(record) = record else {
        return acme_error(
            StatusCode::BAD_REQUEST,
            "malformed",
            "certificateId or certificate is required and must reference an issued certificate",
        );
    };

    if let Some(ref account_id) = jws.account_id {
        let record_account_id = record
            .issuing_acme_account_id
            .as_deref()
            .or_else(|| record.issued_by.strip_prefix("acme:"))
            .unwrap_or("");
        if record_account_id != account_id {
            return acme_error(
                StatusCode::FORBIDDEN,
                "unauthorized",
                "certificate does not belong to acme account",
            );
        }
    }

    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("acme-revoke-cert")
        .to_string();
    let revoked_by = jws
        .account_id
        .as_ref()
        .map(|id| format!("acme:{}", id))
        .unwrap_or_else(|| "acme-cert-key".to_string());
    let (revoked_by_acme, revoked_via) = if jws.account_id.is_some() {
        (jws.account_id.clone(), Some("acme-account-key".to_string()))
    } else {
        (None, Some("acme-cert-key".to_string()))
    };

    let updated = storage::revoke_certificate(
        &config.cert_db_path,
        &record.id,
        &revoked_by,
        &reason,
        None,
        revoked_by_acme,
        revoked_via,
    )
    .ok()
    .flatten();

    let Some(updated) = updated else {
        return acme_error(StatusCode::NOT_FOUND, "malformed", "certificate not found");
    };

    (
        resp_headers,
        Json(json!({
            "status": "revoked",
            "certificateId": updated.id,
            "revokedAt": updated.revoked_at,
        })),
    )
        .into_response()
}

pub async fn key_change(
    State(state): State<AppState>,
    axum::Extension(AuthUser(auth_user)): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let _ = validate_jws(&state, &headers, &body, true, false, Some(&auth_user.id)).await;
    let mut resp_headers = HeaderMap::new();
    inject_nonce(&state, &mut resp_headers).await;
    (resp_headers, Json(json!({ "status": "not-implemented" }))).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn update_order_status(state: &AppState, order_id: &str) {
    let authz_ids: Vec<String> = {
        let orders = state.inner.acme_orders.read().await;
        orders
            .get(order_id)
            .map(|o| o.authz_ids.clone())
            .unwrap_or_default()
    };
    let (all_valid, any_invalid) = {
        let authzs = state.inner.acme_authzs.read().await;
        let all_valid = authz_ids
            .iter()
            .all(|id| authzs.get(id).map(|a| a.status == "valid").unwrap_or(false));
        let any_invalid = authz_ids.iter().any(|id| {
            authzs
                .get(id)
                .map(|a| a.status == "invalid")
                .unwrap_or(false)
        });
        (all_valid, any_invalid)
    };
    if all_valid || any_invalid {
        let mut orders = state.inner.acme_orders.write().await;
        if let Some(o) = orders.get_mut(order_id) {
            if o.status != "valid" {
                o.status = if any_invalid {
                    "invalid".to_string()
                } else {
                    "ready".to_string()
                };
            }
        }
    }
}

async fn mark_challenge_valid(
    state: &AppState,
    challenge_id: &str,
    authz_id: &str,
    order_id: &str,
) {
    {
        let mut challenges = state.inner.acme_challenges.write().await;
        if let Some(c) = challenges.get_mut(challenge_id) {
            c.status = "valid".to_string();
        }
    }
    {
        let mut authzs = state.inner.acme_authzs.write().await;
        if let Some(a) = authzs.get_mut(authz_id) {
            a.status = "valid".to_string();
        }
    }
    update_order_status(state, order_id).await;
}

async fn mark_challenge_invalid(
    state: &AppState,
    challenge_id: &str,
    authz_id: &str,
    order_id: &str,
) {
    {
        let mut challenges = state.inner.acme_challenges.write().await;
        if let Some(c) = challenges.get_mut(challenge_id) {
            c.status = "invalid".to_string();
        }
    }
    {
        let mut authzs = state.inner.acme_authzs.write().await;
        if let Some(a) = authzs.get_mut(authz_id) {
            a.status = "invalid".to_string();
        }
    }
    update_order_status(state, order_id).await;
}

/// Background task: poll challenge validation up to `check_count` times, sleeping
/// `check_interval` between attempts (first attempt runs immediately).
#[allow(clippy::too_many_arguments)]
async fn validate_challenge_background(
    state: AppState,
    challenge_id: String,
    domain: String,
    challenge_snap: AcmeChallenge,
    authz_id: String,
    order_id: String,
    check_count: u32,
    check_interval: std::time::Duration,
) {
    for attempt in 0..check_count {
        if attempt > 0 {
            tokio::time::sleep(check_interval).await;
        }

        // Bail if another request already resolved this challenge
        {
            let challenges = state.inner.acme_challenges.read().await;
            match challenges.get(&challenge_id).map(|c| c.status.as_str()) {
                Some("valid") | Some("invalid") | None => return,
                _ => {}
            }
        }

        let valid = match challenge_snap.validation_method.as_str() {
            "http-01" => {
                validate_http_01(
                    &domain,
                    &challenge_snap.token,
                    &challenge_snap.key_authorization,
                    challenge_snap.http_challenge_port,
                )
                .await
            }
            "dns-01" => {
                validate_dns_01(
                    &domain,
                    &challenge_snap.key_authorization,
                    &state.inner.dns_resolver,
                )
                .await
            }
            _ => false,
        };

        if valid {
            tracing::info!(
                domain = %domain,
                method = %challenge_snap.validation_method,
                attempt = attempt + 1,
                "ACME challenge validated successfully"
            );
            mark_challenge_valid(&state, &challenge_id, &authz_id, &order_id).await;
            return;
        }

        tracing::debug!(
            domain = %domain,
            method = %challenge_snap.validation_method,
            attempt = attempt + 1,
            total = check_count,
            "ACME challenge validation attempt failed"
        );
    }

    tracing::warn!(
        domain = %domain,
        method = %challenge_snap.validation_method,
        "ACME challenge validation exhausted all attempts"
    );
    mark_challenge_invalid(&state, &challenge_id, &authz_id, &order_id).await;
}

async fn save_accounts(state: &AppState) -> anyhow::Result<()> {
    let accounts: Vec<AcmeAccountRecord> = {
        let map = state.inner.acme_accounts.read().await;
        map.values().cloned().collect()
    };
    storage::write_acme_accounts(&state.config().acme_accounts_db_path, &accounts)
}

fn order_response(order: &AcmeOrder, host: &str, scheme: &str) -> Value {
    let authz_urls: Vec<String> = order
        .authz_ids
        .iter()
        .map(|id| absolute(host, scheme, &format!("/acme/authz/{}", id)))
        .collect();
    json!({
        "status": order.status,
        "expires": order.expires,
        "identifiers": order.identifiers.iter().map(|id| json!({ "type": id.id_type, "value": id.value })).collect::<Vec<_>>(),
        "authorizations": authz_urls,
        "finalize": absolute(host, scheme, &order.finalize_path),
        "certificate": order.certificate_path.as_ref().map(|p| absolute(host, scheme, p)),
    })
}

/// Load persisted ACME accounts into state at startup.
pub async fn restore_accounts(state: &AppState) -> anyhow::Result<()> {
    let accounts = storage::read_acme_accounts(&state.config().acme_accounts_db_path)?;
    let mut map = state.inner.acme_accounts.write().await;
    let mut counter = state.inner.acme_id_counter.lock().await;
    for account in accounts {
        let n = account_counter_from_id(&account.id);
        if n > *counter {
            *counter = n;
        }
        map.insert(account.id.clone(), account);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{validate_dns_01, validate_http_01};
    use axum::{extract::Path, routing::get, Router};
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;

    /// Start an HTTP server on a random port serving the challenge path.
    /// The `challenge` Arc can be updated after the server starts to set the
    /// expected (token, key_auth) pair. Returns (port, challenge, shutdown_tx).
    async fn start_mock_server() -> (
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

    #[tokio::test]
    async fn http_01_correct_response_returns_true() {
        let (port, challenge, _s) = start_mock_server().await;
        *challenge.lock().unwrap() = Some(("tok1".to_string(), "tok1.thumbprint".to_string()));
        assert!(validate_http_01("127.0.0.1", "tok1", "tok1.thumbprint", port).await);
    }

    #[tokio::test]
    async fn http_01_wrong_body_returns_false() {
        let (port, challenge, _s) = start_mock_server().await;
        *challenge.lock().unwrap() = Some(("tok2".to_string(), "wrong-key-auth".to_string()));
        assert!(!validate_http_01("127.0.0.1", "tok2", "tok2.thumbprint", port).await);
    }

    #[tokio::test]
    async fn http_01_not_found_returns_false() {
        let (port, _challenge, _s) = start_mock_server().await;
        // challenge is None → server returns 404 for any token
        assert!(!validate_http_01("127.0.0.1", "tok3", "k", port).await);
    }

    #[tokio::test]
    async fn http_01_connection_refused_returns_false() {
        // Bind, get a port, then drop so nothing is listening
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(!validate_http_01("127.0.0.1", "tok", "k", port).await);
    }

    #[tokio::test]
    async fn dns_01_nonexistent_domain_returns_false() {
        // RFC 2606 reserves .invalid for guaranteed NXDOMAIN — NS lookup will fail,
        // find_authoritative_ns_ips returns empty, validate_dns_01 returns false.
        let resolver = crate::state::build_dns_resolver(&[]);
        assert!(
            !validate_dns_01("nonexistent-credo-test.invalid", "fake-key-auth", &resolver).await
        );
    }
}
