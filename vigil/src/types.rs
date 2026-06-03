use serde::{Deserialize, Serialize};

// Role and ClientIdentity live in credo-lib; re-export for convenience.
pub use credo_lib::types::Role;

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VigilUser {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub active: bool,
    pub public_key_pem: String,
    pub public_key_fingerprint256: String,
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRecord {
    pub id: String,
    pub serial_number: String,
    pub subject: String,
    pub fingerprint256: String,
    pub valid_from: String,
    pub valid_to: String,
    pub cert_path: String,
    pub issued_at: String,
    pub issued_by: String,
    pub owner_vigil_user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_acme_account_id: Option<String>,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by_vigil_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by_acme_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// ACME account records (persisted to disk)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeRsaJwk {
    pub kty: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeAccountRecord {
    pub id: String,
    pub status: String,
    pub vigil_user_id: String,
    pub contact: Vec<String>,
    pub orders: Vec<String>,
    pub jwk_thumbprint: String,
    pub public_jwk: AcmeRsaJwk,
}

// ---------------------------------------------------------------------------
// ACME in-memory state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeOrder {
    pub id: String,
    pub account_id: String,
    pub status: String,
    pub expires: String,
    pub identifiers: Vec<AcmeIdentifier>,
    pub authz_ids: Vec<String>,
    pub finalize_path: String,
    pub certificate_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeAuthz {
    pub id: String,
    pub order_id: String,
    pub identifier: AcmeIdentifier,
    pub status: String,
    pub challenge_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeChallenge {
    pub id: String,
    pub authz_id: String,
    pub order_id: String,
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub status: String,
    pub token: String,
}

// ---------------------------------------------------------------------------
// CA metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootCAMetadata {
    pub subject: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint256: String,
    pub key_path: String,
    pub cert_path: String,
}

// ---------------------------------------------------------------------------
// Signed certificate result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SignedCertificate {
    pub id: String,
    pub serial_number: String,
    pub subject: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint256: String,
    pub cert_pem: String,
    pub chain_pem: String,
    pub fullchain_pem: String,
}

// ---------------------------------------------------------------------------
// OCSP / CRL
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OcspStatusResponse {
    pub status: String,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub this_update: String,
    pub next_update: String,
    pub produced_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrlEntry {
    pub certificate_id: String,
    pub serial_number: String,
    pub subject: String,
    pub revoked_at: String,
    pub revoke_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrlResponse {
    pub issuer: CrlIssuer,
    pub generated_at: String,
    pub this_update: String,
    pub next_update: String,
    pub revoked_certificates: Vec<CrlEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrlIssuer {
    pub subject: String,
    pub serial_number: String,
    pub fingerprint256: String,
}
