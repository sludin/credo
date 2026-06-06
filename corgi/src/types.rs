use serde::{Deserialize, Serialize};

// Role and ClientIdentity live in credo-lib; re-export for convenience.
pub use credo_lib::types::{ClientIdentity, Role};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlockSummary {
    pub name: String,
    pub fingerprint256: Option<String>,
    pub valid_to: Option<String>,
    pub lifetime_days: Option<f64>,
    pub san_names: Vec<String>,
    pub domain: Option<String>,
    pub status: String,
    pub key_exists: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateStatus {
    pub name: String,
    pub domain: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub cert_exists: bool,
    pub key_exists: bool,
    pub cert_matches_key: bool,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub fingerprint256: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub expires_in_days: Option<i64>,
    pub hooks: Vec<String>,
    pub last_checked_at: String,
}

// ---------------------------------------------------------------------------
// Shepherd wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedAssignment {
    pub corgi: String,
    pub cert_name: String,
    pub fingerprint256: Option<String>,
    pub ca: Option<String>,
    pub issuer: Option<String>,
    pub renew_before_days: Option<u32>,
    pub days: Option<u32>,
    pub domain: Option<String>,
    pub identity_uri: Option<String>,
    pub monitor: Option<bool>,
    #[serde(default)]
    pub hooks: Vec<HookRef>,
    pub csr_subject: Option<CsrSubjectWire>,
    #[serde(default)]
    pub sans: Vec<String>,
    pub restart: Option<bool>,
    pub cert_mode: Option<String>,
    pub key_mode: Option<String>,
    pub cert_owner: Option<String>,
    pub cert_group: Option<String>,
    pub key_owner: Option<String>,
    pub key_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrSubjectWire {
    #[serde(rename = "commonName")]
    pub common_name: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organization: Option<String>,
    #[serde(rename = "organizationalUnit")]
    pub organizational_unit: Option<String>,
    #[serde(rename = "emailAddress")]
    pub email_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HookRef {
    Simple(String),
    Parameterized {
        name: String,
        args: std::collections::HashMap<String, String>,
    },
}

impl HookRef {
    pub fn name(&self) -> &str {
        match self {
            HookRef::Simple(s) => s,
            HookRef::Parameterized { name, .. } => name,
        }
    }

    pub fn args(&self) -> std::collections::HashMap<String, String> {
        match self {
            HookRef::Simple(_) => std::collections::HashMap::new(),
            HookRef::Parameterized { args, .. } => args.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentsResponse {
    pub corgi_id: String,
    pub assignments: Vec<ManagedAssignment>,
    pub shepherd_ca: Option<ShepherdCa>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShepherdCa {
    pub fingerprint: String,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShepherdCertResponse {
    pub cert_name: String,
    pub ca: Option<String>,
    pub fingerprint256: Option<String>,
    pub expires_in_days: Option<i64>,
    pub cert_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub fullchain_pem: Option<String>,
    pub key_pem: Option<String>,
}

// ---------------------------------------------------------------------------
// ACME challenge record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRecord {
    pub token: String,
    pub response: String,
    pub domain: Option<String>,
    pub file_path: Option<String>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Assignment cache file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentsCacheFile {
    pub node_id: String,
    pub shepherd_url: String,
    pub last_updated_at: String,
    pub source: String,
    pub assignments: Vec<ManagedAssignment>,
}

// ---------------------------------------------------------------------------
// Install request body
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallRequest {
    pub cert_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub fullchain_pem: Option<String>,
    pub key_pem: Option<String>,
    pub restart: Option<bool>,
}

// ---------------------------------------------------------------------------
// CSR request body
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CsrRequest {
    pub sans: Option<Vec<String>>,
    pub common_name: Option<String>,
    pub identity_uri: Option<String>,
    pub csr_subject: Option<CsrSubjectWire>,
}
