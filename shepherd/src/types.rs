use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

pub use credo_lib::types::{HookRef, Role};

// ---------------------------------------------------------------------------
// Account (RBAC — identities[] only, no credentials field)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub role: Role,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub identities: Vec<String>,
    #[serde(default)]
    pub notes: String,
    pub created_at: Option<DateTime<Utc>>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsFile {
    #[serde(default)]
    pub accounts: Vec<Account>,
}

// ---------------------------------------------------------------------------
// Corgi node config (from shepherd.corgis.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CorgiNodeConfig {
    pub name: String,
    pub url: String,
    pub identity_uri: Option<String>,
    pub mtls: CorgiMtlsConfig,
    pub insecure_skip_verify: bool,
    /// Port Corgi's http-01 challenge listener runs on. Forwarded to Vigil in ACME orders.
    /// None means use Vigil's default (80 unless Vigil is configured otherwise).
    pub http_challenge_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct CorgiMtlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    /// Fallback used when cert_path doesn't exist yet (bootstrap window).
    pub bootstrap_cert_path: Option<PathBuf>,
    pub bootstrap_key_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// CA config (from shepherd.ca.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub name: String,
    pub protocol: String,
    pub provider: String,
    pub config: AcmeCaConfig,
}

#[derive(Debug, Clone)]
pub struct AcmeCaConfig {
    pub directory_url: String,
    pub account_email: Option<String>,
    pub account_key_path: PathBuf,
    pub renew_before_days: Option<f64>,
    pub days: Option<u32>,
    pub eab: Option<ExternalAccountBinding>,
    pub validation: HashMap<String, ValidationMethodConfig>,
    pub supported_validations: Vec<String>,
    pub default_validation: String,
    pub tls: Option<AcmeTlsConfig>,
    pub insecure_skip_verify: bool,
}

#[derive(Debug, Clone)]
pub struct ExternalAccountBinding {
    pub kid: String,
    pub hmac_key: String,
}

#[derive(Debug, Clone)]
pub struct ValidationMethodConfig {
    pub provider: Option<String>,
    pub provider_config: Option<serde_json::Value>,
    pub propagation_delay_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct AcmeTlsConfig {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Managed assignment (from shepherd.assignments.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedAssignment {
    #[serde(default)]
    pub cert_name: String,
    pub corgi: Option<String>,
    pub ca: String,
    pub domain: Option<String>,
    #[serde(default)]
    pub sans: Vec<String>,
    pub renew_before_days: Option<u32>,
    pub days: Option<u32>,
    pub identity_uri: Option<String>,
    pub validation: Option<AssignmentValidation>,
    pub cert_mode: Option<String>,
    pub key_mode: Option<String>,
    pub cert_owner: Option<String>,
    pub cert_group: Option<String>,
    pub key_owner: Option<String>,
    pub key_group: Option<String>,
    pub key_algorithm: Option<String>,
    /// Hook names to run on the corgi after cert install.
    /// None/absent = inherit corgi's defaultHooks. Some([]) = explicitly no hooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Vec<HookRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentValidation {
    #[serde(rename = "type")]
    pub validation_type: Option<String>,
    #[serde(default)]
    pub force_revalidate: bool,
    pub methods: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Renewal job state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenewalPhase {
    Queued,
    SubmittingOrder,
    Validating,
    Finalizing,
    Installing,
    Completed,
    Failed,
    Cancelled,
    RateLimited,
}

impl RenewalPhase {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            RenewalPhase::Completed | RenewalPhase::Failed | RenewalPhase::Cancelled
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEntry {
    pub at: String,
    pub step: String,
    pub detail: Option<String>,
    pub identifier: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalJob {
    pub id: Uuid,
    pub cert_name: String,
    pub ca: String,
    pub domains: Vec<String>,
    pub phase: RenewalPhase,
    pub created_at: i64,
    pub updated_at: i64,
    pub error: Option<String>,
    pub fingerprint256: Option<String>,
    #[serde(default)]
    pub trace: Vec<TraceEntry>,
    pub rate_limited_until: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Issuance ledger types
// ---------------------------------------------------------------------------

/// One record per successful ACME issuance — persisted in shepherd.issuance-log.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceEvent {
    pub cert_name: String,
    pub ca: String,
    /// eTLD+1 extracted from SANs (e.g., "example.com" for "api.example.com").
    pub registered_domain: String,
    /// Sorted, deduplicated canonical SAN list; CN is always included.
    pub sans: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub fingerprint256: String,
}

/// Per-registered-domain quota status returned by GET /api/rate-limits.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainQuotaStatus {
    pub registered_domain: String,
    pub ca: String,
    pub issued_7d: u32,
    pub limit_7d: u32,
    pub next_slot_at: Option<DateTime<Utc>>,
}

/// Per-cert (exact SAN set) quota status returned by GET /api/rate-limits.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierSetQuotaStatus {
    pub cert_name: String,
    pub sans: Vec<String>,
    pub ca: String,
    pub issued_7d: u32,
    pub limit_7d: u32,
    pub next_slot_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Corgi runtime state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CorgiStatus {
    Unknown,
    Reachable,
    Unreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorgiFlockEntry {
    pub name: String,
    pub fingerprint256: Option<String>,
    pub valid_to: Option<String>,
    pub lifetime_days: Option<f64>,
    pub status: Option<String>,
    #[serde(default)]
    pub san_names: Vec<String>,
    pub key_exists: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CorgiNodeState {
    pub status: CorgiStatus,
    pub last_health_check: Option<i64>,
    pub flock: Vec<CorgiFlockEntry>,
    pub error: Option<String>,
}

impl Default for CorgiNodeState {
    fn default() -> Self {
        Self::new()
    }
}

impl CorgiNodeState {
    pub fn new() -> Self {
        Self {
            status: CorgiStatus::Unknown,
            last_health_check: None,
            flock: vec![],
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Authenticated user (injected into API requests by api_auth_middleware)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub identity_uri: String,
    pub role: Role,
    pub account_id: Option<String>,
    pub account_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Cert store entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertStoreEntry {
    pub name: String,
    pub fingerprint256: Option<String>,
    pub valid_to: Option<DateTime<Utc>>,
    pub expires_in_days: Option<i64>,
    pub subject: Option<String>,
}
