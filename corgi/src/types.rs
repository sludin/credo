use serde::{Deserialize, Serialize};

// Role, ClientIdentity, HookRef, and the monitor types live in credo-lib;
// re-export for convenience.
pub use credo_lib::types::{
    ClientIdentity, HookRef, MonitorConfig, MonitorProtocol, MonitorResult, MonitorStatus, Role,
};

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
    pub monitor: MonitorResult,
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
    /// Endpoint(s) to verify the installed cert against. Legacy payloads and
    /// cached assignment files carried a boolean here; those parse as None.
    /// A single endpoint object and an array of endpoints (SAN certs) are
    /// both accepted; see `credo_lib::types::parse_monitor_list`.
    #[serde(
        default,
        deserialize_with = "credo_lib::types::deserialize_monitor_list",
        serialize_with = "credo_lib::types::serialize_monitor_list"
    )]
    pub monitor: Option<Vec<MonitorConfig>>,
    #[serde(default)]
    pub hooks: Option<Vec<HookRef>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use credo_lib::types::{MonitorConfig, MonitorProtocol};

    fn assignment_json(monitor: &str) -> String {
        format!(
            r#"{{"corgi":"corgi-01","certName":"api.example.com","monitor":{}}}"#,
            monitor
        )
    }

    fn endpoint(host: &str, port: u16) -> MonitorConfig {
        MonitorConfig {
            host: host.into(),
            port,
            protocol: MonitorProtocol::Https,
            ca_path: None,
            resolve_ip: None,
        }
    }

    #[test]
    fn assignment_monitor_accepts_endpoint_object() {
        let a: ManagedAssignment = serde_json::from_str(&assignment_json(
            r#"{"host":"api.example.com","port":8443}"#,
        ))
        .unwrap();
        assert_eq!(a.monitor, Some(vec![endpoint("api.example.com", 8443)]));
    }

    #[test]
    fn assignment_monitor_accepts_endpoint_array() {
        // SAN cert: multiple endpoints to check for one assignment.
        let a: ManagedAssignment = serde_json::from_str(&assignment_json(
            r#"[{"host":"api.example.com","port":443},{"host":"api2.example.com","port":443}]"#,
        ))
        .unwrap();
        assert_eq!(
            a.monitor,
            Some(vec![
                endpoint("api.example.com", 443),
                endpoint("api2.example.com", 443),
            ])
        );
    }

    #[test]
    fn assignment_monitor_empty_array_is_none() {
        let a: ManagedAssignment = serde_json::from_str(&assignment_json("[]")).unwrap();
        assert_eq!(a.monitor, None);
    }

    #[test]
    fn assignment_monitor_tolerates_legacy_bool() {
        // Older shepherd versions and cached assignment files carry the
        // vestigial expiry-monitoring boolean; it must parse as "no endpoint".
        let a: ManagedAssignment = serde_json::from_str(&assignment_json("true")).unwrap();
        assert_eq!(a.monitor, None);
        let a: ManagedAssignment = serde_json::from_str(&assignment_json("false")).unwrap();
        assert_eq!(a.monitor, None);
    }

    #[test]
    fn assignment_monitor_absent_or_null_is_none() {
        let a: ManagedAssignment =
            serde_json::from_str(r#"{"corgi":"corgi-01","certName":"api.example.com"}"#).unwrap();
        assert_eq!(a.monitor, None);
        let a: ManagedAssignment = serde_json::from_str(&assignment_json("null")).unwrap();
        assert_eq!(a.monitor, None);
    }

    #[test]
    fn assignment_monitor_single_endpoint_serializes_as_bare_object() {
        // Wire back-compat: existing dashboard/API clients expect a single
        // endpoint to round-trip as an object, not a one-element array.
        let a: ManagedAssignment =
            serde_json::from_str(&assignment_json(r#"{"host":"api.example.com","port":443}"#))
                .unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert!(v["monitor"].is_object());
        assert_eq!(v["monitor"]["host"], "api.example.com");
    }

    #[test]
    fn assignment_monitor_multi_endpoint_serializes_as_array() {
        let a: ManagedAssignment = serde_json::from_str(&assignment_json(
            r#"[{"host":"api.example.com","port":443},{"host":"api2.example.com","port":443}]"#,
        ))
        .unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert!(v["monitor"].is_array());
        assert_eq!(v["monitor"].as_array().unwrap().len(), 2);
    }
}
