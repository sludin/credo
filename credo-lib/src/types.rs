use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Hook reference — used by Corgi for cert-install hooks; shared on the wire
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HookRef {
    Simple(String),
    Parameterized {
        name: String,
        args: HashMap<String, String>,
    },
}

impl HookRef {
    pub fn name(&self) -> &str {
        match self {
            HookRef::Simple(s) => s,
            HookRef::Parameterized { name, .. } => name,
        }
    }

    pub fn args(&self) -> HashMap<String, String> {
        match self {
            HookRef::Simple(_) => HashMap::new(),
            HookRef::Parameterized { args, .. } => args.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Readonly,
}

impl Role {
    pub fn rank(&self) -> u8 {
        match self {
            Role::Readonly => 0,
            Role::Operator => 1,
            Role::Admin => 2,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "operator" => Role::Operator,
            "readonly" => Role::Readonly,
            _ => Role::Admin,
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint monitoring — shared between Shepherd (assignment config) and Corgi
// (checker + flock report)
// ---------------------------------------------------------------------------

/// Endpoint to verify a certificate against: a periodic TLS handshake to
/// host:port checks that the served leaf matches the installed cert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorConfig {
    pub host: String,
    #[serde(default = "default_monitor_port")]
    pub port: u16,
    #[serde(default)]
    pub protocol: MonitorProtocol,
}

fn default_monitor_port() -> u16 {
    443
}

/// How to reach the certificate. Both variants are a direct TLS handshake in
/// v1; the enum exists so `starttls-*` variants can be added without a schema
/// break.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MonitorProtocol {
    #[default]
    Https,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MonitorStatus {
    Ok,
    CertMismatch,
    Unreachable,
    /// No endpoint configured for this cert.
    Unmonitored,
    /// Endpoint configured but not checked yet (e.g. right after startup).
    Pending,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorResult {
    pub status: MonitorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    /// Leaf fingerprint the endpoint actually served (set on ok/mismatch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl MonitorResult {
    pub fn unmonitored() -> Self {
        Self {
            status: MonitorStatus::Unmonitored,
            checked_at: None,
            seen_fingerprint: None,
            error: None,
        }
    }

    pub fn pending() -> Self {
        Self {
            status: MonitorStatus::Pending,
            checked_at: None,
            seen_fingerprint: None,
            error: None,
        }
    }
}

/// Identity extracted from a client certificate (mTLS or proxy headers).
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub fingerprint256: String,
    pub subject: String,
    pub san_uris: Vec<String>,
    pub san_dns: Vec<String>,
}

impl ClientIdentity {
    /// Short display label for request logs: last URI path segment, or subject.
    pub fn display_name(&self) -> &str {
        for uri in &self.san_uris {
            let seg = uri.trim_end_matches('/').rsplit('/').next().unwrap_or(uri);
            if !seg.is_empty() {
                return seg;
            }
        }
        &self.subject
    }

    pub fn is_anonymous(&self) -> bool {
        self.fingerprint256.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_config_defaults_port_and_protocol() {
        let cfg: MonitorConfig = serde_json::from_str(r#"{"host":"api.example.com"}"#).unwrap();
        assert_eq!(cfg.host, "api.example.com");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.protocol, MonitorProtocol::Https);
    }

    #[test]
    fn monitor_config_accepts_explicit_fields() {
        let cfg: MonitorConfig =
            serde_json::from_str(r#"{"host":"db.internal","port":5432,"protocol":"tls"}"#).unwrap();
        assert_eq!(cfg.host, "db.internal");
        assert_eq!(cfg.port, 5432);
        assert_eq!(cfg.protocol, MonitorProtocol::Tls);
    }

    #[test]
    fn monitor_status_serializes_kebab_case() {
        assert_eq!(serde_json::to_value(MonitorStatus::Ok).unwrap(), "ok");
        assert_eq!(
            serde_json::to_value(MonitorStatus::CertMismatch).unwrap(),
            "cert-mismatch"
        );
        assert_eq!(
            serde_json::to_value(MonitorStatus::Unreachable).unwrap(),
            "unreachable"
        );
        assert_eq!(
            serde_json::to_value(MonitorStatus::Unmonitored).unwrap(),
            "unmonitored"
        );
        assert_eq!(
            serde_json::to_value(MonitorStatus::Pending).unwrap(),
            "pending"
        );
    }

    #[test]
    fn monitor_result_camel_case_and_omits_absent_fields() {
        let res = MonitorResult {
            status: MonitorStatus::Ok,
            checked_at: Some("2026-07-18T00:00:00Z".into()),
            seen_fingerprint: None,
            error: None,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["checkedAt"], "2026-07-18T00:00:00Z");
        assert!(v.get("seenFingerprint").is_none());
        assert!(v.get("error").is_none());
    }
}
