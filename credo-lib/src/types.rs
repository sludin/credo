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

    /// Parses a role string, defaulting anything unrecognized to `Readonly`
    /// (least privilege) rather than escalating. Suitable for trusted,
    /// internally-produced strings (e.g. a role Shepherd itself signed into a
    /// JWT) where "this should never happen" is the only realistic case for
    /// a mismatch. At a trust boundary where the input is attacker- or
    /// user-submitted (an HTTP request body, a CLI flag), prefer
    /// `try_from_str` and reject unrecognized values outright instead of
    /// silently downgrading them.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self::try_from_str(s).unwrap_or(Role::Readonly)
    }

    /// Parses a role string, returning `None` for anything other than the
    /// three known values (case-insensitive, trimmed).
    pub fn try_from_str(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "readonly" => Some(Role::Readonly),
            _ => None,
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
    /// PEM CA bundle to additionally verify the served chain against (e.g.
    /// Vigil's `credo-catrust.pem`, or any other private root). Diagnostic
    /// only: chain trust never changes the ok/cert-mismatch/unreachable
    /// status, which stays based purely on the fingerprint compare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_path: Option<String>,
    /// Connect to this address instead of resolving `host` via DNS. `host`
    /// (or the flock entry's domain) is still sent as the TLS server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_ip: Option<std::net::IpAddr>,
}

fn default_monitor_port() -> u16 {
    443
}

/// Parses a `monitor` JSON value: a single endpoint object (the historical
/// wire shape), an array of endpoints (SAN certs / several checks per cert),
/// or the vestigial legacy boolean / null — all of which mean "no endpoint
/// configured". Shared by both the serde `deserialize_with` below and Corgi's
/// hand-rolled `serde_json::Value` config parsing.
pub fn parse_monitor_list(
    v: &serde_json::Value,
) -> Result<Option<Vec<MonitorConfig>>, serde_json::Error> {
    match v {
        serde_json::Value::Object(_) => {
            serde_json::from_value(v.clone()).map(|cfg| Some(vec![cfg]))
        }
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                return Ok(None);
            }
            items
                .iter()
                .cloned()
                .map(serde_json::from_value)
                .collect::<Result<Vec<_>, _>>()
                .map(Some)
        }
        _ => Ok(None),
    }
}

/// `deserialize_with` for a `monitor: Option<Vec<MonitorConfig>>` field —
/// see `parse_monitor_list`.
pub fn deserialize_monitor_list<'de, D>(d: D) -> Result<Option<Vec<MonitorConfig>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    match v {
        Some(val) => parse_monitor_list(&val).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// `serialize_with` for a `monitor: Option<Vec<MonitorConfig>>` field: a
/// single endpoint serializes as a bare object (so existing dashboard/API
/// clients built for the single-endpoint wire shape keep working unchanged);
/// more than one serializes as an array.
pub fn serialize_monitor_list<S>(
    value: &Option<Vec<MonitorConfig>>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(list) if list.len() == 1 => list[0].serialize(s),
        Some(list) => list.serialize(s),
        None => s.serialize_none(),
    }
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
    /// Multiple endpoints configured (e.g. a SAN cert): some checked ok,
    /// others did not.
    PartialSuccess,
}

/// A previously-archived version of a cert whose fingerprint matches what an
/// endpoint actually served — identifies a stale install (e.g. a hook that
/// never reloaded the service) instead of leaving the mismatch unexplained.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchedArchiveVersion {
    /// Archive ordinal, e.g. "006".
    pub ordinal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// not_before of the cert currently installed in live/, for the
    /// "...superseded by the version issued <date>" message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_issued_at: Option<String>,
}

/// Diagnostic detail for a single monitored endpoint: what was dialed, what
/// was seen. Kept even on failure so a false "mismatch" caused by DNS drift
/// or a wrong port is distinguishable from a real fingerprint change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointCheckResult {
    pub host: String,
    pub port: u16,
    pub sni: String,
    /// The concrete address actually dialed (post DNS resolution or
    /// `resolve_ip` override), e.g. "203.0.113.5:443".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_fingerprint: Option<String>,
    /// Common name of the served leaf, e.g. to tell at a glance which cert
    /// an endpoint is actually presenting on a mismatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_common_name: Option<String>,
    /// SAN entries (DNS/URI/IPv4) of the served leaf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seen_san_names: Vec<String>,
    /// Whether the served chain verified against `MonitorConfig::ca_path`.
    /// `None` when no CA was configured for this endpoint. Diagnostic only —
    /// never affects `status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_trusted: Option<bool>,
    pub status: MonitorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_archive_version: Option<MatchedArchiveVersion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorResult {
    pub status: MonitorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    /// Leaf fingerprint the endpoint actually served (set on ok/mismatch).
    /// Mirrors the single endpoint's fingerprint; left `None` when several
    /// endpoints are configured, since it would be ambiguous — see `endpoints`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Per-endpoint breakdown; always populated once checked, even for the
    /// single-endpoint case, so the exact address/SNI/fingerprint dialed is
    /// always visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<EndpointCheckResult>,
}

impl MonitorResult {
    pub fn unmonitored() -> Self {
        Self {
            status: MonitorStatus::Unmonitored,
            checked_at: None,
            seen_fingerprint: None,
            error: None,
            endpoints: Vec::new(),
        }
    }

    pub fn pending() -> Self {
        Self {
            status: MonitorStatus::Pending,
            checked_at: None,
            seen_fingerprint: None,
            error: None,
            endpoints: Vec::new(),
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
    fn role_from_str_parses_known_values_case_insensitively() {
        assert_eq!(Role::from_str("admin"), Role::Admin);
        assert_eq!(Role::from_str("Operator"), Role::Operator);
        assert_eq!(Role::from_str("  READONLY  "), Role::Readonly);
    }

    /// Regression test for a Medium finding: an unrecognized role string used
    /// to silently escalate to Admin. It must now default to Readonly (least
    /// privilege), not Admin.
    #[test]
    fn role_from_str_defaults_unrecognized_input_to_readonly_not_admin() {
        assert_eq!(Role::from_str("not-a-real-role"), Role::Readonly);
        assert_eq!(Role::from_str(""), Role::Readonly);
        assert_eq!(Role::from_str("admni"), Role::Readonly);
    }

    #[test]
    fn role_try_from_str_rejects_unrecognized_input() {
        assert_eq!(Role::try_from_str("admin"), Some(Role::Admin));
        assert_eq!(Role::try_from_str("not-a-real-role"), None);
        assert_eq!(Role::try_from_str(""), None);
    }

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
        assert_eq!(
            serde_json::to_value(MonitorStatus::PartialSuccess).unwrap(),
            "partial-success"
        );
    }

    #[test]
    fn monitor_result_camel_case_and_omits_absent_fields() {
        let res = MonitorResult {
            status: MonitorStatus::Ok,
            checked_at: Some("2026-07-18T00:00:00Z".into()),
            seen_fingerprint: None,
            error: None,
            endpoints: Vec::new(),
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["checkedAt"], "2026-07-18T00:00:00Z");
        assert!(v.get("seenFingerprint").is_none());
        assert!(v.get("error").is_none());
        assert!(v.get("endpoints").is_none());
    }

    #[test]
    fn monitor_config_accepts_ca_path_and_resolve_ip() {
        let cfg: MonitorConfig = serde_json::from_str(
            r#"{"host":"corgi-01.vigilcert.com","caPath":"/etc/credo/credo-catrust.pem","resolveIp":"203.0.113.5"}"#,
        )
        .unwrap();
        assert_eq!(cfg.ca_path.as_deref(), Some("/etc/credo/credo-catrust.pem"));
        assert_eq!(
            cfg.resolve_ip,
            Some("203.0.113.5".parse::<std::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn monitor_config_omits_ca_path_and_resolve_ip_when_absent() {
        let cfg: MonitorConfig = serde_json::from_str(r#"{"host":"api.example.com"}"#).unwrap();
        assert_eq!(cfg.ca_path, None);
        assert_eq!(cfg.resolve_ip, None);
        let v = serde_json::to_value(&cfg).unwrap();
        assert!(v.get("caPath").is_none());
        assert!(v.get("resolveIp").is_none());
    }
}
