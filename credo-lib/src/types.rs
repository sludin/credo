use serde::{Deserialize, Serialize};

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
