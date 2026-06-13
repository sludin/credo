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
