use anyhow::{Context, Result};
use chrono::Utc;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::types::Role;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    pub identity_uri: String,
    pub role: String,
    pub account_name: Option<String>,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TokenFile {
    tokens: HashMap<String, RefreshTokenEntry>,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RefreshTokenStore {
    tokens: Arc<RwLock<HashMap<String, RefreshTokenEntry>>>,
    store_path: Option<PathBuf>,
}

impl RefreshTokenStore {
    pub fn new(store_path: Option<PathBuf>) -> Self {
        let tokens = if let Some(ref path) = store_path {
            load_from_disk(path).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            tokens: Arc::new(RwLock::new(tokens)),
            store_path,
        }
    }

    pub async fn issue_token(
        &self,
        identity_uri: &str,
        role: &Role,
        account_name: Option<&str>,
        expires_at: i64,
    ) -> String {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();

        let entry = RefreshTokenEntry {
            identity_uri: identity_uri.to_string(),
            role: format!("{:?}", role).to_lowercase(),
            account_name: account_name.map(str::to_string),
            expires_at,
            created_at: Utc::now().timestamp(),
        };

        let mut tokens = self.tokens.write().await;
        tokens.insert(token.clone(), entry);
        drop(tokens);

        self.persist().await.ok();
        token
    }

    pub async fn validate_token(&self, token: &str) -> Option<RefreshTokenEntry> {
        let tokens = self.tokens.read().await;
        let entry = tokens.get(token)?.clone();
        if entry.expires_at < Utc::now().timestamp() {
            return None;
        }
        Some(entry)
    }

    pub async fn revoke_token(&self, token: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token);
        drop(tokens);
        self.persist().await.ok();
    }

    async fn persist(&self) -> Result<()> {
        let Some(ref path) = self.store_path else {
            return Ok(());
        };
        let tokens = self.tokens.read().await;
        let file = TokenFile {
            tokens: tokens.clone(),
        };
        drop(tokens);
        let content = serde_json::to_string_pretty(&file).context("Serializing refresh tokens")?;
        std::fs::write(path, content)
            .with_context(|| format!("Writing refresh tokens: {}", path.display()))
    }
}

fn load_from_disk(path: &PathBuf) -> Result<HashMap<String, RefreshTokenEntry>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Reading refresh tokens: {}", path.display()))?;
    let file: TokenFile = serde_json::from_str(&content)
        .with_context(|| format!("Parsing refresh tokens: {}", path.display()))?;

    // Prune expired
    let now = Utc::now().timestamp();
    Ok(file
        .tokens
        .into_iter()
        .filter(|(_, e)| e.expires_at > now)
        .collect())
}
