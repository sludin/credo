use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::config::VigilConfig;
use crate::types::{AcmeAccountRecord, AcmeAuthz, AcmeChallenge, AcmeOrder, RootCAMetadata};

// ---------------------------------------------------------------------------
// AppState: Arc-wrapped shared state for all request handlers
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<StateInner>,
}

pub struct StateInner {
    pub config: VigilConfig,
    pub ca_metadata: RootCAMetadata,

    // File-backed storage (protected by Mutex for write serialization)
    pub storage_lock: Mutex<()>,

    // ACME in-memory state
    // TODO(resilience): orders, authzs, challenges, and nonces are held only in memory
    // and are lost on restart. See docs/vigil-rs-port-plan.md for the SQLite persistence plan.
    pub acme_accounts: RwLock<HashMap<String, AcmeAccountRecord>>,
    pub acme_orders: RwLock<HashMap<String, AcmeOrder>>,
    pub acme_authzs: RwLock<HashMap<String, AcmeAuthz>>,
    pub acme_challenges: RwLock<HashMap<String, AcmeChallenge>>,
    pub nonces: Mutex<HashSet<String>>,
    pub acme_id_counter: Mutex<u64>,

    // Bootstrap mode: Some(secret_hex) while active, None after first use or when not in bootstrap
    pub bootstrap_secret: Mutex<Option<String>>,
}

impl AppState {
    pub fn new(config: VigilConfig, ca_metadata: RootCAMetadata, bootstrap_secret: Option<String>) -> Self {
        AppState {
            inner: Arc::new(StateInner {
                config,
                ca_metadata,
                storage_lock: Mutex::new(()),
                acme_accounts: RwLock::new(HashMap::new()),
                acme_orders: RwLock::new(HashMap::new()),
                acme_authzs: RwLock::new(HashMap::new()),
                acme_challenges: RwLock::new(HashMap::new()),
                nonces: Mutex::new(HashSet::new()),
                acme_id_counter: Mutex::new(0),
                bootstrap_secret: Mutex::new(bootstrap_secret),
            }),
        }
    }

    pub fn config(&self) -> &VigilConfig {
        &self.inner.config
    }

    pub fn ca_metadata(&self) -> &RootCAMetadata {
        &self.inner.ca_metadata
    }
}
