use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{CorgiConfig, FlockEntry};
use crate::types::{ChallengeRecord, ManagedAssignment};

/// Shared application state, cheaply cloneable via Arc.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<CorgiConfig>,
    /// Active flock entries (merged from config + Shepherd assignments).
    pub flock: Arc<RwLock<Vec<FlockEntry>>>,
    /// ACME HTTP-01 challenge tokens in-memory.
    pub challenges: Arc<RwLock<HashMap<String, ChallengeRecord>>>,
    /// Last fetched Shepherd assignments (used for fail-stale).
    pub assignments: Arc<RwLock<Vec<ManagedAssignment>>>,
    /// Last successful sync timestamp (Unix seconds).
    pub last_sync_at: Arc<RwLock<Option<u64>>>,
}

impl AppState {
    pub fn new(config: CorgiConfig) -> Self {
        let flock = config.flock.clone();
        Self {
            config: Arc::new(config),
            flock: Arc::new(RwLock::new(flock)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            assignments: Arc::new(RwLock::new(vec![])),
            last_sync_at: Arc::new(RwLock::new(None)),
        }
    }
}
