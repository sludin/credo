use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{CorgiConfig, FlockEntry};
use crate::shepherd::build_shepherd_client;
use crate::types::{ChallengeRecord, ManagedAssignment};

/// Shared application state, cheaply cloneable via Arc.
#[derive(Clone)]
pub struct AppState {
    /// Main config — hot-swappable on SIGHUP via ArcSwap (lock-free reads).
    pub config: Arc<ArcSwap<CorgiConfig>>,
    /// Cached mTLS client for Shepherd — rebuilt on SIGHUP when credentials change.
    pub shepherd_client: Arc<RwLock<reqwest::Client>>,
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
    pub fn new(config: CorgiConfig) -> anyhow::Result<Self> {
        let flock = config.flock.clone();
        let shepherd_client = match build_shepherd_client(&config) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error=%e, "mTLS client build failed at startup; using plain client (expected before bootstrap)");
                reqwest::Client::builder().use_rustls_tls().build()?
            }
        };
        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            shepherd_client: Arc::new(RwLock::new(shepherd_client)),
            flock: Arc::new(RwLock::new(flock)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            assignments: Arc::new(RwLock::new(vec![])),
            last_sync_at: Arc::new(RwLock::new(None)),
        })
    }
}
