use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{CorgiConfig, FlockEntry};
use crate::shepherd::build_shepherd_client;
use crate::types::{ChallengeRecord, InstallIssue, ManagedAssignment};

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
    /// Serializes reconcile passes: the periodic loop and shepherd-triggered
    /// sync nudges (`POST /sync/assignments`) must not reconcile concurrently.
    pub sync_lock: Arc<tokio::sync::Mutex<()>>,
    /// Latest endpoint-monitor result per cert name (reported via /flock).
    pub monitor_results: Arc<RwLock<HashMap<String, credo_lib::types::MonitorResult>>>,
    /// Ongoing install failures per cert name (reported via /flock). Cleared
    /// on the next successful install; see `sync::record_install_failure`.
    pub install_issues: Arc<RwLock<HashMap<String, InstallIssue>>>,
    /// Handle to this service's rotating log file + live broadcast, used by
    /// the `/logs` route. `credo_lib::LoggingHandle::disabled()` in tests,
    /// since the test harness can't call `init_logging_with_config` (it
    /// installs a process-global tracing subscriber, only allowed once per
    /// process, and the harness builds many instances in one test binary).
    pub logging_handle: Arc<credo_lib::LoggingHandle>,
}

impl AppState {
    pub fn new(
        config: CorgiConfig,
        logging_handle: Arc<credo_lib::LoggingHandle>,
    ) -> anyhow::Result<Self> {
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
            sync_lock: Arc::new(tokio::sync::Mutex::new(())),
            monitor_results: Arc::new(RwLock::new(HashMap::new())),
            install_issues: Arc::new(RwLock::new(HashMap::new())),
            logging_handle,
        })
    }
}
