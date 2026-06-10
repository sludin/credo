use arc_swap::ArcSwap;
use hickory_resolver::TokioResolver;
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
    /// Main config — hot-swappable on SIGHUP via ArcSwap (lock-free reads).
    pub config: Arc<ArcSwap<VigilConfig>>,
    pub inner: Arc<StateInner>,
}

pub struct StateInner {
    pub ca_metadata: RootCAMetadata,

    // DNS resolver shared across all dns-01 validations (avoids per-call setup cost).
    pub dns_resolver: TokioResolver,

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
    pub fn new(
        config: VigilConfig,
        ca_metadata: RootCAMetadata,
        bootstrap_secret: Option<String>,
    ) -> Self {
        let dns_resolver = build_dns_resolver(&config.dns_resolver_addrs);

        AppState {
            config: Arc::new(ArcSwap::from_pointee(config)),
            inner: Arc::new(StateInner {
                ca_metadata,
                dns_resolver,
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

    /// Load the current config (lock-free).
    pub fn config(&self) -> arc_swap::Guard<Arc<VigilConfig>> {
        self.config.load()
    }

    pub fn ca_metadata(&self) -> &RootCAMetadata {
        &self.inner.ca_metadata
    }
}

/// Build a DNS resolver from explicit IPs, or fall back to the system resolver.
/// Used for http-01 validation and for NS lookups in dns-01.
pub fn build_dns_resolver(addrs: &[std::net::IpAddr]) -> TokioResolver {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};

    if !addrs.is_empty() {
        let mut config = ResolverConfig::default();
        for &ip in addrs {
            config.add_name_server(NameServerConfig::udp_and_tcp(ip));
        }
        return TokioResolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .build()
        .expect("building configured DNS resolver");
    }

    TokioResolver::builder_tokio()
        .and_then(|b| b.build())
        .unwrap_or_else(|_| {
            let mut config = ResolverConfig::default();
            config.add_name_server(NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            )));
            config.add_name_server(NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(8, 8, 4, 4),
            )));
            TokioResolver::builder_with_config(
                config,
                hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
            )
            .build()
            .expect("building fallback DNS resolver")
        })
}
