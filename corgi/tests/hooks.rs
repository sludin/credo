/// Hook execution logging — regression coverage for the corgi-02.vigilcert.com
/// incident where `/flock/<name>/install` ran hooks silently because it called
/// `run_hooks` directly instead of the logging wrapper. All three call sites
/// (sync reconcile, flock_install, flock_restart) must go through
/// `run_hooks_logged` so a "Hook executed" event is always emitted.
use corgi::config::{
    AuthConfig, AuthMode, CorgiConfig, FilePolicyConfig, FlockEntry, HttpChallengeConfig,
    MtlsConfig, ProxyAuthConfig, ServiceHookDef, ShepherdSyncConfig, TlsConfig,
};
use corgi::hooks::run_hooks_logged;
use credo_lib::types::HookRef;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tracing::field::{Field, Visit};
use tracing::Event;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_config(dir: &TempDir) -> CorgiConfig {
    CorgiConfig {
        node_id: "corgi-01".to_string(),
        common_name: "corgi-01.credo.test".to_string(),
        identity_uri: Some("vigil://credo/node/corgi-01".to_string()),
        shepherd_url: "http://127.0.0.1:0".to_string(),
        dns_override: HashMap::new(),
        tls: TlsConfig {
            cert_path: dir.path().join("tls.pem"),
            key_path: dir.path().join("tls.key"),
        },
        mtls: MtlsConfig {
            cert_path: dir.path().join("mtls.pem"),
            key_path: dir.path().join("mtls.key"),
            ca_path: None,
        },
        cert_store_dir: dir.path().join("certstore"),
        flock: vec![],
        http_challenge: HttpChallengeConfig {
            enabled: false,
            port: 0,
            bind: "127.0.0.1".to_string(),
        },
        mtls_port: 0,
        bind: "127.0.0.1".to_string(),
        service_hooks: HashMap::new(),
        default_hooks: vec![],
        log_level: credo_lib::LogLevel::Warn,
        logging: credo_lib::LoggingConfig::default(),
        auth: AuthConfig {
            mode: AuthMode::Mtls,
        },
        rbac_identities: vec![],
        proxy_auth: ProxyAuthConfig {
            client_cert_header: "X-Client-Cert".to_string(),
            client_fingerprint_header: "X-Client-Fingerprint".to_string(),
            client_subject_header: "X-Client-Subject".to_string(),
            client_san_uri_header: "X-Client-San-Uri".to_string(),
        },
        shepherd_sync: ShepherdSyncConfig {
            enabled: false,
            interval_seconds: 60,
            stale_warning_seconds: 300,
            assignments_cache_path: dir.path().join("assignments.json"),
        },
        monitor_interval_seconds: 900,
        config_path: dir.path().join("corgi.config.json"),
        accounts_path: dir.path().join("corgi.accounts.json"),
        chain_path: None,
        fullchain_path: None,
        csr_path: None,
        file_policy: FilePolicyConfig {
            owner: None,
            group: None,
            cert_mode: None,
            key_mode: None,
        },
    }
}

fn empty_entry(name: &str, dir: &TempDir) -> FlockEntry {
    FlockEntry {
        name: name.to_string(),
        path: dir.path().join(format!("{name}.cert.pem")),
        key_path: dir.path().join(format!("{name}.key.pem")),
        chain_path: None,
        fullchain_path: None,
        csr_path: None,
        domain: None,
        monitor: None,
        hooks: None,
        csr_subject: None,
        identity_uri: None,
        sans: vec![],
        cert_mode: None,
        key_mode: None,
        cert_owner: None,
        cert_group: None,
        key_owner: None,
        key_group: None,
    }
}

/// Captures every tracing event's message plus its string-ish fields, so
/// tests can assert on log output without depending on a formatting layer.
#[derive(Default, Clone)]
struct CapturedEvent {
    message: String,
    fields: HashMap<String, String>,
}

#[derive(Default)]
struct RecordingVisitor {
    event: CapturedEvent,
}

impl Visit for RecordingVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.store(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.store(field, format!("{value:?}"));
    }
}

impl RecordingVisitor {
    fn store(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.event.message = value;
        } else {
            self.event.fields.insert(field.name().to_string(), value);
        }
    }
}

struct RecordingLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> Layer<S> for RecordingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = RecordingVisitor::default();
        event.record(&mut visitor);
        self.events.lock().unwrap().push(visitor.event);
    }
}

/// Runs `f` with a thread-local tracing subscriber installed, returning every
/// event it emitted. Uses `set_default` (not `with_default`) because `f` is a
/// future to be awaited in place — nesting another runtime via `block_on`
/// inside an already-running `#[tokio::test]` task would panic.
async fn capture_events<F: std::future::Future<Output = ()>>(f: F) -> Vec<CapturedEvent> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let layer = RecordingLayer {
        events: events.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    f.await;
    drop(_guard);
    let events = events.lock().unwrap();
    events.clone()
}

// ---------------------------------------------------------------------------
// run_hooks_logged
// ---------------------------------------------------------------------------

/// Every call site (sync reconcile, flock_install, flock_restart) now shares
/// this function, so a successful hook run must always produce an INFO
/// "Hook executed" event — this was previously missing on the
/// flock_install path, which is what made real hook runs invisible in logs.
#[tokio::test]
async fn run_hooks_logged_emits_hook_executed_event() {
    let dir = TempDir::new().unwrap();
    let mut config = make_config(&dir);
    config.service_hooks.insert(
        "restart-service".to_string(),
        ServiceHookDef::Simple(vec!["true".to_string()]),
    );

    let mut entry = empty_entry("corgi-02.vigilcert.com", &dir);
    entry.hooks = Some(vec![HookRef::Simple("restart-service".to_string())]);

    let events = capture_events(async {
        run_hooks_logged(&entry, &config).await;
    })
    .await;

    let hook_event = events
        .iter()
        .find(|e| e.message == "Hook executed")
        .expect("expected a \"Hook executed\" event to be logged");

    assert!(hook_event
        .fields
        .get("hook")
        .is_some_and(|v| v.contains("restart-service")));
    assert!(hook_event
        .fields
        .get("cert_name")
        .is_some_and(|v| v.contains("corgi-02.vigilcert.com")));
}

/// No hooks configured means no "Hook executed" events — silence here is
/// legitimate (distinct from silence caused by a missing log call).
#[tokio::test]
async fn run_hooks_logged_emits_nothing_when_no_hooks_configured() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let mut entry = empty_entry("no-hooks-cert", &dir);
    entry.hooks = Some(vec![]);

    let events = capture_events(async {
        run_hooks_logged(&entry, &config).await;
    })
    .await;

    assert!(!events.iter().any(|e| e.message == "Hook executed"));
}
