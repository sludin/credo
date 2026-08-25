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
// Serialization
// ---------------------------------------------------------------------------

/// Unix signals are process-global — the credo_signal test below sends a real
/// SIGHUP to this test binary's own PID, and the kernel may deliver it to any
/// thread in the process. Run cargo's default parallel test threads and that
/// signal can land while an unrelated test on another thread is mid-flight,
/// which was observed to spuriously drop that test's tracing-capture events.
/// Every test in this file takes this lock for its full duration (held across
/// `.await`, hence `tokio::sync::Mutex` rather than `std::sync::Mutex`) so
/// only one runs at a time, regardless of `--test-threads`.
static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serialize() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().await
}

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
        log_hook_output: false,
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
    let _serial = serialize().await;
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
    let _serial = serialize().await;
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

/// A hook that exits non-zero must always log at ERROR with its stdout,
/// stderr, and exit code — regardless of `log_hook_output` — so a failing
/// post-install hook is visible without opting in to anything.
#[tokio::test]
async fn run_hooks_logged_logs_error_on_nonzero_exit() {
    let _serial = serialize().await;
    let dir = TempDir::new().unwrap();
    let mut config = make_config(&dir);
    config.service_hooks.insert(
        "broken-reload".to_string(),
        ServiceHookDef::Simple(vec![
            "echo out-marker; echo err-marker 1>&2; exit 7".to_string()
        ]),
    );

    let mut entry = empty_entry("failing.example.com", &dir);
    entry.hooks = Some(vec![HookRef::Simple("broken-reload".to_string())]);

    let events = capture_events(async {
        run_hooks_logged(&entry, &config).await;
    })
    .await;

    let failure_event = events
        .iter()
        .find(|e| e.message == "Hook failed")
        .expect("expected a \"Hook failed\" ERROR event to be logged");

    assert!(failure_event
        .fields
        .get("hook")
        .is_some_and(|v| v.contains("broken-reload")));
    assert!(failure_event
        .fields
        .get("exit_code")
        .is_some_and(|v| v.contains('7')));
    assert!(failure_event
        .fields
        .get("stdout")
        .is_some_and(|v| v.contains("out-marker")));
    assert!(failure_event
        .fields
        .get("stderr")
        .is_some_and(|v| v.contains("err-marker")));

    // A failed hook still must not silently succeed elsewhere.
    assert!(!events.iter().any(|e| e.message == "Hook executed"));
}

/// A successful hook's INFO "Hook executed" event omits stdout/stderr by
/// default — success output is noisy and not worth logging unless asked for.
#[tokio::test]
async fn run_hooks_logged_omits_output_on_success_by_default() {
    let _serial = serialize().await;
    let dir = TempDir::new().unwrap();
    let mut config = make_config(&dir);
    assert!(!config.log_hook_output, "default must be opt-in (false)");
    config.service_hooks.insert(
        "quiet-reload".to_string(),
        ServiceHookDef::Simple(vec!["echo should-not-appear".to_string()]),
    );

    let mut entry = empty_entry("quiet.example.com", &dir);
    entry.hooks = Some(vec![HookRef::Simple("quiet-reload".to_string())]);

    let events = capture_events(async {
        run_hooks_logged(&entry, &config).await;
    })
    .await;

    let hook_event = events
        .iter()
        .find(|e| e.message == "Hook executed")
        .expect("expected a \"Hook executed\" event to be logged");
    assert!(!hook_event.fields.contains_key("stdout"));
}

/// With `log_hook_output` enabled, a successful hook's stdout/stderr ride
/// along on the same INFO "Hook executed" event.
#[tokio::test]
async fn run_hooks_logged_includes_output_on_success_when_enabled() {
    let _serial = serialize().await;
    let dir = TempDir::new().unwrap();
    let mut config = make_config(&dir);
    config.log_hook_output = true;
    config.service_hooks.insert(
        "verbose-reload".to_string(),
        ServiceHookDef::Simple(vec!["echo should-appear".to_string()]),
    );

    let mut entry = empty_entry("verbose.example.com", &dir);
    entry.hooks = Some(vec![HookRef::Simple("verbose-reload".to_string())]);

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
        .get("stdout")
        .is_some_and(|v| v.contains("should-appear")));
}

// ---------------------------------------------------------------------------
// CredoSignal — the tighter, in-process hook kind for credo's own services
// ---------------------------------------------------------------------------

/// A CredoSignal hook must deliver a real SIGHUP (not just report success in
/// its HookResult) and must NOT fire for an unrelated hook. Both cases live
/// in one test function, not two `#[tokio::test]`s: `tokio::signal::unix`
/// SIGHUP listeners are process-global, so a sibling test self-signalling
/// concurrently could otherwise produce a false positive here.
#[tokio::test]
async fn credo_signal_hook_delivers_real_sighup_and_only_when_configured() {
    let _serial = serialize().await;
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::time::{timeout, Duration};

    let dir = TempDir::new().unwrap();
    let mut config = make_config(&dir);

    let pid_file = dir.path().join("self.pid");
    std::fs::write(&pid_file, format!("{}\n", std::process::id())).unwrap();
    config.service_hooks.insert(
        "corgi-self-reload".to_string(),
        ServiceHookDef::CredoSignal {
            pid_file: pid_file.clone(),
            signal: nix::sys::signal::Signal::SIGHUP,
        },
    );

    let mut hup = signal(SignalKind::hangup()).expect("registering SIGHUP listener");

    // Positive case: entry's hook is the CredoSignal — expect a real SIGHUP.
    let mut own_entry = empty_entry("corgi-01.credo.test", &dir);
    own_entry.hooks = Some(vec![HookRef::Simple("corgi-self-reload".to_string())]);

    let results = run_hooks_logged(&own_entry, &config).await;
    assert!(results.iter().any(|r| r.hook == "corgi-self-reload"));

    timeout(Duration::from_secs(2), hup.recv())
        .await
        .expect("SIGHUP should have been delivered within 2s")
        .expect("signal stream should not have closed");

    // Negative case: an unrelated cert with no hooks must not self-signal.
    let mut other_entry = empty_entry("nginx.example.com", &dir);
    other_entry.hooks = Some(vec![]);
    run_hooks_logged(&other_entry, &config).await;

    let result = timeout(Duration::from_millis(300), hup.recv()).await;
    assert!(result.is_err(), "unrelated hook run must not send a SIGHUP");
}
