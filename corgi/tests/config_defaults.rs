/// Production-tuned `shepherdSync` defaults.
///
/// Shepherd drives reconciliation (probes + sync nudges), so corgi's own
/// periodic pull is a slow safety net, not the primary sync path.
use std::io::Write;

/// Single test on purpose: `load_config` reads the `CORGI_CONFIG_PATH`
/// environment variable, which is process-global. Keeping every assertion in
/// one test avoids races with parallel test threads.
#[test]
fn shepherd_sync_defaults_are_safety_net_paced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corgi.config.json");
    let mut f = std::fs::File::create(&path).unwrap();
    write!(
        f,
        r#"{{
            "nodeId": "corgi-defaults-test",
            "commonName": "corgi-defaults-test.example.com",
            "shepherdUrl": "https://shepherd.example.com:7010"
        }}"#
    )
    .unwrap();

    std::env::set_var("CORGI_CONFIG_PATH", &path);
    let config = corgi::config::load_config().unwrap();
    std::env::remove_var("CORGI_CONFIG_PATH");

    assert_eq!(
        config.shepherd_sync.interval_seconds, 1800,
        "safety-net pull should default to 30 minutes"
    );
    assert_eq!(
        config.shepherd_sync.stale_warning_seconds, 3900,
        "stale warning should default to ~2 missed pulls"
    );
    assert!(config.shepherd_sync.enabled);
}
