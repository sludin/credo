/// DNS provider tests — direct calls, no real network access assumed.
use shepherd::dns_providers::he::HeProvider;
use shepherd::dns_providers::{DnsProvider, DnsProviderContext};
use std::io;
use std::sync::{Arc, Mutex};

/// A `tracing` writer that appends everything written to it into a shared buffer,
/// so a test can assert on what was logged.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Regression test for a High finding: the HE DNS provider logged the DDNS
/// credential (`password`) in cleartext at `info` on every TXT update. The
/// network call itself will fail in a sandboxed test environment (no route to
/// dyn.dns.he.net) — that's fine, since the log line under test is emitted
/// before the request is ever sent, and the returned `Err` is not asserted on.
#[tokio::test]
async fn create_never_logs_the_ddns_credential() {
    let buf = SharedBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let secret_marker = "super-secret-ddns-key-marker-zzz";
    let provider =
        HeProvider::new(&serde_json::json!({ "ddnsKey": secret_marker })).expect("valid config");
    let ctx = DnsProviderContext {
        record_name: "_acme-challenge.example.test".to_string(),
        txt_value: "some-key-authorization-value".to_string(),
        identifier: "example.test".to_string(),
    };

    let _ = provider.create(&ctx).await;

    drop(guard);
    let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("HE DNS TXT update request"),
        "expected log line missing entirely: {logged}"
    );
    assert!(
        !logged.contains(secret_marker),
        "ddns credential leaked into logs: {logged}"
    );
}
