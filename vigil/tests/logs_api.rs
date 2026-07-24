/// Log query API tests — vigil's mTLS control port.
///
/// The actual query/filter/live-tail logic (historical + SSE follow) is
/// already thoroughly tested in credo-lib itself. These tests only cover
/// what's specific to vigil: auth enforcement on `/logs`, and that the
/// route is correctly wired to `state.inner.logging_handle`. The test
/// harness's `AppState` always holds a `LoggingHandle::disabled()` (it
/// can't call `init_logging_with_config` - that installs a process-global
/// tracing subscriber, and the harness builds many service instances in
/// one test binary), so an authenticated request against it deterministically
/// hits the "file logging is not enabled" response rather than exercising
/// the full query logic.
use credo_test::vigil_harness::TestVigil;

/// GET /logs requires a valid client identity - returns 401 without one.
#[tokio::test]
async fn logs_requires_auth() {
    let vigil = TestVigil::start().await.unwrap();

    let resp = vigil
        .client
        .get(format!("{}/logs", vigil.url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "/logs must require auth");
}

/// GET /logs with a sufficient role reaches the shared handler - which,
/// against the test harness's disabled LoggingHandle, means a 400
/// Bad Request ("file logging is not enabled"), not a 401/403. This
/// proves the route and auth wiring, not the query logic itself.
#[tokio::test]
async fn logs_with_role_reaches_handler() {
    let vigil = TestVigil::start_authed().await.unwrap();

    let resp = vigil
        .client
        .get(format!("{}/logs", vigil.url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}
