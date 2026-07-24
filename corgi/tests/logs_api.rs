/// Log query control API tests — corgi's mTLS control port.
///
/// The actual query/filter/live-tail logic (historical + SSE follow) is
/// already thoroughly tested in credo-lib itself. These tests only cover
/// what's specific to corgi: auth enforcement on `/logs`, and that the
/// route is correctly wired to `state.logging_handle`. The test harness's
/// `AppState` always holds a `LoggingHandle::disabled()` (it can't call
/// `init_logging_with_config` — that installs a process-global tracing
/// subscriber, and the harness builds many service instances in one test
/// binary), so an authenticated request against it deterministically hits
/// the "file logging is not enabled" response rather than exercising the
/// full query logic.
use credo_test::corgi_harness::TestCorgi;

/// GET /logs requires auth — returns 401 without a Role extension.
#[tokio::test]
async fn logs_requires_auth() {
    let corgi = TestCorgi::start().await.unwrap();

    let resp = corgi
        .client
        .get(format!("{}/logs", corgi.control_url))
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
    let corgi = TestCorgi::start_authed().await.unwrap();

    let resp = corgi
        .client
        .get(format!("{}/logs", corgi.control_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}
