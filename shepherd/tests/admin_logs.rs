use credo_test::shepherd_harness::TestShepherd;

/// GET /admin/logs requires auth - returns 401 without a token/cert.
#[tokio::test]
async fn admin_logs_requires_auth() {
    let shepherd = TestShepherd::start().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "/admin/logs must require auth");
}

/// An unrecognized target value is a 400, not a panic or 500.
#[tokio::test]
async fn admin_logs_unknown_target_returns_400() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/logs?target=bogus",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=shepherd (the default) reaches credo_lib::log_query::historical_logs
/// against shepherd's own LoggingHandle - which, in the test harness, is
/// always LoggingHandle::disabled() (the harness can't call
/// init_logging_with_config: it installs a process-global tracing
/// subscriber, only allowed once per process). So a successfully-authed,
/// default-target request deterministically gets a 400 ("file logging is
/// not enabled"), proving the dispatch and delegation, not the query logic
/// itself (credo-lib's own tests already cover that in depth).
#[tokio::test]
async fn admin_logs_default_target_shepherd_reaches_handler() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!("{}/admin/logs", shepherd.dashboard_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=vigil with no Vigil configured (the test harness's default) is a
/// 400, not a panic - proves the "Vigil not configured" / "Vigil client
/// unavailable" guard rather than the real proxy call (which needs a live
/// Vigil instance - out of scope for this test).
#[tokio::test]
async fn admin_logs_target_vigil_not_configured_returns_400() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/logs?target=vigil",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// target=corgi:<name> for a name that isn't in state.corgis is a clean 404.
#[tokio::test]
async fn admin_logs_target_unknown_corgi_returns_404() {
    let shepherd = TestShepherd::start_authed().await.unwrap();

    let resp = shepherd
        .client
        .get(format!(
            "{}/admin/logs?target=corgi:nonexistent",
            shepherd.dashboard_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}
