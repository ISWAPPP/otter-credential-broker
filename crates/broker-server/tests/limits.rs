#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Limits on three levels, the token, its tenant and the provider for every
//! tenant: each level only counts what the levels below it let through,
//! refusals name the level, and the provider's limits reload with it.

mod common;

use std::path::Path;
use std::time::Duration;

use axum::http::StatusCode;
use broker_core::CallContext;
use broker_core::limits::Limits;
use broker_server::ServerConfig;
use broker_server::reload::{ReloadResult, Reloader};
use common::*;
use futures_util::future::join_all;
use serde_json::{Value, json};

const ADMIN: CallContext<'static> = CallContext { actor: "core", trace_id: None };

/// The provider `anthropic` on a fake upstream, with `limits` for every
/// tenant; tenant-a and tenant-b have keys.
async fn env_with(limits: &str) -> Option<Env> {
    let (upstream, addr) = start_upstream().await;
    let env = Env::with_llm(EnvOptions::default(), llm_config(&provider(&addr.to_string(), limits)), (upstream, addr))
        .await?;
    env.seed_keys().await;
    Some(env)
}

fn provider(addr: &str, limits: &str) -> String {
    format!(
        r#"
        [llm.providers.anthropic]
        kind = "anthropic"
        base_url = "http://{addr}"
        allow_http = true
        limits = {{ {limits} }}

        [[llm.pricing]]
        provider = "anthropic"
        model = "test-model"
        input = 3.0
        output = 15.0

        [[llm.pricing]]
        provider = "anthropic"
        model = "slow-json"
        input = 1.0
        output = 1.0
        "#
    )
}

async fn set_limits(env: &Env, tenant: &str, limits: Value) {
    let limits: Limits = serde_json::from_value(limits).unwrap();
    env.state.keeper.set_tenant_limits(ADMIN, tenant, limits).await.unwrap();
}

async fn send(env: &Env, token: &str) -> TestResponse {
    env.llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", token)], Some(anthropic_body("test-model", false)))
        .await
}

/// The level a refusal names, in its body and in `ocb-limit-level`, which
/// must agree.
fn level(r: &TestResponse) -> String {
    let body = r.json()["error"]["level"].as_str().unwrap_or_default().to_owned();
    let header = r.headers.get("ocb-limit-level").map(|v| v.to_str().unwrap().to_owned()).unwrap_or_default();
    assert_eq!(body, header, "{}", r.text());
    body
}

fn counter(series: &str) -> u64 {
    let text = telemetry().metrics.render();
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse::<f64>().ok())).map_or(0, |v| v as u64)
}

#[tokio::test]
async fn a_token_far_over_its_rate_takes_nothing_from_its_neighbours() {
    let Some(env) = env_with("rpm = 6").await else { return };
    env.clock.set(T0 - T0 % 60 + 1);
    set_limits(&env, "tenant-a", json!({"rpm": 4})).await;
    let (hammer, _) = env.llm_token("tenant-a", json!({"rate_limit_per_minute": 2})).await;
    let (neighbour, _) = env.llm_token("tenant-a", json!({"rate_limit_per_minute": 10})).await;
    let (other, _) = env.llm_token("tenant-b", json!({"rate_limit_per_minute": 10})).await;
    let denied_before =
        counter("ocb_limit_denials_total{level=\"token\",kind=\"rpm\",provider=\"anthropic\",tenant=\"tenant-a\"}");

    // Ten times its rate, all at once: two pass, the rest are refused by
    // the token's own limit.
    let hammered = join_all((0..20).map(|_| send(&env, &hammer))).await;
    let ok = hammered.iter().filter(|r| r.status == StatusCode::OK).count();
    assert_eq!(ok, 2);
    for r in hammered.iter().filter(|r| r.status != StatusCode::OK) {
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.text());
        assert_eq!(level(r), "token");
        assert_eq!(r.json()["error"]["code"], "rate_limited");
        assert_eq!(r.headers.get("retry-after").unwrap(), "59");
    }
    assert_eq!(
        counter("ocb_limit_denials_total{level=\"token\",kind=\"rpm\",provider=\"anthropic\",tenant=\"tenant-a\"}"),
        denied_before + 18
    );

    // Its neighbour in the tenant and another tenant get the rest of the
    // tenant's (4) and the provider's (6) requests: not a single 429.
    for token in [&neighbour, &neighbour, &other, &other] {
        let r = send(&env, token).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    }
    // Then the tenant's limit refuses, without counting for the provider...
    let r = send(&env, &neighbour).await;
    assert_eq!((r.status, level(&r)), (StatusCode::TOO_MANY_REQUESTS, "tenant".to_owned()));
    let message = r.json()["error"]["message"].as_str().unwrap().to_owned();
    assert_eq!(message, "rate limit of the tenant exceeded (4 requests per minute), retry after 59s");
    // ... and the provider's, without numbers: they come from every tenant.
    let r = send(&env, &other).await;
    assert_eq!((r.status, level(&r)), (StatusCode::TOO_MANY_REQUESTS, "global".to_owned()));
    assert_eq!(r.json()["error"]["message"], "rate limit of provider anthropic exceeded, retry after 59s");
    assert_eq!(r.json()["error"]["type"], "rate_limit_error");

    // A new minute is a new window on every level.
    env.clock.advance(60);
    for token in [&hammer, &neighbour, &other] {
        assert_eq!(send(&env, token).await.status, StatusCode::OK);
    }
    env.cleanup().await;
}

#[tokio::test]
async fn requests_in_flight_are_capped_per_tenant_and_provider() {
    let Some(env) = env_with("concurrent = 2").await else { return };
    set_limits(&env, "tenant-a", json!({"concurrent": 1})).await;
    let (a1, _) = env.llm_token("tenant-a", json!({})).await;
    let (a2, _) = env.llm_token("tenant-a", json!({})).await;
    let (b1, _) = env.llm_token("tenant-b", json!({})).await;
    let (b2, _) = env.llm_token("tenant-b", json!({})).await;
    let slow = |token: &str| {
        let (public, token) = (env.public.clone(), token.to_owned());
        tokio::spawn(async move {
            let h = [("x-api-key", token.as_str())];
            raw_call(&public, "POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("slow-json", false)))
                .await
                .status
        })
    };
    // a1 holds tenant-a's only slot for 1.5 s.
    let first = slow(&a1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = send(&env, &a2).await;
    assert_eq!((r.status, level(&r)), (StatusCode::TOO_MANY_REQUESTS, "tenant".to_owned()));
    assert_eq!(
        (r.json()["error"]["code"].as_str(), r.headers.get("retry-after").unwrap().to_str().unwrap()),
        (Some("too_many_in_flight"), "1")
    );
    // tenant-b takes the provider's second slot; then the provider is full.
    let second = slow(&b1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        (env.state.proxy.inflight().tenant_count("tenant-a"), env.state.proxy.inflight().provider_count("anthropic")),
        (1, 2)
    );
    let r = send(&env, &b2).await;
    assert_eq!((r.status, level(&r)), (StatusCode::TOO_MANY_REQUESTS, "global".to_owned()));
    assert_eq!(r.json()["error"]["message"], "too many requests in flight for provider anthropic");
    assert_eq!((first.await.unwrap(), second.await.unwrap()), (StatusCode::OK, StatusCode::OK));
    env.settle().await;
    assert_eq!(env.state.proxy.inflight().provider_count("anthropic"), 0);
    for token in [&a2, &b2] {
        assert_eq!(send(&env, token).await.status, StatusCode::OK, "the slots are free again");
    }
    env.cleanup().await;
}

/// Replaces the file the way a ConfigMap update does: all at once.
fn write(path: &Path, content: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

#[tokio::test]
async fn limits_of_a_provider_reload_with_it() {
    let (upstream, addr) = start_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    write(&path, &provider(&addr.to_string(), ""));
    let cfg = ServerConfig::load(Some(&path)).unwrap();
    let Some(env) = Env::with_llm(EnvOptions::default(), cfg.llm.clone(), (upstream, addr)).await else { return };
    let mut reloader = Reloader::new(Some(path.clone()), cfg, env.state.proxy.clone());
    assert_eq!(reloader.check(), None);
    env.seed_keys().await;
    env.clock.set(T0 - T0 % 60 + 1);
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    for _ in 0..3 {
        assert_eq!(send(&env, &token).await.status, StatusCode::OK);
    }
    // A rate limit for every tenant arrives with a reload; its window
    // starts with the first request after it.
    write(&path, &provider(&addr.to_string(), "rpm = 1"));
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_eq!(send(&env, &token).await.status, StatusCode::OK);
    let r = send(&env, &token).await;
    assert_eq!((r.status, level(&r)), (StatusCode::TOO_MANY_REQUESTS, "global".to_owned()));
    // And goes with the next one.
    write(&path, &provider(&addr.to_string(), ""));
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_eq!(send(&env, &token).await.status, StatusCode::OK);
    env.cleanup().await;
}

/// 2030-03-17T00:00:00Z, the day of `T0`.
const DAY0: i64 = T0 - T0 % 86_400;

type SpendRow = (String, String, String, String, i64, i64, i64);

/// Every row of `limit_spend`: level, tenant, provider, period, its start,
/// spent and reserved tokens.
async fn spend(env: &Env) -> Vec<SpendRow> {
    sqlx::query_as(
        "SELECT level, tenant_id, provider, period_kind, period_start, spent_tokens, reserved_tokens FROM limit_spend
         ORDER BY level, tenant_id, provider, period_kind, period_start",
    )
    .fetch_all(env.state.keeper.store().pool())
    .await
    .unwrap()
}

fn row(level: &str, tenant: &str, provider: &str, start: i64, spent: i64, reserved: i64) -> SpendRow {
    (level.into(), tenant.into(), provider.into(), "day".into(), start, spent, reserved)
}

/// A request of `model` in a task of its own.
fn in_background(env: &Env, token: &str, model: &str, stream: bool) -> tokio::task::JoinHandle<TestResponse> {
    let (public, token, body) = (env.public.clone(), token.to_owned(), anthropic_body(model, stream));
    tokio::spawn(async move {
        raw_call(&public, "POST", "/llm/anthropic/v1/messages", &[("x-api-key", token.as_str())], Some(body)).await
    })
}

/// Waits until the requests in flight have reserved `tokens` on the
/// tenant's row.
async fn reserved(env: &Env, tenant: &str, tokens: i64) {
    for _ in 0..200 {
        if spend(env).await.iter().any(|r| r.1 == tenant && r.6 == tokens) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {tokens} reserved tokens for {tenant}: {:?}", spend(env).await);
}

#[tokio::test]
async fn budgets_count_what_requests_in_flight_reserved_until_they_are_accounted() {
    let Some(env) = env_with("budget_tokens = { day = 1_000 }").await else { return };
    set_limits(&env, "tenant-a", json!({"budget_tokens": {"day": 100}})).await;
    let (a, _) = env.llm_token("tenant-a", json!({})).await;
    let (b, _) = env.llm_token("tenant-b", json!({})).await;

    // Two requests in flight hold their max_tokens (64) each, before
    // either has spent anything.
    let first = in_background(&env, &a, "slow-json", false);
    let second = in_background(&env, &a, "slow-json", false);
    reserved(&env, "tenant-a", 128).await;
    assert_eq!(
        spend(&env).await,
        [row("global", "", "anthropic", DAY0, 0, 128), row("tenant", "tenant-a", "", DAY0, 0, 128)]
    );
    // So a third is refused: what is reserved counts like what is spent.
    while env.upstream.count() < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let r = send(&env, &a).await;
    assert_eq!((r.status, level(&r)), (StatusCode::PAYMENT_REQUIRED, "tenant".to_owned()));
    assert_eq!(
        (r.json()["error"]["code"].as_str(), r.json()["error"]["type"].as_str()),
        (Some("budget_exceeded"), Some("billing_error"))
    );
    let message = r.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.starts_with("daily token budget of the tenant is used up (128 of 100 tokens"), "{message}");
    assert!(message.ends_with("it renews at 2030-03-18T00:00:00Z"), "{message}");
    assert!(r.headers.get("retry-after").is_none());
    assert_eq!(env.upstream.count(), 2, "nothing refused reached the provider");

    // Accounting swaps the reservations for what was used: 250 tokens each.
    assert_eq!((first.await.unwrap().status, second.await.unwrap().status), (StatusCode::OK, StatusCode::OK));
    env.settle().await;
    assert_eq!(
        spend(&env).await,
        [row("global", "", "anthropic", DAY0, 500, 0), row("tenant", "tenant-a", "", DAY0, 500, 0)]
    );
    assert_eq!(send(&env, &a).await.status, StatusCode::PAYMENT_REQUIRED, "spent beyond the budget");

    // tenant-b has no budget of its own: the provider's applies, and its
    // refusal shows when it renews, not its numbers.
    for _ in 0..2 {
        assert_eq!(send(&env, &b).await.status, StatusCode::OK);
        env.settle().await;
    }
    let r = send(&env, &b).await;
    assert_eq!((r.status, level(&r)), (StatusCode::PAYMENT_REQUIRED, "global".to_owned()));
    assert_eq!(
        r.json()["error"]["message"],
        "daily token budget of provider anthropic is used up; it renews at 2030-03-18T00:00:00Z"
    );
    assert_eq!(spend(&env).await[0], row("global", "", "anthropic", DAY0, 1000, 0));
    // A new day is a new row.
    env.clock.set(DAY0 + 86_400);
    assert_eq!(send(&env, &b).await.status, StatusCode::OK);
    env.cleanup().await;
}

#[tokio::test]
async fn a_stream_across_midnight_counts_in_the_day_it_started() {
    let Some(env) = env_with("").await else { return };
    set_limits(&env, "tenant-a", json!({"budget_tokens": {"day": 1_000_000}})).await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    env.clock.set(DAY0 + 86_400 - 5);
    // About two seconds of stream; midnight passes while it runs.
    let stream = in_background(&env, &token, "long-stream", true);
    reserved(&env, "tenant-a", 64).await;
    env.clock.advance(60);
    let r = stream.await.unwrap();
    assert!(r.status == StatusCode::OK && r.text().contains("message_stop"));
    env.settle().await;
    // Accounted after midnight, counted in the day it was authorized in:
    // 120 input, 1000 cache reads and 5000 output tokens.
    let (_, usage) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/usage", None).await;
    assert!(usage[0]["ts"].as_i64().unwrap() >= DAY0 + 86_400, "{usage}");
    assert_eq!(spend(&env).await, [row("tenant", "tenant-a", "", DAY0, 6120, 0)]);
    // A request of the new day counts there.
    assert_eq!(send(&env, &token).await.status, StatusCode::OK);
    env.settle().await;
    assert_eq!(
        spend(&env).await,
        [row("tenant", "tenant-a", "", DAY0, 6120, 0), row("tenant", "tenant-a", "", DAY0 + 86_400, 250, 0)]
    );
    env.cleanup().await;
}

#[tokio::test]
async fn usd_budgets_take_only_priced_models() {
    let Some(env) = env_with("budget_usd = { day = 5.0 }").await else { return };
    set_limits(&env, "tenant-a", json!({"budget_usd": {"month": 10.0}})).await;
    let (a, _) = env.llm_token("tenant-a", json!({})).await;
    let (b, _) = env.llm_token("tenant-b", json!({})).await;
    let unpriced = Some(anthropic_body("unpriced-model", false));
    for (token, whose) in [(&a, "the tenant"), (&b, "provider anthropic")] {
        let r = env.llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", token)], unpriced.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
        assert_eq!(
            r.json()["error"]["message"],
            format!(
                "invalid request: model unpriced-model has no configured price; \
                 the USD budget of {whose} can only be used with priced models"
            )
        );
    }
    assert_eq!(env.upstream.count(), 0);
    let usd = || async {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT level || '/' || period_kind, spent_micro_usd, reserved_micro_usd FROM limit_spend ORDER BY 1",
        )
        .fetch_all(env.state.keeper.store().pool())
        .await
        .unwrap();
        rows
    };
    // A priced model reserves the cost of its most output: 64 tokens at 1.0
    // per million.
    let slow = in_background(&env, &a, "slow-json", false);
    reserved(&env, "tenant-a", 64).await;
    assert_eq!(usd().await, [("global/day".to_owned(), 0, 64), ("tenant/month".to_owned(), 0, 64)]);
    assert_eq!(slow.await.unwrap().status, StatusCode::OK);
    env.settle().await;
    // 200 input and 50 output tokens at 1.0.
    assert_eq!(usd().await, [("global/day".to_owned(), 250, 0), ("tenant/month".to_owned(), 250, 0)]);
    env.cleanup().await;
}

#[tokio::test]
async fn a_request_that_ends_before_the_provider_gives_its_reservation_back() {
    let Some(env) = env_with("budget_tokens = { day = 1_000 }").await else { return };
    // tenant-c has no key for the provider: refused after the reservation.
    let (c, _) = env.llm_token("tenant-c", json!({})).await;
    let r = send(&env, &c).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    env.settle().await;
    assert_eq!(spend(&env).await, [row("global", "", "anthropic", DAY0, 0, 0)]);
    env.cleanup().await;
}

#[tokio::test]
async fn without_limits_nothing_is_counted_beyond_the_token() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, token_id) = env.llm_token("tenant-a", json!({"budget_tokens": 1000})).await;
    for uri in ["/llm/anthropic/v1/messages", "/llm/p/anthropic/v1/messages"] {
        let r = env.llm("POST", uri, &[("x-api-key", &token)], Some(anthropic_body("test-model", true))).await;
        assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, ANTHROPIC_SSE));
    }
    let r =
        env.llm("POST", "/llm/anthropic/v1/messages/count_tokens", &[("x-api-key", &token)], Some("{}".into())).await;
    assert_eq!(r.status, StatusCode::OK);
    env.settle().await;
    let pool = env.state.keeper.store().pool();
    for table in ["tenant_limits", "limit_rpm", "limit_spend"] {
        let (n,): (i64,) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}"))).fetch_one(pool).await.unwrap();
        assert_eq!(n, 0, "{table}");
    }
    let (_, t) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{token_id}"), None).await;
    assert_eq!((t["spent_tokens"].as_i64(), t["request_count"].as_i64()), (Some(2 * 1150), Some(3)));
    env.cleanup().await;
}
