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

/// Waits until this replica counts `tenant_n` requests in flight for
/// `tenant` and `provider_n` for the provider `anthropic`. A request is
/// counted before anything else is done for it, so the slot is then held.
async fn in_flight(env: &Env, tenant: &str, tenant_n: u32, provider_n: u32) {
    let inflight = env.state.proxy.inflight();
    let counts = || (inflight.tenant_count(tenant), inflight.provider_count("anthropic"));
    for _ in 0..200 {
        if counts() == (tenant_n, provider_n) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {:?} requests in flight for {tenant} and anthropic: {:?}", (tenant_n, provider_n), counts());
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
    in_flight(&env, "tenant-a", 1, 1).await;
    let r = send(&env, &a2).await;
    assert_eq!((r.status, level(&r)), (StatusCode::TOO_MANY_REQUESTS, "tenant".to_owned()));
    assert_eq!(
        (r.json()["error"]["code"].as_str(), r.headers.get("retry-after").unwrap().to_str().unwrap()),
        (Some("too_many_in_flight"), "1")
    );
    // tenant-b takes the provider's second slot; then the provider is full.
    let second = slow(&b1);
    in_flight(&env, "tenant-b", 1, 2).await;
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

fn header(r: &TestResponse, name: &str) -> Option<String> {
    r.headers.get(name).map(|v| v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn every_answer_shows_the_caller_its_limits_and_the_provider_cannot_override_them() {
    let Some(env) = env_with("rpm = 1000, budget_tokens = { day = 1_000_000 }").await else { return };
    env.clock.set(DAY0 + 86_400 - 3600 - 20);
    set_limits(&env, "tenant-a", json!({"rpm": 50, "budget_tokens": {"day": 1000}})).await;
    let (token, _) = env.llm_token("tenant-a", json!({"budget_tokens": 10_000})).await;
    let h = [("x-api-key", token.as_str())];

    // The provider sends RateLimit and ocb-budget-* headers of its own; the
    // caller only ever sees the broker's. The tenant's day budget, with
    // this request's 64 tokens reserved, is nearer to running out than the
    // token's budget; the provider's own limits are not shown.
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("many-headers", false))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let want = [
        ("ratelimit-policy", "\"token\";q=120;w=60, \"tenant\";q=50;w=60"),
        ("ratelimit", "\"token\";r=119;t=20, \"tenant\";r=49;t=20"),
        ("ocb-budget-limit", "1000"),
        ("ocb-budget-remaining", "936"),
        ("ocb-budget-unit", "tokens"),
        ("ocb-budget-reset", "3620"),
        ("ocb-limit-level", "tenant"),
    ];
    for (name, value) in want {
        assert_eq!(header(&r, name).as_deref(), Some(value), "{name}");
    }
    env.settle().await;

    // An upstream error and a stream carry them too, with the spend so far.
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("many-headers-429", false))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&r, "ocb-budget-remaining").as_deref(), Some("686"), "250 spent, 64 reserved");
    assert_eq!(header(&r, "ratelimit").as_deref(), Some("\"token\";r=118;t=20, \"tenant\";r=48;t=20"));
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", true))).await;
    assert!(r.headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/event-stream"));
    assert_eq!(header(&r, "ocb-limit-level").as_deref(), Some("tenant"));
    env.settle().await;

    // So do refusals of the broker, which name the level that refused.
    set_limits(&env, "tenant-a", json!({"rpm": 50, "budget_tokens": {"day": 300}})).await;
    let r = send(&env, &token).await;
    assert_eq!((r.status, level(&r)), (StatusCode::PAYMENT_REQUIRED, "tenant".to_owned()));
    assert_eq!(header(&r, "ocb-budget-remaining").as_deref(), Some("0"));
    let r = env.llm("POST", "/llm/anthropic/v1/messages/count_tokens", &h, Some("{}".into())).await;
    assert_eq!(r.status, StatusCode::OK, "free endpoints still pass");
    assert_eq!(header(&r, "ocb-budget-remaining").as_deref(), Some("0"));

    // Without a known token there is nothing to show.
    for r in [
        env.llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", "ocb_llm_x")], Some("{}".into())).await,
        env.llm("POST", "/llm/p/nowhere/v1/messages", &h, Some("{}".into())).await,
    ] {
        assert!(r.status.is_client_error());
        assert!(r.headers.get("ratelimit").is_none() && r.headers.get("ocb-limit-level").is_none());
    }
    env.cleanup().await;
}

async fn limits_of(env: &Env, token: &str) -> TestResponse {
    env.llm("GET", "/llm/_/limits", &[("authorization", &format!("Bearer {token}"))], None).await
}

#[tokio::test]
async fn the_limits_endpoint_shows_the_callers_own_and_counts_no_request() {
    let Some(env) = env_with("rpm = 1000, budget_tokens = { day = 1_050 }").await else { return };
    env.clock.set(DAY0 + 3601);
    set_limits(
        &env,
        "tenant-a",
        json!({"rpm": 50, "concurrent": 4, "budget_tokens": {"day": 500},
                                        "budget_usd": {"month": 7.25}}),
    )
    .await;
    set_limits(&env, "tenant-b", json!({"rpm": 7, "budget_tokens": {"day": 777}})).await;
    let (a, a_id) = env
        .llm_token("tenant-a", json!({"rate_limit_per_minute": 2, "budget_tokens": 5000, "label": "worker-1"}))
        .await;
    let (b, b_id) = env.llm_token("tenant-b", json!({})).await;

    // Asking does not use up the token's rate limit: both requests of the
    // minute still pass.
    for _ in 0..10 {
        let r = limits_of(&env, &a).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    }
    for _ in 0..2 {
        assert_eq!(send(&env, &a).await.status, StatusCode::OK);
    }
    env.settle().await;
    let v = limits_of(&env, &a).await.json();
    let resets_at = DAY0 + 3660;
    assert_eq!(
        v["token"],
        json!({"id": a_id, "label": "worker-1", "expires_at": DAY0 + 3601 + 86_400, "providers": null,
               "rpm": {"limit": 2, "remaining": 0, "resets_at": resets_at}, "concurrent": 16,
               "budget_tokens": {"limit": 5000, "spent": 500, "remaining": 4500}, "budget_usd": null})
    );
    assert_eq!(
        v["tenant"],
        json!({"id": "tenant-a", "rpm": {"limit": 50, "remaining": 48, "resets_at": resets_at}, "concurrent": 4,
               "budgets": [
                   {"period": "day", "unit": "tokens", "limit": 500, "spent": 500, "reserved": 0,
                    "remaining": 0, "resets_at": DAY0 + 86_400},
                   {"period": "month", "unit": "usd", "limit": 7.25, "spent": 0.0027, "reserved": 0.0,
                    "remaining": 7.2473, "resets_at": 1_901_232_000}]})
    );
    // The provider's limits for every tenant: only how near they are.
    assert_eq!(v["global"], json!([{"provider": "anthropic", "status": "ok", "resets_at": null}]));

    // tenant-b's requests bring the provider near its day budget, then
    // past it; tenant-a sees that, and nothing else of tenant-b.
    for _ in 0..2 {
        assert_eq!(send(&env, &b).await.status, StatusCode::OK);
        env.settle().await;
    }
    let near = limits_of(&env, &a).await;
    assert_eq!(near.json()["global"], json!([{"provider": "anthropic", "status": "near", "resets_at": DAY0 + 86_400}]));
    assert_eq!(send(&env, &b).await.status, StatusCode::OK);
    env.settle().await;
    let exhausted = limits_of(&env, &a).await;
    let v = exhausted.json();
    assert_eq!(v["global"], json!([{"provider": "anthropic", "status": "exhausted", "resets_at": DAY0 + 86_400}]));
    // tenant-b's budget would show as a number: random ids can hold "777".
    for text in [near.text(), exhausted.text()] {
        assert!(!text.contains("tenant-b") && !text.contains(&b_id) && !text.contains(":777"), "{text}");
    }
    // tenant-b sees its own.
    let v = limits_of(&env, &b).await.json();
    assert_eq!((v["token"]["id"].as_str(), v["tenant"]["id"].as_str()), (Some(b_id.as_str()), Some("tenant-b")));
    assert_eq!(v["tenant"]["budgets"][0]["spent"], 750);
    assert_eq!(v["tenant"]["rpm"]["remaining"], 4);

    // Without a valid token there is nothing to see.
    for auth in ["Bearer ocb_llm_nope", "Bearer sk-not-a-token", ""] {
        let h: Vec<(&str, &str)> = if auth.is_empty() { vec![] } else { vec![("authorization", auth)] };
        let r = env.llm("GET", "/llm/_/limits", &h, None).await;
        assert_eq!((r.status, r.json()["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("unauthorized")));
    }
    let (_, revoke) =
        env.admin_call("POST", &format!("/v1/admin/tenants/tenant-b/llm-tokens/{b_id}/revoke"), None).await;
    assert_eq!(revoke, Value::Null);
    assert_eq!(limits_of(&env, &b).await.status, StatusCode::UNAUTHORIZED);
    env.cleanup().await;
}

fn minute() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 60
}

#[tokio::test]
async fn the_limits_endpoint_has_a_rate_limit_of_its_own() {
    let (upstream, addr) = start_upstream().await;
    let llm = llm_config(&format!("[llm]\nlimits_endpoint_per_minute = 3\n{}", provider(&addr.to_string(), "")));
    let options = EnvOptions { auth_failures_per_minute: 2, ..EnvOptions::default() };
    let Some(env) = Env::with_llm(options, llm, (upstream, addr)).await else { return };
    env.seed_keys().await;
    let (a, _) = env.llm_token("tenant-a", json!({})).await;
    let (b, _) = env.llm_token("tenant-a", json!({})).await;
    let start = minute();
    let codes: Vec<StatusCode> = join_all((0..4).map(|_| limits_of(&env, &a))).await.iter().map(|r| r.status).collect();
    let other = limits_of(&env, &b).await;
    // Per token and minute: unless the test straddles a minute boundary,
    // the fourth is refused and another token is not affected.
    if minute() == start {
        assert_eq!(codes.iter().filter(|c| **c == StatusCode::TOO_MANY_REQUESTS).count(), 1, "{codes:?}");
        assert_eq!(other.status, StatusCode::OK);
    }
    // Failed token checks count against the caller's address, as on the
    // proxy: after two, even a valid token is refused from there.
    let public = env.serve_public().await;
    let client = reqwest::Client::new();
    let get = |token: String| {
        let client = client.clone();
        async move {
            client
                .get(format!("http://{public}/llm/_/limits"))
                .header("x-api-key", token)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let start = minute();
    let bad = format!("ocb_llm_{}", "0".repeat(64));
    let codes = [get(bad.clone()).await, get(bad).await, get(b.clone()).await];
    if minute() == start {
        assert_eq!(codes.map(|c| c.as_u16()), [401, 401, 429]);
    }
    env.cleanup().await;
}

#[tokio::test]
async fn the_admin_api_shows_the_providers_limits_with_their_numbers() {
    let Some(env) = env_with("rpm = 1000, concurrent = 5, budget_tokens = { day = 1_050 }").await else { return };
    env.clock.set(DAY0 + 3601);
    let (b, _) = env.llm_token("tenant-b", json!({})).await;
    for _ in 0..2 {
        assert_eq!(send(&env, &b).await.status, StatusCode::OK);
    }
    env.settle().await;
    let (s, v) = env.admin_call("GET", "/v1/admin/limits", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["global"],
        json!([{"provider": "anthropic",
                "limits": {"rpm": 1000, "concurrent": 5, "budget_tokens": {"day": 1050, "month": null},
                           "budget_usd": {"day": null, "month": null}},
                "usage": {"rpm": {"count": 2, "resets_at": DAY0 + 3660}, "in_flight": 0,
                          "periods": [{"period": "day", "start": DAY0, "resets_at": DAY0 + 86_400,
                                       "spent_tokens": 500, "spent_usd": 0.0027, "reserved_tokens": 0,
                                       "reserved_usd": 0.0}]}}])
    );
    assert_eq!(v["tenants"], json!([]));
    env.cleanup().await;
}

/// The value of a series in the metrics output; NaN shows as `NaN`.
fn gauge(series: &str) -> Option<f64> {
    let text = telemetry().metrics.render();
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse::<f64>().ok()))
}

#[tokio::test]
async fn budgets_and_labelled_tokens_are_exported_as_gauges() {
    let Some(env) = env_with("budget_tokens = { day = 10_000 }, budget_usd = { month = 50.0 }").await else { return };
    // A tenant of its own: the metrics recorder is shared by every test.
    env.put_secret("gauges", "llm.anthropic", "llm_api_key", KEY_A).await;
    set_limits(&env, "gauges", json!({"budget_tokens": {"day": 1000}})).await;
    let (token, _) = env.llm_token("gauges", json!({"label": "agent", "ttl_secs": 3600})).await;
    env.llm_token("gauges", json!({"label": "agent", "ttl_secs": 7200})).await;
    let (_, probe) = env.llm_token("gauges", json!({"label": "probe", "ttl_secs": 600})).await;
    env.llm_token("gauges", json!({"ttl_secs": 600})).await;
    assert_eq!(send(&env, &token).await.status, StatusCode::OK);
    env.settle().await;

    let mut gauges = broker_server::limit_metrics::LimitGauges::new(env.state.keeper.clone(), env.state.proxy.clone());
    gauges.refresh().await.unwrap();
    let tenant = |name: &str, kind: &str| {
        gauge(&format!("{name}{{level=\"tenant\",tenant=\"gauges\",provider=\"\",kind=\"{kind}\"}}"))
    };
    let global = |name: &str, kind: &str| {
        gauge(&format!("{name}{{level=\"global\",tenant=\"\",provider=\"anthropic\",kind=\"{kind}\"}}"))
    };
    // 250 tokens used, at a cost of $0.00135.
    assert_eq!(
        (tenant("ocb_limit_quota", "tokens_day"), tenant("ocb_limit_remaining", "tokens_day")),
        (Some(1000.0), Some(750.0))
    );
    assert_eq!(global("ocb_limit_remaining", "tokens_day"), Some(9750.0));
    assert_eq!(global("ocb_limit_quota", "usd_month"), Some(50.0));
    assert!((global("ocb_limit_remaining", "usd_month").unwrap() - 49.998_65).abs() < 1e-9);
    let expiry = |label: &str| gauge(&format!("ocb_llm_token_expiry_timestamp{{tenant=\"gauges\",label=\"{label}\"}}"));
    assert_eq!(expiry("agent"), Some((T0 + 7200) as f64), "the latest token of a label");
    assert_eq!(expiry("probe"), Some((T0 + 600) as f64));

    // A revoked token and a removed budget leave no stale values behind.
    env.admin_call("POST", &format!("/v1/admin/tenants/gauges/llm-tokens/{probe}/revoke"), None).await;
    set_limits(&env, "gauges", json!({})).await;
    gauges.refresh().await.unwrap();
    assert!(expiry("probe").unwrap().is_nan());
    assert!(tenant("ocb_limit_remaining", "tokens_day").unwrap().is_nan());
    assert_eq!(expiry("agent"), Some((T0 + 7200) as f64));
    env.cleanup().await;
}
