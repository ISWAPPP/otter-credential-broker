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
