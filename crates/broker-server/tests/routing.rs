#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Routing of `/llm/*` with several providers, two of them of the Anthropic
//! kind, each behind its own fake upstream.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};

const OPENAI_KEY: &str = "sk-openai-FAKE-tenant-a-DDDDDDDDDDDDDDDDDDDDDDDDDDDD";
const GATEWAY_KEY: &str = "sk-gateway-FAKE-tenant-a-EEEEEEEEEEEEEEEEEEEEEEEEEEE";

struct Routes {
    env: Env,
    anthropic: Upstream,
    openai: Upstream,
    gateway: Upstream,
    gateway_port: u16,
}

/// Providers `anthropic` and `gateway` (both of the Anthropic kind; the
/// gateway serves two endpoints, only to tokens that name it, and is priced
/// like `anthropic`) and `openai`; tenant-a has a key for each.
async fn routes() -> Option<Routes> {
    let (anthropic, a) = start_upstream().await;
    let (openai, o) = start_upstream().await;
    let (gateway, g) = start_upstream().await;
    let llm = llm_config(&format!(
        r#"
        [llm.providers.anthropic]
        kind = "anthropic"
        base_url = "http://{a}"
        allow_http = true

        [llm.providers.openai]
        kind = "openai"
        base_url = "http://{o}/v1"
        allow_http = true

        [llm.providers.gateway]
        kind = "anthropic"
        base_url = "http://{g}"
        allow_http = true
        access = "explicit"
        endpoints = ["messages", "count_tokens"]
        pricing_from = "anthropic"

        [[llm.pricing]]
        provider = "anthropic"
        model = "test-model"
        input = 3.0
        output = 15.0
        "#
    ));
    let env = Env::with_llm(EnvOptions::default(), llm, (anthropic.clone(), a)).await?;
    env.put_secret("tenant-a", "llm.anthropic", "llm_api_key", KEY_A).await;
    env.put_secret("tenant-a", "llm.openai", "llm_api_key", OPENAI_KEY).await;
    env.put_secret("tenant-a", "llm.gateway", "llm_api_key", GATEWAY_KEY).await;
    Some(Routes { env, anthropic, openai, gateway, gateway_port: g.port() })
}

impl Routes {
    fn counts(&self) -> [usize; 3] {
        [self.anthropic.count(), self.openai.count(), self.gateway.count()]
    }
}

async fn usage(env: &Env) -> Vec<Value> {
    env.settle().await;
    let (s, v) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/usage?limit=1000", None).await;
    assert_eq!(s, StatusCode::OK);
    v.as_array().unwrap().clone()
}

#[tokio::test]
async fn each_route_reaches_exactly_its_provider() {
    let Some(r) = routes().await else { return };
    let env = &r.env;
    let (token, _) = env.llm_token("tenant-a", json!({"providers": ["anthropic", "gateway", "openai"]})).await;
    let anthropic = || Some(anthropic_body("test-model", false));
    let openai = || Some(openai_body("gpt-test", false, false));
    // (method, path, body, index of the upstream that must see it, key it must carry)
    let cases = [
        ("POST", "/llm/anthropic/v1/messages", anthropic(), 0, KEY_A),
        ("POST", "/llm/p/anthropic/v1/messages", anthropic(), 0, KEY_A),
        ("POST", "/llm/p/gateway/v1/messages", anthropic(), 2, GATEWAY_KEY),
        ("POST", "/llm/p/gateway/v1/messages/count_tokens", anthropic(), 2, GATEWAY_KEY),
        ("POST", "/llm/openai/openai/chat/completions", openai(), 1, OPENAI_KEY),
        ("POST", "/llm/p/openai/chat/completions", openai(), 1, OPENAI_KEY),
        ("GET", "/llm/p/openai/models", None, 1, OPENAI_KEY),
    ];
    for (method, uri, body, target, key) in cases {
        let mut want = r.counts();
        want[target] += 1;
        let resp = env.llm(method, uri, &[("x-api-key", &token)], body).await;
        assert_eq!(resp.status, StatusCode::OK, "{method} {uri}: {}", resp.text());
        assert_eq!(r.counts(), want, "{method} {uri}");
        let seen = [&r.anthropic, &r.openai, &r.gateway][target].last();
        let sent = seen.headers.get("x-api-key").or_else(|| seen.headers.get("authorization")).unwrap();
        assert!(sent.to_str().unwrap().ends_with(key), "{method} {uri}");
    }
    let rows = usage(env).await;
    let by = |p: &str| rows.iter().filter(|u| u["provider"] == p).count();
    assert_eq!((by("anthropic"), by("openai"), by("gateway")), (2, 3, 2), "{rows:?}");
    // The gateway is priced with anthropic's entries: 200 * 3.0 + 50 * 15.0.
    let gw = rows.iter().find(|u| u["provider"] == "gateway" && u["endpoint"] == "v1/messages").unwrap();
    assert_eq!(gw["cost_micro_usd"].as_i64(), Some(1350), "{gw}");
    r.env.cleanup().await;
}

#[tokio::test]
async fn other_paths_reach_no_provider() {
    let Some(r) = routes().await else { return };
    let env = &r.env;
    let (token, _) = env.llm_token("tenant-a", json!({"providers": ["anthropic", "gateway", "openai"]})).await;
    for uri in [
        // A route that implies a kind only reaches providers of that kind.
        "/llm/openai/gateway/v1/messages",
        "/llm/openai/anthropic/chat/completions",
        "/llm/anthropic/gateway/v1/messages",
        // The endpoint must belong to the provider's kind.
        "/llm/p/gateway/chat/completions",
        "/llm/p/openai/v1/messages",
        // Ids and paths are compared as sent: no decoding, no normalisation.
        "/llm/p/unknown/v1/messages",
        "/llm/p/GATEWAY/v1/messages",
        "/llm/p/gateway%2Fv1/messages",
        "/llm/p//gateway/v1/messages",
        "/llm/p/gateway/../anthropic/v1/messages",
        "/llm/p/./gateway/v1/messages",
        "/llm/p/gateway/v1/messages/",
        "/llm/p/gateway",
        // Reserved ids.
        "/llm/p/p/v1/messages",
        "/llm/p/_/limits",
        "/llm/p/limits/v1/messages",
        "/llm/p/",
        "/llm/p",
    ] {
        let resp = env.llm("POST", uri, &[("x-api-key", &token)], Some(anthropic_body("test-model", false))).await;
        assert!(matches!(resp.status.as_u16(), 400 | 404 | 405), "{uri} -> {} {}", resp.status, resp.text());
    }
    // An endpoint of the kind that the provider does not serve.
    let resp = env.llm("GET", "/llm/p/gateway/v1/models", &[("x-api-key", &token)], None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(
        env.llm("GET", "/llm/p/anthropic/v1/models", &[("x-api-key", &token)], None).await.status,
        StatusCode::OK
    );
    assert_eq!(r.counts(), [1, 0, 0], "nothing else may reach an upstream");

    // Errors take the shape of the provider's kind; without a provider, the
    // generic route uses the OpenAI-compatible one.
    let resp = env.llm("POST", "/llm/p/gateway/chat/completions", &[("x-api-key", &token)], None).await;
    assert_eq!((resp.status, resp.json()["type"].as_str()), (StatusCode::NOT_FOUND, Some("error")));
    let resp = env.llm("POST", "/llm/p/unknown/v1/messages", &[("x-api-key", &token)], None).await;
    assert_eq!(resp.json()["error"]["code"], "not_found");
    r.env.cleanup().await;
}

#[tokio::test]
async fn an_explicit_provider_serves_only_tokens_that_name_it() {
    let Some(r) = routes().await else { return };
    let env = &r.env;
    let (unlisted, _) = env.llm_token("tenant-a", json!({})).await;
    let (named, _) = env.llm_token("tenant-a", json!({"providers": ["gateway"]})).await;
    let (other, _) = env.llm_token("tenant-a", json!({"providers": ["anthropic"]})).await;
    let call = |token: String, uri: &'static str| async move {
        env.llm("POST", uri, &[("x-api-key", &token)], Some(anthropic_body("test-model", false))).await
    };
    // A token without a provider list keeps reaching implicit providers...
    assert_eq!(call(unlisted.clone(), "/llm/p/anthropic/v1/messages").await.status, StatusCode::OK);
    // ...but not the explicit one, and neither does a list without it.
    for token in [unlisted, other] {
        let resp = call(token, "/llm/p/gateway/v1/messages").await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.text());
        assert_eq!(resp.json()["error"]["type"], "permission_error");
    }
    assert_eq!(r.gateway.count(), 0);
    let resp = call(named.clone(), "/llm/p/gateway/v1/messages").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(r.gateway.last().headers.get("x-api-key").unwrap(), GATEWAY_KEY);
    assert_eq!(call(named, "/llm/p/anthropic/v1/messages").await.status, StatusCode::FORBIDDEN);
    r.env.cleanup().await;
}

#[tokio::test]
async fn usd_budgets_work_with_borrowed_prices() {
    let Some(r) = routes().await else { return };
    let env = &r.env;
    let (token, token_id) = env.llm_token("tenant-a", json!({"providers": ["gateway"], "budget_usd": 1.0})).await;
    let h = [("x-api-key", token.as_str())];
    let resp = env.llm("POST", "/llm/p/gateway/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    // A model without a price at the source is still refused for a USD budget.
    let resp = env.llm("POST", "/llm/p/gateway/v1/messages", &h, Some(anthropic_body("unpriced", false))).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    env.settle().await;
    let (_, t) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{token_id}"), None).await;
    assert_eq!(t["spent_micro_usd"].as_i64(), Some(1350), "{t}");
    r.env.cleanup().await;
}

#[tokio::test]
async fn the_admin_view_shows_each_providers_routing() {
    let Some(r) = routes().await else { return };
    let (s, v) = r.env.admin_call("GET", "/v1/admin/providers", None).await;
    assert_eq!(s, StatusCode::OK);
    let gw = v["providers"].as_array().unwrap().iter().find(|p| p["id"] == "gateway").unwrap().clone();
    assert_eq!(gw["kind"], "anthropic");
    assert_eq!(gw["access"], "explicit");
    assert_eq!(gw["endpoints"], json!(["messages", "count_tokens"]));
    assert_eq!(gw["pricing_from"], "anthropic");
    assert_eq!(gw["host"], format!("127.0.0.1:{}", r.gateway_port));
    r.env.cleanup().await;
}
