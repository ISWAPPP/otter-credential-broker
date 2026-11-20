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
}

/// Providers `anthropic` and `gateway` (both of the Anthropic kind) and
/// `openai`; tenant-a has a key for each.
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
    Some(Routes { env, anthropic, openai, gateway })
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
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let anthropic = || Some(anthropic_body("test-model", false));
    let openai = || Some(openai_body("gpt-test", false, false));
    // (method, path, body, index of the upstream that must see it, key it must carry)
    let cases = [
        ("POST", "/llm/anthropic/v1/messages", anthropic(), 0, KEY_A),
        ("POST", "/llm/p/anthropic/v1/messages", anthropic(), 0, KEY_A),
        ("POST", "/llm/p/gateway/v1/messages", anthropic(), 2, GATEWAY_KEY),
        ("POST", "/llm/p/gateway/v1/messages/count_tokens", anthropic(), 2, GATEWAY_KEY),
        ("GET", "/llm/p/gateway/v1/models", None, 2, GATEWAY_KEY),
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
    assert_eq!((by("anthropic"), by("openai"), by("gateway")), (2, 3, 3), "{rows:?}");
    r.env.cleanup().await;
}

#[tokio::test]
async fn other_paths_reach_no_provider() {
    let Some(r) = routes().await else { return };
    let env = &r.env;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
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
    assert_eq!(r.counts(), [0, 0, 0], "nothing may reach an upstream");

    // Errors take the shape of the provider's kind; without a provider, the
    // generic route uses the OpenAI-compatible one.
    let resp = env.llm("POST", "/llm/p/gateway/chat/completions", &[("x-api-key", &token)], None).await;
    assert_eq!((resp.status, resp.json()["type"].as_str()), (StatusCode::NOT_FOUND, Some("error")));
    let resp = env.llm("POST", "/llm/p/unknown/v1/messages", &[("x-api-key", &token)], None).await;
    assert_eq!(resp.json()["error"]["code"], "not_found");
    r.env.cleanup().await;
}
