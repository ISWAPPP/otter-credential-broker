#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Which headers pass between callers and providers, in both directions:
//! the fixed allowlists by default, more for a provider with prefixes,
//! never those that carry credentials, cookies or redirects.

mod common;

use std::collections::BTreeSet;

use axum::http::{HeaderMap, StatusCode};
use common::*;
use serde_json::json;

fn names(h: &HeaderMap) -> BTreeSet<String> {
    h.keys().map(|n| n.as_str().to_owned()).collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

/// What a caller may send besides its token: headers of the SDKs and a few
/// that must never reach a provider.
const CALLER_HEADERS: &[(&str, &str)] = &[
    ("anthropic-version", "2023-06-01"),
    ("anthropic-beta", "b1,b2"),
    ("anthropic-dangerous-direct-browser-access", "true"),
    ("anthropic-organization", "org-other"),
    ("accept", "application/json"),
    ("http-referer", "https://agent.example"),
    ("x-title", "agent"),
    ("x-app", "cli"),
    ("x-stainless-os", "Linux"),
    ("user-agent", "sdk/1.0"),
    ("cookie", "session=abc"),
    ("x-forwarded-for", "192.0.2.1"),
    ("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    ("accept-encoding", "gzip, br"),
];

/// Headers the broker itself puts on every upstream request.
const BROKER_REQUEST_HEADERS: &[&str] = &["accept-encoding", "traceparent", "user-agent", "host", "content-length"];

/// Response headers every provider passes back.
const DEFAULT_RESPONSE_HEADERS: &[&str] =
    &["content-type", "cache-control", "retry-after", "request-id", "x-request-id", "x-should-retry"];

/// A route of the older form and what it lets through by default.
struct Route {
    uri: &'static str,
    /// A request body for a model.
    body: fn(&str) -> String,
    /// Caller headers on the allowlist of the provider's kind.
    allowlist: [&'static str; 4],
    /// The auth header the broker sets for the provider's kind.
    auth: &'static str,
}

fn anthropic_request(model: &str) -> String {
    anthropic_body(model, false)
}

fn openai_request(model: &str) -> String {
    openai_body(model, false, false)
}

const OLDER_ROUTES: [Route; 2] = [
    Route {
        uri: "/llm/anthropic/v1/messages",
        body: anthropic_request,
        allowlist: ["content-type", "accept", "anthropic-version", "anthropic-beta"],
        auth: "x-api-key",
    },
    Route {
        uri: "/llm/openai/deepseek/chat/completions",
        body: openai_request,
        allowlist: ["content-type", "accept", "http-referer", "x-title"],
        auth: "authorization",
    },
];

#[tokio::test]
async fn by_default_only_the_fixed_allowlists_pass_either_way() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let mut headers = vec![("x-api-key", token.as_str())];
    headers.extend_from_slice(CALLER_HEADERS);
    for Route { uri, body, allowlist, auth } in OLDER_ROUTES {
        let r = env.llm("POST", uri, &headers, Some(body("many-headers"))).await;
        assert_eq!(r.status, StatusCode::OK, "{uri}: {}", r.text());

        let seen = env.upstream.last();
        let mut want = set(&allowlist);
        want.extend(set(BROKER_REQUEST_HEADERS));
        want.insert(auth.to_owned());
        assert_eq!(names(&seen.headers), want, "{uri}: sent upstream");
        assert_eq!(seen.headers.get("accept-encoding").unwrap(), "identity");
        assert!(seen.headers.get("user-agent").unwrap().to_str().unwrap().starts_with("otter-credential-broker/"));

        assert_eq!(names(&r.headers), set(DEFAULT_RESPONSE_HEADERS), "{uri}: passed back");
        assert_eq!(r.headers.get("x-should-retry").unwrap(), "false");

        // An upstream error comes back with the same headers, so an SDK
        // retries only when the provider says so.
        let r = env.llm("POST", uri, &headers, Some(body("many-headers-429"))).await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{uri}: {}", r.text());
        // The error body is read before it is passed on, so the broker
        // gives its length itself.
        let mut want = set(DEFAULT_RESPONSE_HEADERS);
        want.insert("content-length".into());
        assert_eq!(names(&r.headers), want, "{uri}: passed back with an error");
        assert_eq!(r.headers.get("content-length").unwrap(), r.body.len().to_string().as_str());
        assert_eq!(r.headers.get("x-should-retry").unwrap(), "true");
        assert_eq!(r.headers.get("retry-after").unwrap(), "7");
    }
    env.cleanup().await;
}

/// Providers on one fake upstream: `anthropic` with the defaults,
/// `gateway`, which passes more headers both ways, and `wide`, with broad
/// response prefixes. tenant-a has a key for each.
async fn prefix_env() -> Option<Env> {
    let (upstream, addr) = start_upstream().await;
    let llm = llm_config(&format!(
        r#"
        [llm.providers.anthropic]
        kind = "anthropic"
        base_url = "http://{addr}"
        allow_http = true

        [llm.providers.gateway]
        kind = "anthropic"
        base_url = "http://{addr}"
        allow_http = true
        headers = {{ request_forward_prefixes = ["anthropic-", "x-stainless-"], response_forward_prefixes = ["anthropic-ratelimit-"] }}

        [llm.providers.wide]
        kind = "anthropic"
        base_url = "http://{addr}"
        allow_http = true
        headers = {{ response_forward_prefixes = ["x-", "anthropic-"] }}
        "#
    ));
    let env = Env::with_llm(EnvOptions::default(), llm, (upstream, addr)).await?;
    for id in ["anthropic", "gateway", "wide"] {
        env.put_secret("tenant-a", &format!("llm.{id}"), "llm_api_key", KEY_A).await;
    }
    Some(env)
}

#[tokio::test]
async fn a_provider_passes_more_headers_by_prefix() {
    let Some(env) = prefix_env().await else { return };
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let mut headers = vec![("x-api-key", token.as_str())];
    headers.extend_from_slice(CALLER_HEADERS);
    let gateway_response = set(&[
        "anthropic-ratelimit-unified-status",
        "anthropic-ratelimit-unified-5h-utilization",
        "anthropic-ratelimit-requests-remaining",
    ]);

    let r = env.llm("POST", "/llm/p/gateway/v1/messages", &headers, Some(anthropic_body("many-headers", false))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let seen = env.upstream.last();
    let mut want = set(&[
        "content-type",
        "accept",
        "anthropic-version",
        "anthropic-beta",
        "anthropic-dangerous-direct-browser-access",
        "anthropic-organization",
        "x-stainless-os",
        "x-api-key",
    ]);
    want.extend(set(BROKER_REQUEST_HEADERS));
    assert_eq!(names(&seen.headers), want, "sent upstream");
    assert_eq!(seen.headers.get("x-api-key").unwrap(), KEY_A, "the provider key, never the caller's token");
    assert_eq!(seen.headers.get("anthropic-organization").unwrap(), "org-other");
    let mut want = set(DEFAULT_RESPONSE_HEADERS);
    want.extend(gateway_response.clone());
    assert_eq!(names(&r.headers), want, "passed back");
    assert_eq!(r.headers.get("anthropic-ratelimit-unified-5h-utilization").unwrap(), "0.25");

    // An upstream error carries them too.
    let r =
        env.llm("POST", "/llm/p/gateway/v1/messages", &headers, Some(anthropic_body("many-headers-429", false))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let mut want = set(DEFAULT_RESPONSE_HEADERS);
    want.extend(gateway_response);
    want.insert("content-length".into());
    assert_eq!(names(&r.headers), want, "passed back with an error");

    // Another provider of the same kind keeps to the allowlists.
    let r =
        env.llm("POST", "/llm/p/anthropic/v1/messages", &headers, Some(anthropic_body("many-headers", false))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(env.upstream.last().headers.get("anthropic-organization").is_none());
    assert_eq!(names(&r.headers), set(DEFAULT_RESPONSE_HEADERS));

    // The admin view shows each provider's prefixes.
    let (_, v) = env.admin_call("GET", "/v1/admin/providers", None).await;
    let view = |id: &str| v["providers"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap()["headers"].clone();
    assert_eq!(
        view("gateway"),
        json!({"request_forward_prefixes": ["anthropic-", "x-stainless-"],
               "response_forward_prefixes": ["anthropic-ratelimit-"]})
    );
    assert_eq!(view("anthropic"), json!({"request_forward_prefixes": [], "response_forward_prefixes": []}));
    env.cleanup().await;
}

#[tokio::test]
async fn broad_response_prefixes_never_pass_cookies_challenges_or_redirects() {
    let Some(env) = prefix_env().await else { return };
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let h = [("x-api-key", token.as_str())];
    let mut want = set(DEFAULT_RESPONSE_HEADERS);
    want.extend(set(&[
        "anthropic-ratelimit-unified-status",
        "anthropic-ratelimit-unified-5h-utilization",
        "anthropic-ratelimit-requests-remaining",
        "anthropic-organization-id",
        "x-ratelimit-remaining-requests",
        "x-upstream-debug",
    ]));
    for (model, status) in [("many-headers", StatusCode::OK), ("many-headers-429", StatusCode::TOO_MANY_REQUESTS)] {
        let r = env.llm("POST", "/llm/p/wide/v1/messages", &h, Some(anthropic_body(model, false))).await;
        assert_eq!(r.status, status, "{}", r.text());
        let mut got = names(&r.headers);
        got.remove("content-length");
        assert_eq!(got, want, "{model}");
        for never in ["set-cookie", "www-authenticate", "ratelimit", "ratelimit-policy", "ocb-budget-remaining"] {
            assert!(r.headers.get(never).is_none(), "{model}: {never}");
        }
        assert!(r.headers.get("location").is_none() && r.headers.get("alt-svc").is_none(), "{model}");
    }
    env.cleanup().await;
}
