#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Header and body policies of providers. Which headers pass between
//! callers and providers, in both directions: the fixed allowlists by
//! default, more for a provider with prefixes, never those that carry
//! credentials, cookies or redirects. Which requests a provider refuses:
//! those that would have it run tools or contact MCP servers itself. Both
//! change with a reload, for new requests.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use axum::http::{HeaderMap, StatusCode};
use broker_server::ServerConfig;
use broker_server::reload::{ReloadResult, Reloader};
use common::*;
use serde_json::{Value, json};

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

/// Headers the broker puts on every answer to a caller with a token: the
/// token's requests per minute (see tests/limits.rs). Providers can never
/// set them.
const LIMIT_HEADERS: &[&str] = &["ratelimit-policy", "ratelimit"];

/// What a caller gets back from a provider without prefixes.
fn default_response() -> BTreeSet<String> {
    let mut s = set(DEFAULT_RESPONSE_HEADERS);
    s.extend(set(LIMIT_HEADERS));
    s
}

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

        assert_eq!(names(&r.headers), default_response(), "{uri}: passed back");
        assert_eq!(r.headers.get("x-should-retry").unwrap(), "false");

        // An upstream error comes back with the same headers, so an SDK
        // retries only when the provider says so.
        let r = env.llm("POST", uri, &headers, Some(body("many-headers-429"))).await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{uri}: {}", r.text());
        // The error body is read before it is passed on, so the broker
        // gives its length itself.
        let mut want = default_response();
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
    let mut want = default_response();
    want.extend(gateway_response.clone());
    assert_eq!(names(&r.headers), want, "passed back");
    assert_eq!(r.headers.get("anthropic-ratelimit-unified-5h-utilization").unwrap(), "0.25");

    // An upstream error carries them too.
    let r =
        env.llm("POST", "/llm/p/gateway/v1/messages", &headers, Some(anthropic_body("many-headers-429", false))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let mut want = default_response();
    want.extend(gateway_response);
    want.insert("content-length".into());
    assert_eq!(names(&r.headers), want, "passed back with an error");

    // Another provider of the same kind keeps to the allowlists.
    let r =
        env.llm("POST", "/llm/p/anthropic/v1/messages", &headers, Some(anthropic_body("many-headers", false))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(env.upstream.last().headers.get("anthropic-organization").is_none());
    assert_eq!(names(&r.headers), default_response());

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
    let mut want = default_response();
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
        for never in ["set-cookie", "www-authenticate", "ocb-budget-remaining"] {
            assert!(r.headers.get(never).is_none(), "{model}: {never}");
        }
        // The rate-limit headers are the broker's, never the provider's.
        assert_eq!(r.headers.get("ratelimit-policy").unwrap(), "\"token\";q=120;w=60", "{model}");
        assert!(r.headers.get("ratelimit").unwrap().to_str().unwrap().starts_with("\"token\";r="), "{model}");
        assert!(r.headers.get("location").is_none() && r.headers.get("alt-svc").is_none(), "{model}");
    }
    env.cleanup().await;
}

/// Providers on one fake upstream: `anthropic` with the defaults and
/// `gateway`, which refuses tools it would run itself except web search of
/// one version. tenant-a has a key for each.
async fn tools_env() -> Option<Env> {
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
        body = {{ deny_server_tools = true, server_tool_allowlist = ["web_search_20250305"] }}
        "#
    ));
    let env = Env::with_llm(EnvOptions::default(), llm, (upstream, addr)).await?;
    for id in ["anthropic", "gateway"] {
        env.put_secret("tenant-a", &format!("llm.{id}"), "llm_api_key", KEY_A).await;
    }
    Some(env)
}

/// A messages request with `extra` merged in (tools, MCP servers).
fn request_with(extra: Value) -> String {
    let mut v = json!({"model": "test-model", "max_tokens": 64,
                       "messages": [{"role": "user", "content": "Fetch https://elsewhere.example/?q=..."}]});
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v.to_string()
}

fn counter(series: &str) -> u64 {
    let text = telemetry().metrics.render();
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse::<f64>().ok())).map_or(0, |v| v as u64)
}

#[tokio::test]
async fn tools_the_provider_would_run_itself_are_refused_before_anything_is_sent() {
    let Some(env) = tools_env().await else { return };
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let h = [("x-api-key", token.as_str()), ("anthropic-version", "2023-06-01")];
    let custom = json!({"name": "read_file", "input_schema": {"type": "object"}});
    let denied_before = counter("ocb_llm_rejected_total{reason=\"server_tool_denied\"}");

    // Passed on unchanged: the caller's own tools, an allowed type, no MCP servers.
    for extra in [
        json!({}),
        json!({"tools": [custom]}),
        json!({"tools": [{"type": "custom", "name": "a", "input_schema": {}}]}),
        json!({"tools": [custom, {"type": "web_search_20250305", "name": "web_search"}]}),
        json!({"tools": [], "mcp_servers": []}),
    ] {
        let body = request_with(extra.clone());
        let before = env.upstream.count();
        let r = env.llm("POST", "/llm/p/gateway/v1/messages", &h, Some(body.clone())).await;
        assert_eq!(r.status, StatusCode::OK, "{extra}: {}", r.text());
        assert_eq!(env.upstream.count(), before + 1, "{extra}");
        assert_eq!(env.upstream.last().body, body.as_bytes(), "{extra}: forwarded unchanged");
    }

    // Refused with 400, and nothing reaches the provider.
    let before = env.upstream.count();
    for (uri, extra, says) in [
        (
            "/llm/p/gateway/v1/messages",
            json!({"tools": [custom, {"type": "web_fetch_20260209", "name": "web_fetch"}]}),
            "tools[1] has type web_fetch_20260209",
        ),
        (
            "/llm/p/gateway/v1/messages",
            json!({"tools": [{"type": "web_search_20260209", "name": "web_search"}]}),
            "tools[0] has type web_search_20260209",
        ),
        (
            "/llm/p/gateway/v1/messages",
            json!({"tools": [{"type": "code_execution_20250825", "name": "code_execution"}]}),
            "tools[0] has type code_execution_20250825",
        ),
        (
            "/llm/p/gateway/v1/messages",
            json!({"mcp_servers": [{"type": "url", "url": "https://mcp.example/sse", "name": "x"}],
                   "tools": [{"type": "mcp_toolset", "mcp_server_name": "x"}]}),
            "mcp_servers is not allowed",
        ),
        // Token counting takes the same tools and MCP servers, and is
        // checked the same way.
        (
            "/llm/p/gateway/v1/messages/count_tokens",
            json!({"tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}]}),
            "tools[0] has type web_fetch_20260209",
        ),
        (
            "/llm/p/gateway/v1/messages/count_tokens",
            json!({"mcp_servers": [{"type": "url", "url": "https://mcp.example/sse", "name": "x"}]}),
            "mcp_servers is not allowed",
        ),
    ] {
        let r = env.llm("POST", uri, &h, Some(request_with(extra.clone()))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{extra}: {}", r.text());
        let v = r.json();
        assert_eq!(v["type"], "error");
        assert_eq!(v["error"]["type"], "invalid_request_error");
        assert_eq!(v["error"]["code"], "server_tool_denied");
        assert!(v["error"]["message"].as_str().unwrap().starts_with(says), "{v}");
    }
    // A tool with two types cannot be checked: the provider might read the other one.
    let twice = r#"{"model":"test-model","max_tokens":8,"messages":[],"tools":[{"type":"custom","type":"web_fetch_20260209","name":"f"}]}"#;
    let r = env.llm("POST", "/llm/p/gateway/v1/messages", &h, Some(twice.into())).await;
    assert_eq!((r.status, r.json()["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_request")));
    assert_eq!(env.upstream.count(), before, "nothing refused reached the provider");
    assert!(counter("ocb_llm_rejected_total{reason=\"server_tool_denied\"}") >= denied_before + 6);
    assert!(telemetry().logs.contents().contains("request refused by the body policy of the provider"));

    // Endpoints without a body, and count_tokens with the caller's own tools, pass.
    assert_eq!(env.llm("GET", "/llm/p/gateway/v1/models", &h, None).await.status, StatusCode::OK);
    let count = request_with(json!({"tools": [custom]}));
    assert_eq!(
        env.llm("POST", "/llm/p/gateway/v1/messages/count_tokens", &h, Some(count)).await.status,
        StatusCode::OK
    );

    // A provider without the policy passes every tool on, as before.
    let fetch = request_with(json!({"tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}]}));
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(fetch.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(env.upstream.last().body, fetch.as_bytes());

    // The admin view shows the policy.
    let (_, v) = env.admin_call("GET", "/v1/admin/providers", None).await;
    let body = |id: &str| v["providers"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap()["body"].clone();
    assert_eq!(body("gateway"), json!({"deny_server_tools": true, "server_tool_allowlist": ["web_search_20250305"]}));
    assert_eq!(body("anthropic"), json!({"deny_server_tools": false, "server_tool_allowlist": []}));
    env.cleanup().await;
}

/// Replaces the file the way a ConfigMap update does: all at once.
fn write(path: &Path, content: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// A request to `anthropic` with a header only a prefix lets through.
async fn send(env: &Env, token: &str, body: &str) -> TestResponse {
    let h = [("x-api-key", token), ("anthropic-foo", "1")];
    env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(body.to_owned())).await
}

#[tokio::test]
async fn a_reload_changes_both_policies_for_new_requests() {
    let (upstream, addr) = start_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let config = |policies: &str| {
        format!(
            "[llm.providers.anthropic]\nkind = \"anthropic\"\nbase_url = \"http://{addr}\"\nallow_http = true\n{policies}\n"
        )
    };
    write(&path, &config(""));
    let cfg = ServerConfig::load(Some(&path)).unwrap();
    let Some(env) = Env::with_llm(EnvOptions::default(), cfg.llm.clone(), (upstream, addr)).await else { return };
    let mut reloader = Reloader::new(Some(path.clone()), cfg, env.state.proxy.clone());
    assert_eq!(reloader.check(), None, "the file is the one loaded at start");
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let fetch = request_with(json!({"model": "many-headers", "tools": [{"type": "web_fetch_20260209", "name": "f"}]}));
    let plain = anthropic_body("many-headers", false);

    // No policies at start.
    let r = send(&env, &token, &fetch).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(env.upstream.last().headers.get("anthropic-foo").is_none());
    assert!(r.headers.get("anthropic-ratelimit-requests-remaining").is_none());

    // Both arrive with a reload and apply from the next request on.
    let version = env.state.proxy.snapshot().version();
    write(
        &path,
        &config(concat!(
            "headers = { request_forward_prefixes = [\"anthropic-\"], ",
            "response_forward_prefixes = [\"anthropic-ratelimit-\"] }\n",
            "body = { deny_server_tools = true }",
        )),
    );
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_ne!(env.state.proxy.snapshot().version(), version);
    let r = send(&env, &token, &fetch).await;
    assert_eq!((r.status, r.json()["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("server_tool_denied")));
    let r = send(&env, &token, &plain).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(env.upstream.last().headers.get("anthropic-foo").unwrap(), "1");
    assert_eq!(r.headers.get("anthropic-ratelimit-requests-remaining").unwrap(), "99");
    let (_, v) = env.admin_call("GET", "/v1/admin/providers", None).await;
    assert_eq!(v["config_version"].as_u64(), Some(env.state.proxy.snapshot().version()));
    assert_eq!(v["providers"][0]["body"]["deny_server_tools"], true);
    assert_eq!(v["providers"][0]["headers"]["request_forward_prefixes"], json!(["anthropic-"]));

    // A prefix that could pass the caller's token is refused, and the
    // policies in use stay.
    write(&path, &config("headers = { request_forward_prefixes = [\"x-\"] }"));
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid));
    assert_eq!(send(&env, &token, &fetch).await.status, StatusCode::BAD_REQUEST);

    // Without them again, requests pass as at start.
    write(&path, &config(""));
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_eq!(env.state.proxy.snapshot().version(), version);
    assert_eq!(send(&env, &token, &fetch).await.status, StatusCode::OK);
    assert!(env.upstream.last().headers.get("anthropic-foo").is_none());
    env.cleanup().await;
}
