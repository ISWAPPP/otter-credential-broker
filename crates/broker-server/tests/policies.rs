#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Which headers pass between callers and providers, in both directions.

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
