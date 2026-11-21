//! What a provider lets through: which headers pass between callers and
//! the provider, and which request bodies it refuses.
//!
//! Headers. Callers' headers go upstream when they are on the allowlist of
//! the provider's kind; upstream response headers come back when they are
//! on [`FORWARDED_RESPONSE_HEADERS`]. A provider can add more in each
//! direction by name prefix (`headers` in its configuration); without
//! prefixes it forwards exactly the allowlists. Some headers are never
//! forwarded, whatever the prefixes say: those that carry credentials or
//! cookies, decide where a request goes or with which method, name the
//! client's address, or frame the body, hop-by-hop headers, and headers the
//! broker sets itself. A prefix that could match one of them is refused when
//! the configuration is loaded, and every header forwarded by prefix is
//! checked against them again.
//!
//! Body. A provider of kind `anthropic` with `body.deny_server_tools`
//! refuses requests that would have it reach out on its own: MCP servers it
//! would connect to (`mcp_servers`), and tools it defines and runs itself,
//! such as web search, web fetch or code execution. Such tools are told
//! apart from the caller's own by their `type`: a tool with a type other
//! than `custom` is refused unless the type is on `server_tool_allowlist`.
//! The body is otherwise forwarded unchanged.

use std::fmt;

use axum::http::HeaderMap;
use broker_core::llm::ProviderKind;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::config::{ProviderBody, ProviderHeaders};

/// Upstream response headers passed back for every provider. Everything
/// else (cookies, provider account and rate-limit details, hop-by-hop
/// headers) is dropped unless the provider's prefixes let it through.
/// `x-should-retry` is how a provider tells SDKs whether an error is worth
/// retrying; without it they guess from the status.
pub(crate) const FORWARDED_RESPONSE_HEADERS: &[&str] =
    &["content-type", "cache-control", "retry-after", "request-id", "x-request-id", "x-should-retry"];

/// A header name, or every name that starts with it.
#[derive(Debug, Clone, Copy)]
enum Name {
    Exact(&'static str),
    Prefix(&'static str),
}

impl Name {
    fn matches(self, header: &str) -> bool {
        match self {
            Self::Exact(n) => header == n,
            Self::Prefix(p) => header.starts_with(p),
        }
    }

    /// Whether a header that starts with `prefix` can match.
    fn reachable_from(self, prefix: &str) -> bool {
        match self {
            Self::Exact(n) => n.starts_with(prefix),
            Self::Prefix(p) => p.starts_with(prefix) || prefix.starts_with(p),
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(n) => f.write_str(n),
            Self::Prefix(p) => write!(f, "{p}*"),
        }
    }
}

/// Caller headers never sent upstream.
const NEVER_UPSTREAM: &[Name] = &[
    // Credentials: the caller's carry its internal token; the provider's
    // auth is set by the broker.
    Name::Exact("authorization"),
    Name::Exact("x-api-key"),
    Name::Exact("proxy-authorization"),
    Name::Exact("cookie"),
    // Where the request goes, and with which method: a gateway on the way
    // may honour an override of either.
    Name::Exact("host"),
    Name::Exact("forwarded"),
    Name::Prefix("x-forwarded-"),
    Name::Exact("via"),
    Name::Prefix("x-http-method"),
    Name::Exact("x-method-override"),
    Name::Exact("x-original-method"),
    Name::Exact("x-original-url"),
    Name::Exact("x-rewrite-url"),
    // Who the client is, as proxies and CDNs tell it.
    Name::Exact("x-real-ip"),
    Name::Exact("x-client-ip"),
    Name::Exact("true-client-ip"),
    Name::Exact("cf-connecting-ip"),
    // How the body is framed and encoded: the provider must read it as the
    // broker did.
    Name::Exact("content-length"),
    Name::Exact("content-encoding"),
    Name::Exact("transfer-encoding"),
    // Hop-by-hop.
    Name::Exact("connection"),
    Name::Exact("keep-alive"),
    Name::Exact("proxy-connection"),
    Name::Exact("te"),
    Name::Exact("trailer"),
    Name::Exact("upgrade"),
    // Set by the broker.
    Name::Exact("accept-encoding"),
    Name::Exact("traceparent"),
    Name::Exact("tracestate"),
];

/// Upstream response headers never passed back.
const NEVER_BACK: &[Name] = &[
    // The credentials the broker sends upstream: an upstream that echoes
    // request headers would hand the provider key to the caller.
    Name::Exact("authorization"),
    Name::Exact("proxy-authorization"),
    Name::Exact("x-api-key"),
    // How the broker's own response is framed and encoded.
    Name::Exact("content-length"),
    Name::Exact("content-encoding"),
    Name::Exact("transfer-encoding"),
    // Hop-by-hop.
    Name::Exact("connection"),
    Name::Exact("keep-alive"),
    Name::Exact("proxy-connection"),
    Name::Exact("te"),
    Name::Exact("trailer"),
    Name::Exact("upgrade"),
    Name::Exact("proxy-authenticate"),
    // Sessions and credential challenges of the provider: they are about the
    // provider key, not the caller's token.
    Name::Prefix("set-cookie"),
    Name::Exact("www-authenticate"),
    // Kept for the broker's own limit headers.
    Name::Prefix("ratelimit"),
    Name::Prefix("ocb-"),
    // They would send the caller elsewhere.
    Name::Exact("location"),
    Name::Exact("alt-svc"),
];

/// Checks the `headers` of provider `id`.
pub(crate) fn validate_headers(id: &str, h: &ProviderHeaders) -> Result<(), String> {
    let what = |key: &str| format!("llm.providers.{id}.headers.{key}");
    check_prefixes(&what("request_forward_prefixes"), &h.request_forward_prefixes, NEVER_UPSTREAM)?;
    check_prefixes(&what("response_forward_prefixes"), &h.response_forward_prefixes, NEVER_BACK)
}

fn check_prefixes(what: &str, prefixes: &[String], never: &[Name]) -> Result<(), String> {
    for (i, p) in prefixes.iter().enumerate() {
        if p.is_empty() {
            return Err(format!("{what}: an empty prefix would match every header"));
        }
        // Header names arrive in lowercase.
        if !p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(format!("{what}: {p:?} may only have lowercase letters, digits and '-'"));
        }
        if prefixes[..i].contains(p) {
            return Err(format!("{what}: {p:?} is listed twice"));
        }
        if let Some(n) = never.iter().find(|n| n.reachable_from(p)) {
            return Err(format!("{what}: {p:?} could match {n}, which is never forwarded"));
        }
    }
    Ok(())
}

/// Whether `name` starts with one of `prefixes` and is not on `never`.
fn by_prefix(name: &str, prefixes: &[String], never: &[Name]) -> bool {
    prefixes.iter().any(|p| name.starts_with(p.as_str())) && !never.iter().any(|n| n.matches(name))
}

/// The caller headers sent upstream: those on the allowlist of `kind` and
/// those that start with one of the provider's request prefixes. The
/// provider's auth and the other headers the broker sets come on top.
pub(crate) fn request_headers(kind: ProviderKind, h: &ProviderHeaders, caller: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in caller {
        let n = name.as_str();
        if kind.forwarded_request_headers().contains(&n) || by_prefix(n, &h.request_forward_prefixes, NEVER_UPSTREAM) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// The upstream response headers passed back: those on
/// [`FORWARDED_RESPONSE_HEADERS`] and those that start with one of the
/// provider's response prefixes, except a header whose value holds one of
/// `secrets` (the provider key and the caller's token), which is dropped
/// whole. Also returns how many were dropped that way.
pub(crate) fn response_headers(h: &ProviderHeaders, upstream: &HeaderMap, secrets: &[&[u8]]) -> (HeaderMap, usize) {
    let mut out = HeaderMap::new();
    let mut dropped = 0;
    for (name, value) in upstream {
        let n = name.as_str();
        if !FORWARDED_RESPONSE_HEADERS.contains(&n) && !by_prefix(n, &h.response_forward_prefixes, NEVER_BACK) {
            continue;
        }
        if holds_any(value.as_bytes(), secrets) {
            dropped += 1;
        } else {
            out.append(name.clone(), value.clone());
        }
    }
    (out, dropped)
}

/// Whether `value` holds one of the non-empty `secrets`, byte for byte.
fn holds_any(value: &[u8], secrets: &[&[u8]]) -> bool {
    secrets.iter().any(|s| !s.is_empty() && value.windows(s.len()).any(|w| w == *s))
}

/// Checks the `body` of provider `id`, of kind `kind`.
pub(crate) fn validate_body(id: &str, kind: ProviderKind, b: &ProviderBody) -> Result<(), String> {
    let what = format!("llm.providers.{id}.body");
    if *b == ProviderBody::default() {
        return Ok(());
    }
    if kind != ProviderKind::Anthropic {
        return Err(format!("{what}: only providers of kind anthropic check request bodies"));
    }
    if !b.deny_server_tools {
        return Err(format!("{what}.server_tool_allowlist: has no effect without deny_server_tools = true"));
    }
    for (i, t) in b.server_tool_allowlist.iter().enumerate() {
        if t.is_empty() || !t.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
            return Err(format!(
                "{what}.server_tool_allowlist: {t:?} is not a tool type (lowercase letters, digits and '_', e.g. web_search_20250305)"
            ));
        }
        if b.server_tool_allowlist[..i].contains(t) {
            return Err(format!("{what}.server_tool_allowlist: {t:?} is listed twice"));
        }
    }
    Ok(())
}

/// Why the body policy refused a request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BodyRefusal {
    /// The body is not a JSON object, or its `tools` or `mcp_servers` do
    /// not have their usual shape, a key given twice included: it cannot be
    /// checked.
    Unreadable,
    /// `mcp_servers` names servers the provider would connect to.
    McpServers,
    /// `tools[index]` has a type that is neither `custom` nor allowed. The
    /// type is kept when it looks like one.
    ToolType { index: usize, tool_type: Option<String> },
}

impl BodyRefusal {
    /// The error code callers see.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unreadable => "invalid_request",
            Self::McpServers | Self::ToolType { .. } => "server_tool_denied",
        }
    }
}

impl fmt::Display for BodyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let allowed = "this provider accepts custom tools and only the tool types it is configured to allow";
        match self {
            Self::Unreadable => f.write_str(
                "request body must be a JSON object, with tools an array of objects and mcp_servers an array, \
                 and no key given twice",
            ),
            Self::McpServers => {
                f.write_str("mcp_servers is not allowed: this provider does not connect to MCP servers for a caller")
            }
            Self::ToolType { index, tool_type: Some(t) } => {
                write!(f, "tools[{index}] has type {t}, which is not allowed: {allowed}")
            }
            Self::ToolType { index, tool_type: None } => {
                write!(f, "tools[{index}] has a type that is not allowed: {allowed}")
            }
        }
    }
}

/// The parts of a request body the body policy reads. serde refuses a
/// field given twice, so a body cannot carry two `tools`, or a tool two
/// `type`s, of which the broker would check one and the provider use the
/// other.
#[derive(Deserialize)]
struct BodyTools {
    #[serde(default)]
    tools: Option<Vec<ToolType>>,
    #[serde(default)]
    mcp_servers: Option<Vec<IgnoredAny>>,
}

/// A tool as the body policy sees it. (serde would read a tool given as an
/// array by position; the provider refuses such a tool, so nothing passes
/// that way.)
#[derive(Deserialize)]
struct ToolType {
    /// Absent (or null) for the caller's own tools.
    #[serde(default, rename = "type")]
    tool_type: Option<String>,
}

/// Checks a request body against the provider's body policy.
pub(crate) fn check_body(policy: &ProviderBody, body: &[u8]) -> Result<(), BodyRefusal> {
    if !policy.deny_server_tools {
        return Ok(());
    }
    // serde would also read a struct from an array, by position.
    if body.trim_ascii_start().first() != Some(&b'{') {
        return Err(BodyRefusal::Unreadable);
    }
    let parsed: BodyTools = serde_json::from_slice(body).map_err(|_| BodyRefusal::Unreadable)?;
    if parsed.mcp_servers.is_some_and(|s| !s.is_empty()) {
        return Err(BodyRefusal::McpServers);
    }
    for (index, tool) in parsed.tools.unwrap_or_default().into_iter().enumerate() {
        let Some(t) = tool.tool_type else { continue };
        if t == "custom" || policy.server_tool_allowlist.contains(&t) {
            continue;
        }
        // Shown back only when it cannot be anything but a tool type.
        let plain = !t.is_empty()
            && t.len() <= 64
            && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.');
        return Err(BodyRefusal::ToolType { index, tool_type: plain.then_some(t) });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn headers(names: &[&str]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for n in names {
            m.append(HeaderName::from_bytes(n.as_bytes()).unwrap(), HeaderValue::from_static("v"));
        }
        m
    }

    fn names(m: &HeaderMap) -> Vec<&str> {
        let mut v: Vec<&str> = m.keys().map(HeaderName::as_str).collect();
        v.sort_unstable();
        v
    }

    fn prefixes(request: &[&str], response: &[&str]) -> ProviderHeaders {
        ProviderHeaders {
            request_forward_prefixes: request.iter().map(|p| (*p).to_owned()).collect(),
            response_forward_prefixes: response.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    #[test]
    fn the_allowlists_hold_no_header_that_is_never_forwarded() {
        for kind in [ProviderKind::Anthropic, ProviderKind::Openai] {
            for n in kind.forwarded_request_headers() {
                assert!(!NEVER_UPSTREAM.iter().any(|x| x.matches(n)), "{n}");
            }
        }
        for n in FORWARDED_RESPONSE_HEADERS {
            assert!(!NEVER_BACK.iter().any(|x| x.matches(n)), "{n}");
        }
    }

    #[test]
    fn prefixes_that_could_match_a_header_never_forwarded_are_refused() {
        let ok = |request: &[&str], response: &[&str]| validate_headers("gw", &prefixes(request, response));
        assert!(ok(&[], &[]).is_ok());
        assert!(
            ok(&["anthropic-", "x-stainless-", "x-app"], &["anthropic-ratelimit-", "x-ratelimit-", "retry"]).is_ok()
        );
        // `x-forwarded`, `x-http-method` and `ratelimit` are families: a
        // longer prefix inside one is refused as well as a shorter one.
        for bad in [
            "",
            "x-",
            "x",
            "x-api",
            "x-forwarded",
            "x-forwarded-for",
            "x-http",
            "x-http-method-override-",
            "x-o",
            "x-r",
            "x-real",
            "true",
            "cf-",
            "v",
            "via",
            "auth",
            "a",
            "cookie",
            "host",
            "content-",
            "te",
            "t",
            "trace",
            "accept-encoding",
            "conn",
            "Anthropic-",
            "anthropic_",
            "anthropic-*",
        ] {
            assert!(ok(&[bad], &[]).is_err(), "request prefix {bad:?}");
        }
        for bad in [
            "",
            "x-",
            "x",
            "x-api",
            "authorization",
            "a",
            "proxy-a",
            "set-",
            "set-cookie2",
            "www-",
            "w",
            "rate",
            "ratelimit-policy",
            "ocb",
            "ocb-budget-",
            "content-",
            "transfer-",
            "loc",
            "alt-",
            "proxy-",
            "trailer",
            "X-",
        ] {
            assert!(ok(&[], &[bad]).is_err(), "response prefix {bad:?}");
        }
        assert!(ok(&["anthropic-", "anthropic-"], &[]).is_err(), "listed twice");
        let e = ok(&["x-"], &[]).unwrap_err();
        assert_eq!(
            e,
            "llm.providers.gw.headers.request_forward_prefixes: \"x-\" could match x-api-key, which is never forwarded"
        );
        // Nor back: an upstream that echoes request headers would return the
        // provider key in it.
        let e = ok(&[], &["x-"]).unwrap_err();
        assert_eq!(
            e,
            "llm.providers.gw.headers.response_forward_prefixes: \"x-\" could match x-api-key, which is never forwarded"
        );
        let e = ok(&[], &["ocb"]).unwrap_err();
        assert!(e.ends_with("\"ocb\" could match ocb-*, which is never forwarded"), "{e}");
    }

    #[test]
    fn without_prefixes_exactly_the_allowlists_pass() {
        let caller =
            headers(&["content-type", "accept", "anthropic-version", "anthropic-beta", "anthropic-foo", "x-title"]);
        let none = ProviderHeaders::default();
        assert_eq!(
            names(&request_headers(ProviderKind::Anthropic, &none, &caller)),
            ["accept", "anthropic-beta", "anthropic-version", "content-type"]
        );
        assert_eq!(
            names(&request_headers(ProviderKind::Openai, &none, &caller)),
            ["accept", "content-type", "x-title"]
        );
        let upstream =
            headers(&["content-type", "x-should-retry", "anthropic-ratelimit-tokens-remaining", "set-cookie"]);
        assert_eq!(names(&response_headers(&none, &upstream, &[]).0), ["content-type", "x-should-retry"]);
    }

    #[test]
    fn prefixes_add_headers_and_keep_every_value() {
        let mut caller = headers(&["anthropic-version", "anthropic-foo", "x-stainless-os", "x-app"]);
        caller.append("anthropic-foo", HeaderValue::from_static("second"));
        let p = prefixes(&["anthropic-", "x-stainless-"], &["anthropic-ratelimit-"]);
        let out = request_headers(ProviderKind::Anthropic, &p, &caller);
        assert_eq!(names(&out), ["anthropic-foo", "anthropic-version", "x-stainless-os"]);
        assert_eq!(out.get_all("anthropic-foo").iter().collect::<Vec<_>>(), ["v", "second"]);
        let upstream = headers(&["anthropic-ratelimit-unified-status", "anthropic-organization-id", "request-id"]);
        assert_eq!(
            names(&response_headers(&p, &upstream, &[]).0),
            ["anthropic-ratelimit-unified-status", "request-id"]
        );
    }

    /// Validation refuses these prefixes; forwarding drops the headers they
    /// would let through all the same.
    #[test]
    fn headers_never_forwarded_are_dropped_whatever_the_prefixes() {
        let every: Vec<String> = ('a'..='z').chain('0'..='9').map(String::from).collect();
        let p = ProviderHeaders { request_forward_prefixes: every.clone(), response_forward_prefixes: every };
        let caller = headers(&[
            "authorization",
            "x-api-key",
            "proxy-authorization",
            "cookie",
            "host",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "content-length",
            "content-encoding",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "accept-encoding",
            "traceparent",
            "tracestate",
            "via",
            "x-http-method",
            "x-http-method-override",
            "x-method-override",
            "x-original-method",
            "x-original-url",
            "x-rewrite-url",
            "x-real-ip",
            "x-client-ip",
            "true-client-ip",
            "cf-connecting-ip",
            "x-custom",
        ]);
        assert_eq!(names(&request_headers(ProviderKind::Anthropic, &p, &caller)), ["x-custom"]);
        let upstream = headers(&[
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "content-length",
            "content-encoding",
            "transfer-encoding",
            "connection",
            "proxy-authenticate",
            "set-cookie",
            "set-cookie2",
            "www-authenticate",
            "ratelimit",
            "ratelimit-policy",
            "ocb-budget-remaining",
            "location",
            "alt-svc",
            "x-custom",
        ]);
        assert_eq!(names(&response_headers(&p, &upstream, &[]).0), ["x-custom"]);
    }

    #[test]
    fn response_headers_that_hold_a_secret_are_dropped() {
        let key = b"sk-ant-api03-FAKE-key";
        let token = b"ocb_llm_0123";
        let mut upstream = HeaderMap::new();
        for (name, value) in [
            ("content-type", "application/json"),
            ("request-id", "req_sk-ant-api03-FAKE-key"),
            ("anthropic-ratelimit-unified-status", "allowed"),
            ("anthropic-debug", "token=ocb_llm_0123; more"),
            ("anthropic-echo", "sk-ant-api03-FAKE"),
        ] {
            upstream.append(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        let p = prefixes(&[], &["anthropic-"]);
        let (out, dropped) = response_headers(&p, &upstream, &[key, token]);
        // Dropped whole, wherever the secret sits in the value; part of the
        // key alone is not the key.
        assert_eq!(names(&out), ["anthropic-echo", "anthropic-ratelimit-unified-status", "content-type"]);
        assert_eq!(dropped, 2);
        // Empty secrets match nothing.
        assert_eq!(response_headers(&p, &upstream, &[b"", b""]).1, 0);
    }

    fn deny(allow: &[&str]) -> ProviderBody {
        ProviderBody { deny_server_tools: true, server_tool_allowlist: allow.iter().map(|t| (*t).to_owned()).collect() }
    }

    #[test]
    fn body_policy_settings() {
        let anthropic = ProviderKind::Anthropic;
        assert!(validate_body("gw", anthropic, &ProviderBody::default()).is_ok());
        assert!(validate_body("ds", ProviderKind::Openai, &ProviderBody::default()).is_ok());
        assert!(validate_body("gw", anthropic, &deny(&[])).is_ok());
        assert!(validate_body("gw", anthropic, &deny(&["web_search_20250305", "text_editor_20250728"])).is_ok());
        assert_eq!(
            validate_body("ds", ProviderKind::Openai, &deny(&[])).unwrap_err(),
            "llm.providers.ds.body: only providers of kind anthropic check request bodies"
        );
        let allow_only =
            ProviderBody { deny_server_tools: false, server_tool_allowlist: vec!["web_search_20250305".into()] };
        assert!(validate_body("gw", anthropic, &allow_only).is_err(), "an allowlist without the deny");
        for bad in ["", "web_search_*", "web_search*", "Web_Search_20250305", "web-search", "web_search_20250305 "] {
            assert!(validate_body("gw", anthropic, &deny(&[bad])).is_err(), "{bad:?}");
        }
        assert!(validate_body("gw", anthropic, &deny(&["bash_20250124", "bash_20250124"])).is_err(), "listed twice");
    }

    #[test]
    fn tools_the_provider_would_run_itself_are_refused() {
        let policy = deny(&["web_search_20250305"]);
        let check = |body: &str| check_body(&policy, body.as_bytes());
        let tool = |index, t: &str| Err(BodyRefusal::ToolType { index, tool_type: Some(t.to_owned()) });
        for ok in [
            r#"{"model":"m","messages":[]}"#,
            r#" {"tools":null,"mcp_servers":null}"#,
            r#"{"tools":[],"mcp_servers":[]}"#,
            // The caller's own tools; a `type` inside a tool's schema is not its type.
            r#"{"tools":[{"name":"read_file","input_schema":{"type":"object"}}]}"#,
            r#"{"tools":[{"type":"custom","name":"a","input_schema":{}},{"type":null,"name":"b"}]}"#,
            // An escaped `custom` reads as `custom`, here as at the provider.
            r#"{"tools":[{"type":"cust\u006fm","name":"c"}]}"#,
            // Types that appear elsewhere in the body are not tools.
            r#"{"messages":[{"role":"user","content":[{"type":"web_fetch_tool_result"}]}],"tools":[]}"#,
            // Allowed by name, version date included.
            r#"{"tools":[{"type":"web_search_20250305","name":"web_search"}]}"#,
        ] {
            assert_eq!(check(ok), Ok(()), "{ok}");
        }
        let fetch = r#"{"tools":[{"name":"a"},{"type":"web_fetch_20260209","name":"web_fetch"}]}"#;
        assert_eq!(check(fetch), tool(1, "web_fetch_20260209"));
        let newer = r#"{"tools":[{"type":"web_search_20260209","name":"web_search"}]}"#;
        assert_eq!(check(newer), tool(0, "web_search_20260209"), "exact types only");
        let code = r#"{"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}"#;
        assert_eq!(check(code), tool(0, "code_execution_20250825"));
        // Any type but `custom` needs an entry, the provider's client-side
        // tools included: the broker cannot tell which run where.
        assert_eq!(check(r#"{"tools":[{"type":"bash_20250124","name":"bash"}]}"#), tool(0, "bash_20250124"));
        let toolset = r#"{"tools":[{"type":"mcp_toolset","mcp_server_name":"x"}]}"#;
        assert_eq!(check(toolset), tool(0, "mcp_toolset"));
        for odd in [r#"{"tools":[{"type":""}]}"#, r#"{"tools":[{"type":"web search & more"}]}"#] {
            assert_eq!(check(odd), Err(BodyRefusal::ToolType { index: 0, tool_type: None }), "{odd}");
        }
        let mcp = r#"{"mcp_servers":[{"type":"url","url":"https://mcp.example/sse","name":"x"}],"tools":[]}"#;
        assert_eq!(check(mcp), Err(BodyRefusal::McpServers));

        for unreadable in [
            "",
            "not json",
            "[]",
            r#"[[{"type":"web_fetch_20260209"}]]"#,
            r#""tools""#,
            r#"{"tools":{"type":"web_fetch_20260209"}}"#,
            r#"{"tools":["web_fetch_20260209"]}"#,
            r#"{"tools":[{"type":5}]}"#,
            r#"{"mcp_servers":{"x":{"url":"https://mcp.example"}}}"#,
            r#"{"mcp_servers":"https://mcp.example"}"#,
            // A key given twice: the provider may read the other one.
            r#"{"tools":[{"type":"custom","type":"web_fetch_20260209"}]}"#,
            r#"{"tools":[{"type":"web_fetch_20260209","type":"custom"}]}"#,
            r#"{"tools":[],"tools":[{"type":"web_fetch_20260209"}]}"#,
            r#"{"mcp_servers":[],"mcp_servers":[{"type":"url"}]}"#,
            r#"{"tools":[]} {}"#,
        ] {
            assert_eq!(check(unreadable), Err(BodyRefusal::Unreadable), "{unreadable}");
        }
        // Without deny_server_tools the body is not looked at.
        assert_eq!(check_body(&ProviderBody::default(), b"not json"), Ok(()));
        assert_eq!(check_body(&ProviderBody::default(), fetch.as_bytes()), Ok(()));
    }

    #[test]
    fn refusals_say_what_was_refused_without_echoing_odd_input() {
        let shown = BodyRefusal::ToolType { index: 1, tool_type: Some("web_fetch_20260209".into()) };
        assert!(shown.to_string().starts_with("tools[1] has type web_fetch_20260209, which is not allowed"));
        assert_eq!(shown.code(), "server_tool_denied");
        let hidden = BodyRefusal::ToolType { index: 0, tool_type: None };
        assert!(hidden.to_string().starts_with("tools[0] has a type that is not allowed"));
        assert_eq!(BodyRefusal::McpServers.code(), "server_tool_denied");
        assert_eq!(BodyRefusal::Unreadable.code(), "invalid_request");
    }
}
