//! Which headers pass between callers and providers.
//!
//! Callers' headers go upstream when they are on the allowlist of the
//! provider's kind; upstream response headers come back when they are on
//! [`FORWARDED_RESPONSE_HEADERS`]. A provider can add more in each
//! direction by name prefix (`headers` in its configuration); without
//! prefixes it forwards exactly the allowlists.
//!
//! Some headers are never forwarded, whatever the prefixes say: those that
//! carry credentials or cookies, decide where a request goes or how a body
//! is framed, hop-by-hop headers, and headers the broker sets itself. A
//! prefix that could match one of them is refused when the configuration is
//! loaded, and every header forwarded by prefix is checked against them
//! again.

use std::fmt;

use axum::http::HeaderMap;
use broker_core::llm::ProviderKind;

use crate::config::ProviderHeaders;

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
    // Where the request goes, and how its body is framed and encoded: the
    // provider must read the body as the broker did.
    Name::Exact("host"),
    Name::Exact("forwarded"),
    Name::Prefix("x-forwarded-"),
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
/// provider's response prefixes.
pub(crate) fn response_headers(h: &ProviderHeaders, upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let n = name.as_str();
        if FORWARDED_RESPONSE_HEADERS.contains(&n) || by_prefix(n, &h.response_forward_prefixes, NEVER_BACK) {
            out.append(name.clone(), value.clone());
        }
    }
    out
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
        assert!(ok(&["anthropic-", "x-stainless-", "x-app"], &["anthropic-ratelimit-", "x-", "retry"]).is_ok());
        // `x-forwarded` and `ratelimit` are families: a longer prefix inside
        // one is refused as well as a shorter one.
        for bad in [
            "",
            "x-",
            "x",
            "x-api",
            "x-forwarded",
            "x-forwarded-for",
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
        assert_eq!(names(&response_headers(&none, &upstream)), ["content-type", "x-should-retry"]);
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
        assert_eq!(names(&response_headers(&p, &upstream)), ["anthropic-ratelimit-unified-status", "request-id"]);
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
            "x-custom",
        ]);
        assert_eq!(names(&request_headers(ProviderKind::Anthropic, &p, &caller)), ["x-custom"]);
        let upstream = headers(&[
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
        assert_eq!(names(&response_headers(&p, &upstream)), ["x-custom"]);
    }
}
