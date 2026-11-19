//! Request spans, W3C trace context propagation and per-route latency metrics.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::TraceContextExt;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Histogram buckets (seconds) shared by all latency metrics: 5 ms .. 30 min.
pub const LATENCY_BUCKETS: &[f64] =
    &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0];

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(&value)) {
            self.0.insert(name, value);
        }
    }
}

/// Parent context from incoming `traceparent` / `tracestate` headers.
pub fn extract_context(headers: &HeaderMap) -> opentelemetry::Context {
    TraceContextPropagator::new().extract(&HeaderExtractor(headers))
}

/// Parent context from a stored `traceparent` value.
pub fn context_from_traceparent(traceparent: &str) -> opentelemetry::Context {
    let mut h = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(traceparent) {
        h.insert("traceparent", v);
    }
    extract_context(&h)
}

/// Writes `traceparent` (and a non-empty `tracestate`) for `span` into
/// outgoing headers.
pub fn inject_context(span: &Span, headers: &mut HeaderMap) {
    TraceContextPropagator::new().inject_context(&span.context(), &mut HeaderInjector(headers));
    if headers.get("tracestate").is_some_and(|v| v.is_empty()) {
        headers.remove("tracestate");
    }
}

/// Trace id of a span, if tracing is active (it is whenever the binary runs;
/// tests may run without it).
pub fn trace_id_of(span: &Span) -> Option<String> {
    let cx = span.context();
    let sc = cx.span().span_context().clone();
    sc.is_valid().then(|| sc.trace_id().to_string())
}

pub fn current_trace_id() -> Option<String> {
    trace_id_of(&Span::current())
}

fn route_of<B>(req: &axum::http::Request<B>) -> String {
    req.extensions().get::<MatchedPath>().map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned())
}

/// A fixed set of method names for spans and metric labels: any other method
/// string (HTTP allows arbitrary tokens) becomes `other`, so callers cannot
/// create unbounded label values.
pub fn method_label(m: &Method) -> &'static str {
    match *m {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

/// `make_span_with` for `TraceLayer`: one span per request, carrying route
/// and trace id so every JSON log line of the request can be correlated.
/// Header values are never recorded.
///
/// With `trust_parent`, an incoming W3C `traceparent` becomes the span's
/// parent (the admin listener: the platform core is trusted). Without it the
/// span starts a new trace and only links to the caller's context, so an
/// untrusted caller cannot choose the trace id that ends up in audit and
/// usage rows; the caller's trace id is kept in `caller_trace_id`.
pub fn make_span<B>(req: &axum::http::Request<B>, trust_parent: bool) -> Span {
    let span = tracing::info_span!(
        "http.request",
        method = method_label(req.method()),
        route = %route_of(req),
        status = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        caller_trace_id = tracing::field::Empty,
    );
    let parent = extract_context(req.headers());
    let caller = parent.span().span_context().clone();
    if caller.is_valid() {
        if trust_parent {
            let _ = span.set_parent(parent);
        } else {
            span.add_link(caller.clone());
            span.record("caller_trace_id", caller.trace_id().to_string().as_str());
        }
    }
    let id = trace_id_of(&span).unwrap_or_else(|| {
        let mut b = [0u8; 16];
        let _ = getrandom::fill(&mut b);
        hex::encode(b)
    });
    span.record("trace_id", id.as_str());
    span
}

/// Records `http_request_duration_seconds{method,route,status}` and the
/// status on the request span. `route` is the matched route template, never
/// the raw path, so label cardinality stays bounded.
pub async fn track_metrics(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let route = route_of(&req);
    let method = method_label(req.method());
    let resp = next.run(req).await;
    let status = resp.status().as_u16().to_string();
    Span::current().record("status", status.as_str());
    metrics::histogram!("http_request_duration_seconds", "method" => method, "route" => route, "status" => status)
        .record(start.elapsed().as_secs_f64());
    resp
}
