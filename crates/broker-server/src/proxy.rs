//! LLM proxy: `/llm/p/<provider>/<endpoint>` for any configured provider,
//! plus the older `/llm/anthropic/<endpoint>` (the provider with id
//! `anthropic`) and `/llm/openai/<provider>/<endpoint>` (OpenAI-compatible
//! providers).
//!
//! A caller (an agent pod) authenticates with an internal LLM token, sent the
//! way its SDK sends an API key (`x-api-key` or `Authorization: Bearer`). The
//! proxy then
//! 1. accepts only allowlisted endpoints and query keys of the provider kind;
//!    the upstream URL is built from configuration only;
//! 2. validates the token (tenant, provider allowlist, rate limit, requests
//!    in flight) and the budget, and checks the body against the provider's
//!    body policy, before anything is sent upstream;
//! 3. resolves the tenant's provider key (audited decrypt), builds a fresh
//!    request with the caller headers the provider lets through (an
//!    allowlist per kind, plus the provider's prefixes; see `policy`), sets
//!    the provider auth header itself and forwards the body bytes unchanged;
//! 4. hands the upstream exchange to its own task. That task streams the
//!    response back unchanged (status, the headers the provider lets
//!    through, body bytes) while a tap extracts usage and a redactor
//!    replaces the provider key should it ever appear (a header that holds
//!    the key or the caller's token is dropped). It owns accounting:
//!    when the caller disconnects, reads too slowly, or gives up waiting, the
//!    task keeps reading the upstream response to its end, so usage comes
//!    from the provider's own report and cannot be avoided by hanging up;
//! 5. passes upstream error bodies through only after scrubbing anything
//!    key-like.
//!
//! Request and response bodies, keys and tokens are never logged.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use broker_core::keeper::{Authorized, LlmGrant};
use broker_core::limits::{LimitKind, LimitLevel, LimitRefusal, Reservation};
use broker_core::llm::scrub::{StreamRedactor, scrub_error_body};
use broker_core::llm::usage::{TapReport, Usage, UsageSource, UsageTap};
use broker_core::llm::{Endpoint, HttpMethod, ProviderKind};
use broker_core::store::NewUsageRow;
use broker_core::tokens::TokenDigest;
use broker_core::{BrokerError, Keeper, Secret};
use bytes::Bytes;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::AppState;
use crate::admin::auth_failure;
use crate::config::{LlmConfig, ProviderHeaders};
use crate::error::{classify, llm_error, llm_error_response, llm_limit_error};
use crate::limit_view::LimitView;
use crate::limits::{Inflight, InflightKey, InflightPermit, InflightRefusal, MinuteLimiter, seconds_to_next_minute};
use crate::observe::{context_from_traceparent, inject_context, trace_id_of};
use crate::policy::{BodyRefusal, check_body, request_headers, response_headers};
use crate::registry::{ProviderSnapshot, SnapshotCell, publish};
use crate::tls::{ClientSettings, http_client};

/// Chunks buffered between the exchange task and a caller.
const CLIENT_BUFFER: usize = 32;
/// Upper bound for a request's `max_tokens` used in conservative estimates.
const MAX_TOKENS_CAP: u64 = 10_000_000;

/// Proxy settings that only change with a restart.
#[derive(Debug, Clone, Copy)]
struct Settings {
    max_request_bytes: usize,
    request_read_timeout: Duration,
    response_timeout: Duration,
    idle_timeout: Duration,
    max_error_body_bytes: usize,
    max_buffered_response_bytes: usize,
    max_reservation_tokens: u64,
}

impl Settings {
    fn from(cfg: &LlmConfig) -> Self {
        Self {
            max_request_bytes: cfg.max_request_bytes,
            request_read_timeout: Duration::from_secs(cfg.request_read_timeout_secs),
            response_timeout: Duration::from_secs(cfg.response_timeout_secs),
            idle_timeout: Duration::from_secs(cfg.idle_timeout_secs),
            max_error_body_bytes: cfg.max_error_body_bytes,
            max_buffered_response_bytes: cfg.max_buffered_response_bytes,
            max_reservation_tokens: cfg.max_reservation_tokens,
        }
    }
}

/// The proxy of one process. Providers, prices and the clients of providers
/// with their own TLS settings sit in a snapshot that a configuration reload
/// replaces; everything else lives as long as the process and is never
/// replaced: the exchange tasks (which shutdown waits for), the shutdown
/// switch, the in-flight limits and the client shared by providers without
/// TLS settings.
pub struct LlmProxy {
    snapshot: SnapshotCell,
    /// Platform roots, no client certificate.
    http: reqwest::Client,
    clients: ClientSettings,
    settings: Settings,
    tracker: TaskTracker,
    shutdown: CancellationToken,
    inflight: Arc<Inflight>,
    /// Requests to `GET /llm/_/limits` per token.
    limits_views: MinuteLimiter<TokenDigest>,
}

impl LlmProxy {
    /// Validates `cfg`, reads the TLS files of its providers and sets up
    /// their clients.
    pub fn new(cfg: &LlmConfig) -> Result<Self, String> {
        let clients = ClientSettings {
            connect_timeout: Duration::from_secs(cfg.connect_timeout_secs),
            total_timeout: Duration::from_secs(cfg.max_duration_secs),
        };
        let snapshot = ProviderSnapshot::build(cfg, clients, None)?;
        let http = http_client(clients, None)?;
        publish(&snapshot, None);
        Ok(Self {
            snapshot: SnapshotCell::new(snapshot),
            http,
            clients,
            settings: Settings::from(cfg),
            tracker: TaskTracker::new(),
            shutdown: CancellationToken::new(),
            inflight: Inflight::new(cfg.max_concurrent_per_token, cfg.max_concurrent_total),
            limits_views: MinuteLimiter::new(cfg.limits_endpoint_per_minute),
        })
    }

    /// The providers and prices new requests use.
    pub fn snapshot(&self) -> Arc<ProviderSnapshot> {
        self.snapshot.load()
    }

    /// Builds a snapshot from the providers and prices of `cfg`, with the
    /// current content of their TLS files, without installing it. Only
    /// `llm.providers` and `llm.pricing` are taken from `cfg`: the other
    /// settings of the proxy keep their values from start.
    pub fn prepare(&self, cfg: &LlmConfig) -> Result<ProviderSnapshot, String> {
        ProviderSnapshot::build(cfg, self.clients, Some(&self.snapshot()))
    }

    /// Makes `next` the snapshot of new requests. Requests already running
    /// finish with the snapshot they started with.
    pub fn install(&self, next: ProviderSnapshot) {
        let previous = self.snapshot.replace(next);
        publish(&self.snapshot(), Some(&previous));
    }

    pub fn has_provider(&self, id: &str) -> bool {
        self.snapshot().provider(id).is_some()
    }

    /// Exchange tasks still running (each finishes with its accounting).
    pub fn tracker(&self) -> &TaskTracker {
        &self.tracker
    }

    /// Cuts every running exchange: callers get an aborted response, usage is
    /// accounted conservatively. Used at the end of the shutdown grace period.
    pub fn abort_all(&self) {
        self.shutdown.cancel();
    }

    pub fn inflight(&self) -> &Inflight {
        &self.inflight
    }

    pub(crate) fn limits_views(&self) -> &MinuteLimiter<TokenDigest> {
        &self.limits_views
    }
}

/// `/llm/p/<provider>/<endpoint>`: any configured provider, by id.
pub async fn by_id(State(st): State<AppState>, req: Request) -> Response {
    let (provider, rest) = split_provider(req.uri().path(), "/llm/p/");
    proxy(st, &provider, None, &rest, req).await
}

/// `/llm/anthropic/<endpoint>`: the provider with id `anthropic`.
pub async fn anthropic(State(st): State<AppState>, req: Request) -> Response {
    let rest = req.uri().path().strip_prefix("/llm/anthropic/").unwrap_or("").to_owned();
    proxy(st, "anthropic", Some(ProviderKind::Anthropic), &rest, req).await
}

/// `/llm/openai/<provider>/<endpoint>`: OpenAI-compatible providers.
pub async fn openai(State(st): State<AppState>, req: Request) -> Response {
    let (provider, rest) = split_provider(req.uri().path(), "/llm/openai/");
    proxy(st, &provider, Some(ProviderKind::Openai), &rest, req).await
}

/// Provider id and endpoint path from the raw request path (no decoding).
fn split_provider(path: &str, prefix: &str) -> (String, String) {
    let tail = path.strip_prefix(prefix).unwrap_or("");
    let (provider, rest) = tail.split_once('/').unwrap_or((tail, ""));
    (provider.to_owned(), rest.to_owned())
}

fn reject(kind: ProviderKind, e: &BrokerError) -> Response {
    let (_, code) = classify(e);
    metrics::counter!("ocb_llm_rejected_total", "reason" => code).increment(1);
    llm_error(kind, e)
}

/// 402 or 429 for a request refused by a limit of `level`, which the
/// response names. `provider` labels the denial in the metrics.
fn refused(
    view: &mut LimitView,
    kind: ProviderKind,
    provider: &str,
    tenant: &str,
    level: LimitLevel,
    e: &BrokerError,
) -> Response {
    view.refused(
        level,
        match e {
            BrokerError::Limit(r) => Some(r),
            _ => None,
        },
    );
    let (_, code) = classify(e);
    metrics::counter!("ocb_llm_rejected_total", "reason" => code).increment(1);
    let what = match e {
        BrokerError::Limit(r) => r.kind.as_str(),
        BrokerError::RateLimited { .. } => LimitKind::Rate.as_str(),
        BrokerError::TooManyInFlight(_) => LimitKind::InFlight.as_str(),
        _ => LimitKind::Budget.as_str(),
    };
    metrics::counter!(
        "ocb_limit_denials_total",
        "level" => level.as_str(), "kind" => what, "provider" => provider.to_owned(), "tenant" => tenant.to_owned()
    )
    .increment(1);
    llm_limit_error(kind, level, e)
}

/// The token's own rate limit refusal, worded like those of the other levels.
fn token_rate_refusal(auth: &Authorized, e: BrokerError) -> BrokerError {
    let BrokerError::RateLimited { retry_after_secs } = e else { return e };
    BrokerError::Limit(LimitRefusal {
        level: LimitLevel::Token,
        kind: LimitKind::Rate,
        message: format!(
            "rate limit of this LLM token exceeded ({} requests per minute), retry after {retry_after_secs}s",
            auth.token_rpm.limit
        ),
        retry_after_secs: Some(retry_after_secs),
        budget: None,
    })
}

/// A request over a cap on requests in flight, on this replica. The
/// replica's total is reported at the global level, without naming the
/// provider, whose own cap it is not.
fn in_flight_refusal(refusal: InflightRefusal, provider: &str) -> BrokerError {
    let message = match refusal {
        InflightRefusal::Level(LimitLevel::Token) => "this LLM token has too many requests in flight".to_owned(),
        InflightRefusal::Level(LimitLevel::Tenant) => "the tenant has too many requests in flight".to_owned(),
        InflightRefusal::Level(LimitLevel::Global) => format!("too many requests in flight for provider {provider}"),
        InflightRefusal::Replica => "the broker has too many requests in flight".to_owned(),
    };
    BrokerError::Limit(LimitRefusal {
        level: refusal.level(),
        kind: LimitKind::InFlight,
        message,
        retry_after_secs: None,
        budget: None,
    })
}

/// 400 for a request the provider's body policy refuses. A refused tool is
/// logged, since it can be an agent trying to reach the network through the
/// provider; the body never is.
fn body_refused(kind: ProviderKind, provider: &str, grant: &LlmGrant, refusal: &BodyRefusal) -> Response {
    let code = refusal.code();
    if *refusal != BodyRefusal::Unreadable {
        tracing::warn!(
            provider,
            tenant = %grant.tenant,
            token_id = %grant.token_id,
            reason = %refusal,
            "request refused by the body policy of the provider"
        );
    }
    metrics::counter!("ocb_llm_rejected_total", "reason" => code).increment(1);
    llm_error_response(kind, StatusCode::BAD_REQUEST, code, &refusal.to_string(), &BrokerError::Invalid(String::new()))
}

/// The caller's address, as recorded by the connection loop.
pub(crate) fn peer_ip(req: &Request) -> Option<IpAddr> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip())
}

/// The internal token, from `x-api-key` or `Authorization: Bearer`. More than
/// one value, or two different values, is ambiguous and refused.
pub(crate) fn caller_token(headers: &HeaderMap) -> Result<String, BrokerError> {
    let one = |name: &str| -> Result<Option<String>, BrokerError> {
        let mut it = headers.get_all(name).iter();
        let Some(v) = it.next() else { return Ok(None) };
        if it.next().is_some() {
            return Err(BrokerError::Unauthorized);
        }
        v.to_str().map(|s| Some(s.trim().to_owned())).map_err(|_| BrokerError::Unauthorized)
    };
    let api_key = one("x-api-key")?;
    let bearer = match one("authorization")? {
        Some(v) => match v.split_once(' ') {
            Some((scheme, t)) if scheme.eq_ignore_ascii_case("bearer") => Some(t.trim().to_owned()),
            _ => return Err(BrokerError::Unauthorized),
        },
        None => None,
    };
    match (api_key, bearer) {
        (Some(a), Some(b)) if a == b => Ok(a),
        (Some(_), Some(_)) => Err(BrokerError::Unauthorized),
        (Some(t), None) | (None, Some(t)) if !t.is_empty() => Ok(t),
        _ => Err(BrokerError::Unauthorized),
    }
}

/// Only allowlisted query keys, only plain URL characters; returned verbatim.
fn check_query(kind: ProviderKind, query: Option<&str>) -> Result<Option<String>, BrokerError> {
    let Some(q) = query.filter(|q| !q.is_empty()) else { return Ok(None) };
    let charset_ok = q.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%=&".contains(&b));
    let keys_ok = q.split('&').all(|pair| {
        let key = pair.split('=').next().unwrap_or("");
        kind.allowed_query_keys().contains(&key)
    });
    if charset_ok && keys_ok {
        Ok(Some(q.to_owned()))
    } else {
        Err(BrokerError::Invalid("unsupported query parameters".into()))
    }
}

#[derive(Debug, Default, Deserialize)]
struct Probe {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    stream: Option<bool>,
    #[serde(default)]
    stream_options: Option<StreamOptions>,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    max_completion_tokens: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct StreamOptions {
    #[serde(default)]
    include_usage: Option<bool>,
}

impl Probe {
    /// The most output the request allows, used as the floor of conservative
    /// estimates when a response ends without a usage report.
    fn max_output(&self) -> Option<u64> {
        self.max_tokens.max(self.max_completion_tokens).map(|m| m.min(MAX_TOKENS_CAP))
    }
}

/// Reads the few request fields the proxy needs (the body itself is
/// forwarded byte for byte).
fn probe(body: &[u8]) -> Result<Probe, BrokerError> {
    let p: Probe =
        serde_json::from_slice(body).map_err(|_| BrokerError::Invalid("request body must be a JSON object".into()))?;
    if let Some(m) = &p.model
        && (m.is_empty() || m.len() > 256 || !m.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err(BrokerError::Invalid("model must be 1-256 printable ASCII characters".into()));
    }
    Ok(p)
}

/// Proxies one request to `provider_id`. A route that implies a provider
/// kind (`route_kind`) only reaches providers of that kind.
async fn proxy(
    st: AppState,
    provider_id: &str,
    route_kind: Option<ProviderKind>,
    rest: &str,
    req: Request,
) -> Response {
    let started = Instant::now();
    let px = st.proxy.clone();
    // Taken once: the request keeps these providers and prices to the end of
    // its accounting, whatever a reload does in the meantime.
    let snap = px.snapshot();
    let Some(provider) = snap.provider(provider_id).filter(|p| route_kind.is_none_or(|k| p.kind == k)) else {
        // Without a provider there is no error shape to copy; the generic
        // route answers in the OpenAI-compatible one.
        return reject(
            route_kind.unwrap_or(ProviderKind::Openai),
            &BrokerError::NotFound("unknown LLM provider".into()),
        );
    };
    let kind = provider.kind;
    let method = match *req.method() {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        _ => return reject(kind, &BrokerError::NotFound("unsupported endpoint".into())),
    };
    let Some(endpoint) = provider.endpoint(method, rest) else {
        return reject(kind, &BrokerError::NotFound("unsupported endpoint".into()));
    };
    let query = match check_query(kind, req.uri().query()) {
        Ok(q) => q,
        Err(e) => return reject(kind, &e),
    };
    let peer = peer_ip(&req);
    if !st.limiter.allowed(peer) {
        return reject(kind, &BrokerError::RateLimited { retry_after_secs: seconds_to_next_minute() });
    }
    let token = match caller_token(req.headers()) {
        Ok(t) => Secret::new(t),
        Err(e) => {
            st.limiter.failed(peer);
            auth_failure("llm");
            return reject(kind, &e);
        }
    };
    let auth = match st.keeper.authorize(token.expose(), provider_id, provider.access).await {
        Ok(a) => a,
        Err(e) => {
            if matches!(e, BrokerError::Unauthorized) {
                st.limiter.failed(peer);
                auth_failure("llm");
            }
            return reject(kind, &e);
        }
    };
    // Every answer from here on shows the caller its limits.
    let mut view = LimitView::new(&auth);
    macro_rules! done {
        ($resp:expr) => {{
            let mut resp: Response = $resp;
            view.apply(resp.headers_mut());
            return resp;
        }};
    }
    // Limits, level by level: a level only counts a request the levels
    // below it let through, so a token over its limits never uses up its
    // tenant's, and a tenant over its limits never the provider's.
    let tenant = auth.grant.tenant.clone();
    if let Err(e) = auth.check_token_rate() {
        done!(refused(&mut view, kind, provider_id, &tenant, LimitLevel::Token, &token_rate_refusal(&auth, e)));
    }
    let permit = match px.inflight.acquire_for(InflightKey {
        token_id: &auth.grant.token_id,
        tenant: &tenant,
        tenant_max: auth.tenant_limits.concurrent,
        provider: provider_id,
        provider_max: provider.limits.concurrent,
    }) {
        Ok(p) => p,
        Err(refusal) => {
            let e = in_flight_refusal(refusal, provider_id);
            // Denials of the replica's total are counted for no provider.
            let label = if refusal == InflightRefusal::Replica { "" } else { provider_id };
            done!(refused(&mut view, kind, label, &tenant, refusal.level(), &e))
        }
    };
    match st.keeper.count_request(&auth, provider_id, provider.limits.rpm).await {
        Ok(c) => view.counted(&c),
        Err(e) => done!(match &e {
            BrokerError::Limit(r) => refused(&mut view, kind, provider_id, &tenant, r.level, &e),
            _ => reject(kind, &e),
        }),
    }
    let grant = auth.grant.clone();

    let (parts, body) = req.into_parts();
    let read = tokio::time::timeout(
        px.settings.request_read_timeout,
        axum::body::to_bytes(body, px.settings.max_request_bytes),
    )
    .await;
    let body = match read {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => {
            done!(reject(
                kind,
                &BrokerError::TooLarge(format!("request body exceeds {} bytes", px.settings.max_request_bytes)),
            ));
        }
        Err(_) => done!(reject(kind, &BrokerError::Invalid("request body was not received in time".into()))),
    };
    let probe = if endpoint.billable {
        match probe(&body) {
            Ok(p) => p,
            Err(e) => done!(reject(kind, &e)),
        }
    } else {
        Probe::default()
    };
    if method == HttpMethod::Post
        && let Err(refusal) = check_body(&provider.body, &body)
    {
        done!(body_refused(kind, provider_id, &grant, &refusal));
    }
    let streaming = probe.stream.unwrap_or(false);
    let request_price = probe.model.as_deref().and_then(|m| snap.prices().lookup(provider.price_source(), m));
    if endpoint.billable {
        if let Err(e) = grant.check_budget(probe.model.as_deref(), request_price) {
            let what = match (&e, grant.budget_tokens) {
                (BrokerError::BudgetExceeded(_), Some(b)) if grant.spent_tokens >= b => "tokens",
                (BrokerError::BudgetExceeded(_), _) => "usd",
                _ => "unpriced_model",
            };
            metrics::counter!("ocb_llm_budget_denials_total", "tenant" => grant.tenant.clone(), "kind" => what)
                .increment(1);
            done!(match e {
                BrokerError::BudgetExceeded(_) => refused(&mut view, kind, provider_id, &tenant, LimitLevel::Token, &e),
                _ => reject(kind, &e),
            });
        }
        if kind == ProviderKind::Openai
            && streaming
            && provider.require_stream_usage
            && !probe.stream_options.as_ref().and_then(|o| o.include_usage).unwrap_or(false)
        {
            done!(reject(
                kind,
                &BrokerError::Invalid(
                    "streaming requests must set stream_options.include_usage = true (usage is required for accounting)"
                        .into(),
                ),
            ));
        }
    }
    // Budgets of the tenant and the provider: the request reserves its
    // most output on each, all or nothing, until it is accounted. The
    // token's own budget is checked above, as before.
    let mut held = Held { keeper: st.keeper.clone(), tracker: px.tracker.clone(), reservations: Vec::new() };
    if endpoint.billable && (auth.tenant_limits.has_budget() || provider.limits.has_budget()) {
        if request_price.is_none() {
            let whose = if auth.tenant_limits.has_usd_budget() {
                Some("the tenant".to_owned())
            } else {
                provider.limits.has_usd_budget().then(|| format!("provider {provider_id}"))
            };
            if let Some(whose) = whose {
                metrics::counter!("ocb_llm_budget_denials_total", "tenant" => tenant.clone(), "kind" => "unpriced_model")
                    .increment(1);
                done!(reject(
                    kind,
                    &BrokerError::Invalid(format!(
                        "model {} has no configured price; the USD budget of {whose} can only be used with priced models",
                        probe.model.as_deref().unwrap_or("(none)")
                    )),
                ));
            }
        }
        let cap = px.settings.max_reservation_tokens;
        let tokens = probe.max_output().unwrap_or(cap).min(cap);
        let micro_usd =
            request_price.map_or(0, |p| p.cost_micro_usd(&Usage { output_tokens: tokens, ..Usage::default() }));
        let tokens = i64::try_from(tokens).unwrap_or(i64::MAX);
        match st.keeper.reserve(&auth, provider_id, &provider.limits, tokens, micro_usd).await {
            Ok(r) => {
                view.reserved(&auth.tenant_limits, &tenant, &r.rows);
                held.reservations = r.reservations;
            }
            Err(e) => {
                done!(match &e {
                    BrokerError::Limit(r) => refused(&mut view, kind, provider_id, &tenant, r.level, &e),
                    _ => reject(kind, &e),
                });
            }
        }
    }

    let span = tracing::info_span!(
        "llm.request",
        provider = %provider_id,
        endpoint = %endpoint.path,
        model = probe.model.as_deref().unwrap_or(""),
        response_model = tracing::field::Empty,
        tenant = %grant.tenant,
        run_id = grant.run_id.as_deref().unwrap_or(""),
        token_id = %grant.token_id,
        stream = streaming,
        status = tracing::field::Empty,
        input_tokens = tracing::field::Empty,
        output_tokens = tracing::field::Empty,
        cache_read_tokens = tracing::field::Empty,
        cache_write_tokens = tracing::field::Empty,
        cost_usd = tracing::field::Empty,
        ttft_ms = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        usage_source = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    if let Some(tp) = &grant.trace_parent {
        // The run's trace, set by the platform when it issued the token.
        let _ = span.set_parent(context_from_traceparent(tp));
    }
    let trace_id = trace_id_of(&span);

    let key = match st.keeper.provider_key(&grant, provider_id, trace_id.as_deref()).instrument(span.clone()).await {
        Ok(k) => k,
        Err(e) => {
            let _e = span.enter();
            done!(reject(kind, &e));
        }
    };

    let mut url = format!("{}/{}", provider.base_url, endpoint.path);
    if let Some(q) = &query {
        url.push('?');
        url.push_str(q);
    }
    let mut headers = request_headers(kind, &provider.headers, &parts.headers);
    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    let provider_auth = match kind {
        ProviderKind::Anthropic => {
            HeaderValue::from_str(key.expose()).map(|v| (HeaderName::from_static("x-api-key"), v))
        }
        ProviderKind::Openai => {
            HeaderValue::from_str(&format!("Bearer {}", key.expose())).map(|v| (header::AUTHORIZATION, v))
        }
    };
    let Ok((auth_name, mut auth_value)) = provider_auth else {
        done!(reject(kind, &BrokerError::Internal("stored provider key is not a valid header value".into())));
    };
    auth_value.set_sensitive(true);
    headers.insert(auth_name, auth_value);
    if provider.propagate_trace_context {
        inject_context(&span, &mut headers);
    }
    let up_method = match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
    };
    // A provider with TLS settings has a client of its own; the others share
    // one that never presents a client certificate.
    let http = snap.tls_client(provider_id).map_or(&px.http, |c| &c.http);
    let mut request = http.request(up_method, &url).headers(headers);
    if method == HttpMethod::Post {
        request = request.body(body.clone());
    }

    let fin = Finisher {
        keeper: st.keeper.clone(),
        snapshot: snap.clone(),
        span: span.clone(),
        grant,
        provider: provider_id.to_owned(),
        price_source: provider.price_source().to_owned(),
        endpoint,
        model: probe.model.clone(),
        max_output: probe.max_output(),
        started,
        request_bytes: body.len() as u64,
        trace_id,
        status: 0,
        reservations: held.take(),
    };
    drop(body);
    let exchange = Exchange {
        kind,
        request,
        key,
        token,
        header_policy: provider.headers.clone(),
        fin,
        max_error_body: px.settings.max_error_body_bytes,
        json_cap: px.settings.max_buffered_response_bytes,
        idle: px.settings.idle_timeout,
        shutdown: px.shutdown.clone(),
        _permit: permit,
    };
    let (head_tx, head_rx) = oneshot::channel();
    metrics::gauge!("ocb_llm_inflight_requests", "provider" => provider_id.to_owned()).increment(1.0);
    px.tracker.spawn(exchange.run(head_tx).instrument(span));

    // Wait for the response head. If this times out, or the caller goes away
    // (this future is dropped), the exchange carries on and accounts by itself.
    let mut resp = match tokio::time::timeout(px.settings.response_timeout, head_rx).await {
        Ok(Ok(Head::Stream { status, headers, rx, abort })) => {
            let mut r = Response::new(client_body(rx, abort));
            *r.status_mut() = status;
            *r.headers_mut() = headers;
            r
        }
        Ok(Ok(Head::Full { status, headers, body })) => {
            let mut r = (status, body).into_response();
            *r.headers_mut() = headers;
            r
        }
        Ok(Ok(Head::Failed { status, code, message })) => {
            metrics::counter!("ocb_llm_rejected_total", "reason" => code).increment(1);
            llm_error_response(kind, status, code, message, &BrokerError::Internal(String::new()))
        }
        Ok(Err(_)) => reject(kind, &BrokerError::Internal("upstream exchange ended without a response".into())),
        Err(_) => {
            metrics::counter!("ocb_llm_rejected_total", "reason" => "upstream_timeout").increment(1);
            llm_error_response(
                kind,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                "upstream provider did not answer in time",
                &BrokerError::Internal(String::new()),
            )
        }
    };
    view.apply(resp.headers_mut());
    resp
}

/// What the exchange task tells the waiting handler.
enum Head {
    Stream { status: StatusCode, headers: HeaderMap, rx: mpsc::Receiver<Bytes>, abort: CancellationToken },
    Full { status: StatusCode, headers: HeaderMap, body: Vec<u8> },
    Failed { status: StatusCode, code: &'static str, message: &'static str },
}

/// The caller's response body: chunks from the exchange task. An aborted
/// exchange ends it with an error, so the caller sees a broken response
/// rather than a truncated one that looks complete.
fn client_body(rx: mpsc::Receiver<Bytes>, abort: CancellationToken) -> Body {
    let aborted = || std::io::Error::other("upstream response aborted");
    let stream = futures_util::stream::unfold((rx, abort, false), move |(mut rx, abort, done)| async move {
        if done {
            return None;
        }
        tokio::select! {
            biased;
            item = rx.recv() => match item {
                Some(b) => Some((Ok(b), (rx, abort, false))),
                None if abort.is_cancelled() => Some((Err(aborted()), (rx, abort, true))),
                None => None,
            },
            () = abort.cancelled() => Some((Err(aborted()), (rx, abort, true))),
        }
    });
    Body::from_stream(stream)
}

async fn deliver(tx: &mpsc::Sender<Bytes>, chunk: Bytes, idle: Duration) -> bool {
    matches!(tokio::time::timeout(idle, tx.send(chunk)).await, Ok(Ok(())))
}

async fn read_bounded(mut resp: reqwest::Response, limit: usize, idle: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    while let Ok(Ok(Some(chunk))) = tokio::time::timeout(idle, resp.chunk()).await {
        let room = limit.saturating_sub(out.len());
        out.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if out.len() >= limit {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Response streamed to the caller to the end.
    Complete,
    /// The caller went away, read too slowly or stopped waiting; the upstream
    /// response was still read to the end for accounting.
    ClientGone,
    /// The upstream body failed mid-stream (reset, idle or total timeout).
    StreamError,
    /// Upstream answered with a non-2xx status.
    UpstreamStatus,
    /// No response headers within the total time limit.
    Timeout,
    /// No connection could be made; nothing reached the provider.
    Connect,
    /// The request failed after the connection was made.
    SendError,
    /// A compressed response body (cannot be inspected or redacted).
    BadEncoding,
    /// Cut at the end of the shutdown grace period.
    Shutdown,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ClientGone => "client_gone",
            Self::StreamError => "stream_error",
            Self::UpstreamStatus => "upstream_status",
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::SendError => "send_error",
            Self::BadEncoding => "bad_encoding",
            Self::Shutdown => "shutdown",
        }
    }

    /// The provider may have generated (and billed) output that was never
    /// reported to us.
    fn may_have_billed_unseen_output(self) -> bool {
        matches!(self, Self::StreamError | Self::Timeout | Self::SendError | Self::BadEncoding | Self::Shutdown)
    }
}

/// One upstream request and its response, run in its own task.
struct Exchange {
    kind: ProviderKind,
    request: reqwest::RequestBuilder,
    key: Secret<String>,
    token: Secret<String>,
    /// Decides which response headers are passed back.
    header_policy: ProviderHeaders,
    fin: Finisher,
    max_error_body: usize,
    json_cap: usize,
    /// Longest pause between upstream chunks, and longest wait for the
    /// caller to accept a chunk.
    idle: Duration,
    shutdown: CancellationToken,
    _permit: InflightPermit,
}

impl Exchange {
    async fn run(self, head_tx: oneshot::Sender<Head>) {
        let Exchange {
            kind,
            request,
            key,
            token,
            header_policy,
            mut fin,
            max_error_body,
            json_cap,
            idle,
            shutdown,
            _permit,
        } = self;
        let provider = fin.provider.clone();
        let sent = tokio::select! {
            r = request.send() => r,
            () = shutdown.cancelled() => {
                fin.finish(fin.no_response(Outcome::Shutdown), Outcome::Shutdown).await;
                let _ = head_tx.send(Head::Failed {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    code: "shutting_down",
                    message: "the broker is shutting down",
                });
                metrics::gauge!("ocb_llm_inflight_requests", "provider" => provider).decrement(1.0);
                return;
            }
        };
        let resp = match sent {
            Ok(r) => r,
            Err(e) => {
                let outcome = if e.is_connect() {
                    Outcome::Connect
                } else if e.is_timeout() {
                    Outcome::Timeout
                } else {
                    Outcome::SendError
                };
                tracing::warn!(error = %e.without_url(), outcome = outcome.as_str(), "upstream request failed");
                fin.finish(fin.no_response(outcome), outcome).await;
                let (status, code, message) = match outcome {
                    Outcome::Timeout => {
                        (StatusCode::GATEWAY_TIMEOUT, "upstream_timeout", "upstream provider timed out")
                    }
                    _ => (StatusCode::BAD_GATEWAY, "upstream_unavailable", "upstream provider unreachable"),
                };
                let _ = head_tx.send(Head::Failed { status, code, message });
                metrics::gauge!("ocb_llm_inflight_requests", "provider" => provider).decrement(1.0);
                return;
            }
        };

        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        fin.status = status.as_u16();
        let (headers, dropped) =
            response_headers(&header_policy, resp.headers(), &[key.expose().as_bytes(), token.expose().as_bytes()]);
        if dropped > 0 {
            tracing::warn!(count = dropped, "provider key or caller token found in upstream response headers; dropped");
            metrics::counter!("ocb_llm_key_redactions_total", "provider" => provider.clone()).increment(dropped as u64);
        }
        if !status.is_success() {
            // Read a little more than the limit so a key straddling the cut is
            // still found whole, scrub, then cut.
            let extra = key.expose().len().saturating_add(token.expose().len());
            let raw = read_bounded(resp, max_error_body.saturating_add(extra), idle).await;
            let mut body = scrub_error_body(&raw, &[key.expose().as_bytes(), token.expose().as_bytes()]);
            body.truncate(max_error_body);
            fin.finish(fin.no_usage(), Outcome::UpstreamStatus).await;
            let _ = head_tx.send(Head::Full { status, headers, body });
            metrics::gauge!("ocb_llm_inflight_requests", "provider" => provider).decrement(1.0);
            return;
        }
        let encoded = resp
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
        if encoded {
            drop(resp);
            tracing::warn!("upstream sent a compressed response despite accept-encoding: identity; refused");
            fin.finish(fin.no_response(Outcome::BadEncoding), Outcome::BadEncoding).await;
            let _ = head_tx.send(Head::Failed {
                status: StatusCode::BAD_GATEWAY,
                code: "upstream_bad_encoding",
                message: "upstream provider sent a compressed response",
            });
            metrics::gauge!("ocb_llm_inflight_requests", "provider" => provider).decrement(1.0);
            return;
        }

        let content_type =
            resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let mut tap = UsageTap::new(kind, content_type.as_deref(), json_cap);
        let mut redactor = StreamRedactor::new(key.expose().as_bytes());
        drop(key);
        drop(token);
        let (tx, rx) = mpsc::channel::<Bytes>(CLIENT_BUFFER);
        let abort = CancellationToken::new();
        let mut client = head_tx.send(Head::Stream { status, headers, rx, abort: abort.clone() }).is_ok().then_some(tx);
        let mut client_gone = client.is_none();
        let mut stream = resp.bytes_stream();
        let mut outcome = loop {
            let next = tokio::select! {
                n = tokio::time::timeout(idle, stream.next()) => match n {
                    Ok(n) => n,
                    Err(_) => {
                        tracing::warn!("upstream response stalled longer than the idle timeout");
                        break Outcome::StreamError;
                    }
                },
                () = shutdown.cancelled() => break Outcome::Shutdown,
            };
            match next {
                Some(Ok(chunk)) => {
                    tap.feed(&chunk, Instant::now());
                    if let Some(c) = &client {
                        let out = redactor.push(&chunk);
                        if !out.is_empty() && !deliver(c, Bytes::from(out), idle).await {
                            // Gone or not reading: stop forwarding, keep reading.
                            client = None;
                            client_gone = true;
                            abort.cancel();
                        }
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e.without_url(), "upstream response stream failed");
                    break Outcome::StreamError;
                }
                None => break Outcome::Complete,
            }
        };
        if outcome == Outcome::Complete {
            if let Some(c) = &client {
                let tail = redactor.finish();
                if !tail.is_empty() && !deliver(c, Bytes::from(tail), idle).await {
                    client_gone = true;
                    abort.cancel();
                }
            }
            if client_gone {
                outcome = Outcome::ClientGone;
            }
        } else {
            abort.cancel();
        }
        drop(client);
        if redactor.redactions() > 0 {
            tracing::warn!(count = redactor.redactions(), "provider key found in upstream response; redacted");
            metrics::counter!("ocb_llm_key_redactions_total", "provider" => provider.clone())
                .increment(redactor.redactions());
        }
        let report = tap.finish(fin.endpoint.billable, fin.request_bytes);
        fin.finish(report, outcome).await;
        metrics::gauge!("ocb_llm_inflight_requests", "provider" => provider).decrement(1.0);
    }
}

/// Everything needed to account for a request once its exchange is over.
struct Finisher {
    keeper: Arc<Keeper>,
    /// The snapshot the request started with: its prices apply.
    snapshot: Arc<ProviderSnapshot>,
    span: Span,
    grant: LlmGrant,
    provider: String,
    /// Provider whose prices apply (`pricing_from`, or the provider itself).
    price_source: String,
    endpoint: &'static Endpoint,
    model: Option<String>,
    max_output: Option<u64>,
    started: Instant,
    request_bytes: u64,
    trace_id: Option<String>,
    status: u16,
    /// What the request holds on the budgets of its tenant and provider,
    /// settled with its usage.
    reservations: Vec<Reservation>,
}

/// Reservations of a request that has not reached its exchange yet. A
/// request that ends before (no key for the provider, the caller gone)
/// gives them back when this is dropped; the exchange takes them over
/// otherwise.
struct Held {
    keeper: Arc<Keeper>,
    tracker: TaskTracker,
    reservations: Vec<Reservation>,
}

impl Held {
    fn take(&mut self) -> Vec<Reservation> {
        std::mem::take(&mut self.reservations)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let reservations = self.take();
        if reservations.is_empty() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let keeper = self.keeper.clone();
        self.tracker.spawn(async move {
            for (attempt, wait_ms) in [(1, 200u64), (2, 1000), (3, 0)] {
                match keeper.release(&reservations).await {
                    Ok(()) => return,
                    Err(e) if attempt < 3 => {
                        tracing::warn!(error = %e, attempt, "giving back a reservation failed; retrying");
                        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to give back a reservation; it stays until its period ends");
                        metrics::counter!("ocb_llm_accounting_failures_total").increment(1);
                    }
                }
            }
        });
    }
}

impl Finisher {
    fn no_usage(&self) -> TapReport {
        TapReport { usage: Usage::default(), source: UsageSource::None, first_content: None, model: None }
    }

    /// Usage when no response body could be read: nothing if nothing reached
    /// the provider, otherwise input estimated from the request and the full
    /// output the request allowed.
    fn no_response(&self, outcome: Outcome) -> TapReport {
        if !self.endpoint.billable || outcome == Outcome::Connect {
            return self.no_usage();
        }
        TapReport {
            usage: Usage {
                input_tokens: self.request_bytes.div_ceil(4),
                output_tokens: self.max_output.unwrap_or(0),
                ..Usage::default()
            },
            source: UsageSource::Estimated,
            first_content: None,
            model: None,
        }
    }

    async fn finish(&self, mut report: TapReport, outcome: Outcome) {
        if self.endpoint.billable
            && report.source != UsageSource::Reported
            && outcome.may_have_billed_unseen_output()
            && let Some(m) = self.max_output
        {
            // Hidden reasoning is billed but not streamed: assume the worst.
            report.usage.output_tokens = report.usage.output_tokens.max(m);
            report.source = UsageSource::Estimated;
        }
        let duration = self.started.elapsed();
        let u = report.usage;
        let (price, fallback) =
            self.snapshot.prices().billing_price(&self.price_source, self.model.as_deref(), report.model.as_deref());
        if fallback {
            tracing::warn!("provider reported a model without a configured price; billed at the highest known price");
            metrics::counter!("ocb_llm_unpriced_response_model_total", "provider" => self.provider.clone())
                .increment(1);
        }
        // Clamp so that sums in the database cannot overflow in practice.
        let cost = price.as_ref().map_or(0, |p| p.cost_micro_usd(&u)).min(1_000_000_000_000_000);
        let ttft = report.first_content.map(|t| t.saturating_duration_since(self.started));
        let i64c = |v: u64| i64::try_from(v.min(1_000_000_000_000_000)).unwrap_or(i64::MAX);
        let span = &self.span;
        span.record("status", self.status);
        if let Some(m) = &report.model {
            span.record("response_model", m.as_str());
        }
        span.record(
            "input_tokens",
            u.input_tokens.saturating_add(u.cache_read_tokens).saturating_add(u.cache_write_tokens),
        );
        span.record("output_tokens", u.output_tokens);
        span.record("cache_read_tokens", u.cache_read_tokens);
        span.record("cache_write_tokens", u.cache_write_tokens);
        span.record("cost_usd", cost as f64 / 1_000_000.0);
        if let Some(t) = ttft {
            span.record("ttft_ms", i64c(t.as_millis().try_into().unwrap_or(u64::MAX)));
        }
        span.record("duration_ms", i64c(duration.as_millis().try_into().unwrap_or(u64::MAX)));
        span.record("usage_source", report.source.as_str());
        span.record("outcome", outcome.as_str());

        let provider = self.provider.clone();
        let label = price.as_ref().map_or_else(|| "other".to_owned(), |p| p.label().to_owned());
        let tenant = self.grant.tenant.clone();
        metrics::histogram!(
            "ocb_llm_request_duration_seconds",
            "provider" => provider.clone(), "model" => label.clone(), "status" => self.status.to_string()
        )
        .record(duration.as_secs_f64());
        if let Some(t) = ttft {
            metrics::histogram!("ocb_llm_time_to_first_token_seconds", "provider" => provider.clone(), "model" => label.clone())
                .record(t.as_secs_f64());
        }
        for (kind, n) in [
            ("input", u.input_tokens),
            ("output", u.output_tokens),
            ("cache_read", u.cache_read_tokens),
            ("cache_write", u.cache_write_tokens),
        ] {
            if n > 0 {
                metrics::counter!(
                    "ocb_llm_tokens_total",
                    "tenant" => tenant.clone(), "provider" => provider.clone(), "model" => label.clone(), "type" => kind
                )
                .increment(n);
            }
        }
        if cost > 0 {
            metrics::counter!(
                "ocb_llm_cost_microdollars_total",
                "tenant" => tenant.clone(), "provider" => provider.clone(), "model" => label.clone()
            )
            .increment(cost.unsigned_abs());
        }
        if report.source == UsageSource::Estimated {
            metrics::counter!("ocb_llm_usage_estimated_total", "provider" => provider.clone()).increment(1);
        }
        if outcome != Outcome::Complete {
            metrics::counter!("ocb_llm_errors_total", "provider" => provider.clone(), "kind" => outcome.as_str())
                .increment(1);
        }

        let row = NewUsageRow {
            ts: self.keeper.now(),
            token_id: self.grant.token_id.clone(),
            tenant,
            run_id: self.grant.run_id.clone(),
            provider,
            endpoint: self.endpoint.path.to_owned(),
            model: self.model.clone(),
            response_model: report.model.clone(),
            status: i32::from(self.status),
            input_tokens: i64c(u.input_tokens),
            output_tokens: i64c(u.output_tokens),
            cache_read_tokens: i64c(u.cache_read_tokens),
            cache_write_tokens: i64c(u.cache_write_tokens),
            cost_micro_usd: cost,
            usage_source: report.source.as_str(),
            duration_ms: i64c(duration.as_millis().try_into().unwrap_or(u64::MAX)),
            ttft_ms: ttft.map(|t| i64c(t.as_millis().try_into().unwrap_or(u64::MAX))),
            trace_id: self.trace_id.clone(),
            billable_tokens: i64c(u.billable_tokens()),
        };
        // A few retries ride out a briefly unavailable database.
        for (attempt, wait_ms) in [(1, 200u64), (2, 1000), (3, 0)] {
            match self.keeper.record_usage_settling(&row, &self.reservations).await {
                Ok(()) => return,
                Err(e) if attempt < 3 => {
                    tracing::warn!(error = %e, attempt, "recording LLM usage failed; retrying");
                    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to record LLM usage");
                    metrics::counter!("ocb_llm_accounting_failures_total").increment(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn token_extraction() {
        assert_eq!(caller_token(&h(&[("x-api-key", "t1")])).unwrap(), "t1");
        assert_eq!(caller_token(&h(&[("authorization", "Bearer t1")])).unwrap(), "t1");
        assert_eq!(caller_token(&h(&[("authorization", "bearer t1"), ("x-api-key", "t1")])).unwrap(), "t1");
        for bad in [
            h(&[]),
            h(&[("x-api-key", "")]),
            h(&[("x-api-key", "a"), ("x-api-key", "b")]),
            h(&[("authorization", "Bearer a"), ("authorization", "Bearer a")]),
            h(&[("authorization", "Bearer a"), ("x-api-key", "b")]),
            h(&[("authorization", "Basic YTpi")]),
        ] {
            assert!(caller_token(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn query_allowlist() {
        let a = ProviderKind::Anthropic;
        assert_eq!(check_query(a, Some("beta=true")).unwrap().as_deref(), Some("beta=true"));
        assert_eq!(check_query(a, None).unwrap(), None);
        assert!(check_query(a, Some("url=http://evil")).is_err());
        assert!(check_query(a, Some("beta=true&x=1")).is_err());
        assert!(check_query(ProviderKind::Openai, Some("beta=true")).is_err());
        assert!(check_query(a, Some("beta=tr ue")).is_err());
    }

    #[test]
    fn probe_parsing() {
        let p = probe(br#"{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[]}"#).unwrap();
        assert_eq!(p.model.as_deref(), Some("m"));
        assert_eq!(p.stream, Some(true));
        assert_eq!(p.max_output(), None);
        assert_eq!(probe(br#"{"max_tokens":100,"max_completion_tokens":300}"#).unwrap().max_output(), Some(300));
        assert_eq!(probe(br#"{"max_tokens":99999999999}"#).unwrap().max_output(), Some(MAX_TOKENS_CAP));
        assert!(probe(b"not json").is_err());
        assert!(probe(br#"{"model":"a\nb"}"#).is_err());
        assert!(probe(br#"{"model":5}"#).is_err());
        assert!(probe(br#"{"max_tokens":-1}"#).is_err());
    }
}
