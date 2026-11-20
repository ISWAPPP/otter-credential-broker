//! Admin API for the platform core: secrets (write-only values), internal LLM
//! tokens, job tokens, limits of tenants, usage, audit, KEK maintenance and
//! read-only views of the configured LLM providers and of every limit. All
//! routes require an admin bearer token and are served on the admin listener
//! only.

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use broker_core::auth::Principal;
use broker_core::clock::Timestamp;
use broker_core::keeper::{Issued, NewJobToken, NewLlmToken, NewSecret, SecretUpdate, TenantLimits, micro_to_usd};
use broker_core::limits::{Limits, Period, window_of, window_reset};
use broker_core::llm::{LLM_KEY_KIND, provider_key_secret_name};
use broker_core::store::{JobTokenInfo, LimitScope, LlmTokenInfo, RpmRow, SpendRow, UsageFilter};
use broker_core::{BrokerError, CallContext, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;
use crate::config::{ProviderBody, ProviderHeaders};
use crate::error::{ApiError, JsonBody};
use crate::observe::current_trace_id;

type ApiResult<T> = Result<T, ApiError>;

pub(crate) fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let v = first.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

pub(crate) fn auth_failure(realm: &'static str) {
    metrics::counter!("ocb_auth_failures_total", "realm" => realm).increment(1);
}

pub async fn require_admin(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let principal = match bearer(req.headers()) {
        Some(t) => st.admin_auth.authenticate(t).await,
        None => None,
    };
    match principal {
        Some(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        None => {
            auth_failure("admin");
            ApiError(BrokerError::Unauthorized).into_response()
        }
    }
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn limit(l: Option<i64>) -> i64 {
    l.unwrap_or(100).clamp(1, 1000)
}

macro_rules! ctx {
    ($p:expr, $trace:ident) => {{
        $trace = current_trace_id();
        CallContext { actor: &$p.name, trace_id: $trace.as_deref() }
    }};
}

// ---------- secrets ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecretBody {
    name: String,
    kind: String,
    value: String,
    #[serde(default)]
    metadata: Option<Value>,
}

#[tracing::instrument(name = "admin.secret.create", skip_all, fields(tenant = %tenant))]
pub async fn create_secret(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tenant): Path<String>,
    JsonBody(b): JsonBody<CreateSecretBody>,
) -> ApiResult<Response> {
    let trace;
    let ctx = ctx!(p, trace);
    let req = NewSecret { name: b.name, kind: b.kind, value: Secret::new(b.value), metadata: b.metadata };
    let meta = st.keeper.create_secret(ctx, &tenant, req).await?;
    Ok((StatusCode::CREATED, Json(meta)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSecretBody {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[tracing::instrument(name = "admin.secret.update", skip_all, fields(tenant = %tenant))]
pub async fn update_secret(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((tenant, name)): Path<(String, String)>,
    JsonBody(b): JsonBody<UpdateSecretBody>,
) -> ApiResult<Response> {
    let trace;
    let ctx = ctx!(p, trace);
    let upd = SecretUpdate { value: b.value.map(Secret::new), metadata: b.metadata };
    Ok(Json(st.keeper.update_secret(ctx, &tenant, &name, upd).await?).into_response())
}

#[tracing::instrument(name = "admin.secret.delete", skip_all, fields(tenant = %tenant))]
pub async fn delete_secret(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((tenant, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let trace;
    let ctx = ctx!(p, trace);
    st.keeper.delete_secret(ctx, &tenant, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[tracing::instrument(name = "admin.secret.get", skip_all, fields(tenant = %tenant))]
pub async fn get_secret(
    State(st): State<AppState>,
    Path((tenant, name)): Path<(String, String)>,
) -> ApiResult<Response> {
    Ok(Json(st.keeper.get_secret(&tenant, &name).await?).into_response())
}

#[tracing::instrument(name = "admin.secret.list", skip_all, fields(tenant = %tenant))]
pub async fn list_secrets(State(st): State<AppState>, Path(tenant): Path<String>) -> ApiResult<Response> {
    Ok(Json(st.keeper.list_secrets(&tenant).await?).into_response())
}

// ---------- LLM tokens ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueLlmTokenBody {
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    providers: Option<Vec<String>>,
    #[serde(default)]
    budget_usd: Option<f64>,
    #[serde(default)]
    budget_tokens: Option<i64>,
    #[serde(default)]
    ttl_secs: Option<i64>,
    #[serde(default)]
    rate_limit_per_minute: Option<i32>,
    /// W3C traceparent of the run; LLM calls with this token join its trace.
    #[serde(default)]
    traceparent: Option<String>,
}

#[derive(Serialize)]
pub struct LlmTokenView {
    #[serde(flatten)]
    info: LlmTokenInfo,
    budget_usd: Option<f64>,
    spent_usd: f64,
}

impl From<LlmTokenInfo> for LlmTokenView {
    fn from(info: LlmTokenInfo) -> Self {
        Self {
            budget_usd: info.budget_micro_usd.map(micro_to_usd),
            spent_usd: micro_to_usd(info.spent_micro_usd),
            info,
        }
    }
}

#[derive(Serialize)]
struct IssuedView<'a, T: Serialize> {
    token: &'a str,
    #[serde(flatten)]
    info: T,
}

/// 201 with the token. It is shown exactly once and never cached.
fn issued<T: Serialize, V: Serialize>(i: Issued<T>, view: impl FnOnce(T) -> V) -> Response {
    let Issued { token, info } = i;
    let body = IssuedView { token: token.expose(), info: view(info) };
    no_store((StatusCode::CREATED, Json(body)).into_response())
}

#[tracing::instrument(name = "admin.llm_token.issue", skip_all, fields(tenant = %tenant))]
pub async fn issue_llm_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tenant): Path<String>,
    JsonBody(b): JsonBody<IssueLlmTokenBody>,
) -> ApiResult<Response> {
    if b.providers.iter().flatten().any(|id| !st.proxy.has_provider(id)) {
        return Err(BrokerError::Invalid("providers lists a provider that is not configured".into()).into());
    }
    let trace;
    let ctx = ctx!(p, trace);
    let req = NewLlmToken {
        run_id: b.run_id,
        label: b.label,
        providers: b.providers,
        budget_usd: b.budget_usd,
        budget_tokens: b.budget_tokens,
        ttl_secs: b.ttl_secs,
        rate_limit_per_minute: b.rate_limit_per_minute,
        trace_parent: b.traceparent,
    };
    let i = st.keeper.issue_llm_token(ctx, &tenant, req).await?;
    Ok(issued(i, LlmTokenView::from))
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
}

#[tracing::instrument(name = "admin.llm_token.list", skip_all, fields(tenant = %tenant))]
pub async fn list_llm_tokens(
    State(st): State<AppState>,
    Path(tenant): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Response> {
    let items: Vec<LlmTokenView> =
        st.keeper.list_llm_tokens(&tenant, limit(q.limit)).await?.into_iter().map(Into::into).collect();
    Ok(Json(items).into_response())
}

#[tracing::instrument(name = "admin.llm_token.get", skip_all, fields(tenant = %tenant))]
pub async fn get_llm_token(
    State(st): State<AppState>,
    Path((tenant, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    Ok(Json(LlmTokenView::from(st.keeper.get_llm_token(&tenant, &id).await?)).into_response())
}

#[tracing::instrument(name = "admin.llm_token.revoke", skip_all, fields(tenant = %tenant))]
pub async fn revoke_llm_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((tenant, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let trace;
    let ctx = ctx!(p, trace);
    st.keeper.revoke_llm_token(ctx, &tenant, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- job tokens ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueJobTokenBody {
    job_id: String,
    secrets: Vec<String>,
    #[serde(default)]
    ttl_secs: Option<i64>,
    /// W3C traceparent of the job; its redemption is recorded in that trace.
    #[serde(default)]
    traceparent: Option<String>,
}

#[tracing::instrument(name = "admin.job_token.issue", skip_all, fields(tenant = %tenant))]
pub async fn issue_job_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tenant): Path<String>,
    JsonBody(b): JsonBody<IssueJobTokenBody>,
) -> ApiResult<Response> {
    let trace;
    let ctx = ctx!(p, trace);
    let req = NewJobToken { trace_parent: b.traceparent, job_id: b.job_id, secrets: b.secrets, ttl_secs: b.ttl_secs };
    let i = st.keeper.issue_job_token(ctx, &tenant, req).await?;
    Ok(issued(i, |info: JobTokenInfo| info))
}

#[tracing::instrument(name = "admin.job_token.list", skip_all, fields(tenant = %tenant))]
pub async fn list_job_tokens(
    State(st): State<AppState>,
    Path(tenant): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Response> {
    Ok(Json(st.keeper.list_job_tokens(&tenant, limit(q.limit)).await?).into_response())
}

#[tracing::instrument(name = "admin.job_token.revoke", skip_all, fields(tenant = %tenant))]
pub async fn revoke_job_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((tenant, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let trace;
    let ctx = ctx!(p, trace);
    st.keeper.revoke_job_token(ctx, &tenant, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- usage, audit, maintenance ----------

#[derive(Deserialize)]
pub struct UsageQuery {
    run_id: Option<String>,
    token_id: Option<String>,
    limit: Option<i64>,
}

#[tracing::instrument(name = "admin.usage", skip_all, fields(tenant = %tenant))]
pub async fn usage(
    State(st): State<AppState>,
    Path(tenant): Path<String>,
    Query(q): Query<UsageQuery>,
) -> ApiResult<Response> {
    let f = UsageFilter { run_id: q.run_id, token_id: q.token_id, limit: limit(q.limit) };
    Ok(Json(st.keeper.list_usage(&tenant, &f).await?).into_response())
}

#[derive(Deserialize)]
pub struct AuditQuery {
    tenant: Option<String>,
    limit: Option<i64>,
}

#[tracing::instrument(name = "admin.audit", skip_all)]
pub async fn audit(State(st): State<AppState>, Query(q): Query<AuditQuery>) -> ApiResult<Response> {
    Ok(Json(st.keeper.audit_log(q.tenant.as_deref(), limit(q.limit)).await?).into_response())
}

#[tracing::instrument(name = "admin.kek.rewrap", skip_all)]
pub async fn rewrap(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Response> {
    let trace;
    let ctx = ctx!(p, trace);
    Ok(Json(st.keeper.rewrap(ctx, q.limit.unwrap_or(500)).await?).into_response())
}

// ---------- providers ----------

#[derive(Serialize)]
struct ProviderView<'a> {
    id: &'a str,
    kind: &'static str,
    /// Host and port of the base URL; its path and query are not shown.
    host: String,
    endpoints: Vec<&'static str>,
    access: &'static str,
    has_tls: bool,
    /// Earliest expiry of the provider's CA and client certificates.
    tls_not_after: Option<i64>,
    pricing_from: Option<&'a str>,
    /// Headers passed through by name prefix, beyond the fixed allowlists.
    headers: &'a ProviderHeaders,
    /// Checks of the request body.
    body: &'a ProviderBody,
}

#[derive(Serialize)]
struct ProvidersView<'a> {
    /// Version of the provider configuration in use on this replica.
    config_version: u64,
    providers: Vec<ProviderView<'a>>,
}

/// `GET /v1/admin/providers`: the providers this replica uses. Read-only:
/// providers change only through the configuration file.
#[tracing::instrument(name = "admin.providers.list", skip_all)]
pub async fn list_providers(State(st): State<AppState>) -> Response {
    let snap = st.proxy.snapshot();
    let providers = snap
        .providers()
        .map(|p| ProviderView {
            id: &p.id,
            kind: p.kind.as_str(),
            host: host(&p.base_url),
            endpoints: p.endpoints.iter().map(|e| e.name).collect(),
            access: p.access.as_str(),
            has_tls: p.tls.is_some(),
            tls_not_after: snap.tls_not_after(&p.id),
            pricing_from: p.pricing_from.as_deref(),
            headers: &p.headers,
            body: &p.body,
        })
        .collect();
    Json(ProvidersView { config_version: snap.version(), providers }).into_response()
}

/// `host[:port]` of a validated base URL.
fn host(base_url: &str) -> String {
    let Ok(url) = reqwest::Url::parse(base_url) else { return String::new() };
    match (url.host_str(), url.port()) {
        (Some(h), Some(port)) => format!("{h}:{port}"),
        (Some(h), None) => h.to_owned(),
        (None, _) => String::new(),
    }
}

// ---------- limits ----------

#[derive(Serialize)]
struct RateUsage {
    /// Requests counted in the current one-minute window.
    count: i64,
    resets_at: Timestamp,
}

#[derive(Serialize)]
struct PeriodUsage {
    period: Period,
    start: Timestamp,
    resets_at: Timestamp,
    spent_tokens: i64,
    spent_usd: f64,
    /// Held by requests in flight until they are accounted.
    reserved_tokens: i64,
    reserved_usd: f64,
}

#[derive(Serialize)]
struct LimitUsage {
    /// `None` without a rate limit.
    rpm: Option<RateUsage>,
    /// Requests in flight on the replica that answers.
    in_flight: u32,
    /// The current day and month, for the periods with a budget.
    periods: Vec<PeriodUsage>,
}

#[derive(Serialize)]
struct TenantLimitsView {
    tenant: String,
    /// `None` when the tenant has no limits.
    limits: Option<Limits>,
    updated_at: Option<Timestamp>,
    updated_by: Option<String>,
    usage: LimitUsage,
}

#[derive(Serialize)]
struct GlobalLimitsView<'a> {
    provider: &'a str,
    limits: &'a Limits,
    usage: LimitUsage,
}

#[derive(Serialize)]
struct LimitsView<'a> {
    /// Version of the provider configuration the global limits come from.
    config_version: u64,
    global: Vec<GlobalLimitsView<'a>>,
    tenants: Vec<TenantLimitsView>,
}

/// What a tenant or provider has used of its limits now.
fn limit_usage(
    scope: &LimitScope,
    limits: &Limits,
    rpm: &[RpmRow],
    spend: &[SpendRow],
    in_flight: u32,
    at: Timestamp,
) -> LimitUsage {
    let rpm = limits.rpm.map(|_| {
        let row = rpm
            .iter()
            .find(|r| r.level == scope.level.as_str() && r.tenant_id == scope.tenant && r.provider == scope.provider);
        let count = row.filter(|r| r.rl_window >= window_of(at)).map_or(0, |r| i64::from(r.rl_count));
        RateUsage { count, resets_at: window_reset(at) }
    });
    let periods = limits
        .budget_periods()
        .map(|period| {
            let s = spend.iter().find(|r| r.is(scope, period)).map(SpendRow::spend).unwrap_or_default();
            PeriodUsage {
                period,
                start: period.start(at),
                resets_at: period.end(at),
                spent_tokens: s.spent_tokens,
                spent_usd: micro_to_usd(s.spent_micro_usd),
                reserved_tokens: s.reserved_tokens,
                reserved_usd: micro_to_usd(s.reserved_micro_usd),
            }
        })
        .collect();
    LimitUsage { rpm, in_flight, periods }
}

fn tenant_view(st: &AppState, t: TenantLimits, rpm: &[RpmRow], spend: &[SpendRow], at: Timestamp) -> TenantLimitsView {
    let in_flight = st.proxy.inflight().tenant_count(&t.tenant);
    let usage = limit_usage(&LimitScope::tenant(&t.tenant), &t.limits, rpm, spend, in_flight, at);
    TenantLimitsView {
        tenant: t.tenant,
        limits: Some(t.limits),
        updated_at: Some(t.updated_at),
        updated_by: Some(t.updated_by),
        usage,
    }
}

/// The limits of a tenant and what it has used of them now.
async fn tenant_limits_view(st: &AppState, tenant: &str) -> ApiResult<TenantLimitsView> {
    let at = st.keeper.now();
    let Some(t) = st.keeper.tenant_limits(tenant).await? else {
        let in_flight = st.proxy.inflight().tenant_count(tenant);
        return Ok(TenantLimitsView {
            tenant: tenant.to_owned(),
            limits: None,
            updated_at: None,
            updated_by: None,
            usage: LimitUsage { rpm: None, in_flight, periods: Vec::new() },
        });
    };
    let (rpm, spend) = st.keeper.limit_usage(&[LimitScope::tenant(tenant)], at).await?;
    Ok(tenant_view(st, t, &rpm, &spend, at))
}

/// Configured providers without prices for which the tenant holds a key: a
/// USD budget of the tenant would never count their usage.
async fn unpriced_keys(st: &AppState, tenant: &str) -> ApiResult<Vec<String>> {
    let snap = st.proxy.snapshot();
    let unpriced: Vec<&str> = snap
        .providers()
        .filter(|p| !snap.prices().providers().any(|x| x == p.price_source()))
        .map(|p| p.id.as_str())
        .collect();
    if unpriced.is_empty() {
        return Ok(Vec::new());
    }
    let keys = st.keeper.list_secrets(tenant).await?;
    Ok(unpriced
        .into_iter()
        .filter(|id| keys.iter().any(|k| k.kind == LLM_KEY_KIND && k.name == provider_key_secret_name(id)))
        .map(str::to_owned)
        .collect())
}

/// `PUT /v1/admin/tenants/{t}/limits`: replaces the limits of a tenant, on
/// every provider. A limit left out is removed; `{}` removes them all.
#[tracing::instrument(name = "admin.tenant_limits.set", skip_all, fields(tenant = %tenant))]
pub async fn put_tenant_limits(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tenant): Path<String>,
    JsonBody(limits): JsonBody<Limits>,
) -> ApiResult<Response> {
    limits.validate().map_err(BrokerError::Invalid)?;
    if limits.has_usd_budget() {
        let unpriced = unpriced_keys(&st, &tenant).await?;
        if !unpriced.is_empty() {
            return Err(BrokerError::Invalid(format!(
                "budget_usd: the tenant has keys for providers without prices ({}), whose usage costs nothing; \
                 add prices for them or use budget_tokens",
                unpriced.join(", ")
            ))
            .into());
        }
    }
    let trace;
    let ctx = ctx!(p, trace);
    st.keeper.set_tenant_limits(ctx, &tenant, limits).await?;
    Ok(Json(tenant_limits_view(&st, &tenant).await?).into_response())
}

/// `GET /v1/admin/tenants/{t}/limits`.
#[tracing::instrument(name = "admin.tenant_limits.get", skip_all, fields(tenant = %tenant))]
pub async fn get_tenant_limits(State(st): State<AppState>, Path(tenant): Path<String>) -> ApiResult<Response> {
    Ok(Json(tenant_limits_view(&st, &tenant).await?).into_response())
}

/// `GET /v1/admin/limits`: the limits of every provider (for every tenant)
/// and of every tenant that has some, with what is used of them now.
#[tracing::instrument(name = "admin.limits", skip_all)]
pub async fn list_limits(State(st): State<AppState>) -> ApiResult<Response> {
    let at = st.keeper.now();
    let snap = st.proxy.snapshot();
    let providers: Vec<_> = snap.providers().filter(|p| !p.limits.is_empty()).collect();
    let tenants = st.keeper.all_tenant_limits().await?;
    let scopes: Vec<LimitScope> = providers
        .iter()
        .map(|p| LimitScope::global(&p.id))
        .chain(tenants.iter().map(|t| LimitScope::tenant(&t.tenant)))
        .collect();
    let (rpm, spend) = st.keeper.limit_usage(&scopes, at).await?;
    let global = providers
        .iter()
        .map(|p| {
            let in_flight = st.proxy.inflight().provider_count(&p.id);
            GlobalLimitsView {
                provider: &p.id,
                limits: &p.limits,
                usage: limit_usage(&LimitScope::global(&p.id), &p.limits, &rpm, &spend, in_flight, at),
            }
        })
        .collect();
    let tenants = tenants.into_iter().map(|t| tenant_view(&st, t, &rpm, &spend, at)).collect();
    Ok(Json(LimitsView { config_version: snap.version(), global, tenants }).into_response())
}

// ---------- worker ----------

#[derive(Serialize)]
struct WorkerSecret<'a> {
    name: &'a str,
    kind: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct WorkerResponse<'a> {
    job_id: &'a str,
    tenant: &'a str,
    secrets: Vec<WorkerSecret<'a>>,
}

/// `POST /v1/worker/secrets` with `Authorization: Bearer <job token>`: returns
/// the secrets listed for that job, once.
#[tracing::instrument(name = "worker.redeem", skip_all)]
pub async fn worker_secrets(State(st): State<AppState>, req: Request) -> Response {
    let peer = crate::proxy::peer_ip(&req);
    if !st.limiter.allowed(peer) {
        let retry_after_secs = crate::limits::seconds_to_next_minute();
        return ApiError(BrokerError::RateLimited { retry_after_secs }).into_response();
    }
    let Some(token) = bearer(req.headers()) else {
        st.limiter.failed(peer);
        auth_failure("job");
        return ApiError(BrokerError::Unauthorized).into_response();
    };
    // On the public listener this is the broker's own trace id (callers'
    // trace context is only linked); a job issued with a traceparent records
    // its redemption in that trace instead.
    let trace = current_trace_id();
    match st.keeper.redeem_job_token(token, trace.as_deref()).await {
        Ok(job) => {
            metrics::counter!("ocb_job_redemptions_total", "result" => "ok").increment(1);
            let body = WorkerResponse {
                job_id: &job.job_id,
                tenant: &job.tenant,
                secrets: job
                    .secrets
                    .iter()
                    .map(|s| WorkerSecret { name: &s.name, kind: &s.kind, value: s.value.expose() })
                    .collect(),
            };
            no_store(Json(body).into_response())
        }
        Err(e) => {
            let result = if matches!(e, BrokerError::Unauthorized) { "unauthorized" } else { "error" };
            if result == "unauthorized" {
                st.limiter.failed(peer);
                auth_failure("job");
            }
            metrics::counter!("ocb_job_redemptions_total", "result" => result).increment(1);
            ApiError(e).into_response()
        }
    }
}
