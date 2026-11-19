//! Admin API for the platform core: secrets (write-only values), internal LLM
//! tokens, job tokens, usage, audit and KEK maintenance. All routes require an
//! admin bearer token and are served on the admin listener only.

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use broker_core::auth::Principal;
use broker_core::keeper::{Issued, NewJobToken, NewLlmToken, NewSecret, SecretUpdate, micro_to_usd};
use broker_core::store::{JobTokenInfo, LlmTokenInfo, UsageFilter};
use broker_core::{BrokerError, CallContext, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;
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
