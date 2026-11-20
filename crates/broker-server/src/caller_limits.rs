//! `GET /llm/_/limits`: a caller's own limits, with its LLM token.
//!
//! The token is checked without counting a request (a read and the row's
//! MAC), so asking does not use up the token's rate limit; instead the
//! endpoint has a small limit of its own per token and replica
//! (`llm.limits_endpoint_per_minute`), and failed token checks count
//! against the caller's address as on the proxy. The answer holds the
//! caller's token and tenant, with their numbers, and for each provider the
//! token may use, only how near its limits for every tenant are (`ok`,
//! `near` or `exhausted`) and when that changes: their numbers come from
//! every tenant's requests.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use broker_core::BrokerError;
use broker_core::clock::Timestamp;
use broker_core::keeper::micro_to_usd;
use broker_core::limits::{Limits, Period, Spend, window_of, window_reset};
use broker_core::llm::ProviderAccess;
use broker_core::store::{LimitScope, RpmRow, SpendRow};
use serde::Serialize;

use crate::AppState;
use crate::admin::auth_failure;
use crate::config::Provider;
use crate::error::ApiError;
use crate::limits::seconds_to_next_minute;
use crate::proxy::{caller_token, peer_ip};

/// Share of a limit left below which a provider's limits are `near`.
const NEAR: f64 = 0.1;

#[derive(Serialize)]
struct Rate {
    limit: i64,
    remaining: i64,
    resets_at: Timestamp,
}

/// Tokens as an integer, USD as dollars.
#[derive(Serialize)]
#[serde(untagged)]
enum Amount {
    Tokens(i64),
    Usd(f64),
}

impl Amount {
    fn of(v: i64, usd: bool) -> Self {
        if usd { Self::Usd(micro_to_usd(v)) } else { Self::Tokens(v) }
    }
}

#[derive(Serialize)]
struct TokenBudget {
    limit: Amount,
    spent: Amount,
    remaining: Amount,
}

#[derive(Serialize)]
struct TokenView<'a> {
    id: &'a str,
    label: Option<&'a str>,
    expires_at: Timestamp,
    providers: Option<&'a [String]>,
    rpm: Rate,
    /// Requests in flight, per replica.
    concurrent: u32,
    budget_tokens: Option<TokenBudget>,
    budget_usd: Option<TokenBudget>,
}

#[derive(Serialize)]
struct PeriodBudget {
    period: Period,
    unit: &'static str,
    limit: Amount,
    spent: Amount,
    /// Held by requests in flight.
    reserved: Amount,
    remaining: Amount,
    resets_at: Timestamp,
}

#[derive(Serialize)]
struct TenantView<'a> {
    id: &'a str,
    rpm: Option<Rate>,
    /// Requests in flight, per replica.
    concurrent: Option<u32>,
    budgets: Vec<PeriodBudget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Ok,
    Near,
    Exhausted,
}

#[derive(Serialize)]
struct GlobalView<'a> {
    provider: &'a str,
    status: Status,
    /// When the status gets better: the end of the window or period of the
    /// limit that decides it. None while `ok`.
    resets_at: Option<Timestamp>,
}

#[derive(Serialize)]
struct LimitsView<'a> {
    token: TokenView<'a>,
    tenant: TenantView<'a>,
    global: Vec<GlobalView<'a>>,
}

fn refuse(e: BrokerError) -> Response {
    ApiError(e).into_response()
}

/// `GET /llm/_/limits`.
#[tracing::instrument(name = "llm.limits", skip_all)]
pub async fn view(State(st): State<AppState>, req: Request) -> Response {
    let peer = peer_ip(&req);
    if !st.limiter.allowed(peer) {
        return refuse(BrokerError::RateLimited { retry_after_secs: seconds_to_next_minute() });
    }
    let failed = || {
        st.limiter.failed(peer);
        auth_failure("llm");
        refuse(BrokerError::Unauthorized)
    };
    let Some(digest) = caller_token(req.headers()).ok().and_then(|t| st.keeper.llm_token_digest(&t)) else {
        return failed();
    };
    if !st.proxy.limits_views().allow(&digest) {
        return refuse(BrokerError::RateLimited { retry_after_secs: seconds_to_next_minute() });
    }
    let seen = match st.keeper.inspect_llm_token(&digest).await {
        Ok(s) => s,
        Err(BrokerError::Unauthorized) => return failed(),
        Err(e) => return refuse(e),
    };
    let (t, at, tenant_limits) = (&seen.token, seen.at, &seen.tenant_limits);
    let snap = st.proxy.snapshot();
    // The providers this token may use, in id order.
    let usable: Vec<&Provider> = snap
        .providers()
        .filter(|p| match &t.providers {
            Some(list) => list.contains(&p.id),
            None => p.access == ProviderAccess::Implicit,
        })
        .collect();
    let mut scopes = Vec::new();
    if !tenant_limits.is_empty() {
        scopes.push(LimitScope::tenant(&t.tenant_id));
    }
    scopes.extend(usable.iter().filter(|p| counted(&p.limits)).map(|p| LimitScope::global(&p.id)));
    let (rpm_rows, spend_rows) = match st.keeper.limit_usage(&scopes, at).await {
        Ok(rows) => rows,
        Err(e) => return refuse(e),
    };

    let window = window_of(at);
    let rate = |limit: i64, window_of_row: i64, count: i64| Rate {
        limit,
        remaining: if window_of_row >= window { (limit - count).max(0) } else { limit },
        resets_at: window_reset(at),
    };
    let tokens_budget = |limit: Option<i64>, spent: i64, usd: bool| {
        let amount = |v: i64| Amount::of(v, usd);
        limit.map(|l| TokenBudget {
            limit: amount(l),
            spent: amount(spent),
            remaining: amount(l.saturating_sub(spent).max(0)),
        })
    };
    let token = TokenView {
        id: &t.id,
        label: t.label.as_deref(),
        expires_at: t.expires_at,
        providers: t.providers.as_deref(),
        rpm: rate(i64::from(t.rate_limit_per_minute), t.rl_window, i64::from(t.rl_count)),
        concurrent: st.proxy.inflight().max_per_token(),
        budget_tokens: tokens_budget(t.budget_tokens, t.spent_tokens, false),
        budget_usd: tokens_budget(t.budget_micro_usd, t.spent_micro_usd, true),
    };
    let tenant_scope = LimitScope::tenant(&t.tenant_id);
    let tenant_rpm = tenant_limits.rpm.map(|limit| {
        let row = rpm_row(&rpm_rows, &tenant_scope);
        rate(i64::from(limit), row.map_or(window, |r| r.rl_window), row.map_or(0, |r| i64::from(r.rl_count)))
    });
    let mut budgets = Vec::new();
    for period in tenant_limits.budget_periods() {
        let s = spend_of(&spend_rows, &tenant_scope, period);
        let resets_at = period.end(at);
        for (unit, limit, spent, reserved) in [
            ("tokens", tenant_limits.tokens(period), s.spent_tokens, s.reserved_tokens),
            ("usd", tenant_limits.micro_usd(period), s.spent_micro_usd, s.reserved_micro_usd),
        ] {
            let Some(limit) = limit else { continue };
            let amount = |v: i64| Amount::of(v, unit == "usd");
            budgets.push(PeriodBudget {
                period,
                unit,
                limit: amount(limit),
                spent: amount(spent),
                reserved: amount(reserved),
                remaining: amount(limit.saturating_sub(spent.saturating_add(reserved)).max(0)),
                resets_at,
            });
        }
    }
    let tenant = TenantView { id: &t.tenant_id, rpm: tenant_rpm, concurrent: tenant_limits.concurrent, budgets };
    let global = usable
        .iter()
        .map(|p| {
            let (status, resets_at) = global_status(p, &rpm_rows, &spend_rows, at);
            GlobalView { provider: &p.id, status, resets_at }
        })
        .collect();
    let mut resp = Json(LimitsView { token, tenant, global }).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Whether a provider has limits kept in the database (requests in flight
/// are counted per replica and not shown).
fn counted(l: &Limits) -> bool {
    l.rpm.is_some() || l.has_budget()
}

fn rpm_row<'a>(rows: &'a [RpmRow], scope: &LimitScope) -> Option<&'a RpmRow> {
    rows.iter().find(|r| r.level == scope.level.as_str() && r.tenant_id == scope.tenant && r.provider == scope.provider)
}

fn spend_of(rows: &[SpendRow], scope: &LimitScope, period: Period) -> Spend {
    rows.iter().find(|r| r.is(scope, period)).map(SpendRow::spend).unwrap_or_default()
}

/// How near a provider is to its limits for every tenant, and when that
/// gets better: an exhausted provider once every exhausted limit renews, a
/// near one when the nearest limit does.
fn global_status(
    p: &Provider,
    rpm_rows: &[RpmRow],
    spend_rows: &[SpendRow],
    at: Timestamp,
) -> (Status, Option<Timestamp>) {
    let scope = LimitScope::global(&p.id);
    // (remaining, limit, renews at)
    let mut items: Vec<(i64, i64, Timestamp)> = Vec::new();
    if let Some(limit) = p.limits.rpm {
        let count =
            rpm_row(rpm_rows, &scope).filter(|r| r.rl_window >= window_of(at)).map_or(0, |r| i64::from(r.rl_count));
        items.push((i64::from(limit) - count, i64::from(limit), window_reset(at)));
    }
    for period in p.limits.budget_periods() {
        let s = spend_of(spend_rows, &scope, period);
        for (limit, used) in
            [(p.limits.tokens(period), s.used_tokens()), (p.limits.micro_usd(period), s.used_micro_usd())]
        {
            if let Some(limit) = limit {
                items.push((limit.saturating_sub(used), limit, period.end(at)));
            }
        }
    }
    let status = |(remaining, limit, _): &(i64, i64, Timestamp)| {
        if *remaining <= 0 {
            Status::Exhausted
        } else if (*remaining as f64) < NEAR * *limit as f64 {
            Status::Near
        } else {
            Status::Ok
        }
    };
    let worst = items.iter().map(status).max().unwrap_or(Status::Ok);
    let resets_at = match worst {
        Status::Ok => None,
        Status::Exhausted => items.iter().filter(|i| status(i) == Status::Exhausted).map(|i| i.2).max(),
        Status::Near => items
            .iter()
            .filter(|i| status(i) == Status::Near)
            .min_by(|a, b| (a.0 as f64 / a.1 as f64).total_cmp(&(b.0 as f64 / b.1 as f64)))
            .map(|i| i.2),
    };
    (worst, resets_at)
}
