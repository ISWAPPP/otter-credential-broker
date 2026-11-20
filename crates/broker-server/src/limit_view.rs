//! What a caller sees of its limits on every proxied response, once its
//! token is accepted for the provider:
//!
//! - `RateLimit-Policy` and `RateLimit` (IETF HTTP API rate limit fields)
//!   for the requests per minute of the token and, if it has a limit, of
//!   its tenant: `"token";q=120;w=60` and `"token";r=117;t=42`;
//! - `ocb-budget-limit`, `ocb-budget-remaining`, `ocb-budget-unit` (`tokens`
//!   or `usd`) and `ocb-budget-reset` (seconds until it renews; a token's
//!   budget never does) for the budget of the token or tenant nearest to
//!   running out, reservations of requests in flight counted as spent;
//! - `ocb-limit-level`: the level that refused the request, or else the
//!   level of that budget.
//!
//! The limits of a provider for every tenant are never shown here: their
//! numbers come from every tenant's requests. The broker sets these headers
//! after those passed on from the provider, which can never pass headers of
//! these names anyway, so they cannot be overridden.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use broker_core::clock::Timestamp;
use broker_core::keeper::{Authorized, Counted, RateCount};
use broker_core::limits::{LimitKind, LimitLevel, LimitRefusal, Limits, Period, Spend, WINDOW_SECS, window_reset};
use broker_core::store::SpendRow;

use crate::error::LIMIT_LEVEL;

const RATELIMIT_POLICY: HeaderName = HeaderName::from_static("ratelimit-policy");
const RATELIMIT: HeaderName = HeaderName::from_static("ratelimit");
const BUDGET_LIMIT: HeaderName = HeaderName::from_static("ocb-budget-limit");
const BUDGET_REMAINING: HeaderName = HeaderName::from_static("ocb-budget-remaining");
const BUDGET_UNIT: HeaderName = HeaderName::from_static("ocb-budget-unit");
const BUDGET_RESET: HeaderName = HeaderName::from_static("ocb-budget-reset");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    level: LimitLevel,
    /// `None` for the budget of a token, which lasts as long as the token.
    period: Option<Period>,
    usd: bool,
    limit: i64,
    used: i64,
}

impl Budget {
    fn remaining(&self) -> i64 {
        self.limit.saturating_sub(self.used).max(0)
    }

    /// Share of the budget left, for picking the one nearest to running out.
    fn left(&self) -> f64 {
        if self.limit <= 0 { 0.0 } else { self.remaining() as f64 / self.limit as f64 }
    }
}

/// The limits of one request, as far as its caller may see them.
#[derive(Debug, Clone)]
pub(crate) struct LimitView {
    at: Timestamp,
    token_rpm: RateCount,
    tenant_rpm_limit: Option<u32>,
    tenant_rpm: Option<RateCount>,
    /// Of the token first, then of the tenant per period.
    budgets: Vec<Budget>,
    refused: Option<LimitLevel>,
}

impl LimitView {
    pub(crate) fn new(a: &Authorized) -> Self {
        let mut budgets = Vec::new();
        let g = &a.grant;
        for (usd, limit, spent) in
            [(false, g.budget_tokens, g.spent_tokens), (true, g.budget_micro_usd, g.spent_micro_usd)]
        {
            if let Some(limit) = limit {
                budgets.push(Budget { level: LimitLevel::Token, period: None, usd, limit, used: spent });
            }
        }
        let mut view = Self {
            at: a.at,
            token_rpm: a.token_rpm,
            tenant_rpm_limit: a.tenant_limits.rpm,
            tenant_rpm: None,
            budgets,
            refused: None,
        };
        view.tenant_budgets(&a.tenant_limits, |p| a.tenant_spend.get(p).unwrap_or_default());
        view
    }

    fn tenant_budgets(&mut self, limits: &Limits, spend: impl Fn(Period) -> Spend) {
        self.budgets.retain(|b| b.level != LimitLevel::Tenant);
        for period in limits.budget_periods() {
            let s = spend(period);
            for (usd, limit, used) in
                [(false, limits.tokens(period), s.used_tokens()), (true, limits.micro_usd(period), s.used_micro_usd())]
            {
                if let Some(limit) = limit {
                    self.budgets.push(Budget { level: LimitLevel::Tenant, period: Some(period), usd, limit, used });
                }
            }
        }
    }

    /// The tenant's window as the request was counted in it.
    pub(crate) fn counted(&mut self, c: &Counted) {
        self.tenant_rpm = c.tenant;
    }

    /// The tenant's budgets as they are after the request reserved on them.
    pub(crate) fn reserved(&mut self, limits: &Limits, tenant: &str, rows: &[SpendRow]) {
        let fresh = |p: Period| {
            rows.iter()
                .find(|r| {
                    r.level == LimitLevel::Tenant.as_str() && r.tenant_id == tenant && r.period_kind == p.as_str()
                })
                .map(SpendRow::spend)
                .unwrap_or_default()
        };
        self.tenant_budgets(limits, fresh);
    }

    /// Records a refusal by a limit of `level`, and what it says about the
    /// state of that limit.
    pub(crate) fn refused(&mut self, level: LimitLevel, refusal: Option<&LimitRefusal>) {
        self.refused = Some(level);
        match (level, refusal) {
            (LimitLevel::Tenant, Some(r)) if r.kind == LimitKind::Rate => {
                let limit = i64::from(self.tenant_rpm_limit.unwrap_or_default());
                self.tenant_rpm = Some(RateCount { limit, count: limit });
            }
            (LimitLevel::Tenant, Some(LimitRefusal { budget: Some(b), .. })) => {
                let refused =
                    |x: &Budget| x.level == LimitLevel::Tenant && x.period == Some(b.period) && x.usd == b.usd;
                for x in self.budgets.iter_mut().filter(|x| refused(x)) {
                    x.used = b.used.max(x.limit);
                }
            }
            _ => {}
        }
    }

    /// The budget nearest to running out; ties go to the lower level, then
    /// to the shorter period.
    fn nearest(&self) -> Option<&Budget> {
        self.budgets.iter().reduce(|best, b| if b.left() < best.left() { b } else { best })
    }

    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        let reset = window_reset(self.at) - self.at;
        let rates = [("token", Some(self.token_rpm)), ("tenant", self.tenant_rpm)];
        let rates: Vec<(&str, RateCount)> = rates.into_iter().filter_map(|(n, r)| Some((n, r?))).collect();
        let policy: Vec<String> = rates.iter().map(|(n, r)| format!("\"{n}\";q={};w={WINDOW_SECS}", r.limit)).collect();
        let state: Vec<String> = rates
            .iter()
            .map(|(n, r)| format!("\"{n}\";r={};t={reset}", r.limit.saturating_sub(r.count).max(0)))
            .collect();
        set(headers, RATELIMIT_POLICY, &policy.join(", "));
        set(headers, RATELIMIT, &state.join(", "));
        for name in [&BUDGET_LIMIT, &BUDGET_REMAINING, &BUDGET_UNIT, &BUDGET_RESET] {
            headers.remove(name);
        }
        let nearest = self.nearest();
        if let Some(b) = nearest {
            let amount = |v: i64| if b.usd { usd(v) } else { v.to_string() };
            set(headers, BUDGET_LIMIT, &amount(b.limit));
            set(headers, BUDGET_REMAINING, &amount(b.remaining()));
            set(headers, BUDGET_UNIT, if b.usd { "usd" } else { "tokens" });
            if let Some(p) = b.period {
                set(headers, BUDGET_RESET, &(p.end(self.at) - self.at).to_string());
            }
        }
        match self.refused.or(nearest.map(|b| b.level)) {
            Some(level) => set(headers, LIMIT_LEVEL, level.as_str()),
            None => {
                headers.remove(LIMIT_LEVEL);
            }
        }
    }
}

/// Micro-USD as dollars with six decimals.
fn usd(micro: i64) -> String {
    let micro = micro.max(0);
    format!("{}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

fn set(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use broker_core::keeper::LlmGrant;
    use broker_core::limits::{PerPeriod, RefusedBudget};

    /// 2030-03-17T17:46:40Z.
    const AT: i64 = 1_900_000_000;

    fn authorized(budget_tokens: Option<i64>, spent: i64, tenant: Limits, day: Spend) -> Authorized {
        Authorized {
            grant: LlmGrant {
                token_id: "t".into(),
                tenant: "tenant-a".into(),
                run_id: None,
                budget_micro_usd: None,
                budget_tokens,
                spent_micro_usd: 0,
                spent_tokens: spent,
                trace_parent: None,
            },
            at: AT,
            token_rpm: RateCount { limit: 120, count: 3 },
            tenant_limits: tenant,
            tenant_spend: PerPeriod { day: Some(day), month: None },
        }
    }

    fn headers(v: &LimitView) -> Vec<(String, String)> {
        let mut h = HeaderMap::new();
        h.insert("ratelimit", HeaderValue::from_static("\"upstream\";r=1;t=1"));
        h.insert("ocb-budget-remaining", HeaderValue::from_static("999"));
        v.apply(&mut h);
        let mut out: Vec<(String, String)> =
            h.iter().map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned())).collect();
        out.sort();
        out
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = p.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        out.sort();
        out
    }

    #[test]
    fn a_token_without_budgets_shows_its_rate() {
        let v = LimitView::new(&authorized(None, 0, Limits::default(), Spend::default()));
        assert_eq!(
            headers(&v),
            pairs(&[("ratelimit-policy", "\"token\";q=120;w=60"), ("ratelimit", "\"token\";r=117;t=20")])
        );
    }

    #[test]
    fn the_budget_nearest_to_running_out_is_shown() {
        let tenant = Limits {
            rpm: Some(600),
            budget_tokens: PerPeriod { day: Some(1000), month: None },
            budget_usd: PerPeriod { day: Some(2.0), month: None },
            ..Limits::default()
        };
        let day = Spend { spent_tokens: 600, reserved_tokens: 100, spent_micro_usd: 100_000, ..Spend::default() };
        // Token: 400 of 1000 left; tenant: 300 of 1000 tokens, $1.9 of $2.
        let mut v = LimitView::new(&authorized(Some(1000), 600, tenant, day));
        v.counted(&Counted { tenant: Some(RateCount { limit: 600, count: 10 }), global: None });
        assert_eq!(
            headers(&v),
            pairs(&[
                ("ratelimit-policy", "\"token\";q=120;w=60, \"tenant\";q=600;w=60"),
                ("ratelimit", "\"token\";r=117;t=20, \"tenant\";r=590;t=20"),
                ("ocb-budget-limit", "1000"),
                ("ocb-budget-remaining", "300"),
                ("ocb-budget-unit", "tokens"),
                ("ocb-budget-reset", "22400"),
                ("ocb-limit-level", "tenant"),
            ])
        );
        // The token's budget when it is nearer, with no reset.
        let mut v = LimitView::new(&authorized(Some(1000), 990, tenant, day));
        v.counted(&Counted::default());
        let h = headers(&v);
        assert!(h.contains(&("ocb-budget-remaining".into(), "10".into())), "{h:?}");
        assert!(h.contains(&("ocb-limit-level".into(), "token".into())));
        assert!(!h.iter().any(|(k, _)| k == "ocb-budget-reset"));
        // After a reservation, the fresh rows; USD in dollars.
        let row = SpendRow {
            level: "tenant".into(),
            tenant_id: "tenant-a".into(),
            provider: String::new(),
            period_kind: "day".into(),
            period_start: AT - AT % 86_400,
            spent_tokens: 0,
            spent_micro_usd: 1_999_000,
            reserved_tokens: 0,
            reserved_micro_usd: 500,
            limit_tokens: Some(1000),
            limit_micro_usd: Some(2_000_000),
        };
        let mut v = LimitView::new(&authorized(None, 0, tenant, day));
        v.reserved(&tenant, "tenant-a", &[row]);
        let h = headers(&v);
        for want in [("ocb-budget-limit", "2.000000"), ("ocb-budget-remaining", "0.000500"), ("ocb-budget-unit", "usd")]
        {
            assert!(h.contains(&(want.0.into(), want.1.into())), "{want:?} in {h:?}");
        }
    }

    #[test]
    fn refusals_name_their_level_and_show_the_limit_used_up() {
        let tenant =
            Limits { rpm: Some(5), budget_tokens: PerPeriod { day: Some(100), month: None }, ..Limits::default() };
        let mut v = LimitView::new(&authorized(None, 0, tenant, Spend::default()));
        let rate = LimitRefusal {
            level: LimitLevel::Tenant,
            kind: LimitKind::Rate,
            message: String::new(),
            retry_after_secs: Some(20),
            budget: None,
        };
        v.refused(LimitLevel::Tenant, Some(&rate));
        let h = headers(&v);
        assert!(h.contains(&("ratelimit".into(), "\"token\";r=117;t=20, \"tenant\";r=0;t=20".into())), "{h:?}");
        assert!(h.contains(&("ocb-limit-level".into(), "tenant".into())));
        // A budget the reservation found used up, unlike what authorization read.
        let mut v = LimitView::new(&authorized(None, 0, tenant, Spend::default()));
        let budget = LimitRefusal {
            kind: LimitKind::Budget,
            budget: Some(RefusedBudget { period: Period::Day, usd: false, limit: 100, used: 128, renews_at: 0 }),
            ..rate
        };
        v.refused(LimitLevel::Tenant, Some(&budget));
        assert!(headers(&v).contains(&("ocb-budget-remaining".into(), "0".into())));
        // A provider's refusal names the level and shows none of its numbers.
        let mut v = LimitView::new(&authorized(None, 0, Limits::default(), Spend::default()));
        v.refused(LimitLevel::Global, None);
        let h = headers(&v);
        assert!(h.contains(&("ocb-limit-level".into(), "global".into())));
        assert!(!h.iter().any(|(k, _)| k.starts_with("ocb-budget-")), "{h:?}");
        assert_eq!(usd(1_500_000), "1.500000");
        assert_eq!(usd(-5), "0.000000");
    }
}
