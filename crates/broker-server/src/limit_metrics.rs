//! Gauges read from the database, refreshed on every replica every
//! [`REFRESH_EVERY`] (all replicas export the same values):
//!
//! - `ocb_limit_quota` and `ocb_limit_remaining {level, tenant, provider,
//!   kind}` for each budget of a tenant (`level="tenant"`, `provider=""`) or
//!   of a provider for every tenant (`level="global"`, `tenant=""`) in the
//!   current day or month; `kind` is `tokens_day`, `tokens_month`,
//!   `usd_day` or `usd_month`, USD in dollars, and what requests in flight
//!   reserved counts as used. One series per budget, so their number grows
//!   with the tenants that have budgets;
//! - `ocb_llm_token_expiry_timestamp {tenant, label}`: the latest expiry of
//!   the live tokens with that label. Labels are chosen by the platform;
//!   only the first [`MAX_LABELLED_TOKENS`] tenant and label pairs are
//!   exported, so a label per token (a run id, say) cannot grow the series
//!   without bound, but would crowd out the ones that matter.
//!
//! A series whose budget or token is gone is set to NaN rather than left at
//! its last value.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use broker_core::limits::{Limits, Period};
use broker_core::store::{LimitScope, SpendRow};
use broker_core::{BrokerError, Keeper};
use tokio_util::sync::CancellationToken;

use crate::proxy::LlmProxy;

/// How often the gauges are read from the database.
pub const REFRESH_EVERY: Duration = Duration::from_secs(30);

/// Most tenant and label pairs exported as token expiry series.
pub const MAX_LABELLED_TOKENS: i64 = 1000;

/// level, tenant, provider, kind
type BudgetSeries = (&'static str, String, String, &'static str);

pub struct LimitGauges {
    keeper: Arc<Keeper>,
    proxy: Arc<LlmProxy>,
    /// Series set by the last refresh.
    budgets: BTreeSet<BudgetSeries>,
    expiries: BTreeSet<(String, String)>,
}

fn kind(period: Period, usd: bool) -> &'static str {
    match (period, usd) {
        (Period::Day, false) => "tokens_day",
        (Period::Month, false) => "tokens_month",
        (Period::Day, true) => "usd_day",
        (Period::Month, true) => "usd_month",
    }
}

impl LimitGauges {
    pub fn new(keeper: Arc<Keeper>, proxy: Arc<LlmProxy>) -> Self {
        Self { keeper, proxy, budgets: BTreeSet::new(), expiries: BTreeSet::new() }
    }

    /// Reads the budgets and labelled tokens once and sets the gauges.
    pub async fn refresh(&mut self) -> Result<(), BrokerError> {
        let at = self.keeper.now();
        let snap = self.proxy.snapshot();
        let mut levels: Vec<(LimitScope, Limits)> =
            snap.providers().filter(|p| p.limits.has_budget()).map(|p| (LimitScope::global(&p.id), p.limits)).collect();
        for t in self.keeper.all_tenant_limits().await? {
            if t.limits.has_budget() {
                levels.push((LimitScope::tenant(&t.tenant), t.limits));
            }
        }
        let scopes: Vec<LimitScope> = levels.iter().map(|(s, _)| s.clone()).collect();
        let (_, spend) = self.keeper.limit_usage(&scopes, at).await?;
        let mut budgets = BTreeSet::new();
        for (scope, limits) in &levels {
            for period in limits.budget_periods() {
                let s = spend.iter().find(|r| r.is(scope, period)).map(SpendRow::spend).unwrap_or_default();
                for (usd, limit, used) in [
                    (false, limits.tokens(period), s.used_tokens()),
                    (true, limits.micro_usd(period), s.used_micro_usd()),
                ] {
                    let Some(limit) = limit else { continue };
                    let amount = |v: i64| if usd { v as f64 / 1_000_000.0 } else { v as f64 };
                    let series =
                        (scope.level.as_str(), scope.tenant.clone(), scope.provider.clone(), kind(period, usd));
                    set_budget(&series, "ocb_limit_quota", amount(limit));
                    set_budget(&series, "ocb_limit_remaining", amount(limit.saturating_sub(used).max(0)));
                    budgets.insert(series);
                }
            }
        }
        for gone in self.budgets.difference(&budgets) {
            set_budget(gone, "ocb_limit_quota", f64::NAN);
            set_budget(gone, "ocb_limit_remaining", f64::NAN);
        }
        self.budgets = budgets;

        let mut tokens = self.keeper.labelled_token_expiry(MAX_LABELLED_TOKENS + 1).await?;
        if tokens.len() > usize::try_from(MAX_LABELLED_TOKENS).unwrap_or(usize::MAX) {
            tracing::warn!(
                max = MAX_LABELLED_TOKENS,
                "more labelled tokens than the expiry metric exports; use labels that name a role, not a run"
            );
            tokens.truncate(usize::try_from(MAX_LABELLED_TOKENS).unwrap_or(usize::MAX));
        }
        let mut expiries = BTreeSet::new();
        for t in tokens {
            set_expiry(&t.tenant_id, &t.label, t.expires_at as f64);
            expiries.insert((t.tenant_id, t.label));
        }
        for (tenant, label) in self.expiries.difference(&expiries) {
            set_expiry(tenant, label, f64::NAN);
        }
        self.expiries = expiries;
        Ok(())
    }

    /// Refreshes every `every` until `stop` is cancelled.
    pub async fn run(mut self, every: Duration, stop: CancellationToken) {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = stop.cancelled() => return,
            }
            if let Err(e) = self.refresh().await {
                tracing::warn!(error = %e, "reading limits for their metrics failed");
            }
        }
    }
}

fn set_budget(s: &BudgetSeries, name: &'static str, value: f64) {
    let (level, tenant, provider, kind) = s;
    metrics::gauge!(name, "level" => *level, "tenant" => tenant.clone(), "provider" => provider.clone(), "kind" => *kind)
        .set(value);
}

fn set_expiry(tenant: &str, label: &str, value: f64) {
    metrics::gauge!("ocb_llm_token_expiry_timestamp", "tenant" => tenant.to_owned(), "label" => label.to_owned())
        .set(value);
}
