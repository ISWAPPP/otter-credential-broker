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
//! These series are not kept by the metrics recorder, which keeps every
//! series it was ever given for the life of the process: a budget removed
//! or a label whose tokens are all gone would stay. Each refresh replaces
//! the series instead, and `/metrics` renders the last ones after the
//! recorder's, so a series that is gone is gone from the output too.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::{Arc, PoisonError, RwLock};
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

/// The series of the last refresh, shared with `/metrics`.
#[derive(Clone, Default)]
pub struct LimitSeries(Arc<RwLock<Series>>);

#[derive(Default)]
struct Series {
    /// Quota and remaining of each budget.
    budgets: BTreeMap<BudgetSeries, (f64, f64)>,
    /// Latest expiry per tenant and label.
    expiries: BTreeMap<(String, String), f64>,
}

impl LimitSeries {
    /// The series in the Prometheus text format, a family only when it has
    /// a series.
    pub fn render(&self) -> String {
        let s = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let mut out = String::new();
        let budget_labels = ["level", "tenant", "provider", "kind"];
        for (name, pick) in [("ocb_limit_quota", 0), ("ocb_limit_remaining", 1)] {
            let samples = s.budgets.iter().map(|((level, tenant, provider, kind), values)| {
                ([*level, tenant.as_str(), provider.as_str(), *kind], if pick == 0 { values.0 } else { values.1 })
            });
            family(&mut out, name, budget_labels, samples);
        }
        let samples = s.expiries.iter().map(|((tenant, label), at)| ([tenant.as_str(), label.as_str()], *at));
        family(&mut out, "ocb_llm_token_expiry_timestamp", ["tenant", "label"], samples);
        out
    }

    fn replace(&self, next: Series) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = next;
    }
}

/// Writes one gauge family: its type line, then a line per series.
fn family<'a, const N: usize>(
    out: &mut String,
    name: &str,
    labels: [&str; N],
    samples: impl Iterator<Item = ([&'a str; N], f64)>,
) {
    let mut samples = samples.peekable();
    if samples.peek().is_none() {
        return;
    }
    let _ = writeln!(out, "# TYPE {name} gauge");
    for (values, value) in samples {
        out.push_str(name);
        out.push('{');
        for (i, (label, v)) in labels.iter().zip(values).enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{label}=\"{}\"", escape(v));
        }
        let _ = writeln!(out, "}} {value}");
    }
    out.push('\n');
}

/// A label value as the Prometheus text format writes it. Tenant ids,
/// labels and provider ids have none of these characters; this keeps the
/// output valid should that ever change.
fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

pub struct LimitGauges {
    keeper: Arc<Keeper>,
    proxy: Arc<LlmProxy>,
    series: LimitSeries,
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
        Self { keeper, proxy, series: LimitSeries::default() }
    }

    /// The series `/metrics` renders; they change with every refresh.
    pub fn series(&self) -> LimitSeries {
        self.series.clone()
    }

    /// Reads the budgets and labelled tokens once and replaces the series.
    /// When reading fails, the series of the last refresh stay.
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
        let mut next = Series::default();
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
                    next.budgets.insert(series, (amount(limit), amount(limit.saturating_sub(used).max(0))));
                }
            }
        }

        let mut tokens = self.keeper.labelled_token_expiry(MAX_LABELLED_TOKENS + 1).await?;
        if tokens.len() > usize::try_from(MAX_LABELLED_TOKENS).unwrap_or(usize::MAX) {
            tracing::warn!(
                max = MAX_LABELLED_TOKENS,
                "more labelled tokens than the expiry metric exports; use labels that name a role, not a run"
            );
            tokens.truncate(usize::try_from(MAX_LABELLED_TOKENS).unwrap_or(usize::MAX));
        }
        for t in tokens {
            next.expiries.insert((t.tenant_id, t.label), t.expires_at as f64);
        }
        self.series.replace(next);
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn series_render_in_the_text_format_and_only_while_they_exist() {
        let series = LimitSeries::default();
        assert_eq!(series.render(), "", "no family without a series");
        let mut s = Series::default();
        s.budgets.insert(("tenant", "t1".into(), String::new(), "tokens_day"), (1000.0, 750.0));
        s.budgets.insert(("global", String::new(), "anthropic".into(), "usd_month"), (50.0, 49.998_65));
        s.expiries.insert(("t1".into(), "agent".into()), 1_900_007_200.0);
        series.replace(s);
        assert_eq!(
            series.render(),
            concat!(
                "# TYPE ocb_limit_quota gauge\n",
                "ocb_limit_quota{level=\"global\",tenant=\"\",provider=\"anthropic\",kind=\"usd_month\"} 50\n",
                "ocb_limit_quota{level=\"tenant\",tenant=\"t1\",provider=\"\",kind=\"tokens_day\"} 1000\n",
                "\n",
                "# TYPE ocb_limit_remaining gauge\n",
                "ocb_limit_remaining{level=\"global\",tenant=\"\",provider=\"anthropic\",kind=\"usd_month\"} 49.99865\n",
                "ocb_limit_remaining{level=\"tenant\",tenant=\"t1\",provider=\"\",kind=\"tokens_day\"} 750\n",
                "\n",
                "# TYPE ocb_llm_token_expiry_timestamp gauge\n",
                "ocb_llm_token_expiry_timestamp{tenant=\"t1\",label=\"agent\"} 1900007200\n",
                "\n",
            )
        );
        // A refresh replaces every series: what is gone is not rendered.
        let mut s = Series::default();
        s.expiries.insert(("t1".into(), "probe".into()), 1.0);
        series.replace(s);
        assert_eq!(
            series.render(),
            "# TYPE ocb_llm_token_expiry_timestamp gauge\nocb_llm_token_expiry_timestamp{tenant=\"t1\",label=\"probe\"} 1\n\n"
        );
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
