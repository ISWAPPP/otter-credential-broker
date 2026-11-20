//! Limits on three levels, the strictest of which applies to a request:
//!
//! - **token**: one LLM token. Its rate limit, budget (for the token's whole
//!   life) and requests in flight are set when it is issued;
//! - **tenant**: every token of a tenant, on every provider, set through the
//!   admin API;
//! - **global**: every tenant on one provider, set in the provider's
//!   configuration.
//!
//! The tenant and global levels share the shape of [`Limits`]: requests per
//! minute, requests in flight (per replica) and budgets in tokens or USD per
//! UTC day or month. Each period has a row of its own in the database, keyed
//! by the start of the period, so nothing has to reset counters when a new
//! period starts.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::clock::Timestamp;

/// Where a limit applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitLevel {
    /// One LLM token.
    Token,
    /// Every token of a tenant.
    Tenant,
    /// Every tenant on a provider.
    Global,
}

impl LimitLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Tenant => "tenant",
            Self::Global => "global",
        }
    }
}

impl fmt::Display for LimitLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a limit counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Requests per minute.
    Rate,
    /// Requests in flight.
    InFlight,
    /// Tokens or cost per period.
    Budget,
}

impl LimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rate => "rpm",
            Self::InFlight => "concurrent",
            Self::Budget => "budget",
        }
    }
}

/// A request refused by a limit of the tenant or of a provider. (The
/// token's own limits are reported as before, with the variants of
/// [`crate::BrokerError`] for rate limits, requests in flight and budgets.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitRefusal {
    pub level: LimitLevel,
    pub kind: LimitKind,
    /// Shown to the caller. A global refusal never carries the numbers of
    /// the provider, which would show other tenants' activity.
    pub message: String,
    /// For rate limits: seconds until the window that refused ends.
    pub retry_after_secs: Option<u64>,
}

impl fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Length of a rate-limit window.
pub const WINDOW_SECS: i64 = 60;

/// The one-minute window `ts` falls in.
pub fn window_of(ts: Timestamp) -> i64 {
    ts.div_euclid(WINDOW_SECS)
}

/// When the window `ts` falls in ends.
pub fn window_reset(ts: Timestamp) -> Timestamp {
    (window_of(ts) + 1) * WINDOW_SECS
}

/// A budget period. Periods are calendar days and months in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    Day,
    Month,
}

const DAY_SECS: i64 = 86_400;

impl Period {
    pub const ALL: [Self; 2] = [Self::Day, Self::Month];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Month => "month",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// Start of the period that contains `ts`.
    pub fn start(self, ts: Timestamp) -> Timestamp {
        let day = ts.div_euclid(DAY_SECS);
        match self {
            Self::Day => day * DAY_SECS,
            Self::Month => {
                let (y, m, _) = civil_from_days(day);
                days_from_civil(y, m, 1) * DAY_SECS
            }
        }
    }

    /// Start of the period after the one that contains `ts`.
    pub fn end(self, ts: Timestamp) -> Timestamp {
        match self {
            Self::Day => self.start(ts) + DAY_SECS,
            Self::Month => {
                let (y, m, _) = civil_from_days(ts.div_euclid(DAY_SECS));
                let (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                days_from_civil(y, m, 1) * DAY_SECS
            }
        }
    }
}

impl fmt::Display for Period {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Year, month (1-12) and day (1-31) of a day counted from 1970-01-01
/// (proleptic Gregorian calendar).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Days from 1970-01-01 to a date (the inverse of [`civil_from_days`]).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A value per period, `{ day = ..., month = ... }`; either may be left out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PerPeriod<T> {
    #[serde(default)]
    pub day: Option<T>,
    #[serde(default)]
    pub month: Option<T>,
}

impl<T: Copy> PerPeriod<T> {
    pub fn get(&self, p: Period) -> Option<T> {
        match p {
            Period::Day => self.day,
            Period::Month => self.month,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.day.is_none() && self.month.is_none()
    }
}

/// Largest requests-per-minute limit of a tenant or provider.
pub const MAX_RPM: u32 = 10_000_000;
/// Largest limit on requests in flight of a tenant or provider.
pub const MAX_CONCURRENT: u32 = 1_000_000;
/// Largest token budget per period.
pub const MAX_BUDGET_TOKENS: u64 = 1_000_000_000_000_000;
/// Largest USD budget per period.
pub const MAX_BUDGET_USD: f64 = 1_000_000_000.0;

/// Limits of a tenant or of a provider. Anything left out is not limited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Requests per minute, in fixed one-minute windows, across replicas.
    #[serde(default)]
    pub rpm: Option<u32>,
    /// Requests in flight, per replica.
    #[serde(default)]
    pub concurrent: Option<u32>,
    /// Billable tokens (all input, cache reads and writes included, plus
    /// output) per UTC day and month.
    #[serde(default)]
    pub budget_tokens: PerPeriod<u64>,
    /// Cost in USD per UTC day and month.
    #[serde(default)]
    pub budget_usd: PerPeriod<f64>,
}

impl Limits {
    /// Checks the ranges of every value. The message names the key.
    pub fn validate(&self) -> Result<(), String> {
        if self.rpm.is_some_and(|r| !(1..=MAX_RPM).contains(&r)) {
            return Err(format!("rpm must be between 1 and {MAX_RPM}"));
        }
        if self.concurrent.is_some_and(|c| !(1..=MAX_CONCURRENT).contains(&c)) {
            return Err(format!("concurrent must be between 1 and {MAX_CONCURRENT}"));
        }
        for p in Period::ALL {
            if self.budget_tokens.get(p).is_some_and(|t| t > MAX_BUDGET_TOKENS) {
                return Err(format!("budget_tokens.{p} must be between 0 and {MAX_BUDGET_TOKENS}"));
            }
            if self.budget_usd.get(p).is_some_and(|u| !u.is_finite() || !(0.0..=MAX_BUDGET_USD).contains(&u)) {
                return Err(format!("budget_usd.{p} must be between 0 and {MAX_BUDGET_USD}"));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.rpm.is_none() && self.concurrent.is_none() && !self.has_budget()
    }

    /// Whether any budget is set (in tokens or USD, for any period).
    pub fn has_budget(&self) -> bool {
        !self.budget_tokens.is_empty() || !self.budget_usd.is_empty()
    }

    pub fn has_usd_budget(&self) -> bool {
        !self.budget_usd.is_empty()
    }

    /// The token budget of a period.
    pub fn tokens(&self, p: Period) -> Option<i64> {
        self.budget_tokens.get(p).map(|t| i64::try_from(t).unwrap_or(i64::MAX))
    }

    /// The USD budget of a period, in micro-USD.
    pub fn micro_usd(&self, p: Period) -> Option<i64> {
        self.budget_usd.get(p).map(usd_to_micro)
    }

    /// The periods with a budget, in tokens or USD.
    pub fn budget_periods(&self) -> impl Iterator<Item = Period> + '_ {
        Period::ALL.into_iter().filter(|p| self.tokens(*p).is_some() || self.micro_usd(*p).is_some())
    }

    /// Limits as stored in the database: USD in micro-USD.
    pub fn from_stored(
        rpm: Option<i32>,
        concurrent: Option<i32>,
        tokens: [Option<i64>; 2],
        micro_usd: [Option<i64>; 2],
    ) -> Self {
        let tokens = tokens.map(|t| t.and_then(|t| u64::try_from(t).ok()));
        let usd = micro_usd.map(|m| m.map(micro_to_usd));
        Self {
            rpm: rpm.and_then(|r| u32::try_from(r).ok()),
            concurrent: concurrent.and_then(|c| u32::try_from(c).ok()),
            budget_tokens: PerPeriod { day: tokens[0], month: tokens[1] },
            budget_usd: PerPeriod { day: usd[0], month: usd[1] },
        }
    }
}

/// Micro-USD (rounded) of a USD amount that [`Limits::validate`] accepted.
fn usd_to_micro(usd: f64) -> i64 {
    let micro = (usd * 1_000_000.0).round();
    if micro.is_finite() && micro >= 0.0 && micro < i64::MAX as f64 { micro as i64 } else { 0 }
}

fn micro_to_usd(micro: i64) -> f64 {
    micro as f64 / 1_000_000.0
}

/// What a level has used of one period: billed spend plus the reservations
/// of requests still in flight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Spend {
    pub spent_tokens: i64,
    pub spent_micro_usd: i64,
    pub reserved_tokens: i64,
    pub reserved_micro_usd: i64,
}

impl Spend {
    pub fn used_tokens(&self) -> i64 {
        self.spent_tokens.saturating_add(self.reserved_tokens)
    }

    pub fn used_micro_usd(&self) -> i64 {
        self.spent_micro_usd.saturating_add(self.reserved_micro_usd)
    }
}

/// An amount held on a budget row from authorization until the request is
/// accounted. `tenant` is empty for the global level and `provider` for
/// the tenant level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub level: LimitLevel,
    pub tenant: String,
    pub provider: String,
    pub period: Period,
    /// The period the request was authorized in, also when it is accounted
    /// in the next one.
    pub period_start: Timestamp,
    pub tokens: i64,
    pub micro_usd: i64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn periods_are_utc_days_and_months() {
        // 2030-03-17T17:46:40Z
        let t = 1_900_000_000;
        assert_eq!(Period::Day.start(t), 1_899_936_000);
        assert_eq!(Period::Day.end(t), 1_900_022_400);
        assert_eq!(Period::Month.start(t), 1_898_553_600, "2030-03-01");
        assert_eq!(Period::Month.end(t), 1_901_232_000, "2030-04-01");
        // The last second of a year, and the first of the next.
        assert_eq!(Period::Month.start(1_767_225_599), 1_764_547_200, "2025-12-01");
        assert_eq!(Period::Month.end(1_767_225_599), 1_767_225_600, "2026-01-01");
        assert_eq!(Period::Month.start(1_767_225_600), 1_767_225_600);
        assert_eq!(Period::Day.start(1_767_225_600), 1_767_225_600);
        // Leap day.
        assert_eq!(Period::Month.start(1_709_164_800), 1_706_745_600, "2024-02-01");
        assert_eq!(Period::Month.end(1_709_164_800), 1_709_251_200, "2024-03-01");
        assert_eq!(Period::Month.start(951_782_400 + 3600), 949_363_200, "2000-02-01");
        // Before 1970.
        assert_eq!(Period::Day.start(-1), -86_400);
        assert_eq!(Period::Month.start(-1), -2_678_400, "1969-12-01");
        assert_eq!(Period::Month.end(-1), 0);
        // Every day of 400 years maps back to itself.
        for day in -146_097..146_097 {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
            assert!((1..=12).contains(&m) && (1..=31).contains(&d));
        }
        assert_eq!(Period::parse("month"), Some(Period::Month));
        assert_eq!(Period::parse("week"), None);
    }

    #[test]
    fn windows_are_minutes() {
        assert_eq!(window_of(119), 1);
        assert_eq!(window_reset(119), 120);
        assert_eq!(window_reset(120), 180);
        assert_eq!(window_of(-1), -1);
    }

    #[test]
    fn limits_are_checked_and_converted() {
        let l = Limits {
            rpm: Some(300),
            concurrent: Some(8),
            budget_tokens: PerPeriod { day: None, month: Some(50_000_000) },
            budget_usd: PerPeriod { day: Some(12.345_678_9), month: None },
        };
        assert!(l.validate().is_ok());
        assert!(l.has_budget() && l.has_usd_budget() && !l.is_empty());
        assert_eq!(l.tokens(Period::Month), Some(50_000_000));
        assert_eq!(l.tokens(Period::Day), None);
        assert_eq!(l.micro_usd(Period::Day), Some(12_345_679));
        assert_eq!(l.budget_periods().collect::<Vec<_>>(), [Period::Day, Period::Month]);
        let stored = Limits::from_stored(Some(300), Some(8), [None, Some(50_000_000)], [Some(12_345_679), None]);
        assert_eq!(stored.micro_usd(Period::Day), Some(12_345_679));
        assert_eq!(stored.budget_tokens, l.budget_tokens);
        assert!(Limits::default().is_empty());
        assert_eq!(Limits::default().budget_periods().count(), 0);
        // A zero budget is a limit: nothing billable passes.
        let zero = Limits { budget_tokens: PerPeriod { day: Some(0), month: None }, ..Limits::default() };
        assert!(zero.validate().is_ok() && zero.has_budget());

        for bad in [
            Limits { rpm: Some(0), ..Limits::default() },
            Limits { rpm: Some(MAX_RPM + 1), ..Limits::default() },
            Limits { concurrent: Some(0), ..Limits::default() },
            Limits { budget_tokens: PerPeriod { day: Some(MAX_BUDGET_TOKENS + 1), month: None }, ..Limits::default() },
            Limits { budget_usd: PerPeriod { day: None, month: Some(-1.0) }, ..Limits::default() },
            Limits { budget_usd: PerPeriod { day: Some(f64::NAN), month: None }, ..Limits::default() },
            Limits { budget_usd: PerPeriod { day: Some(2e9), month: None }, ..Limits::default() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let e = Limits { budget_usd: PerPeriod { day: None, month: Some(-1.0) }, ..Limits::default() }.validate();
        assert!(e.unwrap_err().starts_with("budget_usd.month "));
    }

    #[test]
    fn limits_read_from_json() {
        let l: Limits =
            serde_json::from_str(r#"{"rpm": 5, "budget_tokens": {"month": 100}, "budget_usd": {"day": 2}}"#).unwrap();
        assert_eq!((l.rpm, l.tokens(Period::Month), l.micro_usd(Period::Day)), (Some(5), Some(100), Some(2_000_000)));
        for bad in [r#"{"rpm": -1}"#, r#"{"budget_tokens": {"week": 1}}"#, r#"{"burst": 1}"#, r#"{"rpm": 1.5}"#] {
            assert!(serde_json::from_str::<Limits>(bad).is_err(), "{bad}");
        }
    }
}
