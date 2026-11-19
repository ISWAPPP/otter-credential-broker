//! Price table for cost accounting. Prices come only from configuration (they
//! change over time and differ per provider); nothing is hard-coded.

use serde::{Deserialize, Serialize};

use super::usage::Usage;
use crate::validate;

/// Price of one model at one provider, in USD per million tokens.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    pub provider: String,
    /// Exact model id, or a prefix followed by `*` (the longest match wins).
    pub model: String,
    pub input: f64,
    pub output: f64,
    /// Cache reads; defaults to `input`.
    #[serde(default)]
    pub cache_read: Option<f64>,
    /// Cache writes (Anthropic: 5-minute TTL); defaults to `input`.
    #[serde(default)]
    pub cache_write: Option<f64>,
    /// Anthropic 1-hour cache writes; defaults to `cache_write`.
    #[serde(default)]
    pub cache_write_1h: Option<f64>,
    /// Marks a deliberately free model (e.g. a local model server). Without
    /// it, `input` and `output` must be greater than zero, so a forgotten
    /// placeholder cannot silently disable USD budgets.
    #[serde(default)]
    pub free: bool,
}

const MAX_PRICE: f64 = 100_000.0;

impl ModelPrice {
    fn validate(&self) -> Result<(), String> {
        validate::provider_id(&self.provider).map_err(|e| e.to_string())?;
        let pattern = self.model.strip_suffix('*').unwrap_or(&self.model);
        if pattern.is_empty()
            || pattern.len() > 200
            || pattern.contains('*')
            || !pattern.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(format!("pricing: invalid model pattern for provider {}", self.provider));
        }
        let prices = [Some(self.input), Some(self.output), self.cache_read, self.cache_write, self.cache_write_1h];
        if prices.into_iter().flatten().any(|p| !p.is_finite() || !(0.0..=MAX_PRICE).contains(&p)) {
            return Err(format!(
                "pricing: prices for {}/{} must be between 0 and {MAX_PRICE}",
                self.provider, self.model
            ));
        }
        if !self.free && (self.input <= 0.0 || self.output <= 0.0) {
            return Err(format!(
                "pricing: {}/{} has a zero input or output price; set `free = true` if that is intended",
                self.provider, self.model
            ));
        }
        Ok(())
    }

    fn is_prefix(&self) -> bool {
        self.model.ends_with('*')
    }

    fn pattern(&self) -> &str {
        self.model.strip_suffix('*').unwrap_or(&self.model)
    }

    /// Bounded label for metrics: the configured pattern without `*`. Caller
    /// supplied model names never become metric labels.
    pub fn label(&self) -> &str {
        self.pattern()
    }

    /// Cost in micro-USD, rounded up. With prices in USD per million tokens,
    /// micro-USD = tokens x price.
    pub fn cost_micro_usd(&self, u: &Usage) -> i64 {
        let cache_read = self.cache_read.unwrap_or(self.input);
        let cache_write = self.cache_write.unwrap_or(self.input);
        let cache_write_1h = self.cache_write_1h.unwrap_or(cache_write);
        let write_1h = u.cache_write_1h_tokens.min(u.cache_write_tokens);
        let write_5m = u.cache_write_tokens - write_1h;
        let total = u.input_tokens as f64 * self.input
            + u.output_tokens as f64 * self.output
            + u.cache_read_tokens as f64 * cache_read
            + write_5m as f64 * cache_write
            + write_1h as f64 * cache_write_1h;
        let micro = total.ceil();
        if micro.is_finite() && micro < i64::MAX as f64 { micro.max(0.0) as i64 } else { i64::MAX }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PriceTable {
    entries: Vec<ModelPrice>,
}

impl PriceTable {
    pub fn new(entries: Vec<ModelPrice>) -> Result<Self, String> {
        for (i, e) in entries.iter().enumerate() {
            e.validate()?;
            if entries[..i].iter().any(|o| o.provider == e.provider && o.model == e.model) {
                return Err(format!("pricing: duplicate entry {}/{}", e.provider, e.model));
            }
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn providers(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.provider.as_str())
    }

    /// The highest configured price of each component for a provider: used
    /// when the provider reports a model that has no price of its own, so an
    /// unknown model is never billed below any known one.
    pub fn most_expensive(&self, provider: &str) -> Option<ModelPrice> {
        let mut it = self.entries.iter().filter(|e| e.provider == provider);
        let first = it.next()?.clone();
        let max = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (x, y) => x.or(y),
        };
        let start = ModelPrice {
            model: "max".into(),
            cache_read: first.cache_read.or(Some(first.input)),
            cache_write: first.cache_write.or(Some(first.input)),
            cache_write_1h: first.cache_write_1h.or(first.cache_write).or(Some(first.input)),
            free: false,
            ..first
        };
        Some(it.fold(start, |acc, e| ModelPrice {
            input: acc.input.max(e.input),
            output: acc.output.max(e.output),
            cache_read: max(acc.cache_read, e.cache_read.or(Some(e.input))),
            cache_write: max(acc.cache_write, e.cache_write.or(Some(e.input))),
            cache_write_1h: max(acc.cache_write_1h, e.cache_write_1h.or(e.cache_write).or(Some(e.input))),
            ..acc
        }))
    }

    /// The price to bill a request with: the request's model, unless the
    /// provider reports a different model that actually answered (routing,
    /// fallbacks). A dated variant of the requested model keeps the request's
    /// price; another priced model is billed at its own price; an unpriced
    /// one at the provider's highest configured price. Returns the price and
    /// whether that conservative fallback was used.
    pub fn billing_price(
        &self,
        provider: &str,
        requested: Option<&str>,
        reported: Option<&str>,
    ) -> (Option<ModelPrice>, bool) {
        let request_price = requested.and_then(|m| self.lookup(provider, m)).cloned();
        let Some(reported) = reported else { return (request_price, false) };
        if let Some(req) = requested
            && (reported == req || reported.strip_prefix(req).is_some_and(|rest| rest.starts_with('-')))
        {
            return (request_price, false);
        }
        if let Some(p) = self.lookup(provider, reported) {
            return (Some(p.clone()), false);
        }
        match self.most_expensive(provider) {
            Some(p) => (Some(p), true),
            None => (request_price, false),
        }
    }

    /// Exact match first, then the longest matching prefix pattern.
    pub fn lookup(&self, provider: &str, model: &str) -> Option<&ModelPrice> {
        let candidates = || self.entries.iter().filter(move |e| e.provider == provider);
        if let Some(exact) = candidates().find(|e| !e.is_prefix() && e.model == model) {
            return Some(exact);
        }
        candidates().filter(|e| e.is_prefix() && model.starts_with(e.pattern())).max_by_key(|e| e.pattern().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price(provider: &str, model: &str, input: f64, output: f64) -> ModelPrice {
        ModelPrice {
            provider: provider.into(),
            model: model.into(),
            input,
            output,
            cache_read: None,
            cache_write: None,
            cache_write_1h: None,
            free: false,
        }
    }

    #[test]
    fn zero_prices_need_free() {
        assert!(PriceTable::new(vec![price("a", "m", 0.0, 1.0)]).is_err());
        assert!(PriceTable::new(vec![price("a", "m", 1.0, 0.0)]).is_err());
        let mut p = price("a", "local", 0.0, 0.0);
        p.free = true;
        assert!(PriceTable::new(vec![p]).is_ok());
    }

    #[test]
    fn billing_price_follows_the_answering_model() {
        let t = PriceTable::new(vec![
            price("or", "cheap", 1.0, 1.0),
            price("or", "pricey", 10.0, 50.0),
            price("or", "mid", 5.0, 5.0),
        ])
        .unwrap();
        let io = |p: (Option<ModelPrice>, bool)| (p.0.map(|p| (p.input, p.output)), p.1);
        assert_eq!(io(t.billing_price("or", Some("cheap"), None)), (Some((1.0, 1.0)), false));
        assert_eq!(io(t.billing_price("or", Some("cheap"), Some("cheap-2026-01-01"))), (Some((1.0, 1.0)), false));
        assert_eq!(io(t.billing_price("or", Some("cheap"), Some("pricey"))), (Some((10.0, 50.0)), false));
        // Unknown answering model: the highest price of every component.
        assert_eq!(io(t.billing_price("or", Some("cheap"), Some("unknown"))), (Some((10.0, 50.0)), true));
        assert_eq!(io(t.billing_price("other", Some("cheap"), Some("unknown"))), (None, false));
    }

    #[test]
    fn lookup_rules() {
        let t = PriceTable::new(vec![
            price("anthropic", "model-*", 1.0, 1.0),
            price("anthropic", "model-big-*", 2.0, 2.0),
            price("anthropic", "model-big-1", 3.0, 3.0),
            price("deepseek", "deepseek-chat", 0.5, 1.0),
        ])
        .unwrap();
        assert_eq!(t.lookup("anthropic", "model-big-1").unwrap().input, 3.0);
        assert_eq!(t.lookup("anthropic", "model-big-2").unwrap().input, 2.0);
        assert_eq!(t.lookup("anthropic", "model-small").unwrap().input, 1.0);
        assert!(t.lookup("anthropic", "gpt-x").is_none());
        assert!(t.lookup("openai", "model-big-1").is_none());
        assert!(t.lookup("deepseek", "deepseek-chat-v2").is_none());
        assert_eq!(t.lookup("anthropic", "model-big-2").unwrap().label(), "model-big-");
    }

    #[test]
    fn validation() {
        assert!(PriceTable::new(vec![price("anthropic", "*", 1.0, 1.0)]).is_err());
        assert!(PriceTable::new(vec![price("anthropic", "a*b", 1.0, 1.0)]).is_err());
        assert!(PriceTable::new(vec![price("anthropic", "m", -1.0, 1.0)]).is_err());
        assert!(PriceTable::new(vec![price("anthropic", "m", f64::NAN, 1.0)]).is_err());
        assert!(PriceTable::new(vec![price("Bad Provider", "m", 1.0, 1.0)]).is_err());
        assert!(PriceTable::new(vec![price("a", "m", 1.0, 1.0), price("a", "m", 2.0, 1.0)]).is_err());
    }

    #[test]
    fn cost() {
        let mut p = price("anthropic", "m", 3.0, 15.0);
        p.cache_read = Some(0.3);
        p.cache_write = Some(3.75);
        p.cache_write_1h = Some(6.0);
        let u = Usage {
            input_tokens: 1000,
            output_tokens: 200,
            cache_read_tokens: 10_000,
            cache_write_tokens: 2000,
            cache_write_1h_tokens: 500,
        };
        // 1000*3 + 200*15 + 10000*0.3 + 1500*3.75 + 500*6 = 3000+3000+3000+5625+3000
        assert_eq!(p.cost_micro_usd(&u), 17_625);
        // Defaults: cache prices fall back to input.
        let q = price("x", "m", 2.0, 4.0);
        let u = Usage {
            input_tokens: 1,
            output_tokens: 1,
            cache_read_tokens: 1,
            cache_write_tokens: 1,
            ..Usage::default()
        };
        assert_eq!(q.cost_micro_usd(&u), 2 + 4 + 2 + 2);
        // Rounds up.
        let r = price("x", "m", 0.1, 0.0);
        assert_eq!(r.cost_micro_usd(&Usage { input_tokens: 3, ..Usage::default() }), 1);
    }
}
