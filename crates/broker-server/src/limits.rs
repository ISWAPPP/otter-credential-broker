//! In-process limits of one replica: requests in flight (per LLM token, per
//! tenant and per provider where their limits set a cap, and in total) and
//! failed token checks per client address. They bound memory and database
//! load; budgets and rate limits, which must hold across replicas, live in
//! PostgreSQL.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use broker_core::limits::LimitLevel;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Caps on concurrent proxied requests. The counts live as long as the
/// process; caps of tenants and providers come with each request, so a
/// changed cap applies to the requests already counted.
pub struct Inflight {
    counts: Mutex<Counts>,
    max_per_token: u32,
    total: Arc<Semaphore>,
}

#[derive(Default)]
struct Counts {
    tokens: HashMap<String, u32>,
    tenants: HashMap<String, u32>,
    providers: HashMap<String, u32>,
}

/// One request for [`Inflight::acquire_for`]: its token, its tenant and its
/// provider, with the caps of the tenant and the provider on this replica.
pub struct InflightKey<'a> {
    pub token_id: &'a str,
    pub tenant: &'a str,
    pub tenant_max: Option<u32>,
    pub provider: &'a str,
    pub provider_max: Option<u32>,
}

/// Why [`Inflight::acquire_for`] refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflightRefusal {
    /// The cap of the token, of its tenant or of its provider.
    Level(LimitLevel),
    /// The replica's total (`llm.max_concurrent_total`), which belongs to no
    /// tenant or provider.
    Replica,
}

impl InflightRefusal {
    /// The level the refusal is reported at. Callers know three levels; the
    /// replica's total is reported as global.
    pub fn level(self) -> LimitLevel {
        match self {
            Self::Level(level) => level,
            Self::Replica => LimitLevel::Global,
        }
    }
}

/// Held for the whole life of a proxied request, including accounting.
pub struct InflightPermit {
    inflight: Arc<Inflight>,
    token_id: String,
    tenant: Option<String>,
    provider: Option<String>,
    _total: OwnedSemaphorePermit,
}

fn add(map: &mut HashMap<String, u32>, key: &str) {
    *map.entry(key.to_owned()).or_insert(0) += 1;
}

fn sub(map: &mut HashMap<String, u32>, key: &str) {
    if let Some(n) = map.get_mut(key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(key);
        }
    }
}

impl Inflight {
    pub fn new(max_per_token: u32, max_total: u32) -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::new(Counts::default()),
            max_per_token: max_per_token.max(1),
            total: Arc::new(Semaphore::new(usize::try_from(max_total.max(1)).unwrap_or(usize::MAX))),
        })
    }

    // Counts are changed under the lock in one go, so a poisoned lock
    // still holds consistent counts.
    fn counts(&self) -> MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `None` when the token or the replica is at its limit.
    pub fn acquire(self: &Arc<Self>, token_id: &str) -> Option<InflightPermit> {
        let mut c = self.counts();
        if c.tokens.get(token_id).copied().unwrap_or(0) >= self.max_per_token {
            return None;
        }
        let total = self.total.clone().try_acquire_owned().ok()?;
        add(&mut c.tokens, token_id);
        Some(InflightPermit {
            inflight: self.clone(),
            token_id: token_id.to_owned(),
            tenant: None,
            provider: None,
            _total: total,
        })
    }

    /// A permit for a request, checked level by level: the token, then its
    /// tenant, then its provider, then the replica's total. A refusal names
    /// the first level at its cap, or the replica when only its total is
    /// full, and nothing is counted for a refused request.
    pub fn acquire_for(self: &Arc<Self>, k: InflightKey<'_>) -> Result<InflightPermit, InflightRefusal> {
        let mut c = self.counts();
        let at_cap = |map: &HashMap<String, u32>, key: &str, max: u32| map.get(key).copied().unwrap_or(0) >= max;
        if at_cap(&c.tokens, k.token_id, self.max_per_token) {
            return Err(InflightRefusal::Level(LimitLevel::Token));
        }
        if k.tenant_max.is_some_and(|m| at_cap(&c.tenants, k.tenant, m)) {
            return Err(InflightRefusal::Level(LimitLevel::Tenant));
        }
        if k.provider_max.is_some_and(|m| at_cap(&c.providers, k.provider, m)) {
            return Err(InflightRefusal::Level(LimitLevel::Global));
        }
        let total = self.total.clone().try_acquire_owned().map_err(|_| InflightRefusal::Replica)?;
        add(&mut c.tokens, k.token_id);
        add(&mut c.tenants, k.tenant);
        add(&mut c.providers, k.provider);
        Ok(InflightPermit {
            inflight: self.clone(),
            token_id: k.token_id.to_owned(),
            tenant: Some(k.tenant.to_owned()),
            provider: Some(k.provider.to_owned()),
            _total: total,
        })
    }

    /// The cap on requests in flight per token.
    pub fn max_per_token(&self) -> u32 {
        self.max_per_token
    }

    /// Requests in flight for a token (for tests and diagnostics).
    pub fn count(&self, token_id: &str) -> u32 {
        self.counts().tokens.get(token_id).copied().unwrap_or(0)
    }

    /// Requests in flight for a tenant, on this replica.
    pub fn tenant_count(&self, tenant: &str) -> u32 {
        self.counts().tenants.get(tenant).copied().unwrap_or(0)
    }

    /// Requests in flight to a provider, on this replica.
    pub fn provider_count(&self, provider: &str) -> u32 {
        self.counts().providers.get(provider).copied().unwrap_or(0)
    }
}

impl Drop for InflightPermit {
    fn drop(&mut self) {
        let mut c = self.inflight.counts();
        sub(&mut c.tokens, &self.token_id);
        if let Some(t) = &self.tenant {
            sub(&mut c.tenants, t);
        }
        if let Some(p) = &self.provider {
            sub(&mut c.providers, p);
        }
    }
}

/// Fixed one-minute windows of requests per key, for endpoints that are
/// cheap to call in a loop and should not be. At most [`MAX_TRACKED_KEYS`]
/// keys are kept: while that many have requests in the current window, a
/// new key is refused.
pub struct MinuteLimiter<K> {
    max_per_minute: u32,
    windows: Mutex<HashMap<K, (u64, u32)>>,
}

impl<K: Eq + std::hash::Hash + Clone> MinuteLimiter<K> {
    pub fn new(max_per_minute: u32) -> Self {
        Self { max_per_minute: max_per_minute.max(1), windows: Mutex::new(HashMap::new()) }
    }

    fn windows(&self) -> MutexGuard<'_, HashMap<K, (u64, u32)>> {
        self.windows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `key` has used up its limit in the current window. Counts
    /// nothing, so it can be asked before the key is known to be valid.
    pub fn exceeded(&self, key: &K) -> bool {
        self.exceeded_at(key, minute())
    }

    fn exceeded_at(&self, key: &K, now: u64) -> bool {
        self.windows().get(key).is_some_and(|(w, n)| *w == now && *n >= self.max_per_minute)
    }

    /// Counts a request of `key`; `false` once the key is over its limit in
    /// the current window, or when it is new and the limiter is full.
    pub fn allow(&self, key: &K) -> bool {
        self.allow_at(key, minute())
    }

    fn allow_at(&self, key: &K, now: u64) -> bool {
        let mut m = self.windows();
        if m.len() >= MAX_TRACKED_KEYS && !m.contains_key(key) {
            m.retain(|_, (w, _)| *w == now);
            if m.len() >= MAX_TRACKED_KEYS {
                return false;
            }
        }
        let e = m.entry(key.clone()).or_insert((now, 0));
        if e.0 != now {
            *e = (now, 0);
        }
        e.1 = e.1.saturating_add(1);
        e.1 <= self.max_per_minute
    }

    /// Keys kept now (for tests and diagnostics).
    pub fn tracked(&self) -> usize {
        self.windows().len()
    }
}

/// Fixed one-minute windows of failed token checks per client address.
pub struct AuthFailureLimiter {
    max_per_minute: u32,
    windows: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

/// Keys (client addresses, tokens) a limiter keeps before it drops those of
/// earlier minutes; a [`MinuteLimiter`] never keeps more.
const MAX_TRACKED_KEYS: usize = 10_000;

fn minute() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() / 60).unwrap_or(0)
}

/// Seconds until the next one-minute window starts.
pub fn seconds_to_next_minute() -> u64 {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    60 - s % 60
}

impl AuthFailureLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self { max_per_minute: max_per_minute.max(1), windows: Mutex::new(HashMap::new()) }
    }

    /// Whether this address may attempt a token check now. Requests without a
    /// known address (in-process callers) are not limited.
    pub fn allowed(&self, addr: Option<IpAddr>) -> bool {
        let Some(addr) = addr else { return true };
        let now = minute();
        self.windows.lock().map_or(true, |m| match m.get(&addr) {
            Some((w, n)) if *w == now => *n < self.max_per_minute,
            _ => true,
        })
    }

    /// Records a failed token check.
    pub fn failed(&self, addr: Option<IpAddr>) {
        let Some(addr) = addr else { return };
        let now = minute();
        if let Ok(mut m) = self.windows.lock() {
            if m.len() >= MAX_TRACKED_KEYS {
                m.retain(|_, (w, _)| *w == now);
            }
            let e = m.entry(addr).or_insert((now, 0));
            if e.0 != now {
                *e = (now, 0);
            }
            e.1 = e.1.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn inflight_caps() {
        let f = Inflight::new(2, 3);
        let a1 = f.acquire("a").unwrap();
        let _a2 = f.acquire("a").unwrap();
        assert!(f.acquire("a").is_none(), "per-token cap");
        let _b1 = f.acquire("b").unwrap();
        assert!(f.acquire("c").is_none(), "total cap");
        drop(a1);
        assert_eq!(f.count("a"), 1);
        assert!(f.acquire("c").is_some());
    }

    #[test]
    fn inflight_caps_per_level() {
        let f = Inflight::new(2, 4);
        let key = |token_id, tenant, provider| InflightKey {
            token_id,
            tenant,
            tenant_max: Some(2),
            provider,
            provider_max: Some(3),
        };
        let level = |l| Some(InflightRefusal::Level(l));
        let a1 = f.acquire_for(key("a", "t1", "p")).unwrap();
        let _a2 = f.acquire_for(key("a", "t1", "p")).unwrap();
        assert_eq!(f.acquire_for(key("a", "t1", "p")).err(), level(LimitLevel::Token));
        assert_eq!(f.acquire_for(key("b", "t1", "p")).err(), level(LimitLevel::Tenant), "t1 holds two");
        let _c1 = f.acquire_for(key("c", "t2", "p")).unwrap();
        assert_eq!(f.acquire_for(key("d", "t3", "p")).err(), level(LimitLevel::Global), "p holds three");
        let _e1 = f.acquire_for(key("e", "t3", "q")).unwrap();
        assert_eq!(f.acquire_for(key("f", "t4", "r")).err(), Some(InflightRefusal::Replica), "the replica holds four");
        assert_eq!((f.tenant_count("t1"), f.provider_count("p"), f.count("b")), (2, 3, 0), "refusals count nothing");
        drop(a1);
        assert_eq!((f.count("a"), f.tenant_count("t1"), f.provider_count("p")), (1, 1, 2));
        // Without caps, a tenant and a provider are counted all the same.
        let open = InflightKey { token_id: "g", tenant: "t5", tenant_max: None, provider: "q", provider_max: None };
        let _g = f.acquire_for(open).unwrap();
        assert_eq!((f.tenant_count("t5"), f.provider_count("q")), (1, 2));
    }

    #[test]
    fn a_full_replica_is_not_a_cap_of_the_provider() {
        let f = Inflight::new(4, 1);
        let open =
            |token_id, provider| InflightKey { token_id, tenant: "t", tenant_max: None, provider, provider_max: None };
        let _a = f.acquire_for(open("a", "p")).unwrap();
        // Provider q has no cap and holds nothing: the replica's total refuses.
        let refusal = f.acquire_for(open("b", "q")).err();
        assert_eq!(refusal, Some(InflightRefusal::Replica));
        assert_eq!(refusal.map(InflightRefusal::level), Some(LimitLevel::Global));
        assert_eq!((f.provider_count("q"), f.tenant_count("t")), (0, 1));
    }

    #[test]
    fn requests_per_key_and_minute() {
        let l = MinuteLimiter::new(2);
        assert!(!l.exceeded(&"a"));
        assert!(l.allow(&"a") && l.allow(&"a"));
        assert!(l.exceeded(&"a"), "used up, without counting another");
        assert!(!l.allow(&"a"));
        assert!(l.allow(&"b"), "keys are counted apart");
        assert!(!l.exceeded(&"c") && l.tracked() == 2, "asking keeps nothing");
    }

    #[test]
    fn a_minute_limiter_keeps_no_more_keys_than_its_cap() {
        let l = MinuteLimiter::new(2);
        for k in 0..MAX_TRACKED_KEYS {
            assert!(l.allow_at(&k, 7));
        }
        assert!(!l.allow_at(&MAX_TRACKED_KEYS, 7), "a new key while full");
        assert_eq!(l.tracked(), MAX_TRACKED_KEYS);
        assert!(l.allow_at(&0, 7), "a key it keeps is still counted");
        assert!(!l.allow_at(&0, 7) && l.exceeded_at(&0, 7));
        // The next minute makes room: the old windows go.
        assert!(l.allow_at(&MAX_TRACKED_KEYS, 8));
        assert_eq!(l.tracked(), 1);
        assert!(!l.exceeded_at(&0, 8));
    }

    #[test]
    fn auth_failures_per_address() {
        let l = AuthFailureLimiter::new(2);
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let other: IpAddr = "10.1.2.4".parse().unwrap();
        assert!(l.allowed(Some(ip)));
        l.failed(Some(ip));
        l.failed(Some(ip));
        assert!(!l.allowed(Some(ip)));
        assert!(l.allowed(Some(other)));
        assert!(l.allowed(None));
    }
}
