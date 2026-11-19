//! In-process limits of one replica: requests in flight (per LLM token and
//! in total) and failed token checks per client address. They bound memory
//! and database load; budgets and the per-token rate limit, which must hold
//! across replicas, live in PostgreSQL.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Caps on concurrent proxied requests.
pub struct Inflight {
    per_token: Mutex<HashMap<String, u32>>,
    max_per_token: u32,
    total: Arc<Semaphore>,
}

/// Held for the whole life of a proxied request, including accounting.
pub struct InflightPermit {
    inflight: Arc<Inflight>,
    token_id: String,
    _total: OwnedSemaphorePermit,
}

impl Inflight {
    pub fn new(max_per_token: u32, max_total: u32) -> Arc<Self> {
        Arc::new(Self {
            per_token: Mutex::new(HashMap::new()),
            max_per_token: max_per_token.max(1),
            total: Arc::new(Semaphore::new(usize::try_from(max_total.max(1)).unwrap_or(usize::MAX))),
        })
    }

    /// `None` when the token or the replica is at its limit.
    pub fn acquire(self: &Arc<Self>, token_id: &str) -> Option<InflightPermit> {
        let total = self.total.clone().try_acquire_owned().ok()?;
        let mut map = self.per_token.lock().ok()?;
        let n = map.entry(token_id.to_owned()).or_insert(0);
        if *n >= self.max_per_token {
            return None;
        }
        *n += 1;
        Some(InflightPermit { inflight: self.clone(), token_id: token_id.to_owned(), _total: total })
    }

    /// Requests in flight for a token (for tests and diagnostics).
    pub fn count(&self, token_id: &str) -> u32 {
        self.per_token.lock().ok().and_then(|m| m.get(token_id).copied()).unwrap_or(0)
    }
}

impl Drop for InflightPermit {
    fn drop(&mut self) {
        if let Ok(mut map) = self.inflight.per_token.lock()
            && let Some(n) = map.get_mut(&self.token_id)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.token_id);
            }
        }
    }
}

/// Fixed one-minute windows of failed token checks per client address.
pub struct AuthFailureLimiter {
    max_per_minute: u32,
    windows: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

const MAX_TRACKED_ADDRESSES: usize = 10_000;

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
            if m.len() >= MAX_TRACKED_ADDRESSES {
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
