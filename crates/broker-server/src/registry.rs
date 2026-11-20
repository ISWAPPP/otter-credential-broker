//! The provider registry: validated providers and their prices, held as one
//! immutable snapshot. A configuration reload builds a new snapshot and
//! swaps it in as a whole; a request takes the snapshot once and keeps it
//! until its accounting is done, so a reload never changes a request that is
//! already running.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

use broker_core::llm::pricing::PriceTable;
use sha2::{Digest, Sha256};

use crate::config::{LlmConfig, Provider};

/// Providers and prices of one configuration.
pub struct ProviderSnapshot {
    providers: BTreeMap<String, Provider>,
    prices: PriceTable,
    version: u64,
}

impl ProviderSnapshot {
    /// Validates the providers and prices of `cfg`.
    pub fn build(cfg: &LlmConfig) -> Result<Self, String> {
        let (providers, prices) = cfg.validate()?;
        let version = fingerprint(cfg)?;
        Ok(Self { providers, prices, version })
    }

    pub fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.get(id)
    }

    /// Providers in id order.
    pub fn providers(&self) -> impl Iterator<Item = &Provider> {
        self.providers.values()
    }

    pub fn prices(&self) -> &PriceTable {
        &self.prices
    }

    /// Identifies the configuration: the first 48 bits of a SHA-256 over
    /// providers and prices. Replicas that serve the same configuration
    /// report the same version.
    pub fn version(&self) -> u64 {
        self.version
    }
}

fn fingerprint(cfg: &LlmConfig) -> Result<u64, String> {
    let canonical = serde_json::to_vec(&(&cfg.providers, &cfg.pricing)).map_err(|e| format!("llm: {e}"))?;
    let d = Sha256::digest(&canonical);
    Ok(u64::from_be_bytes([0, 0, d[0], d[1], d[2], d[3], d[4], d[5]]))
}

/// Holds the current snapshot. Readers clone the `Arc` and keep it for as
/// long as they need; a reload replaces the `Arc` here without touching
/// them.
pub(crate) struct SnapshotCell(RwLock<Arc<ProviderSnapshot>>);

impl SnapshotCell {
    pub(crate) fn new(s: ProviderSnapshot) -> Self {
        Self(RwLock::new(Arc::new(s)))
    }

    pub(crate) fn load(&self) -> Arc<ProviderSnapshot> {
        // The lock is only held to clone or replace the `Arc`; nothing can
        // panic while it is held, so a poisoned lock still has a valid value.
        self.0.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Installs `next` and returns the snapshot it replaced.
    pub(crate) fn replace(&self, next: ProviderSnapshot) -> Arc<ProviderSnapshot> {
        let mut current = self.0.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, Arc::new(next))
    }
}

/// Publishes the version of the snapshot in use.
pub(crate) fn publish(s: &ProviderSnapshot) {
    // Exact: versions have 48 bits.
    metrics::gauge!("ocb_config_version").set(s.version as f64);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::config::ProviderConfig;
    use broker_core::llm::ProviderKind;

    fn config(base_url: &str) -> LlmConfig {
        let mut c = LlmConfig::default();
        c.providers.insert("anthropic".into(), ProviderConfig::new(ProviderKind::Anthropic, base_url));
        c
    }

    #[test]
    fn version_follows_the_provider_configuration() {
        let a = ProviderSnapshot::build(&config("https://a.example")).unwrap();
        let same = ProviderSnapshot::build(&config("https://a.example")).unwrap();
        let other = ProviderSnapshot::build(&config("https://b.example")).unwrap();
        assert_eq!(a.version(), same.version());
        assert_ne!(a.version(), other.version());
        assert!(a.version() < 1 << 48);
        // Settings outside providers and prices do not change it.
        let mut c = config("https://a.example");
        c.max_concurrent_total = 1;
        assert_eq!(ProviderSnapshot::build(&c).unwrap().version(), a.version());
    }

    #[test]
    fn readers_keep_their_snapshot_across_a_swap() {
        let cell = SnapshotCell::new(ProviderSnapshot::build(&config("https://a.example")).unwrap());
        let held = cell.load();
        let old = cell.replace(ProviderSnapshot::build(&config("https://b.example")).unwrap());
        assert!(Arc::ptr_eq(&held, &old));
        assert_eq!(held.provider("anthropic").unwrap().base_url, "https://a.example");
        assert_eq!(cell.load().provider("anthropic").unwrap().base_url, "https://b.example");
    }
}
