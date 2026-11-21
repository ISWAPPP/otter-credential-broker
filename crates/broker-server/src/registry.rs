//! The provider registry: validated providers, their prices and the HTTP
//! clients of providers with their own TLS settings, held as one immutable
//! snapshot. A configuration reload builds a new snapshot and swaps it in as
//! a whole; a request takes the snapshot once and keeps it until its
//! accounting is done, so a reload never changes a request that is already
//! running.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use broker_core::llm::pricing::PriceTable;
use sha2::{Digest, Sha256};

use crate::config::{LlmConfig, Provider};
use crate::tls::{ClientSettings, http_client};

/// The HTTP client of a provider with `tls`.
pub(crate) struct TlsClient {
    pub http: reqwest::Client,
    /// Of the TLS material the client was built from.
    digest: [u8; 32],
    /// Earliest expiry of its CA and client certificates.
    not_after: Option<i64>,
}

/// Providers, prices and TLS clients of one configuration.
pub struct ProviderSnapshot {
    providers: BTreeMap<String, Provider>,
    prices: PriceTable,
    tls: BTreeMap<String, TlsClient>,
    /// SHA-256 of every TLS file in use, to notice rotations.
    tls_files: BTreeMap<PathBuf, [u8; 32]>,
    version: u64,
}

impl ProviderSnapshot {
    /// Validates the providers and prices of `cfg`, reads the TLS files of
    /// its providers and sets up their clients. A client of `previous` is
    /// reused when its TLS material is unchanged, which keeps its
    /// connections.
    pub(crate) fn build(
        cfg: &LlmConfig,
        clients: ClientSettings,
        previous: Option<&ProviderSnapshot>,
    ) -> Result<Self, String> {
        let (providers, prices) = cfg.validate()?;
        let mut tls = BTreeMap::new();
        let mut tls_files = BTreeMap::new();
        for p in providers.values() {
            let Some(t) = &p.tls else { continue };
            let what = format!("llm.providers.{}.tls", p.id);
            let material = crate::tls::load(t).map_err(|e| format!("{what}: {e}"))?;
            let reused = previous.and_then(|s| s.tls.values().find(|c| c.digest == material.digest));
            let http = match reused {
                Some(c) => c.http.clone(),
                None => http_client(clients, Some(&material)).map_err(|e| format!("{what}: {e}"))?,
            };
            tls_files.extend(material.files.iter().cloned());
            tls.insert(p.id.clone(), TlsClient { http, digest: material.digest, not_after: material.not_after });
        }
        let version = fingerprint(cfg, &tls_files)?;
        Ok(Self { providers, prices, tls, tls_files, version })
    }

    pub fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.get(id)
    }

    /// The client of a provider with `tls`; `None` means the shared client.
    pub(crate) fn tls_client(&self, id: &str) -> Option<&TlsClient> {
        self.tls.get(id)
    }

    /// Earliest expiry (Unix seconds) of the CA and client certificates of
    /// a provider with `tls`.
    pub fn tls_not_after(&self, id: &str) -> Option<i64> {
        self.tls.get(id).and_then(|c| c.not_after)
    }

    /// SHA-256 of every TLS file this snapshot was built from.
    pub fn tls_files(&self) -> &BTreeMap<PathBuf, [u8; 32]> {
        &self.tls_files
    }

    /// Providers in id order.
    pub fn providers(&self) -> impl Iterator<Item = &Provider> {
        self.providers.values()
    }

    pub fn prices(&self) -> &PriceTable {
        &self.prices
    }

    /// Identifies the configuration: the first 48 bits of a SHA-256 over
    /// providers, prices and the content of the TLS files. Replicas that
    /// serve the same configuration report the same version.
    pub fn version(&self) -> u64 {
        self.version
    }
}

fn fingerprint(cfg: &LlmConfig, tls_files: &BTreeMap<PathBuf, [u8; 32]>) -> Result<u64, String> {
    let canonical = serde_json::to_vec(&(&cfg.providers, &cfg.pricing)).map_err(|e| format!("llm: {e}"))?;
    let mut h = Sha256::new();
    h.update(&canonical);
    for (path, digest) in tls_files {
        h.update(path.as_os_str().as_encoded_bytes());
        h.update(digest);
    }
    let d = h.finalize();
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

/// Publishes the version and certificate expiries of the snapshot in use.
/// Providers of `previous` that no longer have TLS get NaN, so no stale
/// expiry stays behind until the next restart.
pub(crate) fn publish(s: &ProviderSnapshot, previous: Option<&ProviderSnapshot>) {
    // Exact: versions have 48 bits.
    metrics::gauge!("ocb_config_version").set(s.version as f64);
    for (id, c) in &s.tls {
        let at = c.not_after.map_or(f64::NAN, |t| t as f64);
        metrics::gauge!("ocb_upstream_tls_cert_expiry_timestamp", "provider" => id.clone()).set(at);
    }
    for id in previous.iter().flat_map(|p| p.tls.keys()).filter(|id| !s.tls.contains_key(*id)) {
        metrics::gauge!("ocb_upstream_tls_cert_expiry_timestamp", "provider" => id.clone()).set(f64::NAN);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::config::{ProviderConfig, ProviderTls};
    use broker_core::llm::ProviderKind;
    use std::path::Path;
    use std::time::Duration;

    const CLIENTS: ClientSettings =
        ClientSettings { connect_timeout: Duration::from_secs(1), total_timeout: Duration::from_secs(1) };

    fn config(base_url: &str) -> LlmConfig {
        let mut c = LlmConfig::default();
        c.providers.insert("anthropic".into(), ProviderConfig::new(ProviderKind::Anthropic, base_url));
        c
    }

    fn build(cfg: &LlmConfig) -> ProviderSnapshot {
        ProviderSnapshot::build(cfg, CLIENTS, None).unwrap()
    }

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls").join(name)
    }

    #[test]
    fn version_follows_the_provider_configuration() {
        let a = build(&config("https://a.example"));
        let same = build(&config("https://a.example"));
        let other = build(&config("https://b.example"));
        assert_eq!(a.version(), same.version());
        assert_ne!(a.version(), other.version());
        assert!(a.version() < 1 << 48);
        // Settings outside providers and prices do not change it.
        let mut c = config("https://a.example");
        c.max_concurrent_total = 1;
        assert_eq!(build(&c).version(), a.version());
    }

    #[test]
    fn only_providers_with_tls_get_a_client_of_their_own() {
        let mut c = config("https://api.anthropic.com");
        let mut gw = ProviderConfig::new(ProviderKind::Anthropic, "https://gateway.example");
        gw.tls = Some(ProviderTls {
            ca_file: fixture("ca.pem"),
            client_cert: Some(fixture("client-a.pem")),
            client_key: Some(fixture("client-a.key")),
        });
        c.providers.insert("gateway".into(), gw);
        let s = build(&c);
        assert!(s.tls_client("gateway").is_some());
        assert!(s.tls_client("anthropic").is_none(), "uses the shared client, which has no identity");
        assert_eq!(s.tls_not_after("gateway"), Some(4_904_409_600));
        assert_eq!(s.tls_files().len(), 3);
        // TLS files are part of the version.
        let mut rotated = c.clone();
        let tls = rotated.providers.get_mut("gateway").unwrap().tls.as_mut().unwrap();
        tls.client_cert = Some(fixture("client-b.pem"));
        tls.client_key = Some(fixture("client-b.key"));
        let r = ProviderSnapshot::build(&rotated, CLIENTS, Some(&s)).unwrap();
        assert_ne!(r.version(), s.version());
        assert_eq!(r.tls_not_after("gateway"), Some(4_912_358_400));
        // Unreadable TLS files make the configuration invalid.
        let mut broken = c.clone();
        broken.providers.get_mut("gateway").unwrap().tls.as_mut().unwrap().ca_file = fixture("missing.pem");
        assert!(ProviderSnapshot::build(&broken, CLIENTS, Some(&s)).is_err());
    }

    #[test]
    fn readers_keep_their_snapshot_across_a_swap() {
        let cell = SnapshotCell::new(build(&config("https://a.example")));
        let held = cell.load();
        let old = cell.replace(build(&config("https://b.example")));
        assert!(Arc::ptr_eq(&held, &old));
        assert_eq!(held.provider("anthropic").unwrap().base_url, "https://a.example");
        assert_eq!(cell.load().provider("anthropic").unwrap().base_url, "https://b.example");
    }
}
