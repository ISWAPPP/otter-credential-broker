//! Configuration reload without a restart.
//!
//! Every `reload_interval_secs` the reloader reads the config file and
//! compares a hash of its content with the content it looked at last. The
//! file is read through its path, so the atomic swap of a Kubernetes
//! ConfigMap volume (its `..data` link) is seen; a `subPath` mount is never
//! updated by the kubelet and is not supported. When the content changed,
//! the whole configuration is loaded and validated again, as at start:
//! - it does not load or validate: the running configuration stays
//!   (`invalid`);
//! - a key outside `llm.providers` and `llm.pricing` differs from the
//!   running value: nothing is applied and the keys are logged
//!   (`restart_required`);
//! - otherwise a new provider snapshot replaces the current one (`applied`),
//!   unless it equals the current one (`unchanged`).
//!
//! The TLS files of providers are checked the same way, by content: when
//! one changed (a renewed certificate, say), the snapshot is rebuilt from the
//! running configuration (`applied`), or kept if the new files cannot be
//! used (`invalid`, e.g. a certificate without its matching key).
//!
//! Every outcome is counted in `ocb_config_reload_total{result}`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::config::ServerConfig;
use crate::proxy::LlmProxy;
use crate::tls::{read_file, sha256};

/// What looking at a changed configuration led to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadResult {
    /// New requests use the new providers and prices.
    Applied,
    /// The file changed but its providers and prices did not.
    Unchanged,
    /// The new configuration does not load or validate; the old one stays.
    Invalid,
    /// Keys changed that only take effect at start; the old configuration
    /// stays.
    RestartRequired,
}

impl ReloadResult {
    pub const ALL: [Self; 4] = [Self::Applied, Self::Unchanged, Self::Invalid, Self::RestartRequired];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Unchanged => "unchanged",
            Self::Invalid => "invalid",
            Self::RestartRequired => "restart_required",
        }
    }
}

pub struct Reloader {
    path: Option<PathBuf>,
    proxy: Arc<LlmProxy>,
    /// The configuration in use.
    running: ServerConfig,
    /// Hash of the content looked at last, whether it was applied or not.
    seen: Option<[u8; 32]>,
    /// Whether the file could be read last time; a failure is reported once.
    readable: bool,
    /// The first look usually finds the content loaded at start; that is not
    /// worth a log line or a count.
    first: bool,
    /// TLS files of a change that could not be applied; reported once.
    failed_tls: Option<BTreeMap<PathBuf, Option<[u8; 32]>>>,
}

impl Reloader {
    /// `running` is the configuration the process started with, loaded from
    /// `path` (`None`: no config file, nothing to reload).
    pub fn new(path: Option<PathBuf>, running: ServerConfig, proxy: Arc<LlmProxy>) -> Self {
        for r in ReloadResult::ALL {
            metrics::counter!("ocb_config_reload_total", "result" => r.as_str()).increment(0);
        }
        Self { path, proxy, running, seen: None, readable: true, first: true, failed_tls: None }
    }

    /// Looks at the config file and the TLS files in use once and applies
    /// what changed. `None` when there was nothing new to look at.
    pub fn check(&mut self) -> Option<ReloadResult> {
        self.check_file().or_else(|| self.check_tls())
    }

    fn check_file(&mut self) -> Option<ReloadResult> {
        let path = self.path.as_ref()?;
        let content = match std::fs::read(path) {
            Ok(c) => {
                self.readable = true;
                c
            }
            Err(e) => {
                if !std::mem::replace(&mut self.readable, false) {
                    return None;
                }
                tracing::warn!(error = %e, file = %path.display(), "cannot read the config file; keeping the current configuration");
                return Some(count(ReloadResult::Invalid));
            }
        };
        let hash = sha256(&content);
        if self.seen == Some(hash) {
            return None;
        }
        self.seen = Some(hash);
        let result = self.reload(&content);
        if std::mem::take(&mut self.first) && result == ReloadResult::Unchanged {
            return None;
        }
        Some(count(result))
    }

    fn reload(&mut self, content: &[u8]) -> ReloadResult {
        let file = self.path.as_deref().map(|p| p.display().to_string()).unwrap_or_default();
        let parsed = std::str::from_utf8(content)
            .map_err(|_| "the file is not UTF-8".to_owned())
            .and_then(|text| ServerConfig::parse(text).map_err(|e| e.to_string()));
        let next = match parsed {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, %file, "the changed config file does not load; keeping the current configuration");
                return ReloadResult::Invalid;
            }
        };
        let snapshot = match self.proxy.prepare(&next.llm) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, %file, "the changed configuration is invalid; keeping the current one");
                return ReloadResult::Invalid;
            }
        };
        let keys = match restart_keys(&self.running, &next) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, %file, "the changed configuration cannot be compared; keeping the current one");
                return ReloadResult::Invalid;
            }
        };
        if !keys.is_empty() {
            tracing::warn!(
                keys = %keys.join(", "),
                %file,
                "configuration changed outside llm.providers and llm.pricing; keeping the current one until a restart"
            );
            return ReloadResult::RestartRequired;
        }
        self.running = next;
        let current = self.proxy.snapshot().version();
        if snapshot.version() == current {
            return ReloadResult::Unchanged;
        }
        tracing::info!(
            version = snapshot.version(),
            previous = current,
            providers = snapshot.providers().count(),
            "provider configuration reloaded"
        );
        self.proxy.install(snapshot);
        ReloadResult::Applied
    }

    /// Rebuilds the snapshot from the running configuration when a TLS file
    /// in use has changed.
    fn check_tls(&mut self) -> Option<ReloadResult> {
        let current = self.proxy.snapshot();
        if current.tls_files().is_empty() {
            return None;
        }
        let now: BTreeMap<PathBuf, Option<[u8; 32]>> =
            current.tls_files().keys().map(|p| (p.clone(), read_file(p).ok().map(|c| sha256(c.expose())))).collect();
        if now.iter().all(|(p, h)| h.as_ref() == current.tls_files().get(p)) {
            self.failed_tls = None;
            return None;
        }
        if self.failed_tls.as_ref() == Some(&now) {
            return None;
        }
        let result = match self.proxy.prepare(&self.running.llm) {
            Ok(next) if next.version() == current.version() => ReloadResult::Unchanged,
            Ok(next) => {
                tracing::info!(
                    version = next.version(),
                    previous = current.version(),
                    "TLS files of a provider changed; new requests use them"
                );
                self.failed_tls = None;
                self.proxy.install(next);
                ReloadResult::Applied
            }
            Err(e) => {
                tracing::warn!(error = %e, "TLS files of a provider changed but cannot be used; keeping the current ones");
                self.failed_tls = Some(now);
                ReloadResult::Invalid
            }
        };
        Some(count(result))
    }

    /// Checks every `every` until `stop` is cancelled.
    pub async fn run(mut self, every: Duration, stop: CancellationToken) {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = stop.cancelled() => return,
            }
            // Reading files and setting up clients is blocking work.
            match tokio::task::spawn_blocking(move || {
                self.check();
                self
            })
            .await
            {
                Ok(r) => self = r,
                Err(e) => {
                    tracing::error!(error = %e, "configuration reload failed; no further reloads");
                    return;
                }
            }
        }
    }
}

fn count(r: ReloadResult) -> ReloadResult {
    metrics::counter!("ocb_config_reload_total", "result" => r.as_str()).increment(1);
    r
}

/// Keys outside `llm.providers` and `llm.pricing` whose values differ
/// between `a` and `b` (dotted paths; values are never part of the result).
fn restart_keys(a: &ServerConfig, b: &ServerConfig) -> Result<Vec<String>, String> {
    let fixed = |c: &ServerConfig| -> Result<Value, String> {
        let mut v = serde_json::to_value(c).map_err(|e| e.to_string())?;
        if let Some(llm) = v.get_mut("llm").and_then(Value::as_object_mut) {
            llm.remove("providers");
            llm.remove("pricing");
        }
        Ok(v)
    };
    let mut out = Vec::new();
    diff("", &fixed(a)?, &fixed(b)?, &mut out);
    Ok(out)
}

fn diff(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for key in x.keys().chain(y.keys()).collect::<BTreeSet<_>>() {
                let p = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                diff(&p, x.get(key).unwrap_or(&Value::Null), y.get(key).unwrap_or(&Value::Null), out);
            }
        }
        _ if a != b => out.push(path.to_owned()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn only_keys_outside_providers_and_pricing_need_a_restart() {
        let base = ServerConfig::parse(
            r#"
            [database]
            url = "postgres://broker:secret-password@db/broker"

            [llm.providers.anthropic]
            kind = "anthropic"
            base_url = "https://api.anthropic.com"
            "#,
        )
        .unwrap();
        let mut next = base.clone();
        next.llm.providers.get_mut("anthropic").unwrap().base_url = "https://gateway.example".into();
        next.llm.pricing.clear();
        assert!(restart_keys(&base, &next).unwrap().is_empty());

        next.llm.max_concurrent_total = 1;
        next.http.shutdown_grace_secs = 1;
        next.database.url = Some("postgres://broker:other-password@db/broker".into());
        next.reload_interval_secs = 60;
        let keys = restart_keys(&base, &next).unwrap();
        assert_eq!(
            keys,
            ["database.url", "http.shutdown_grace_secs", "llm.max_concurrent_total", "reload_interval_secs"]
        );
        assert!(!keys.concat().contains("password"), "only key names, never values");
    }
}
