//! Server configuration: defaults <- TOML file <- `OCB_` environment variables
//! (nested keys use `__`, e.g. `OCB_LLM__MAX_DURATION_SECS=600`).
//!
//! Upstream LLM base URLs come only from here; callers can never choose a
//! host. They are validated at startup.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use broker_core::KeeperSettings;
use broker_core::llm::ProviderKind;
use broker_core::llm::pricing::{ModelPrice, PriceTable};
use broker_core::validate;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// LLM proxy (`/llm/*`) and worker endpoint (`/v1/worker/*`). Reached by
    /// agent pods and workers.
    pub listen: SocketAddr,
    /// Admin API (`/v1/admin/*`). Reached only by the platform core.
    pub admin_listen: SocketAddr,
    /// Prometheus metrics. Separate so tenant-labelled metrics are not
    /// readable by agent pods.
    pub metrics_listen: SocketAddr,
    pub database: DatabaseConfig,
    pub kek: KekConfig,
    /// File with `<principal> <token>` lines (tokens >= 32 chars).
    pub admin_tokens_file: PathBuf,
    /// File with the token key (64 hex chars): keys the digests of issued
    /// tokens and the MACs of token rows. Changing it invalidates all tokens.
    pub token_key_file: PathBuf,
    pub http: HttpSettings,
    pub keeper: KeeperSettings,
    pub llm: LlmConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// PostgreSQL URL. Prefer `url_file` (e.g. a mounted Secret) so the
    /// password is neither in the config file nor in the environment.
    pub url: Option<String>,
    pub url_file: Option<PathBuf>,
    pub max_connections: u32,
    pub acquire_timeout_secs: u64,
    /// Apply migrations at startup. Disable when migrations run as a separate
    /// step with a more privileged role (`otter-credential-broker migrate`).
    pub run_migrations: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KekConfig {
    /// Id of the current KEK, stored with every record it wraps.
    pub id: String,
    /// File with the current KEK: 64 hex chars.
    pub file: PathBuf,
    /// Retired KEKs, still used to unwrap records until they are re-wrapped.
    #[serde(default)]
    pub previous: Vec<PreviousKek>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousKek {
    pub id: String,
    pub file: PathBuf,
}

/// HTTP server settings. Request timeout and body limit apply to the admin
/// API and the worker endpoint (the LLM proxy has its own, under `llm`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpSettings {
    pub request_timeout_secs: u64,
    pub body_limit_bytes: usize,
    /// A connection must deliver complete request headers within this time.
    pub header_read_timeout_secs: u64,
    /// Open connections per listener; further clients wait in the backlog.
    pub max_connections: usize,
    /// On shutdown, time given to in-flight requests (including LLM streams)
    /// before they are cut and accounted conservatively.
    pub shutdown_grace_secs: u64,
    /// Use a caller's `traceparent` on the public listener as the parent of
    /// its spans. Off by default: callers there are untrusted, so their trace
    /// context is only recorded as a span link and never reaches audit or
    /// usage rows. (The admin listener always trusts it.)
    pub trust_caller_trace_context: bool,
    /// Failed token checks per client address and minute before further
    /// attempts from that address are refused without a database lookup.
    pub auth_failures_per_minute: u32,
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self {
            request_timeout_secs: 30,
            body_limit_bytes: 256 * 1024,
            header_read_timeout_secs: 10,
            max_connections: 4096,
            shutdown_grace_secs: 300,
            trust_caller_trace_context: false,
            auth_failures_per_minute: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    /// Largest request body forwarded upstream.
    pub max_request_bytes: usize,
    /// Longest time to receive the request body from the caller.
    pub request_read_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    /// Until the upstream response headers arrive.
    pub response_timeout_secs: u64,
    /// Longest pause between two response body chunks.
    pub idle_timeout_secs: u64,
    /// Hard cap on one request including the streamed body.
    pub max_duration_secs: u64,
    /// Upstream error bodies are cut to this size (then scrubbed).
    pub max_error_body_bytes: usize,
    /// JSON (non-streaming) responses up to this size are inspected for usage.
    pub max_buffered_response_bytes: usize,
    /// Requests in flight per LLM token (per replica).
    pub max_concurrent_per_token: u32,
    /// Requests in flight in total (per replica).
    pub max_concurrent_total: u32,
    /// Upstream providers by id. `/llm/anthropic/...` uses the provider with
    /// id `anthropic`; `/llm/openai/<id>/...` uses OpenAI-compatible ones.
    pub providers: BTreeMap<String, ProviderConfig>,
    /// USD per million tokens, per provider and model.
    pub pricing: Vec<ModelPrice>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    /// Base URL, e.g. `https://api.anthropic.com` or `https://api.openai.com/v1`.
    pub base_url: String,
    /// Permit `http://` (local model servers, tests). Off by default.
    #[serde(default)]
    pub allow_http: bool,
    /// Send a W3C `traceparent` upstream.
    #[serde(default = "yes")]
    pub propagate_trace_context: bool,
    /// OpenAI-compatible only: refuse streaming requests that do not ask for
    /// usage (`stream_options.include_usage: true`), since the body is never
    /// modified and usage would otherwise be missing.
    #[serde(default = "yes")]
    pub require_stream_usage: bool,
}

fn yes() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 8080)),
            admin_listen: SocketAddr::from(([0, 0, 0, 0], 8081)),
            metrics_listen: SocketAddr::from(([0, 0, 0, 0], 9090)),
            database: DatabaseConfig {
                url: None,
                url_file: Some(PathBuf::from("/etc/otter-credential-broker/database/url")),
                max_connections: 10,
                acquire_timeout_secs: 5,
                run_migrations: true,
            },
            kek: KekConfig {
                id: "local-1".into(),
                file: PathBuf::from("/etc/otter-credential-broker/kek/current"),
                previous: Vec::new(),
            },
            admin_tokens_file: PathBuf::from("/etc/otter-credential-broker/admin/tokens"),
            token_key_file: PathBuf::from("/etc/otter-credential-broker/kek/token-key"),
            http: HttpSettings::default(),
            keeper: KeeperSettings::default(),
            llm: LlmConfig::default(),
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 16 * 1024 * 1024,
            request_read_timeout_secs: 60,
            connect_timeout_secs: 10,
            response_timeout_secs: 300,
            idle_timeout_secs: 300,
            max_duration_secs: 1800,
            max_error_body_bytes: 64 * 1024,
            max_buffered_response_bytes: 32 * 1024 * 1024,
            max_concurrent_per_token: 16,
            max_concurrent_total: 1024,
            providers: BTreeMap::new(),
            pricing: Vec::new(),
        }
    }
}

const TOP_LEVEL_KEYS: &[&str] = &[
    "listen",
    "admin_listen",
    "metrics_listen",
    "database",
    "kek",
    "admin_tokens_file",
    "token_key_file",
    "http",
    "keeper",
    "llm",
];

impl ServerConfig {
    pub fn load(file: Option<&Path>) -> Result<Self, Box<figment::Error>> {
        let mut fig = Figment::from(Serialized::defaults(Self::default()));
        if let Some(f) = file {
            fig = fig.merge(Toml::file_exact(f));
        }
        // Only known keys: OCB_CONFIG and test variables are not config.
        let env = Env::prefixed("OCB_")
            .filter(|k| TOP_LEVEL_KEYS.iter().any(|t| k.as_str().split("__").next() == Some(*t)))
            .split("__");
        fig.merge(env).extract().map_err(Box::new)
    }
}

/// A provider after validation.
#[derive(Debug, Clone)]
pub struct Provider {
    pub id: String,
    pub kind: ProviderKind,
    /// Without trailing slash.
    pub base_url: String,
    pub propagate_trace_context: bool,
    pub require_stream_usage: bool,
}

impl LlmConfig {
    /// Validates providers and prices. Rejects anything that could let a
    /// caller influence where requests go.
    pub fn validate(&self) -> Result<(BTreeMap<String, Provider>, PriceTable), String> {
        let mut out = BTreeMap::new();
        for (id, p) in &self.providers {
            validate::provider_id(id).map_err(|e| format!("llm.providers.{id}: {e}"))?;
            if p.kind == ProviderKind::Anthropic && id != "anthropic" {
                return Err(format!("llm.providers.{id}: providers of kind anthropic must have the id `anthropic`"));
            }
            let url = reqwest::Url::parse(&p.base_url).map_err(|e| format!("llm.providers.{id}.base_url: {e}"))?;
            match url.scheme() {
                "https" => {}
                "http" if p.allow_http => {}
                _ => return Err(format!("llm.providers.{id}.base_url: must be https (or http with allow_http)")),
            }
            if url.host_str().is_none_or(str::is_empty)
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(format!(
                    "llm.providers.{id}.base_url: must have a host and no credentials, query or fragment"
                ));
            }
            out.insert(
                id.clone(),
                Provider {
                    id: id.clone(),
                    kind: p.kind,
                    base_url: url.as_str().trim_end_matches('/').to_owned(),
                    propagate_trace_context: p.propagate_trace_context,
                    require_stream_usage: p.require_stream_usage,
                },
            );
        }
        let prices = PriceTable::new(self.pricing.clone())?;
        if let Some(unknown) = prices.providers().find(|p| !out.contains_key(*p)) {
            return Err(format!("llm.pricing: unknown provider {unknown}"));
        }
        for (name, v) in [
            ("request_read_timeout_secs", self.request_read_timeout_secs),
            ("connect_timeout_secs", self.connect_timeout_secs),
            ("response_timeout_secs", self.response_timeout_secs),
            ("idle_timeout_secs", self.idle_timeout_secs),
            ("max_duration_secs", self.max_duration_secs),
        ] {
            if v == 0 {
                return Err(format!("llm.{name} must be positive"));
            }
        }
        if self.max_concurrent_per_token == 0 || self.max_concurrent_total == 0 {
            return Err("llm.max_concurrent_per_token and llm.max_concurrent_total must be positive".into());
        }
        Ok((out, prices))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn provider(kind: ProviderKind, base_url: &str) -> ProviderConfig {
        ProviderConfig {
            kind,
            base_url: base_url.into(),
            allow_http: false,
            propagate_trace_context: true,
            require_stream_usage: true,
        }
    }

    #[test]
    fn provider_validation() {
        let mut c = LlmConfig::default();
        c.providers.insert("anthropic".into(), provider(ProviderKind::Anthropic, "https://api.anthropic.com/"));
        c.providers.insert("deepseek".into(), provider(ProviderKind::Openai, "https://api.deepseek.com"));
        let (p, _) = c.validate().unwrap();
        assert_eq!(p["anthropic"].base_url, "https://api.anthropic.com");

        for (id, kind, url) in [
            ("anthropic", ProviderKind::Anthropic, "http://api.anthropic.com"),
            ("x", ProviderKind::Openai, "https://user:pw@host.example"),
            ("x", ProviderKind::Openai, "https://host.example/?a=1"),
            ("x", ProviderKind::Openai, "file:///etc/passwd"),
            ("x", ProviderKind::Anthropic, "https://host.example"),
            ("Bad.Id", ProviderKind::Openai, "https://host.example"),
        ] {
            let mut c = LlmConfig::default();
            c.providers.insert(id.into(), provider(kind, url));
            assert!(c.validate().is_err(), "{id} {url}");
        }
        let mut c = LlmConfig::default();
        let mut local = provider(ProviderKind::Openai, "http://127.0.0.1:8000/v1");
        local.allow_http = true;
        c.providers.insert("local".into(), local);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn defaults_load() {
        let cfg = ServerConfig::load(None).unwrap();
        assert_eq!(cfg.listen.port(), 8080);
        assert_eq!(cfg.admin_listen.port(), 8081);
    }
}
