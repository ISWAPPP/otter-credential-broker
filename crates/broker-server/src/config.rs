//! Server configuration: defaults <- TOML file <- `OCB_` environment variables
//! (nested keys use `__`, e.g. `OCB_LLM__MAX_DURATION_SECS=600`).
//!
//! Upstream LLM base URLs come only from here; callers can never choose a
//! host. They are validated at startup.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use broker_core::KeeperSettings;
use broker_core::llm::pricing::{ModelPrice, PriceTable};
use broker_core::llm::{Endpoint, HttpMethod, ProviderAccess, ProviderKind};
use broker_core::validate;
use figment::Figment;
use figment::providers::{Data, Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

use crate::policy;

/// Provider ids kept free for paths of the broker itself under `/llm/`: `p`,
/// the prefix of the `/llm/p/<id>/...` route, and `limits`, kept for a later
/// endpoint. No route needs them today; see DECISIONS.md, D-018.
pub const RESERVED_PROVIDER_IDS: &[&str] = &["p", "limits"];

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
    /// How often the config file is checked for changes. Changes to
    /// `llm.providers` and `llm.pricing` apply without a restart; other
    /// changes are reported as needing one. 0 turns checking off.
    pub reload_interval_secs: u64,
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
    /// Upstream providers by id. `/llm/p/<id>/...` reaches any of them;
    /// the older routes stay: `/llm/anthropic/...` uses the provider with id
    /// `anthropic`, `/llm/openai/<id>/...` OpenAI-compatible ones.
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
    /// `implicit`: every LLM token of a tenant may use the provider unless
    /// its `providers` list leaves it out. `explicit`: only tokens whose
    /// `providers` list names it.
    #[serde(default)]
    pub access: ProviderAccess,
    /// Endpoints served, by name: a subset of the kind's endpoints
    /// (`messages`, `count_tokens`, `models` for `anthropic`;
    /// `chat_completions`, `models` for `openai`). All of them when left out.
    #[serde(default)]
    pub endpoints: Option<Vec<String>>,
    /// Price this provider's usage with the `[[llm.pricing]]` entries of
    /// another provider of the same kind (e.g. a gateway in front of it).
    /// The provider then has no entries of its own.
    #[serde(default)]
    pub pricing_from: Option<String>,
    /// TLS to the provider with a private CA and, optionally, a client
    /// certificate. The provider gets an HTTP client of its own that trusts
    /// only `ca_file`; providers without `tls` share one client that trusts
    /// the usual public roots and never presents a client certificate.
    #[serde(default)]
    pub tls: Option<ProviderTls>,
    /// Headers passed through by name prefix, beyond the fixed allowlists.
    /// None by default.
    #[serde(default)]
    pub headers: ProviderHeaders,
    /// Checks of the request body. None by default.
    #[serde(default)]
    pub body: ProviderBody,
}

/// Checks of the request body before it goes upstream; the body itself is
/// never changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBody {
    /// Kind `anthropic` only: refuse requests that would have the provider
    /// reach out on its own, that is with a non-empty `mcp_servers` or with
    /// a tool whose `type` is anything but `custom` (web search, web fetch,
    /// code execution and the provider's other tools), unless the type is
    /// in `server_tool_allowlist`.
    #[serde(default)]
    pub deny_server_tools: bool,
    /// Tool types let through all the same, compared exactly, version date
    /// included: `web_search_20250305` does not let `web_search_20260209`
    /// through.
    #[serde(default)]
    pub server_tool_allowlist: Vec<String>,
}

/// Headers a provider passes through besides the fixed allowlists, chosen
/// by the start of their (lowercase) names. Headers that carry credentials,
/// cookies, routing or framing, and headers the broker sets itself, are
/// never passed, whatever the prefixes say; a prefix that could match one
/// is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHeaders {
    /// Caller headers that start with one of these are sent upstream too,
    /// e.g. `["anthropic-"]` for a gateway that needs every header of the
    /// Anthropic SDK.
    #[serde(default)]
    pub request_forward_prefixes: Vec<String>,
    /// Upstream response headers that start with one of these are passed
    /// back to the caller too, e.g. `["anthropic-ratelimit-"]`.
    #[serde(default)]
    pub response_forward_prefixes: Vec<String>,
}

/// TLS files of a provider, all PEM. Their content is checked for changes
/// like the config file (see `reload_interval_secs`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTls {
    /// The CA certificate(s) the provider's server certificate must chain to.
    pub ca_file: PathBuf,
    /// Client certificate (chain) presented to the provider; needs
    /// `client_key`.
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    /// Private key of `client_cert` (PKCS#8, PKCS#1 or SEC1, unencrypted).
    #[serde(default)]
    pub client_key: Option<PathBuf>,
}

impl ProviderTls {
    /// The files named: `ca_file`, then `client_cert` and `client_key` if set.
    pub fn files(&self) -> impl Iterator<Item = &PathBuf> {
        [Some(&self.ca_file), self.client_cert.as_ref(), self.client_key.as_ref()].into_iter().flatten()
    }
}

fn yes() -> bool {
    true
}

impl ProviderConfig {
    /// A provider with every optional setting at its default.
    pub fn new(kind: ProviderKind, base_url: impl Into<String>) -> Self {
        Self {
            kind,
            base_url: base_url.into(),
            allow_http: false,
            propagate_trace_context: true,
            require_stream_usage: true,
            access: ProviderAccess::default(),
            endpoints: None,
            pricing_from: None,
            tls: None,
            headers: ProviderHeaders::default(),
            body: ProviderBody::default(),
        }
    }
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
            reload_interval_secs: 5,
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
    "reload_interval_secs",
    "http",
    "keeper",
    "llm",
];

impl ServerConfig {
    pub fn load(file: Option<&Path>) -> Result<Self, Box<figment::Error>> {
        Self::extract(file.map(Toml::file_exact))
    }

    /// Like [`ServerConfig::load`], with the content of the file given.
    pub fn parse(toml: &str) -> Result<Self, Box<figment::Error>> {
        Self::extract(Some(Toml::string(toml)))
    }

    fn extract(file: Option<Data<Toml>>) -> Result<Self, Box<figment::Error>> {
        let mut fig = Figment::from(Serialized::defaults(Self::default()));
        if let Some(f) = file {
            fig = fig.merge(f);
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
    pub access: ProviderAccess,
    /// The endpoints this provider serves (a subset of its kind's).
    pub endpoints: Vec<&'static Endpoint>,
    /// Provider whose prices apply to this one.
    pub pricing_from: Option<String>,
    pub tls: Option<ProviderTls>,
    pub headers: ProviderHeaders,
    pub body: ProviderBody,
}

impl Provider {
    /// The provider whose `[[llm.pricing]]` entries price this one's usage.
    pub fn price_source(&self) -> &str {
        self.pricing_from.as_deref().unwrap_or(&self.id)
    }

    /// The endpoint at `path` for `method`, if this provider serves it.
    pub fn endpoint(&self, method: HttpMethod, path: &str) -> Option<&'static Endpoint> {
        self.endpoints.iter().copied().find(|e| e.method == method && e.path == path)
    }
}

/// The endpoints named in a provider's configuration; all of its kind's
/// when none are named.
fn provider_endpoints(id: &str, p: &ProviderConfig) -> Result<Vec<&'static Endpoint>, String> {
    let Some(names) = &p.endpoints else { return Ok(p.kind.endpoints().iter().collect()) };
    if names.is_empty() {
        return Err(format!("llm.providers.{id}.endpoints: must not be empty (leave it out to allow all)"));
    }
    let mut out: Vec<&'static Endpoint> = Vec::new();
    for name in names {
        let Some(e) = p.kind.endpoint_named(name) else {
            let known: Vec<&str> = p.kind.endpoints().iter().map(|e| e.name).collect();
            return Err(format!(
                "llm.providers.{id}.endpoints: {name:?} is not an endpoint of kind {}; known: {}",
                p.kind.as_str(),
                known.join(", ")
            ));
        };
        if out.contains(&e) {
            return Err(format!("llm.providers.{id}.endpoints: {name:?} is listed twice"));
        }
        out.push(e);
    }
    Ok(out)
}

impl LlmConfig {
    /// Validates providers and prices. Rejects anything that could let a
    /// caller influence where requests go.
    pub fn validate(&self) -> Result<(BTreeMap<String, Provider>, PriceTable), String> {
        let mut out = BTreeMap::new();
        for (id, p) in &self.providers {
            if RESERVED_PROVIDER_IDS.contains(&id.as_str()) {
                return Err(format!("llm.providers.{id}: this id is reserved"));
            }
            validate::provider_id(id).map_err(|e| format!("llm.providers.{id}: {e}"))?;
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
            if let Some(tls) = &p.tls {
                if url.scheme() != "https" {
                    return Err(format!("llm.providers.{id}.tls: needs an https base_url"));
                }
                if tls.client_cert.is_some() != tls.client_key.is_some() {
                    return Err(format!("llm.providers.{id}.tls: client_cert and client_key go together"));
                }
                if tls.files().any(|f| f.as_os_str().is_empty()) {
                    return Err(format!("llm.providers.{id}.tls: file paths must not be empty"));
                }
            }
            policy::validate_headers(id, &p.headers)?;
            policy::validate_body(id, p.kind, &p.body)?;
            out.insert(
                id.clone(),
                Provider {
                    id: id.clone(),
                    kind: p.kind,
                    base_url: url.as_str().trim_end_matches('/').to_owned(),
                    propagate_trace_context: p.propagate_trace_context,
                    require_stream_usage: p.require_stream_usage,
                    access: p.access,
                    endpoints: provider_endpoints(id, p)?,
                    pricing_from: p.pricing_from.clone(),
                    tls: p.tls.clone(),
                    headers: p.headers.clone(),
                    body: p.body.clone(),
                },
            );
        }
        let prices = PriceTable::new(self.pricing.clone())?;
        if let Some(unknown) = prices.providers().find(|p| !out.contains_key(*p)) {
            return Err(format!("llm.pricing: unknown provider {unknown}"));
        }
        for (id, p) in &self.providers {
            let Some(source) = &p.pricing_from else { continue };
            let what = format!("llm.providers.{id}.pricing_from");
            let Some(s) = self.providers.get(source).filter(|_| source != id) else {
                return Err(format!("{what}: must name another configured provider"));
            };
            if s.kind != p.kind {
                return Err(format!("{what}: {source} is of another kind"));
            }
            if s.pricing_from.is_some() {
                return Err(format!("{what}: {source} takes its prices from elsewhere itself (no chains)"));
            }
            if prices.providers().any(|x| x == id) {
                return Err(format!("llm.pricing: {id} takes its prices from {source}; remove its own entries"));
            }
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
        ProviderConfig::new(kind, base_url)
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
            ("Bad.Id", ProviderKind::Openai, "https://host.example"),
            ("p", ProviderKind::Anthropic, "https://host.example"),
            ("limits", ProviderKind::Openai, "https://host.example"),
            ("_", ProviderKind::Openai, "https://host.example"),
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
    fn several_providers_of_one_kind() {
        let mut c = LlmConfig::default();
        c.providers.insert("anthropic".into(), provider(ProviderKind::Anthropic, "https://api.anthropic.com"));
        c.providers.insert("gateway".into(), provider(ProviderKind::Anthropic, "https://gateway.example:8443/"));
        let (p, _) = c.validate().unwrap();
        assert_eq!(p["gateway"].kind, ProviderKind::Anthropic);
        assert_eq!(p["gateway"].base_url, "https://gateway.example:8443");
    }

    #[test]
    fn provider_access() {
        let cfg = ServerConfig::parse(
            r#"
            [llm.providers.anthropic]
            kind = "anthropic"
            base_url = "https://api.anthropic.com"

            [llm.providers.gateway]
            kind = "anthropic"
            base_url = "https://gateway.example"
            access = "explicit"
            "#,
        )
        .unwrap();
        let (p, _) = cfg.llm.validate().unwrap();
        assert_eq!(p["anthropic"].access, ProviderAccess::Implicit);
        assert_eq!(p["gateway"].access, ProviderAccess::Explicit);
        let bad = "[llm.providers.x]\nkind = \"openai\"\nbase_url = \"https://x.example\"\naccess = \"open\"\n";
        assert!(ServerConfig::parse(bad).is_err());
    }

    #[test]
    fn provider_endpoints() {
        let mut c = LlmConfig::default();
        let mut gw = provider(ProviderKind::Anthropic, "https://gateway.example");
        gw.endpoints = Some(vec!["messages".into(), "count_tokens".into()]);
        c.providers.insert("gateway".into(), gw);
        c.providers.insert("deepseek".into(), provider(ProviderKind::Openai, "https://api.deepseek.com"));
        let (p, _) = c.validate().unwrap();
        let names = |id: &str| p[id].endpoints.iter().map(|e| e.name).collect::<Vec<_>>();
        assert_eq!(names("gateway"), ["messages", "count_tokens"]);
        assert_eq!(names("deepseek"), ["chat_completions", "models"]);
        assert!(p["gateway"].endpoint(HttpMethod::Post, "v1/messages").is_some());
        assert!(p["gateway"].endpoint(HttpMethod::Get, "v1/models").is_none());

        for bad in [vec![], vec!["chat_completions"], vec!["v1/messages"], vec!["messages", "messages"]] {
            let mut c = LlmConfig::default();
            let mut gw = provider(ProviderKind::Anthropic, "https://gateway.example");
            gw.endpoints = Some(bad.iter().map(|s| s.to_string()).collect());
            c.providers.insert("gateway".into(), gw);
            assert!(c.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn pricing_from() {
        let price = |provider: &str| ModelPrice {
            provider: provider.into(),
            model: "m".into(),
            input: 1.0,
            output: 2.0,
            cache_read: None,
            cache_write: None,
            cache_write_1h: None,
            free: false,
        };
        let config = |pricing_from: &[(&str, &str)], pricing: Vec<ModelPrice>| {
            let mut c = LlmConfig::default();
            for id in ["anthropic", "gateway", "gateway-2"] {
                c.providers.insert(id.into(), provider(ProviderKind::Anthropic, "https://host.example"));
            }
            c.providers.insert("openai".into(), provider(ProviderKind::Openai, "https://api.openai.com/v1"));
            for (id, from) in pricing_from {
                c.providers.get_mut(*id).unwrap().pricing_from = Some((*from).into());
            }
            c.pricing = pricing;
            c.validate()
        };
        let (p, prices) =
            config(&[("gateway", "anthropic"), ("gateway-2", "anthropic")], vec![price("anthropic")]).unwrap();
        assert_eq!(p["gateway"].price_source(), "anthropic");
        assert_eq!(p["anthropic"].price_source(), "anthropic");
        assert_eq!(prices.lookup(p["gateway"].price_source(), "m").unwrap().output, 2.0);
        // Without prices of its own the source is still fine (no prices then).
        assert!(config(&[("gateway", "anthropic")], vec![]).is_ok());

        for (bad, pricing) in [
            (vec![("gateway", "missing")], vec![]),
            (vec![("gateway", "gateway")], vec![]),
            (vec![("gateway", "openai")], vec![]),
            (vec![("gateway", "anthropic"), ("anthropic", "gateway-2")], vec![]),
            (vec![("gateway", "gateway-2"), ("gateway-2", "anthropic")], vec![]),
            (vec![("gateway", "anthropic")], vec![price("anthropic"), price("gateway")]),
        ] {
            assert!(config(&bad, pricing).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn provider_tls() {
        let cfg = ServerConfig::parse(
            r#"
            [llm.providers.gateway]
            kind = "anthropic"
            base_url = "https://gateway.example:8443"
            tls = { ca_file = "/tls/ca.crt", client_cert = "/tls/tls.crt", client_key = "/tls/tls.key" }

            [llm.providers.internal]
            kind = "openai"
            base_url = "https://models.example/v1"
            tls = { ca_file = "/tls/ca.crt" }
            "#,
        )
        .unwrap();
        let (p, _) = cfg.llm.validate().unwrap();
        assert_eq!(p["gateway"].tls.as_ref().unwrap().client_key.as_deref(), Some(Path::new("/tls/tls.key")));
        assert!(p["internal"].tls.as_ref().unwrap().client_cert.is_none());

        let tls = |ca: &str, cert: Option<&str>, key: Option<&str>| ProviderTls {
            ca_file: ca.into(),
            client_cert: cert.map(Into::into),
            client_key: key.map(Into::into),
        };
        for (url, bad) in [
            ("https://gateway.example", tls("/tls/ca.crt", Some("/tls/tls.crt"), None)),
            ("https://gateway.example", tls("/tls/ca.crt", None, Some("/tls/tls.key"))),
            ("https://gateway.example", tls("", None, None)),
            ("http://gateway.example", tls("/tls/ca.crt", None, None)),
        ] {
            let mut c = LlmConfig::default();
            let mut gw = provider(ProviderKind::Anthropic, url);
            gw.allow_http = true;
            gw.tls = Some(bad.clone());
            c.providers.insert("gateway".into(), gw);
            assert!(c.validate().is_err(), "{url} {bad:?}");
        }
        let unknown = "[llm.providers.x]\nkind = \"openai\"\nbase_url = \"https://x.example\"\ntls = { ca_file = \"/a\", verify = false }\n";
        assert!(ServerConfig::parse(unknown).is_err());
    }

    #[test]
    fn provider_headers() {
        let cfg = ServerConfig::parse(
            r#"
            [llm.providers.gateway]
            kind = "anthropic"
            base_url = "https://gateway.example"
            headers = { request_forward_prefixes = ["anthropic-"], response_forward_prefixes = ["anthropic-ratelimit-"] }

            [llm.providers.local]
            kind = "openai"
            base_url = "https://models.example/v1"
            headers = { response_forward_prefixes = ["x-ratelimit-"] }

            [llm.providers.deepseek]
            kind = "openai"
            base_url = "https://api.deepseek.com"
            "#,
        )
        .unwrap();
        let (p, _) = cfg.llm.validate().unwrap();
        assert_eq!(p["gateway"].headers.request_forward_prefixes, ["anthropic-"]);
        assert_eq!(p["gateway"].headers.response_forward_prefixes, ["anthropic-ratelimit-"]);
        assert!(p["local"].headers.request_forward_prefixes.is_empty());
        assert_eq!(p["deepseek"].headers, ProviderHeaders::default());

        let with = |headers: &str| {
            format!(
                "[llm.providers.x]\nkind = \"openai\"\nbase_url = \"https://x.example\"\nheaders = {{ {headers} }}\n"
            )
        };
        // Prefixes only; any other key is refused.
        for unknown in ["forward = [\"x-app\"]", "request_forward_prefixes = \"anthropic-\""] {
            assert!(ServerConfig::parse(&with(unknown)).is_err(), "{unknown}");
        }
        // A prefix that could match a header never forwarded makes the
        // configuration invalid.
        let wide = ServerConfig::parse(&with("request_forward_prefixes = [\"x-\"]")).unwrap();
        let e = wide.llm.validate().unwrap_err();
        assert!(e.starts_with("llm.providers.x.headers.request_forward_prefixes: "), "{e}");
    }

    #[test]
    fn provider_body() {
        let cfg = ServerConfig::parse(
            r#"
            [llm.providers.gateway]
            kind = "anthropic"
            base_url = "https://gateway.example"
            body = { deny_server_tools = true, server_tool_allowlist = ["web_search_20250305"] }

            [llm.providers.anthropic]
            kind = "anthropic"
            base_url = "https://api.anthropic.com"
            "#,
        )
        .unwrap();
        let (p, _) = cfg.llm.validate().unwrap();
        assert!(p["gateway"].body.deny_server_tools);
        assert_eq!(p["gateway"].body.server_tool_allowlist, ["web_search_20250305"]);
        assert_eq!(p["anthropic"].body, ProviderBody::default());

        let with = |kind: &str, body: &str| {
            format!("[llm.providers.x]\nkind = \"{kind}\"\nbase_url = \"https://x.example\"\nbody = {{ {body} }}\n")
        };
        assert!(ServerConfig::parse(&with("anthropic", "deny_mcp = true")).is_err(), "unknown key");
        let valid = |kind: &str, body: &str| ServerConfig::parse(&with(kind, body)).unwrap().llm.validate().is_ok();
        assert!(valid("openai", "deny_server_tools = false"));
        // Only the anthropic kind checks bodies; an OpenAI-compatible
        // provider that asks for it is refused rather than left unchecked.
        assert!(!valid("openai", "deny_server_tools = true"));
        assert!(!valid("anthropic", "server_tool_allowlist = [\"web_search_20250305\"]"));
    }

    #[test]
    fn defaults_load() {
        let cfg = ServerConfig::load(None).unwrap();
        assert_eq!(cfg.listen.port(), 8080);
        assert_eq!(cfg.admin_listen.port(), 8081);
    }

    /// The TOML embedded in the ConfigMap of the Kubernetes manifest.
    fn manifest_config() -> String {
        let yaml = include_str!("../../../deploy/k8s/broker.yaml");
        let (_, rest) = yaml.split_once("config.toml: |\n").unwrap();
        let lines: Vec<&str> = rest
            .lines()
            .take_while(|l| l.is_empty() || l.starts_with("    "))
            .map(|l| l.strip_prefix("    ").unwrap_or(l))
            .collect();
        lines.join("\n")
    }

    #[test]
    fn shipped_configs_load_as_they_are() {
        for (name, text) in [
            ("deploy/k8s/broker.yaml", manifest_config()),
            ("config/example.toml", include_str!("../../../config/example.toml").to_owned()),
            ("config/dev.toml", include_str!("../../../config/dev.toml").to_owned()),
        ] {
            let cfg = ServerConfig::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let (providers, _) = cfg.llm.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(providers["anthropic"].kind, ProviderKind::Anthropic, "{name}");
            assert_eq!(providers["deepseek"].kind, ProviderKind::Openai, "{name}");
        }
        assert_eq!(ServerConfig::parse(&manifest_config()).unwrap().database.max_connections, 10);
    }
}
