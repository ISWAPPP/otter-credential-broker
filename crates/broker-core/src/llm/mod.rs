//! Provider-independent pieces of the LLM proxy: which upstream endpoints may
//! be called, usage extraction from responses, pricing and scrubbing.

pub mod pricing;
pub mod scrub;
pub mod usage;

use serde::{Deserialize, Serialize};

/// Wire protocol of an upstream provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Anthropic Messages API (`x-api-key`, SSE with `message_start` / `message_delta` usage).
    Anthropic,
    /// OpenAI-compatible Chat Completions API (`Authorization: Bearer`), e.g.
    /// OpenAI, DeepSeek, OpenRouter.
    Openai,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
        }
    }

    /// Upstream endpoints that may be called through the proxy. Anything else
    /// (batches, files, admin APIs, ...) is refused: those would either bypass
    /// usage accounting or expose data unrelated to the agent's job.
    pub fn endpoints(self) -> &'static [Endpoint] {
        match self {
            Self::Anthropic => ANTHROPIC_ENDPOINTS,
            Self::Openai => OPENAI_ENDPOINTS,
        }
    }

    /// Query parameters that may be forwarded. Anything else is refused.
    pub fn allowed_query_keys(self) -> &'static [&'static str] {
        match self {
            // `beta=true` is sent by some SDK versions; the rest page `/v1/models`.
            Self::Anthropic => &["beta", "limit", "after_id", "before_id"],
            Self::Openai => &[],
        }
    }

    /// Request headers forwarded from the caller (everything else is dropped;
    /// authentication is always set by the proxy).
    pub fn forwarded_request_headers(self) -> &'static [&'static str] {
        match self {
            Self::Anthropic => &["content-type", "accept", "anthropic-version", "anthropic-beta"],
            Self::Openai => &["content-type", "accept", "http-referer", "x-title"],
        }
    }

    pub fn find_endpoint(self, method: HttpMethod, path: &str) -> Option<&'static Endpoint> {
        self.endpoints().iter().find(|e| e.method == method && e.path == path)
    }
}

/// Which LLM tokens of a tenant may use a provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAccess {
    /// Every token, unless its `providers` list leaves the provider out.
    #[default]
    Implicit,
    /// Only tokens whose `providers` list names the provider.
    Explicit,
}

impl ProviderAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implicit => "implicit",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// An upstream endpoint, relative to the provider's configured base URL.
#[derive(Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub method: HttpMethod,
    pub path: &'static str,
    /// Generates tokens that cost money (usage is accounted and budgets apply).
    pub billable: bool,
}

const ANTHROPIC_ENDPOINTS: &[Endpoint] = &[
    Endpoint { method: HttpMethod::Post, path: "v1/messages", billable: true },
    Endpoint { method: HttpMethod::Post, path: "v1/messages/count_tokens", billable: false },
    Endpoint { method: HttpMethod::Get, path: "v1/models", billable: false },
];

const OPENAI_ENDPOINTS: &[Endpoint] = &[
    Endpoint { method: HttpMethod::Post, path: "chat/completions", billable: true },
    Endpoint { method: HttpMethod::Get, path: "models", billable: false },
];

/// Name of the secret holding a tenant's API key for a provider. The secret
/// must have kind [`LLM_KEY_KIND`].
pub fn provider_key_secret_name(provider_id: &str) -> String {
    format!("llm.{provider_id}")
}

/// Kind of secrets that hold provider API keys. Secrets of this kind are only
/// ever used by the proxy and are never handed out, not even to workers.
pub const LLM_KEY_KIND: &str = "llm_api_key";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_allowlist() {
        let a = ProviderKind::Anthropic;
        assert!(a.find_endpoint(HttpMethod::Post, "v1/messages").is_some_and(|e| e.billable));
        assert!(a.find_endpoint(HttpMethod::Get, "v1/messages").is_none());
        for p in ["v1/messages/batches", "v1/files", "v1/messages/../files", "/v1/messages", "v1/messages/"] {
            assert!(a.find_endpoint(HttpMethod::Post, p).is_none(), "{p}");
        }
        let o = ProviderKind::Openai;
        assert!(o.find_endpoint(HttpMethod::Post, "chat/completions").is_some());
        assert!(o.find_endpoint(HttpMethod::Post, "v1/chat/completions").is_none());
        assert!(o.find_endpoint(HttpMethod::Post, "files").is_none());
        assert_eq!(provider_key_secret_name("deepseek"), "llm.deepseek");
    }
}
