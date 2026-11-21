//! Library error type. Binaries wrap these with `anyhow`.
//!
//! Messages are shown to API callers, so they never contain secret values or
//! echo caller input that could carry one.

use crate::crypto::CryptoError;
use crate::limits::LimitRefusal;

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("too large: {0}")]
    TooLarge(String),
    /// Missing, unknown, expired, revoked or already used credential. The
    /// message is deliberately generic.
    #[error("invalid or expired token")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// A rate limit without a level: the token's own as the keeper checks
    /// it, or failed token checks from one address. The proxy reports the
    /// token's as a [`BrokerError::Limit`] of the token's level.
    #[error("rate limit exceeded, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    /// The token's budget is used up. The proxy reports it as it is, naming
    /// the token's level.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),
    /// A request refused by a limit, with its level and kind. The proxy
    /// reports every refusal by a rate limit or a cap on requests in flight
    /// this way, the token's own included, and those by a budget of the
    /// tenant or of a provider.
    #[error("{0}")]
    Limit(LimitRefusal),
    #[error("crypto failure")]
    Crypto(#[from] CryptoError),
    #[error("storage failure: {0}")]
    Storage(#[from] sqlx::Error),
    #[error("migration failure: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A write whose commit got no answer, and whose outcome the database
    /// could not tell afterwards: it may or may not have taken effect, so
    /// it must not be retried.
    #[error("outcome of a commit unknown: {0}")]
    CommitUnknown(String),
    #[error("internal error: {0}")]
    Internal(String),
}
