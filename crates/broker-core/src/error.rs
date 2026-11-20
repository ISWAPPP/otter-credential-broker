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
    #[error("rate limit exceeded, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("too many requests in flight: {0}")]
    TooManyInFlight(String),
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),
    /// A limit of the tenant or of a provider (the token's own limits use
    /// the three variants above).
    #[error("{0}")]
    Limit(LimitRefusal),
    #[error("crypto failure")]
    Crypto(#[from] CryptoError),
    #[error("storage failure: {0}")]
    Storage(#[from] sqlx::Error),
    #[error("migration failure: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("internal error: {0}")]
    Internal(String),
}
