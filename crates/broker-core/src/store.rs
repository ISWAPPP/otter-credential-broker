//! PostgreSQL persistence. Queries are checked at runtime, so the build does
//! not need a live database.
//!
//! Every query on tenant-owned data filters on `tenant_id`; the only lookups
//! that are not tenant-scoped are token lookups by digest, which is how the
//! tenant of a token is discovered in the first place.

use std::time::Duration;

use serde::Serialize;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{FromRow, Postgres, Transaction};

use crate::clock::Timestamp;
use crate::crypto::SealedRecord;
use crate::error::BrokerError;
use crate::limits::{LimitLevel, Limits, Period, Reservation, Spend};
use crate::secret::Secret;
use crate::tokens::TokenDigest;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Secret metadata as returned by the admin API. Never contains the value.
#[derive(Debug, Clone, Serialize)]
pub struct SecretMeta {
    pub tenant: String,
    pub name: String,
    pub kind: String,
    pub metadata: serde_json::Value,
    pub version: i64,
    pub kek_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub created_by: String,
    pub updated_by: String,
}

#[derive(FromRow)]
struct SecretMetaRow {
    tenant_id: String,
    name: String,
    kind: String,
    metadata: String,
    version: i64,
    kek_id: String,
    created_at: i64,
    updated_at: i64,
    created_by: String,
    updated_by: String,
}

impl From<SecretMetaRow> for SecretMeta {
    fn from(r: SecretMetaRow) -> Self {
        Self {
            tenant: r.tenant_id,
            name: r.name,
            kind: r.kind,
            metadata: serde_json::from_str(&r.metadata).unwrap_or_else(|_| serde_json::json!({})),
            version: r.version,
            kek_id: r.kek_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            created_by: r.created_by,
            updated_by: r.updated_by,
        }
    }
}

// Column lists are macros so that every query stays a compile-time literal
// (no SQL is ever assembled at runtime).
macro_rules! secret_meta_cols {
    () => {
        "tenant_id, name, kind, metadata::text AS metadata, version, kek_id, created_at, updated_at, created_by, updated_by"
    };
}

#[derive(FromRow)]
struct SealedRow {
    id: String,
    tenant_id: String,
    name: String,
    kind: String,
    kek_id: String,
    wrapped_dek: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// A stored secret with its sealed value (still encrypted).
#[derive(Debug, Clone)]
pub struct SealedSecret {
    pub id: String,
    pub tenant: String,
    pub name: String,
    pub kind: String,
    pub record: SealedRecord,
}

impl From<SealedRow> for SealedSecret {
    fn from(r: SealedRow) -> Self {
        Self {
            id: r.id,
            tenant: r.tenant_id,
            name: r.name,
            kind: r.kind,
            record: SealedRecord { kek_id: r.kek_id, wrapped_dek: r.wrapped_dek, ciphertext: r.ciphertext },
        }
    }
}

macro_rules! sealed_cols {
    () => {
        "id, tenant_id, name, kind, kek_id, wrapped_dek, ciphertext"
    };
}

pub struct NewSecretRow<'a> {
    pub id: &'a str,
    pub tenant: &'a str,
    pub name: &'a str,
    pub kind: &'a str,
    pub metadata_json: &'a str,
    pub record: &'a SealedRecord,
    pub now: Timestamp,
    pub actor: &'a str,
}

/// LLM token as shown to admin callers. Never contains the token itself.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct LlmTokenInfo {
    pub id: String,
    #[sqlx(rename = "tenant_id")]
    pub tenant: String,
    pub run_id: Option<String>,
    pub label: Option<String>,
    pub providers: Option<Vec<String>>,
    pub budget_micro_usd: Option<i64>,
    pub budget_tokens: Option<i64>,
    pub spent_micro_usd: i64,
    pub spent_tokens: i64,
    pub request_count: i64,
    pub rate_limit_per_minute: i32,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub created_by: String,
}

macro_rules! llm_token_cols {
    () => {
        "id, tenant_id, run_id, label, providers, budget_micro_usd, budget_tokens, spent_micro_usd, spent_tokens, \
         request_count, rate_limit_per_minute, created_at, expires_at, revoked_at, last_used_at, created_by"
    };
}

pub struct NewLlmTokenRow<'a> {
    pub id: &'a str,
    pub digest: &'a TokenDigest,
    pub auth_mac: &'a [u8],
    pub tenant: &'a str,
    pub run_id: Option<&'a str>,
    pub label: Option<&'a str>,
    pub providers: Option<&'a [String]>,
    pub budget_micro_usd: Option<i64>,
    pub budget_tokens: Option<i64>,
    pub rate_limit_per_minute: i32,
    pub trace_parent: Option<&'a str>,
    pub now: Timestamp,
    pub expires_at: Timestamp,
    pub actor: &'a str,
}

/// What the proxy learns from a valid LLM token (one atomic query also counts
/// the request against the token's rate-limit window), with the limits of
/// its tenant and the tenant's spend in the current day and month.
#[derive(Debug, Clone, FromRow)]
pub struct AuthorizedRow {
    #[sqlx(flatten)]
    pub token: LlmGrantRow,
    pub tenant_rpm: Option<i32>,
    pub tenant_concurrent: Option<i32>,
    pub tenant_tokens_day: Option<i64>,
    pub tenant_tokens_month: Option<i64>,
    pub tenant_micro_usd_day: Option<i64>,
    pub tenant_micro_usd_month: Option<i64>,
    pub day_spent_tokens: Option<i64>,
    pub day_spent_micro_usd: Option<i64>,
    pub day_reserved_tokens: Option<i64>,
    pub day_reserved_micro_usd: Option<i64>,
    pub month_spent_tokens: Option<i64>,
    pub month_spent_micro_usd: Option<i64>,
    pub month_reserved_tokens: Option<i64>,
    pub month_reserved_micro_usd: Option<i64>,
}

impl AuthorizedRow {
    pub fn tenant_limits(&self) -> Limits {
        Limits::from_stored(
            self.tenant_rpm,
            self.tenant_concurrent,
            [self.tenant_tokens_day, self.tenant_tokens_month],
            [self.tenant_micro_usd_day, self.tenant_micro_usd_month],
        )
    }

    /// The tenant's spend in the current period; `None` when it has no row.
    pub fn tenant_spend(&self, p: Period) -> Option<Spend> {
        let (spent_tokens, spent_micro_usd, reserved_tokens, reserved_micro_usd) = match p {
            Period::Day => (
                self.day_spent_tokens?,
                self.day_spent_micro_usd?,
                self.day_reserved_tokens?,
                self.day_reserved_micro_usd?,
            ),
            Period::Month => (
                self.month_spent_tokens?,
                self.month_spent_micro_usd?,
                self.month_reserved_tokens?,
                self.month_reserved_micro_usd?,
            ),
        };
        Some(Spend { spent_tokens, spent_micro_usd, reserved_tokens, reserved_micro_usd })
    }
}

/// The token part of [`AuthorizedRow`].
#[derive(Debug, Clone, FromRow)]
pub struct LlmGrantRow {
    pub id: String,
    pub tenant_id: String,
    pub run_id: Option<String>,
    pub providers: Option<Vec<String>>,
    pub budget_micro_usd: Option<i64>,
    pub budget_tokens: Option<i64>,
    pub spent_micro_usd: i64,
    pub spent_tokens: i64,
    pub rate_limit_per_minute: i32,
    pub rl_count: i32,
    pub trace_parent: Option<String>,
    pub expires_at: Timestamp,
    pub auth_mac: Vec<u8>,
}

/// A valid LLM token as it is, read without counting a request.
#[derive(Debug, Clone, FromRow)]
pub struct LlmTokenState {
    pub id: String,
    pub tenant_id: String,
    pub label: Option<String>,
    pub providers: Option<Vec<String>>,
    pub budget_micro_usd: Option<i64>,
    pub budget_tokens: Option<i64>,
    pub spent_micro_usd: i64,
    pub spent_tokens: i64,
    pub rate_limit_per_minute: i32,
    pub rl_window: i64,
    pub rl_count: i32,
    pub expires_at: Timestamp,
    pub auth_mac: Vec<u8>,
}

/// Limits of a tenant as stored.
#[derive(Debug, Clone, FromRow)]
pub struct TenantLimitsRow {
    pub tenant_id: String,
    pub rpm: Option<i32>,
    pub concurrent: Option<i32>,
    pub budget_tokens_day: Option<i64>,
    pub budget_tokens_month: Option<i64>,
    pub budget_micro_usd_day: Option<i64>,
    pub budget_micro_usd_month: Option<i64>,
    pub updated_at: Timestamp,
    pub updated_by: String,
}

impl TenantLimitsRow {
    pub fn limits(&self) -> Limits {
        Limits::from_stored(
            self.rpm,
            self.concurrent,
            [self.budget_tokens_day, self.budget_tokens_month],
            [self.budget_micro_usd_day, self.budget_micro_usd_month],
        )
    }
}

macro_rules! tenant_limits_cols {
    () => {
        "tenant_id, rpm, concurrent, budget_tokens_day, budget_tokens_month, budget_micro_usd_day, \
         budget_micro_usd_month, updated_at, updated_by"
    };
}

/// A tenant or a provider, as the levels above a token key their rows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LimitScope {
    pub level: LimitLevel,
    /// Empty on the global level.
    pub tenant: String,
    /// Empty on the tenant level.
    pub provider: String,
}

impl LimitScope {
    pub fn tenant(tenant: &str) -> Self {
        Self { level: LimitLevel::Tenant, tenant: tenant.to_owned(), provider: String::new() }
    }

    pub fn global(provider: &str) -> Self {
        Self { level: LimitLevel::Global, tenant: String::new(), provider: provider.to_owned() }
    }
}

/// The current request window of a tenant or provider.
#[derive(Debug, Clone, FromRow)]
pub struct RpmRow {
    pub level: String,
    pub tenant_id: String,
    pub provider: String,
    pub rl_window: i64,
    pub rl_count: i32,
}

/// Spend of a tenant or provider in one period.
#[derive(Debug, Clone, FromRow)]
pub struct SpendRow {
    pub level: String,
    pub tenant_id: String,
    pub provider: String,
    pub period_kind: String,
    pub period_start: Timestamp,
    pub spent_tokens: i64,
    pub spent_micro_usd: i64,
    pub reserved_tokens: i64,
    pub reserved_micro_usd: i64,
    pub limit_tokens: Option<i64>,
    pub limit_micro_usd: Option<i64>,
}

impl SpendRow {
    pub fn spend(&self) -> Spend {
        Spend {
            spent_tokens: self.spent_tokens,
            spent_micro_usd: self.spent_micro_usd,
            reserved_tokens: self.reserved_tokens,
            reserved_micro_usd: self.reserved_micro_usd,
        }
    }

    pub fn is(&self, scope: &LimitScope, period: Period) -> bool {
        self.level == scope.level.as_str()
            && self.tenant_id == scope.tenant
            && self.provider == scope.provider
            && self.period_kind == period.as_str()
    }
}

macro_rules! spend_cols {
    () => {
        "s.level, s.tenant_id, s.provider, s.period_kind, s.period_start, s.spent_tokens, s.spent_micro_usd, \
         s.reserved_tokens, s.reserved_micro_usd, s.limit_tokens, s.limit_micro_usd"
    };
}

/// A reservation to take: `tokens` and `micro_usd` on the row of `scope`
/// for `period` starting at `period_start`, unless what the row has spent
/// and reserved already reaches one of its limits.
#[derive(Debug, Clone)]
pub struct BudgetClaim {
    pub scope: LimitScope,
    pub period: Period,
    pub period_start: Timestamp,
    pub limit_tokens: Option<i64>,
    pub limit_micro_usd: Option<i64>,
    pub tokens: i64,
    pub micro_usd: i64,
}

/// Result of counting a request in the windows of its tenant and provider.
#[derive(Debug, Clone, Copy, FromRow)]
pub struct RequestCounts {
    /// The tenant has no request limit, or the request fits in its window.
    pub tenant_passed: bool,
    pub tenant_count: Option<i32>,
    /// Like `tenant_passed`, for the provider; only counted when the tenant
    /// passed.
    pub global_passed: bool,
    pub global_count: Option<i32>,
}

/// A live labelled token, by tenant and label (the latest expiry).
#[derive(Debug, Clone, FromRow)]
pub struct LabelledTokenExpiry {
    pub tenant_id: String,
    pub label: String,
    pub expires_at: Timestamp,
}

/// The order in which rows of `limit_spend` are locked wherever they
/// change, so that two transactions never wait for each other: a tenant's
/// rows before a provider's (every tenant shares those, so they are taken
/// last and held for the shortest time), then by key. Matches the
/// `ORDER BY` of [`Store::settle_tx`].
fn lock_order<'a>(
    level: LimitLevel,
    tenant: &'a str,
    provider: &'a str,
    period: Period,
    start: Timestamp,
) -> (bool, &'a [u8], &'a [u8], &'static str, Timestamp) {
    (level != LimitLevel::Tenant, tenant.as_bytes(), provider.as_bytes(), period.as_str(), start)
}

/// Column arrays of reservations, in lock order.
struct ReservationArrays {
    level: Vec<&'static str>,
    tenant: Vec<String>,
    provider: Vec<String>,
    period: Vec<&'static str>,
    start: Vec<i64>,
    tokens: Vec<i64>,
    micro_usd: Vec<i64>,
}

impl ReservationArrays {
    fn new(reservations: &[Reservation]) -> Self {
        let mut sorted: Vec<&Reservation> = reservations.iter().collect();
        sorted.sort_by(|a, b| {
            lock_order(a.level, &a.tenant, &a.provider, a.period, a.period_start).cmp(&lock_order(
                b.level,
                &b.tenant,
                &b.provider,
                b.period,
                b.period_start,
            ))
        });
        Self {
            level: sorted.iter().map(|r| r.level.as_str()).collect(),
            tenant: sorted.iter().map(|r| r.tenant.clone()).collect(),
            provider: sorted.iter().map(|r| r.provider.clone()).collect(),
            period: sorted.iter().map(|r| r.period.as_str()).collect(),
            start: sorted.iter().map(|r| r.period_start).collect(),
            tokens: sorted.iter().map(|r| r.tokens).collect(),
            micro_usd: sorted.iter().map(|r| r.micro_usd).collect(),
        }
    }
}

/// Job token as shown to admin callers.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct JobTokenInfo {
    pub id: String,
    #[sqlx(rename = "tenant_id")]
    pub tenant: String,
    pub job_id: String,
    pub secret_names: Vec<String>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
    pub created_by: String,
}

macro_rules! job_token_cols {
    () => {
        "id, tenant_id, job_id, secret_names, created_at, expires_at, used_at, revoked_at, created_by"
    };
}

/// A job token row as seen at redemption (with the fields needed to verify
/// its integrity).
#[derive(Debug, Clone, FromRow)]
pub struct RedeemedJobRow {
    pub id: String,
    pub tenant_id: String,
    pub job_id: String,
    pub secret_names: Vec<String>,
    pub expires_at: Timestamp,
    pub trace_parent: Option<String>,
    pub auth_mac: Vec<u8>,
}

pub struct NewJobTokenRow<'a> {
    pub id: &'a str,
    pub digest: &'a TokenDigest,
    pub auth_mac: &'a [u8],
    pub trace_parent: Option<&'a str>,
    pub tenant: &'a str,
    pub job_id: &'a str,
    pub secret_names: &'a [String],
    pub now: Timestamp,
    pub expires_at: Timestamp,
    pub actor: &'a str,
}

/// One accounted LLM request.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct UsageEntry {
    pub id: i64,
    pub ts: Timestamp,
    pub token_id: String,
    #[sqlx(rename = "tenant_id")]
    pub tenant: String,
    pub run_id: Option<String>,
    pub provider: String,
    pub endpoint: String,
    pub model: Option<String>,
    pub response_model: Option<String>,
    pub status: i32,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub cost_micro_usd: i64,
    pub usage_source: String,
    pub duration_ms: i64,
    pub ttft_ms: Option<i64>,
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewUsageRow {
    pub ts: Timestamp,
    pub token_id: String,
    pub tenant: String,
    pub run_id: Option<String>,
    pub provider: String,
    pub endpoint: String,
    pub model: Option<String>,
    pub response_model: Option<String>,
    pub status: i32,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub cost_micro_usd: i64,
    pub usage_source: &'static str,
    pub duration_ms: i64,
    pub ttft_ms: Option<i64>,
    pub trace_id: Option<String>,
    /// Tokens counted against the token budget (all input incl. cache, plus output).
    pub billable_tokens: i64,
}

#[derive(Debug, Clone, Default)]
pub struct UsageFilter {
    pub run_id: Option<String>,
    pub token_id: Option<String>,
    pub limit: i64,
}

/// An audit event. `detail` is free text that must never contain secrets.
#[derive(Debug, Clone, Default)]
pub struct AuditEvent<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub tenant: Option<&'a str>,
    pub secret_name: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: Timestamp,
    pub actor: String,
    pub action: String,
    #[sqlx(rename = "tenant_id")]
    pub tenant: Option<String>,
    pub secret_name: Option<String>,
    pub purpose: Option<String>,
    pub trace_id: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.is_unique_violation())
}

impl Store {
    /// Connects to PostgreSQL. `url` is a libpq-style URL; it usually carries a
    /// password, so it is passed as a [`Secret`] and never logged.
    #[tracing::instrument(name = "db.connect", level = "debug", skip_all)]
    pub async fn connect(
        url: &Secret<String>,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, BrokerError> {
        let opts: PgConnectOptions = url.expose().parse()?;
        Self::connect_with(opts, max_connections, acquire_timeout).await
    }

    pub async fn connect_with(
        opts: PgConnectOptions,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, BrokerError> {
        let opts = opts.application_name("otter-credential-broker");
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(acquire_timeout)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    /// Applies pending migrations. Safe to run from several replicas at once
    /// (sqlx takes an advisory lock).
    #[tracing::instrument(name = "db.migrate", level = "debug", skip_all)]
    pub async fn migrate(&self) -> Result<(), BrokerError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[tracing::instrument(name = "db.ping", level = "debug", skip_all)]
    pub async fn ping(&self) -> Result<(), BrokerError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    async fn audit_tx(
        tx: &mut Transaction<'_, Postgres>,
        now: Timestamp,
        ev: &AuditEvent<'_>,
    ) -> Result<(), BrokerError> {
        sqlx::query(
            "INSERT INTO audit_log (ts, actor, action, tenant_id, secret_name, purpose, trace_id, detail)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(now)
        .bind(ev.actor)
        .bind(ev.action)
        .bind(ev.tenant)
        .bind(ev.secret_name)
        .bind(ev.purpose)
        .bind(ev.trace_id)
        .bind(ev.detail.as_deref())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Writes an audit row on its own (used before every decrypt).
    #[tracing::instrument(name = "db.audit", level = "debug", skip_all)]
    pub async fn audit(&self, now: Timestamp, ev: &AuditEvent<'_>) -> Result<(), BrokerError> {
        let mut tx = self.pool.begin().await?;
        Self::audit_tx(&mut tx, now, ev).await?;
        tx.commit().await?;
        Ok(())
    }

    #[tracing::instrument(name = "db.list_audit", level = "debug", skip_all)]
    pub async fn list_audit(&self, tenant: Option<&str>, limit: i64) -> Result<Vec<AuditEntry>, BrokerError> {
        Ok(sqlx::query_as(
            "SELECT id, ts, actor, action, tenant_id, secret_name, purpose, trace_id, detail FROM audit_log
             WHERE ($1::text IS NULL OR tenant_id = $1) ORDER BY id DESC LIMIT $2",
        )
        .bind(tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    // ---------- secrets ----------

    #[tracing::instrument(name = "db.insert_secret", level = "debug", skip_all)]
    pub async fn insert_secret(
        &self,
        row: &NewSecretRow<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<SecretMeta, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let res: Result<SecretMetaRow, sqlx::Error> = sqlx::query_as(concat!(
            "INSERT INTO secrets (id, tenant_id, name, kind, metadata, version, kek_id, wrapped_dek, ciphertext,
                                  created_at, updated_at, created_by, updated_by)
             VALUES ($1, $2, $3, $4, $5::jsonb, 1, $6, $7, $8, $9, $9, $10, $10)
             RETURNING ",
            secret_meta_cols!()
        ))
        .bind(row.id)
        .bind(row.tenant)
        .bind(row.name)
        .bind(row.kind)
        .bind(row.metadata_json)
        .bind(&row.record.kek_id)
        .bind(&row.record.wrapped_dek)
        .bind(&row.record.ciphertext)
        .bind(row.now)
        .bind(row.actor)
        .fetch_one(&mut *tx)
        .await;
        let meta = match res {
            Ok(m) => m,
            Err(e) if is_unique_violation(&e) => {
                return Err(BrokerError::Conflict("a secret with this name already exists".into()));
            }
            Err(e) => return Err(e.into()),
        };
        Self::audit_tx(&mut tx, row.now, audit).await?;
        tx.commit().await?;
        Ok(meta.into())
    }

    /// Replaces the value (bumping `version`) and/or the metadata of a secret.
    #[tracing::instrument(name = "db.update_secret", level = "debug", skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn update_secret(
        &self,
        tenant: &str,
        name: &str,
        record: Option<&SealedRecord>,
        metadata_json: Option<&str>,
        now: Timestamp,
        actor: &str,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<SecretMeta>, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<SecretMetaRow> = sqlx::query_as(concat!(
            "UPDATE secrets SET
                kek_id      = COALESCE($3, kek_id),
                wrapped_dek = COALESCE($4, wrapped_dek),
                ciphertext  = COALESCE($5, ciphertext),
                version     = CASE WHEN $5::bytea IS NULL THEN version ELSE version + 1 END,
                metadata    = COALESCE($6::jsonb, metadata),
                updated_at  = $7,
                updated_by  = $8
             WHERE tenant_id = $1 AND name = $2
             RETURNING ",
            secret_meta_cols!()
        ))
        .bind(tenant)
        .bind(name)
        .bind(record.map(|r| r.kek_id.as_str()))
        .bind(record.map(|r| r.wrapped_dek.as_slice()))
        .bind(record.map(|r| r.ciphertext.as_slice()))
        .bind(metadata_json)
        .bind(now)
        .bind(actor)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else { return Ok(None) };
        Self::audit_tx(&mut tx, now, audit).await?;
        tx.commit().await?;
        Ok(Some(row.into()))
    }

    #[tracing::instrument(name = "db.delete_secret", level = "debug", skip_all)]
    pub async fn delete_secret(
        &self,
        tenant: &str,
        name: &str,
        now: Timestamp,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let r = sqlx::query("DELETE FROM secrets WHERE tenant_id = $1 AND name = $2")
            .bind(tenant)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        Self::audit_tx(&mut tx, now, audit).await?;
        tx.commit().await?;
        Ok(true)
    }

    #[tracing::instrument(name = "db.get_secret_meta", level = "debug", skip_all)]
    pub async fn get_secret_meta(&self, tenant: &str, name: &str) -> Result<Option<SecretMeta>, BrokerError> {
        let row: Option<SecretMetaRow> =
            sqlx::query_as(concat!("SELECT ", secret_meta_cols!(), " FROM secrets WHERE tenant_id = $1 AND name = $2"))
                .bind(tenant)
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(Into::into))
    }

    #[tracing::instrument(name = "db.list_secrets", level = "debug", skip_all)]
    pub async fn list_secrets(&self, tenant: &str) -> Result<Vec<SecretMeta>, BrokerError> {
        let rows: Vec<SecretMetaRow> =
            sqlx::query_as(concat!("SELECT ", secret_meta_cols!(), " FROM secrets WHERE tenant_id = $1 ORDER BY name"))
                .bind(tenant)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(name = "db.get_sealed", level = "debug", skip_all)]
    pub async fn get_sealed(&self, tenant: &str, name: &str) -> Result<Option<SealedSecret>, BrokerError> {
        let row: Option<SealedRow> =
            sqlx::query_as(concat!("SELECT ", sealed_cols!(), " FROM secrets WHERE tenant_id = $1 AND name = $2"))
                .bind(tenant)
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(Into::into))
    }

    #[tracing::instrument(name = "db.get_sealed_many", level = "debug", skip_all)]
    pub async fn get_sealed_many(&self, tenant: &str, names: &[String]) -> Result<Vec<SealedSecret>, BrokerError> {
        let rows: Vec<SealedRow> = sqlx::query_as(concat!(
            "SELECT ",
            sealed_cols!(),
            " FROM secrets WHERE tenant_id = $1 AND name = ANY($2) ORDER BY name"
        ))
        .bind(tenant)
        .bind(names)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Secrets wrapped by a KEK other than `current_kek_id`.
    #[tracing::instrument(name = "db.secrets_to_rewrap", level = "debug", skip_all)]
    pub async fn secrets_to_rewrap(&self, current_kek_id: &str, limit: i64) -> Result<Vec<SealedSecret>, BrokerError> {
        let rows: Vec<SealedRow> =
            sqlx::query_as(concat!("SELECT ", sealed_cols!(), " FROM secrets WHERE kek_id <> $1 ORDER BY id LIMIT $2"))
                .bind(current_kek_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(name = "db.count_to_rewrap", level = "debug", skip_all)]
    pub async fn count_to_rewrap(&self, current_kek_id: &str) -> Result<i64, BrokerError> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secrets WHERE kek_id <> $1")
            .bind(current_kek_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    /// Stores a re-wrapped DEK, only if the record was not changed meanwhile.
    #[tracing::instrument(name = "db.store_rewrap", level = "debug", skip_all)]
    pub async fn store_rewrap(
        &self,
        id: &str,
        old_kek_id: &str,
        old_wrapped: &[u8],
        new: &SealedRecord,
    ) -> Result<bool, BrokerError> {
        let r = sqlx::query(
            "UPDATE secrets SET kek_id = $3, wrapped_dek = $4
             WHERE id = $1 AND kek_id = $2 AND wrapped_dek = $5 AND ciphertext = $6",
        )
        .bind(id)
        .bind(old_kek_id)
        .bind(&new.kek_id)
        .bind(&new.wrapped_dek)
        .bind(old_wrapped)
        .bind(&new.ciphertext)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---------- LLM tokens ----------

    #[tracing::instrument(name = "db.insert_llm_token", level = "debug", skip_all)]
    pub async fn insert_llm_token(
        &self,
        row: &NewLlmTokenRow<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<LlmTokenInfo, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let info: LlmTokenInfo = sqlx::query_as(concat!(
            "INSERT INTO llm_tokens (id, token_hash, auth_mac, tenant_id, run_id, label, providers, budget_micro_usd,
                                     budget_tokens, rate_limit_per_minute, trace_parent, created_at, expires_at,
                                     created_by)
             VALUES ($1, $2, $14, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING ",
            llm_token_cols!()
        ))
        .bind(row.id)
        .bind(row.digest.as_slice())
        .bind(row.tenant)
        .bind(row.run_id)
        .bind(row.label)
        .bind(row.providers)
        .bind(row.budget_micro_usd)
        .bind(row.budget_tokens)
        .bind(row.rate_limit_per_minute)
        .bind(row.trace_parent)
        .bind(row.now)
        .bind(row.expires_at)
        .bind(row.actor)
        .bind(row.auth_mac)
        .fetch_one(&mut *tx)
        .await?;
        Self::audit_tx(&mut tx, row.now, audit).await?;
        tx.commit().await?;
        Ok(info)
    }

    #[tracing::instrument(name = "db.list_llm_tokens", level = "debug", skip_all)]
    pub async fn list_llm_tokens(&self, tenant: &str, limit: i64) -> Result<Vec<LlmTokenInfo>, BrokerError> {
        Ok(sqlx::query_as(concat!(
            "SELECT ",
            llm_token_cols!(),
            " FROM llm_tokens WHERE tenant_id = $1 ORDER BY created_at DESC, id LIMIT $2"
        ))
        .bind(tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    #[tracing::instrument(name = "db.get_llm_token", level = "debug", skip_all)]
    pub async fn get_llm_token(&self, tenant: &str, id: &str) -> Result<Option<LlmTokenInfo>, BrokerError> {
        Ok(sqlx::query_as(concat!("SELECT ", llm_token_cols!(), " FROM llm_tokens WHERE tenant_id = $1 AND id = $2"))
            .bind(tenant)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Revokes a token of this tenant. Returns false if no such token exists in
    /// the tenant. Revoking twice keeps the first revocation time.
    #[tracing::instrument(name = "db.revoke_llm_token", level = "debug", skip_all)]
    pub async fn revoke_llm_token(
        &self,
        tenant: &str,
        id: &str,
        now: Timestamp,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let r =
            sqlx::query("UPDATE llm_tokens SET revoked_at = COALESCE(revoked_at, $3) WHERE tenant_id = $1 AND id = $2")
                .bind(tenant)
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        Self::audit_tx(&mut tx, now, audit).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Validates an LLM token and counts the request in the token's fixed
    /// one-minute rate-limit window, in a single atomic statement (correct
    /// across replicas). The same statement reads the limits of the token's
    /// tenant and its spend in the day and month starting at `day_start`
    /// and `month_start`. Returns `None` for unknown, revoked or expired
    /// tokens.
    #[tracing::instrument(name = "db.authorize_llm", level = "debug", skip_all)]
    pub async fn authorize_llm(
        &self,
        digest: &TokenDigest,
        now: Timestamp,
        window: i64,
        day_start: Timestamp,
        month_start: Timestamp,
    ) -> Result<Option<AuthorizedRow>, BrokerError> {
        Ok(sqlx::query_as(
            "WITH t AS (
                UPDATE llm_tokens SET
                    rl_count  = CASE WHEN rl_window = $2 THEN LEAST(rl_count, 2147483646) + 1 ELSE 1 END,
                    rl_window = $2
                WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $3
                RETURNING id, tenant_id, run_id, providers, budget_micro_usd, budget_tokens, spent_micro_usd,
                          spent_tokens, rate_limit_per_minute, rl_count, trace_parent, expires_at, auth_mac
             )
             SELECT t.id, t.tenant_id, t.run_id, t.providers, t.budget_micro_usd, t.budget_tokens,
                    t.spent_micro_usd, t.spent_tokens, t.rate_limit_per_minute, t.rl_count, t.trace_parent,
                    t.expires_at, t.auth_mac,
                    l.rpm AS tenant_rpm, l.concurrent AS tenant_concurrent,
                    l.budget_tokens_day AS tenant_tokens_day, l.budget_tokens_month AS tenant_tokens_month,
                    l.budget_micro_usd_day AS tenant_micro_usd_day,
                    l.budget_micro_usd_month AS tenant_micro_usd_month,
                    d.spent_tokens AS day_spent_tokens, d.spent_micro_usd AS day_spent_micro_usd,
                    d.reserved_tokens AS day_reserved_tokens, d.reserved_micro_usd AS day_reserved_micro_usd,
                    m.spent_tokens AS month_spent_tokens, m.spent_micro_usd AS month_spent_micro_usd,
                    m.reserved_tokens AS month_reserved_tokens, m.reserved_micro_usd AS month_reserved_micro_usd
             FROM t
             LEFT JOIN tenant_limits l ON l.tenant_id = t.tenant_id
             LEFT JOIN limit_spend d ON d.level = 'tenant' AND d.tenant_id = t.tenant_id AND d.provider = ''
                                    AND d.period_kind = 'day' AND d.period_start = $4
             LEFT JOIN limit_spend m ON m.level = 'tenant' AND m.tenant_id = t.tenant_id AND m.provider = ''
                                    AND m.period_kind = 'month' AND m.period_start = $5",
        )
        .bind(digest.as_slice())
        .bind(window)
        .bind(now)
        .bind(day_start)
        .bind(month_start)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Reads a valid LLM token without counting a request. Returns `None`
    /// for unknown, revoked or expired tokens.
    #[tracing::instrument(name = "db.find_llm_token", level = "debug", skip_all)]
    pub async fn find_llm_token(
        &self,
        digest: &TokenDigest,
        now: Timestamp,
    ) -> Result<Option<LlmTokenState>, BrokerError> {
        Ok(sqlx::query_as(
            "SELECT id, tenant_id, label, providers, budget_micro_usd, budget_tokens, spent_micro_usd, spent_tokens,
                    rate_limit_per_minute, rl_window, rl_count, expires_at, auth_mac
             FROM llm_tokens WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
        )
        .bind(digest.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Post-accounting: adds the request's cost and tokens to its token and
    /// writes the usage row, atomically.
    pub async fn record_usage(&self, u: &NewUsageRow) -> Result<(), BrokerError> {
        self.record_usage_settling(u, &[]).await
    }

    /// Like [`Store::record_usage`], and in the same transaction settles the
    /// request's reservations: each is released, and the request's cost and
    /// tokens are added to the spend of the period it was reserved in. Any
    /// error but [`BrokerError::CommitUnknown`] means nothing was written,
    /// and the call may be repeated: a commit without an answer is looked up
    /// before an error is returned.
    #[tracing::instrument(name = "db.record_usage", level = "debug", skip_all)]
    pub async fn record_usage_settling(&self, u: &NewUsageRow, settle: &[Reservation]) -> Result<(), BrokerError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE llm_tokens SET
                spent_micro_usd = LEAST(spent_micro_usd::numeric + $2, 9223372036854775807)::bigint,
                spent_tokens    = LEAST(spent_tokens::numeric + $3, 9223372036854775807)::bigint,
                request_count   = LEAST(request_count::numeric + 1, 9223372036854775807)::bigint,
                last_used_at    = $4
             WHERE id = $1",
        )
        .bind(&u.token_id)
        .bind(u.cost_micro_usd)
        .bind(u.billable_tokens)
        .bind(u.ts)
        .execute(&mut *tx)
        .await?;
        let xid: String = sqlx::query_scalar(
            "INSERT INTO llm_usage (ts, token_id, tenant_id, run_id, provider, endpoint, model, status, input_tokens,
                                    output_tokens, cache_read_tokens, cache_write_tokens, cost_micro_usd,
                                    usage_source, duration_ms, ttft_ms, trace_id, response_model)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
             RETURNING pg_current_xact_id()::text",
        )
        .bind(u.ts)
        .bind(&u.token_id)
        .bind(&u.tenant)
        .bind(u.run_id.as_deref())
        .bind(&u.provider)
        .bind(&u.endpoint)
        .bind(u.model.as_deref())
        .bind(u.status)
        .bind(u.input_tokens)
        .bind(u.output_tokens)
        .bind(u.cache_read_tokens)
        .bind(u.cache_write_tokens)
        .bind(u.cost_micro_usd)
        .bind(u.usage_source)
        .bind(u.duration_ms)
        .bind(u.ttft_ms)
        .bind(u.trace_id.as_deref())
        .bind(u.response_model.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        // Last, so the budget rows, a provider's shared by every tenant, are
        // held until the commit only.
        if !settle.is_empty() {
            Self::settle_tx(&mut tx, settle, u.billable_tokens, u.cost_micro_usd).await?;
        }
        self.commit_accounting(tx, &xid).await
    }

    /// Commits a transaction of accounting whose id is `xid`. A commit that
    /// fails without an answer, the connection lost, may still have taken
    /// effect, and a caller that repeats the write would then add usage and
    /// give back reservations twice. So its outcome is asked of PostgreSQL,
    /// which keeps the status of recent transactions (`pg_xact_status`),
    /// waiting a little while it is still running: `Ok` once it took effect,
    /// the commit's error once it did not, and
    /// [`BrokerError::CommitUnknown`] when that cannot be told.
    async fn commit_accounting(&self, tx: Transaction<'_, Postgres>, xid: &str) -> Result<(), BrokerError> {
        let Err(e) = tx.commit().await else { return Ok(()) };
        for wait_ms in [0, 50, 200, 500] {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            match self.transaction_committed(xid).await {
                Ok(Some(true)) => return Ok(()),
                Ok(Some(false)) => return Err(e.into()),
                Ok(None) | Err(_) => {}
            }
        }
        Err(BrokerError::CommitUnknown(e.to_string()))
    }

    /// Whether the transaction `xid` (as `pg_current_xact_id()` gave it)
    /// was committed: `None` while it runs, or once PostgreSQL no longer
    /// keeps its status.
    #[tracing::instrument(name = "db.transaction_committed", level = "debug", skip_all)]
    pub async fn transaction_committed(&self, xid: &str) -> Result<Option<bool>, BrokerError> {
        let status: Option<String> =
            sqlx::query_scalar("SELECT pg_xact_status($1::xid8)").bind(xid).fetch_one(&self.pool).await?;
        Ok(match status.as_deref() {
            Some("committed") => Some(true),
            Some("aborted") => Some(false),
            _ => None,
        })
    }

    #[tracing::instrument(name = "db.list_usage", level = "debug", skip_all)]
    pub async fn list_usage(&self, tenant: &str, f: &UsageFilter) -> Result<Vec<UsageEntry>, BrokerError> {
        Ok(sqlx::query_as(
            "SELECT id, ts, token_id, tenant_id, run_id, provider, endpoint, model, response_model, status, input_tokens,
                    output_tokens, cache_read_tokens, cache_write_tokens, cost_micro_usd, usage_source, duration_ms,
                    ttft_ms, trace_id
             FROM llm_usage
             WHERE tenant_id = $1 AND ($2::text IS NULL OR run_id = $2) AND ($3::text IS NULL OR token_id = $3)
             ORDER BY id DESC LIMIT $4",
        )
        .bind(tenant)
        .bind(f.run_id.as_deref())
        .bind(f.token_id.as_deref())
        .bind(f.limit)
        .fetch_all(&self.pool)
        .await?)
    }

    // ---------- job tokens ----------

    #[tracing::instrument(name = "db.insert_job_token", level = "debug", skip_all)]
    pub async fn insert_job_token(
        &self,
        row: &NewJobTokenRow<'_>,
        audit: &AuditEvent<'_>,
    ) -> Result<JobTokenInfo, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let info: JobTokenInfo = sqlx::query_as(concat!(
            "INSERT INTO job_tokens (id, token_hash, auth_mac, trace_parent, tenant_id, job_id, secret_names,
                                     created_at, expires_at, created_by)
             VALUES ($1, $2, $9, $10, $3, $4, $5, $6, $7, $8)
             RETURNING ",
            job_token_cols!()
        ))
        .bind(row.id)
        .bind(row.digest.as_slice())
        .bind(row.tenant)
        .bind(row.job_id)
        .bind(row.secret_names)
        .bind(row.now)
        .bind(row.expires_at)
        .bind(row.actor)
        .bind(row.auth_mac)
        .bind(row.trace_parent)
        .fetch_one(&mut *tx)
        .await?;
        Self::audit_tx(&mut tx, row.now, audit).await?;
        tx.commit().await?;
        Ok(info)
    }

    #[tracing::instrument(name = "db.list_job_tokens", level = "debug", skip_all)]
    pub async fn list_job_tokens(&self, tenant: &str, limit: i64) -> Result<Vec<JobTokenInfo>, BrokerError> {
        Ok(sqlx::query_as(concat!(
            "SELECT ",
            job_token_cols!(),
            " FROM job_tokens WHERE tenant_id = $1 ORDER BY created_at DESC, id LIMIT $2"
        ))
        .bind(tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    #[tracing::instrument(name = "db.revoke_job_token", level = "debug", skip_all)]
    pub async fn revoke_job_token(
        &self,
        tenant: &str,
        id: &str,
        now: Timestamp,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let r =
            sqlx::query("UPDATE job_tokens SET revoked_at = COALESCE(revoked_at, $3) WHERE tenant_id = $1 AND id = $2")
                .bind(tenant)
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        Self::audit_tx(&mut tx, now, audit).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Marks a job token used and returns it, in one atomic statement: of any
    /// number of concurrent redemptions (on any replica) exactly one succeeds.
    #[tracing::instrument(name = "db.redeem_job_token", level = "debug", skip_all)]
    pub async fn redeem_job_token(
        &self,
        digest: &TokenDigest,
        now: Timestamp,
    ) -> Result<Option<RedeemedJobRow>, BrokerError> {
        Ok(sqlx::query_as(
            "UPDATE job_tokens SET used_at = $2
             WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
             RETURNING id, tenant_id, job_id, secret_names, expires_at, trace_parent, auth_mac",
        )
        .bind(digest.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?)
    }

    // ---------- limits of tenants and providers ----------

    #[tracing::instrument(name = "db.set_tenant_limits", level = "debug", skip_all)]
    pub async fn set_tenant_limits(
        &self,
        tenant: &str,
        limits: &Limits,
        now: Timestamp,
        actor: &str,
        audit: &AuditEvent<'_>,
    ) -> Result<Option<TenantLimitsRow>, BrokerError> {
        let mut tx = self.pool.begin().await?;
        let row = if limits.is_empty() {
            sqlx::query("DELETE FROM tenant_limits WHERE tenant_id = $1").bind(tenant).execute(&mut *tx).await?;
            None
        } else {
            let rpm = limits.rpm.map(|r| i32::try_from(r).unwrap_or(i32::MAX));
            let concurrent = limits.concurrent.map(|c| i32::try_from(c).unwrap_or(i32::MAX));
            Some(
                sqlx::query_as(concat!(
                    "INSERT INTO tenant_limits (tenant_id, rpm, concurrent, budget_tokens_day, budget_tokens_month,
                                                budget_micro_usd_day, budget_micro_usd_month, updated_at, updated_by)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     ON CONFLICT (tenant_id) DO UPDATE SET
                        rpm = EXCLUDED.rpm, concurrent = EXCLUDED.concurrent,
                        budget_tokens_day = EXCLUDED.budget_tokens_day,
                        budget_tokens_month = EXCLUDED.budget_tokens_month,
                        budget_micro_usd_day = EXCLUDED.budget_micro_usd_day,
                        budget_micro_usd_month = EXCLUDED.budget_micro_usd_month,
                        updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
                     RETURNING ",
                    tenant_limits_cols!()
                ))
                .bind(tenant)
                .bind(rpm)
                .bind(concurrent)
                .bind(limits.tokens(Period::Day))
                .bind(limits.tokens(Period::Month))
                .bind(limits.micro_usd(Period::Day))
                .bind(limits.micro_usd(Period::Month))
                .bind(now)
                .bind(actor)
                .fetch_one(&mut *tx)
                .await?,
            )
        };
        Self::audit_tx(&mut tx, now, audit).await?;
        tx.commit().await?;
        Ok(row)
    }

    #[tracing::instrument(name = "db.get_tenant_limits", level = "debug", skip_all)]
    pub async fn get_tenant_limits(&self, tenant: &str) -> Result<Option<TenantLimitsRow>, BrokerError> {
        Ok(sqlx::query_as(concat!("SELECT ", tenant_limits_cols!(), " FROM tenant_limits WHERE tenant_id = $1"))
            .bind(tenant)
            .fetch_optional(&self.pool)
            .await?)
    }

    #[tracing::instrument(name = "db.list_tenant_limits", level = "debug", skip_all)]
    pub async fn list_tenant_limits(&self) -> Result<Vec<TenantLimitsRow>, BrokerError> {
        Ok(sqlx::query_as(concat!("SELECT ", tenant_limits_cols!(), " FROM tenant_limits ORDER BY tenant_id"))
            .fetch_all(&self.pool)
            .await?)
    }

    /// Counts a request in the one-minute `window` of its tenant and then
    /// of its provider, in one statement: the provider's window only counts
    /// the request if the tenant's let it through, and neither counts it
    /// past its limit. A level without a limit (`None`) passes and keeps no
    /// window.
    #[tracing::instrument(name = "db.count_requests", level = "debug", skip_all)]
    pub async fn count_requests(
        &self,
        tenant: &str,
        provider: &str,
        window: i64,
        tenant_rpm: Option<i32>,
        global_rpm: Option<i32>,
    ) -> Result<RequestCounts, BrokerError> {
        // A window older than the one in the row (a replica whose clock is
        // behind) counts into the row's.
        Ok(sqlx::query_as(
            "WITH ten AS (
                INSERT INTO limit_rpm AS r (level, tenant_id, provider, rl_window, rl_count)
                SELECT 'tenant', $1, '', $3, 1 WHERE $4::int IS NOT NULL
                ON CONFLICT (level, tenant_id, provider) DO UPDATE SET
                    rl_count  = CASE WHEN r.rl_window >= EXCLUDED.rl_window THEN r.rl_count + 1 ELSE 1 END,
                    rl_window = GREATEST(r.rl_window, EXCLUDED.rl_window)
                WHERE r.rl_window < EXCLUDED.rl_window OR r.rl_count < $4::int
                RETURNING r.rl_count
             ),
             ten_ok AS (
                SELECT 1 FROM ten UNION ALL SELECT 1 WHERE $4::int IS NULL
             ),
             glob AS (
                INSERT INTO limit_rpm AS r (level, tenant_id, provider, rl_window, rl_count)
                SELECT 'global', '', $2, $3, 1 WHERE $5::int IS NOT NULL AND EXISTS (SELECT 1 FROM ten_ok)
                ON CONFLICT (level, tenant_id, provider) DO UPDATE SET
                    rl_count  = CASE WHEN r.rl_window >= EXCLUDED.rl_window THEN r.rl_count + 1 ELSE 1 END,
                    rl_window = GREATEST(r.rl_window, EXCLUDED.rl_window)
                WHERE r.rl_window < EXCLUDED.rl_window OR r.rl_count < $5::int
                RETURNING r.rl_count
             )
             SELECT EXISTS (SELECT 1 FROM ten_ok) AS tenant_passed,
                    (SELECT rl_count FROM ten) AS tenant_count,
                    ($5::int IS NULL OR EXISTS (SELECT 1 FROM glob)) AS global_passed,
                    (SELECT rl_count FROM glob) AS global_count",
        )
        .bind(tenant)
        .bind(provider)
        .bind(window)
        .bind(tenant_rpm)
        .bind(global_rpm)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Takes every claim or none, in one transaction. A claim passes while
    /// what its row has spent and reserved is below each of its limits
    /// (also when the claim itself would cross one); a limit of 0 lets
    /// nothing pass. Returns the rows as they are after reserving, or, when
    /// a claim did not pass, the indexes of the claims that did not and the
    /// rows as they were.
    #[tracing::instrument(name = "db.reserve", level = "debug", skip_all)]
    pub async fn reserve(&self, claims: &[BudgetClaim]) -> Result<Result<Vec<SpendRow>, ReserveDenied>, BrokerError> {
        // The statement takes the rows in the order of its input.
        let mut sorted: Vec<&BudgetClaim> = claims.iter().collect();
        sorted.sort_by(|a, b| {
            lock_order(a.scope.level, &a.scope.tenant, &a.scope.provider, a.period, a.period_start).cmp(&lock_order(
                b.scope.level,
                &b.scope.tenant,
                &b.scope.provider,
                b.period,
                b.period_start,
            ))
        });
        let levels: Vec<&str> = sorted.iter().map(|c| c.scope.level.as_str()).collect();
        let tenants: Vec<&str> = sorted.iter().map(|c| c.scope.tenant.as_str()).collect();
        let providers: Vec<&str> = sorted.iter().map(|c| c.scope.provider.as_str()).collect();
        let periods: Vec<&str> = sorted.iter().map(|c| c.period.as_str()).collect();
        let starts: Vec<i64> = sorted.iter().map(|c| c.period_start).collect();
        let limit_tokens: Vec<Option<i64>> = sorted.iter().map(|c| c.limit_tokens).collect();
        let limit_usd: Vec<Option<i64>> = sorted.iter().map(|c| c.limit_micro_usd).collect();
        let tokens: Vec<i64> = sorted.iter().map(|c| c.tokens.max(0)).collect();
        let usd: Vec<i64> = sorted.iter().map(|c| c.micro_usd.max(0)).collect();

        let mut tx = self.pool.begin().await?;
        let taken: Vec<SpendRow> = sqlx::query_as(concat!(
            "INSERT INTO limit_spend AS s (level, tenant_id, provider, period_kind, period_start, limit_tokens,
                                           limit_micro_usd, reserved_tokens, reserved_micro_usd)
             SELECT r.level, r.tenant_id, r.provider, r.period_kind, r.period_start, r.limit_tokens,
                    r.limit_micro_usd, r.reserved_tokens, r.reserved_micro_usd
             FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[],
                         $8::bigint[], $9::bigint[])
                  AS r(level, tenant_id, provider, period_kind, period_start, limit_tokens, limit_micro_usd,
                       reserved_tokens, reserved_micro_usd)
             WHERE (r.limit_tokens IS NULL OR r.limit_tokens > 0)
               AND (r.limit_micro_usd IS NULL OR r.limit_micro_usd > 0)
             ON CONFLICT (level, tenant_id, provider, period_kind, period_start) DO UPDATE SET
                reserved_tokens    = LEAST(s.reserved_tokens::numeric + EXCLUDED.reserved_tokens,
                                           9223372036854775807)::bigint,
                reserved_micro_usd = LEAST(s.reserved_micro_usd::numeric + EXCLUDED.reserved_micro_usd,
                                           9223372036854775807)::bigint,
                limit_tokens       = EXCLUDED.limit_tokens,
                limit_micro_usd    = EXCLUDED.limit_micro_usd
             WHERE (EXCLUDED.limit_tokens IS NULL
                    OR s.spent_tokens::numeric + s.reserved_tokens < EXCLUDED.limit_tokens)
               AND (EXCLUDED.limit_micro_usd IS NULL
                    OR s.spent_micro_usd::numeric + s.reserved_micro_usd < EXCLUDED.limit_micro_usd)
             RETURNING ",
            spend_cols!()
        ))
        .bind(&levels)
        .bind(&tenants)
        .bind(&providers)
        .bind(&periods)
        .bind(&starts)
        .bind(&limit_tokens)
        .bind(&limit_usd)
        .bind(&tokens)
        .bind(&usd)
        .fetch_all(&mut *tx)
        .await?;
        let refused: Vec<usize> =
            (0..claims.len()).filter(|i| !taken.iter().any(|r| r.is(&claims[*i].scope, claims[*i].period))).collect();
        if refused.is_empty() {
            tx.commit().await?;
            return Ok(Ok(taken));
        }
        tx.rollback().await?;
        let rows = self.spend_rows_of(claims).await?;
        Ok(Err(ReserveDenied { refused, rows }))
    }

    /// The rows the claims would reserve on, as they are.
    async fn spend_rows_of(&self, claims: &[BudgetClaim]) -> Result<Vec<SpendRow>, BrokerError> {
        let levels: Vec<&str> = claims.iter().map(|c| c.scope.level.as_str()).collect();
        let tenants: Vec<&str> = claims.iter().map(|c| c.scope.tenant.as_str()).collect();
        let providers: Vec<&str> = claims.iter().map(|c| c.scope.provider.as_str()).collect();
        let periods: Vec<&str> = claims.iter().map(|c| c.period.as_str()).collect();
        let starts: Vec<i64> = claims.iter().map(|c| c.period_start).collect();
        Ok(sqlx::query_as(concat!(
            "SELECT ",
            spend_cols!(),
            " FROM limit_spend s
              JOIN unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[])
                   AS k(level, tenant_id, provider, period_kind, period_start)
                ON s.level = k.level AND s.tenant_id = k.tenant_id AND s.provider = k.provider
               AND s.period_kind = k.period_kind AND s.period_start = k.period_start"
        ))
        .bind(&levels)
        .bind(&tenants)
        .bind(&providers)
        .bind(&periods)
        .bind(&starts)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Gives back reservations of requests that ended before they were
    /// sent upstream. Any error but [`BrokerError::CommitUnknown`] means
    /// nothing was given back, and the call may be repeated.
    #[tracing::instrument(name = "db.release", level = "debug", skip_all)]
    pub async fn release(&self, reservations: &[Reservation]) -> Result<(), BrokerError> {
        if reservations.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        let xid: String = sqlx::query_scalar("SELECT pg_current_xact_id()::text").fetch_one(&mut *tx).await?;
        Self::settle_tx(&mut tx, reservations, 0, 0).await?;
        self.commit_accounting(tx, &xid).await
    }

    /// Releases `reservations` and adds `tokens` and `micro_usd` to the
    /// spend of each of their periods. The rows are locked first, in lock
    /// order (see [`lock_order`]).
    async fn settle_tx(
        tx: &mut Transaction<'_, Postgres>,
        reservations: &[Reservation],
        tokens: i64,
        micro_usd: i64,
    ) -> Result<(), BrokerError> {
        let a = ReservationArrays::new(reservations);
        sqlx::query(
            "SELECT 1 FROM limit_spend s
             JOIN unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[])
                  AS k(level, tenant_id, provider, period_kind, period_start)
               ON s.level = k.level AND s.tenant_id = k.tenant_id AND s.provider = k.provider
              AND s.period_kind = k.period_kind AND s.period_start = k.period_start
             ORDER BY s.level <> 'tenant', s.tenant_id COLLATE \"C\", s.provider COLLATE \"C\",
                      s.period_kind COLLATE \"C\", s.period_start
             FOR UPDATE OF s",
        )
        .bind(&a.level)
        .bind(&a.tenant)
        .bind(&a.provider)
        .bind(&a.period)
        .bind(&a.start)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE limit_spend AS s SET
                reserved_tokens    = GREATEST(s.reserved_tokens - r.tokens, 0),
                reserved_micro_usd = GREATEST(s.reserved_micro_usd - r.micro_usd, 0),
                spent_tokens       = LEAST(s.spent_tokens::numeric + $8, 9223372036854775807)::bigint,
                spent_micro_usd    = LEAST(s.spent_micro_usd::numeric + $9, 9223372036854775807)::bigint
             FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[])
                  AS r(level, tenant_id, provider, period_kind, period_start, tokens, micro_usd)
             WHERE s.level = r.level AND s.tenant_id = r.tenant_id AND s.provider = r.provider
               AND s.period_kind = r.period_kind AND s.period_start = r.period_start",
        )
        .bind(&a.level)
        .bind(&a.tenant)
        .bind(&a.provider)
        .bind(&a.period)
        .bind(&a.start)
        .bind(&a.tokens)
        .bind(&a.micro_usd)
        .bind(tokens.max(0))
        .bind(micro_usd.max(0))
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// The request windows and the spend in the day and month starting at
    /// `day_start` and `month_start` of the given tenants and providers.
    /// Levels without a row have nothing counted yet.
    #[tracing::instrument(name = "db.limit_usage", level = "debug", skip_all)]
    pub async fn limit_usage(
        &self,
        scopes: &[LimitScope],
        day_start: Timestamp,
        month_start: Timestamp,
    ) -> Result<(Vec<RpmRow>, Vec<SpendRow>), BrokerError> {
        if scopes.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let levels: Vec<&str> = scopes.iter().map(|s| s.level.as_str()).collect();
        let tenants: Vec<&str> = scopes.iter().map(|s| s.tenant.as_str()).collect();
        let providers: Vec<&str> = scopes.iter().map(|s| s.provider.as_str()).collect();
        let rpm = sqlx::query_as(
            "SELECT r.level, r.tenant_id, r.provider, r.rl_window, r.rl_count FROM limit_rpm r
             JOIN unnest($1::text[], $2::text[], $3::text[]) AS k(level, tenant_id, provider)
               ON r.level = k.level AND r.tenant_id = k.tenant_id AND r.provider = k.provider",
        )
        .bind(&levels)
        .bind(&tenants)
        .bind(&providers)
        .fetch_all(&self.pool)
        .await?;
        let spend = sqlx::query_as(concat!(
            "SELECT ",
            spend_cols!(),
            " FROM limit_spend s
              JOIN unnest($1::text[], $2::text[], $3::text[]) AS k(level, tenant_id, provider)
                ON s.level = k.level AND s.tenant_id = k.tenant_id AND s.provider = k.provider
              WHERE (s.period_kind = 'day' AND s.period_start = $4)
                 OR (s.period_kind = 'month' AND s.period_start = $5)
              ORDER BY s.level, s.tenant_id, s.provider, s.period_kind"
        ))
        .bind(&levels)
        .bind(&tenants)
        .bind(&providers)
        .bind(day_start)
        .bind(month_start)
        .fetch_all(&self.pool)
        .await?;
        Ok((rpm, spend))
    }

    /// Live tokens with a label: the latest expiry per tenant and label, at
    /// most `limit` of them.
    #[tracing::instrument(name = "db.labelled_token_expiry", level = "debug", skip_all)]
    pub async fn labelled_token_expiry(
        &self,
        now: Timestamp,
        limit: i64,
    ) -> Result<Vec<LabelledTokenExpiry>, BrokerError> {
        Ok(sqlx::query_as(
            "SELECT tenant_id, label, MAX(expires_at) AS expires_at FROM llm_tokens
             WHERE label IS NOT NULL AND revoked_at IS NULL AND expires_at > $1
             GROUP BY tenant_id, label ORDER BY tenant_id, label LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}

/// Claims that a reservation did not take: their indexes, and the rows of
/// all claims as they were.
#[derive(Debug, Clone)]
pub struct ReserveDenied {
    pub refused: Vec<usize>,
    pub rows: Vec<SpendRow>,
}
