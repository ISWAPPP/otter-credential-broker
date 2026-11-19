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
/// the request against the token's rate-limit window).
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
    /// across replicas). Returns `None` for unknown, revoked or expired tokens.
    #[tracing::instrument(name = "db.authorize_llm", level = "debug", skip_all)]
    pub async fn authorize_llm(
        &self,
        digest: &TokenDigest,
        now: Timestamp,
        window: i64,
    ) -> Result<Option<LlmGrantRow>, BrokerError> {
        Ok(sqlx::query_as(
            "UPDATE llm_tokens SET
                rl_count  = CASE WHEN rl_window = $2 THEN LEAST(rl_count, 2147483646) + 1 ELSE 1 END,
                rl_window = $2
             WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $3
             RETURNING id, tenant_id, run_id, providers, budget_micro_usd, budget_tokens, spent_micro_usd,
                       spent_tokens, rate_limit_per_minute, rl_count, trace_parent, expires_at, auth_mac",
        )
        .bind(digest.as_slice())
        .bind(window)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Post-accounting: adds the request's cost and tokens to its token and
    /// writes the usage row, atomically.
    #[tracing::instrument(name = "db.record_usage", level = "debug", skip_all)]
    pub async fn record_usage(&self, u: &NewUsageRow) -> Result<(), BrokerError> {
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
        sqlx::query(
            "INSERT INTO llm_usage (ts, token_id, tenant_id, run_id, provider, endpoint, model, status, input_tokens,
                                    output_tokens, cache_read_tokens, cache_write_tokens, cost_micro_usd,
                                    usage_source, duration_ms, ttft_ms, trace_id, response_model)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
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
}
