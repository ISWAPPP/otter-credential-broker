//! The keeper: tenant-scoped secrets, internal LLM tokens and job tokens.
//!
//! Rules enforced here (the HTTP layer only translates):
//! - secret values are write-only for admin callers: no method returns them
//!   except [`Keeper::provider_key`] (used inside the proxy) and
//!   [`Keeper::redeem_job_token`] (worker, single use);
//! - every decrypt is preceded by an audit row (fail closed: no audit row, no
//!   plaintext);
//! - secrets of kind [`LLM_KEY_KIND`] never leave the process, not even to
//!   workers;
//! - every lookup is scoped to the tenant of the caller's token or path.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::clock::{Clock, Timestamp};
use crate::crypto::{Envelope, secret_context};
use crate::error::BrokerError;
use crate::limits::{
    LimitKind, LimitLevel, LimitRefusal, Limits, PerPeriod, Period, RefusedBudget, Reservation, Spend, format_utc,
    window_of, window_reset,
};
use crate::llm::pricing::ModelPrice;
use crate::llm::{LLM_KEY_KIND, ProviderAccess, provider_key_secret_name};
use crate::secret::Secret;
use crate::store::{
    AuditEntry, AuditEvent, BudgetClaim, JobTokenInfo, LabelledTokenExpiry, LimitScope, LlmTokenInfo, LlmTokenState,
    NewJobTokenRow, NewLlmTokenRow, NewSecretRow, NewUsageRow, RedeemedJobRow, RpmRow, SealedSecret, SecretMeta,
    SpendRow, Store, TenantLimitsRow, UsageEntry, UsageFilter,
};
use crate::tokens::{self, TokenDigest, TokenHasher, TokenKind};
use crate::validate;

/// Limits and defaults. All durations in seconds.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeeperSettings {
    pub max_secret_bytes: usize,
    pub max_metadata_bytes: usize,
    pub llm_token_default_ttl_secs: i64,
    pub llm_token_max_ttl_secs: i64,
    pub job_token_default_ttl_secs: i64,
    pub job_token_max_ttl_secs: i64,
    pub max_job_secrets: usize,
    pub default_rate_limit_per_minute: i32,
    pub max_rate_limit_per_minute: i32,
}

impl Default for KeeperSettings {
    fn default() -> Self {
        Self {
            max_secret_bytes: 64 * 1024,
            max_metadata_bytes: 4 * 1024,
            llm_token_default_ttl_secs: 24 * 3600,
            llm_token_max_ttl_secs: 30 * 24 * 3600,
            job_token_default_ttl_secs: 300,
            job_token_max_ttl_secs: 3600,
            max_job_secrets: 32,
            default_rate_limit_per_minute: 120,
            max_rate_limit_per_minute: 100_000,
        }
    }
}

/// Who is calling and in which trace (recorded in audit rows).
#[derive(Debug, Clone, Copy)]
pub struct CallContext<'a> {
    pub actor: &'a str,
    pub trace_id: Option<&'a str>,
}

pub struct NewSecret {
    pub name: String,
    pub kind: String,
    pub value: Secret<String>,
    pub metadata: Option<Value>,
}

pub struct SecretUpdate {
    pub value: Option<Secret<String>>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct NewLlmToken {
    pub run_id: Option<String>,
    pub label: Option<String>,
    pub providers: Option<Vec<String>>,
    pub budget_usd: Option<f64>,
    pub budget_tokens: Option<i64>,
    pub ttl_secs: Option<i64>,
    pub rate_limit_per_minute: Option<i32>,
    /// W3C `traceparent` of the platform's run: the proxy parents its
    /// `llm.request` spans on it, linking LLM calls to the run's trace.
    pub trace_parent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewJobToken {
    /// W3C `traceparent` of the job: redemption is recorded in that trace.
    pub trace_parent: Option<String>,
    pub job_id: String,
    pub secrets: Vec<String>,
    pub ttl_secs: Option<i64>,
}

/// A newly issued token. The token value exists only here; the broker keeps
/// its digest.
pub struct Issued<T> {
    pub token: Secret<String>,
    pub info: T,
}

/// A validated LLM token, as seen by the proxy for one request.
#[derive(Debug, Clone)]
pub struct LlmGrant {
    pub token_id: String,
    pub tenant: String,
    pub run_id: Option<String>,
    pub budget_micro_usd: Option<i64>,
    pub budget_tokens: Option<i64>,
    pub spent_micro_usd: i64,
    pub spent_tokens: i64,
    pub trace_parent: Option<String>,
}

impl LlmGrant {
    /// The refusal of a billable request once what the token spent reaches
    /// its budget, in tokens or USD. It needs nothing from the request, so
    /// the proxy checks it before the request counts in any window above
    /// the token.
    pub fn budget_used_up(&self) -> Option<BrokerError> {
        if let Some(limit) = self.budget_tokens
            && self.spent_tokens >= limit
        {
            return Some(BrokerError::BudgetExceeded(format!(
                "token budget of this LLM token is used up ({} of {limit} tokens)",
                self.spent_tokens
            )));
        }
        if let Some(limit) = self.budget_micro_usd
            && self.spent_micro_usd >= limit
        {
            return Some(BrokerError::BudgetExceeded(format!(
                "USD budget of this LLM token is used up (${:.6} of ${:.6})",
                micro_to_usd(self.spent_micro_usd),
                micro_to_usd(limit)
            )));
        }
        None
    }

    /// Budget pre-check before forwarding a billable request: the budget is
    /// not used up, and a token with a USD budget only uses priced models.
    /// Concurrent requests may each pass and overshoot by at most their own
    /// cost; the next request after post-accounting is refused.
    pub fn check_budget(&self, model: Option<&str>, price: Option<&ModelPrice>) -> Result<(), BrokerError> {
        if let Some(e) = self.budget_used_up() {
            return Err(e);
        }
        if self.budget_micro_usd.is_some() && price.is_none() {
            return Err(BrokerError::Invalid(format!(
                "model {} has no configured price; tokens with a USD budget can only use priced models",
                model.map_or("(none)", |m| m)
            )));
        }
        Ok(())
    }
}

/// A limit and how much of it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateCount {
    pub limit: i64,
    /// Requests counted in the current window, the request at hand included.
    pub count: i64,
}

/// A token that passed authorization for one request (its row was found
/// and is intact, and it may use the provider), with what the levels above
/// it allow.
#[derive(Debug, Clone)]
pub struct Authorized {
    pub grant: LlmGrant,
    /// When the request was authorized: its rate-limit windows and budget
    /// periods are the ones this falls in, also when it is accounted later.
    pub at: Timestamp,
    /// The token's own rate limit and its current window.
    pub token_rpm: RateCount,
    /// Limits of the tenant; empty when it has none.
    pub tenant_limits: Limits,
    /// The tenant's spend in the current day and month, as read at
    /// authorization.
    pub tenant_spend: PerPeriod<Spend>,
}

impl Authorized {
    /// The token's own rate limit: refuses the request when the window,
    /// this request included, is over it.
    pub fn check_token_rate(&self) -> Result<(), BrokerError> {
        if self.token_rpm.count > self.token_rpm.limit {
            metrics::counter!("ocb_llm_rate_limited_total", "tenant" => self.grant.tenant.clone()).increment(1);
            return Err(BrokerError::RateLimited { retry_after_secs: retry_after(self.at) });
        }
        Ok(())
    }

    /// The refusal of a billable request by the first budget of the tenant
    /// that was used up, spent and reserved, when the request was
    /// authorized: the test and the refusal of [`Keeper::reserve`], on the
    /// spend read with the token. It needs nothing from the request, so the
    /// proxy checks it before the request counts in the windows of its
    /// tenant and provider; the reservation still decides, since requests
    /// in flight may use up a budget in between.
    pub fn tenant_budget_used_up(&self) -> Option<BrokerError> {
        let limits = &self.tenant_limits;
        for period in limits.budget_periods() {
            let spend = self.tenant_spend.get(period).unwrap_or_default();
            let claim = BudgetClaim {
                scope: LimitScope::tenant(&self.grant.tenant),
                period,
                period_start: period.start(self.at),
                limit_tokens: limits.tokens(period),
                limit_micro_usd: limits.micro_usd(period),
                tokens: 0,
                micro_usd: 0,
            };
            if claim.limit_tokens.is_some_and(|l| spend.used_tokens() >= l)
                || claim.limit_micro_usd.is_some_and(|l| spend.used_micro_usd() >= l)
            {
                return Some(BrokerError::Limit(budget_refusal(&claim, &spend, "")));
            }
        }
        None
    }
}

/// Seconds until the rate-limit window of `at` ends.
fn retry_after(at: Timestamp) -> u64 {
    u64::try_from(window_reset(at) - at).unwrap_or(60).max(1)
}

/// The windows a request was counted in, of the levels that have a rate
/// limit.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counted {
    pub tenant: Option<RateCount>,
    pub global: Option<RateCount>,
}

/// What a request holds on the budgets of its tenant and provider until it
/// is accounted, and the rows as they are after it took it.
#[derive(Debug, Clone, Default)]
pub struct Reserved {
    pub reservations: Vec<Reservation>,
    pub rows: Vec<SpendRow>,
}

/// Limits of a tenant as set through the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct TenantLimits {
    pub tenant: String,
    pub limits: Limits,
    pub updated_at: Timestamp,
    pub updated_by: String,
}

impl From<TenantLimitsRow> for TenantLimits {
    fn from(r: TenantLimitsRow) -> Self {
        Self { limits: r.limits(), tenant: r.tenant_id, updated_at: r.updated_at, updated_by: r.updated_by }
    }
}

/// A valid token read without counting a request, with its tenant's limits.
#[derive(Debug, Clone)]
pub struct Inspected {
    pub token: LlmTokenState,
    pub at: Timestamp,
    pub tenant_limits: Limits,
}

pub struct RedeemedSecret {
    pub name: String,
    pub kind: String,
    pub value: Secret<String>,
}

pub struct RedeemedJob {
    /// The job's trace context, as set by the platform at issuance.
    pub trace_parent: Option<String>,
    pub token_id: String,
    pub job_id: String,
    pub tenant: String,
    pub secrets: Vec<RedeemedSecret>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewrapReport {
    pub current_kek_id: String,
    pub rewrapped: u64,
    pub skipped: u64,
    pub remaining: i64,
}

pub fn micro_to_usd(micro: i64) -> f64 {
    micro as f64 / 1_000_000.0
}

fn usd_to_micro(usd: f64) -> Result<i64, BrokerError> {
    if !usd.is_finite() || !(0.0..=1_000_000_000.0).contains(&usd) {
        return Err(BrokerError::Invalid("budget_usd must be between 0 and 1e9".into()));
    }
    Ok((usd * 1_000_000.0).round() as i64)
}

/// Checks the W3C `traceparent` format: `00-<32 hex>-<16 hex>-<2 hex>`, ids
/// not all zero.
pub fn valid_traceparent(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let hex = |p: &str, n: usize| p.len() == n && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    parts.len() == 4
        && parts[0] == "00"
        && hex(parts[1], 32)
        && hex(parts[2], 16)
        && hex(parts[3], 2)
        && parts[1].bytes().any(|b| b != b'0')
        && parts[2].bytes().any(|b| b != b'0')
}

/// Provider API keys are sent as HTTP header values: printable ASCII without
/// spaces, so a stored key can never inject or break headers.
fn check_header_safe(value: &str) -> Result<(), BrokerError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(BrokerError::Invalid(format!(
            "values of kind {LLM_KEY_KIND} must be printable ASCII without whitespace"
        )));
    }
    Ok(())
}

fn ttl(requested: Option<i64>, default: i64, max: i64) -> Result<i64, BrokerError> {
    let t = requested.unwrap_or(default);
    if !(1..=max).contains(&t) {
        return Err(BrokerError::Invalid(format!("ttl_secs must be between 1 and {max}")));
    }
    Ok(t)
}

pub struct Keeper {
    store: Store,
    envelope: Envelope,
    hasher: TokenHasher,
    clock: Arc<dyn Clock>,
    settings: KeeperSettings,
}

impl Keeper {
    pub fn new(
        store: Store,
        envelope: Envelope,
        hasher: TokenHasher,
        clock: Arc<dyn Clock>,
        settings: KeeperSettings,
    ) -> Self {
        Self { store, envelope, hasher, clock, settings }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn settings(&self) -> &KeeperSettings {
        &self.settings
    }

    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    fn check_value(&self, kind: &str, value: &Secret<String>) -> Result<(), BrokerError> {
        let v = value.expose();
        if v.is_empty() {
            return Err(BrokerError::Invalid("value must not be empty".into()));
        }
        if v.len() > self.settings.max_secret_bytes {
            return Err(BrokerError::TooLarge(format!("value exceeds {} bytes", self.settings.max_secret_bytes)));
        }
        if kind == LLM_KEY_KIND {
            check_header_safe(v)?;
        }
        Ok(())
    }

    // ---------- secrets ----------

    #[tracing::instrument(name = "keeper.secret.create", skip_all, fields(tenant = %tenant))]
    pub async fn create_secret(
        &self,
        ctx: CallContext<'_>,
        tenant: &str,
        req: NewSecret,
    ) -> Result<SecretMeta, BrokerError> {
        validate::tenant_id(tenant)?;
        validate::secret_name(&req.name)?;
        validate::secret_kind(&req.kind)?;
        self.check_value(&req.kind, &req.value)?;
        let metadata =
            validate::metadata(req.metadata.as_ref().unwrap_or(&json!({})), self.settings.max_metadata_bytes)?;
        let record =
            self.envelope.seal(req.value.expose().as_bytes(), &secret_context(tenant, &req.name, &req.kind)).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = self.clock.now();
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "secret.create",
            tenant: Some(tenant),
            secret_name: Some(&req.name),
            trace_id: ctx.trace_id,
            detail: Some(json!({ "kind": req.kind, "kek_id": record.kek_id }).to_string()),
            ..AuditEvent::default()
        };
        let row = NewSecretRow {
            id: &id,
            tenant,
            name: &req.name,
            kind: &req.kind,
            metadata_json: &metadata,
            record: &record,
            now,
            actor: ctx.actor,
        };
        self.store.insert_secret(&row, &audit).await
    }

    #[tracing::instrument(name = "keeper.secret.update", skip_all, fields(tenant = %tenant))]
    pub async fn update_secret(
        &self,
        ctx: CallContext<'_>,
        tenant: &str,
        name: &str,
        upd: SecretUpdate,
    ) -> Result<SecretMeta, BrokerError> {
        validate::tenant_id(tenant)?;
        validate::secret_name(name)?;
        if upd.value.is_none() && upd.metadata.is_none() {
            return Err(BrokerError::Invalid("nothing to update: give value and/or metadata".into()));
        }
        let current = self.store.get_secret_meta(tenant, name).await?.ok_or_else(|| not_found_secret(name))?;
        let metadata =
            upd.metadata.as_ref().map(|m| validate::metadata(m, self.settings.max_metadata_bytes)).transpose()?;
        let record = match &upd.value {
            Some(v) => {
                self.check_value(&current.kind, v)?;
                Some(self.envelope.seal(v.expose().as_bytes(), &secret_context(tenant, name, &current.kind)).await?)
            }
            None => None,
        };
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "secret.update",
            tenant: Some(tenant),
            secret_name: Some(name),
            trace_id: ctx.trace_id,
            detail: Some(json!({ "value": record.is_some(), "metadata": metadata.is_some() }).to_string()),
            ..AuditEvent::default()
        };
        let now = self.clock.now();
        self.store
            .update_secret(tenant, name, record.as_ref(), metadata.as_deref(), now, ctx.actor, &audit)
            .await?
            .ok_or_else(|| not_found_secret(name))
    }

    #[tracing::instrument(name = "keeper.secret.delete", skip_all, fields(tenant = %tenant))]
    pub async fn delete_secret(&self, ctx: CallContext<'_>, tenant: &str, name: &str) -> Result<(), BrokerError> {
        validate::tenant_id(tenant)?;
        validate::secret_name(name)?;
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "secret.delete",
            tenant: Some(tenant),
            secret_name: Some(name),
            trace_id: ctx.trace_id,
            ..AuditEvent::default()
        };
        if self.store.delete_secret(tenant, name, self.clock.now(), &audit).await? {
            Ok(())
        } else {
            Err(not_found_secret(name))
        }
    }

    pub async fn get_secret(&self, tenant: &str, name: &str) -> Result<SecretMeta, BrokerError> {
        validate::tenant_id(tenant)?;
        validate::secret_name(name)?;
        self.store.get_secret_meta(tenant, name).await?.ok_or_else(|| not_found_secret(name))
    }

    pub async fn list_secrets(&self, tenant: &str) -> Result<Vec<SecretMeta>, BrokerError> {
        validate::tenant_id(tenant)?;
        self.store.list_secrets(tenant).await
    }

    // ---------- LLM tokens ----------

    #[tracing::instrument(name = "keeper.llm_token.issue", skip_all, fields(tenant = %tenant))]
    pub async fn issue_llm_token(
        &self,
        ctx: CallContext<'_>,
        tenant: &str,
        req: NewLlmToken,
    ) -> Result<Issued<LlmTokenInfo>, BrokerError> {
        validate::tenant_id(tenant)?;
        if let Some(r) = &req.run_id {
            validate::reference("run_id", r)?;
        }
        if let Some(l) = &req.label {
            validate::reference("label", l)?;
        }
        let providers = match req.providers {
            Some(mut p) => {
                if p.is_empty() {
                    return Err(BrokerError::Invalid("providers must not be empty (omit it to allow all)".into()));
                }
                for id in &p {
                    validate::provider_id(id)?;
                }
                p.sort();
                p.dedup();
                Some(p)
            }
            None => None,
        };
        let budget_micro_usd = req.budget_usd.map(usd_to_micro).transpose()?;
        if req.budget_tokens.is_some_and(|t| t < 0) {
            return Err(BrokerError::Invalid("budget_tokens must not be negative".into()));
        }
        let ttl = ttl(req.ttl_secs, self.settings.llm_token_default_ttl_secs, self.settings.llm_token_max_ttl_secs)?;
        let rate = req.rate_limit_per_minute.unwrap_or(self.settings.default_rate_limit_per_minute);
        if !(1..=self.settings.max_rate_limit_per_minute).contains(&rate) {
            return Err(BrokerError::Invalid(format!(
                "rate_limit_per_minute must be between 1 and {}",
                self.settings.max_rate_limit_per_minute
            )));
        }
        check_traceparent(req.trace_parent.as_deref())?;
        let token = tokens::generate(TokenKind::Llm)?;
        let digest = self.hasher.digest(token.expose());
        let id = uuid::Uuid::new_v4().to_string();
        let now = self.clock.now();
        let expires_at = now.saturating_add(ttl);
        let auth_mac = self.llm_row_mac(&id, tenant, providers.as_deref(), expires_at);
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "llm_token.issue",
            tenant: Some(tenant),
            trace_id: ctx.trace_id,
            detail: Some(
                json!({
                    "token_id": id, "run_id": req.run_id, "providers": providers, "ttl_secs": ttl,
                    "budget_micro_usd": budget_micro_usd, "budget_tokens": req.budget_tokens,
                    "rate_limit_per_minute": rate,
                })
                .to_string(),
            ),
            ..AuditEvent::default()
        };
        let row = NewLlmTokenRow {
            id: &id,
            digest: &digest,
            auth_mac: &auth_mac,
            tenant,
            run_id: req.run_id.as_deref(),
            label: req.label.as_deref(),
            providers: providers.as_deref(),
            budget_micro_usd,
            budget_tokens: req.budget_tokens,
            rate_limit_per_minute: rate,
            trace_parent: req.trace_parent.as_deref(),
            now,
            expires_at,
            actor: ctx.actor,
        };
        let info = self.store.insert_llm_token(&row, &audit).await?;
        Ok(Issued { token, info })
    }

    pub async fn list_llm_tokens(&self, tenant: &str, limit: i64) -> Result<Vec<LlmTokenInfo>, BrokerError> {
        validate::tenant_id(tenant)?;
        self.store.list_llm_tokens(tenant, limit).await
    }

    pub async fn get_llm_token(&self, tenant: &str, id: &str) -> Result<LlmTokenInfo, BrokerError> {
        validate::tenant_id(tenant)?;
        self.store.get_llm_token(tenant, id).await?.ok_or_else(|| BrokerError::NotFound("LLM token".into()))
    }

    #[tracing::instrument(name = "keeper.llm_token.revoke", skip_all, fields(tenant = %tenant))]
    pub async fn revoke_llm_token(&self, ctx: CallContext<'_>, tenant: &str, id: &str) -> Result<(), BrokerError> {
        validate::tenant_id(tenant)?;
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "llm_token.revoke",
            tenant: Some(tenant),
            trace_id: ctx.trace_id,
            detail: Some(json!({ "token_id": id }).to_string()),
            ..AuditEvent::default()
        };
        if self.store.revoke_llm_token(tenant, id, self.clock.now(), &audit).await? {
            Ok(())
        } else {
            Err(BrokerError::NotFound("LLM token".into()))
        }
    }

    /// Validates an LLM token for one proxied request to `provider` and
    /// counts it against the token's rate limit. A token with a `providers`
    /// list may use only those; a provider with [`ProviderAccess::Explicit`]
    /// only serves tokens whose list names it. No caching: revocation takes
    /// effect on the next request, on every replica.
    pub async fn authorize_llm(
        &self,
        presented: &str,
        provider: &str,
        access: ProviderAccess,
    ) -> Result<LlmGrant, BrokerError> {
        let a = self.authorize(presented, provider, access).await?;
        a.check_token_rate()?;
        Ok(a.grant)
    }

    /// Like [`Keeper::authorize_llm`], but leaves the token's rate limit to
    /// [`Authorized::check_token_rate`], and also returns the limits of the
    /// token's tenant and its current spend (read in the same statement).
    #[tracing::instrument(name = "keeper.llm.authorize", skip_all, fields(provider = %provider))]
    pub async fn authorize(
        &self,
        presented: &str,
        provider: &str,
        access: ProviderAccess,
    ) -> Result<Authorized, BrokerError> {
        let digest = self.hasher.parse(TokenKind::Llm, presented).ok_or(BrokerError::Unauthorized)?;
        let now = self.clock.now();
        let row = self
            .store
            .authorize_llm(&digest, now, window_of(now), Period::Day.start(now), Period::Month.start(now))
            .await?
            .ok_or(BrokerError::Unauthorized)?;
        let t = &row.token;
        if !self.verify_llm_mac(&t.id, &t.tenant_id, t.providers.as_deref(), t.expires_at, &t.auth_mac) {
            integrity_failure("llm_tokens", &t.id);
            return Err(BrokerError::Unauthorized);
        }
        match (&t.providers, access) {
            (Some(allowed), _) if !allowed.iter().any(|p| p == provider) => {
                return Err(BrokerError::Forbidden(format!("this LLM token may not use provider {provider}")));
            }
            (None, ProviderAccess::Explicit) => {
                return Err(BrokerError::Forbidden(format!(
                    "provider {provider} only serves LLM tokens that name it in providers"
                )));
            }
            _ => {}
        }
        let tenant_limits = row.tenant_limits();
        let tenant_spend = PerPeriod { day: row.tenant_spend(Period::Day), month: row.tenant_spend(Period::Month) };
        let t = row.token;
        Ok(Authorized {
            token_rpm: RateCount { limit: i64::from(t.rate_limit_per_minute), count: i64::from(t.rl_count) },
            grant: LlmGrant {
                token_id: t.id,
                tenant: t.tenant_id,
                run_id: t.run_id,
                budget_micro_usd: t.budget_micro_usd,
                budget_tokens: t.budget_tokens,
                spent_micro_usd: t.spent_micro_usd,
                spent_tokens: t.spent_tokens,
                trace_parent: t.trace_parent,
            },
            at: now,
            tenant_limits,
            tenant_spend,
        })
    }

    /// Counts an authorized request in the one-minute windows of its tenant
    /// and then of `provider`, for the levels with a rate limit
    /// (`global_rpm` is the provider's). The provider's window only counts
    /// requests the tenant's let through, so a tenant over its limit does
    /// not use up the provider's for others, as a token over its limit
    /// never reaches its tenant's. A refusal is [`BrokerError::Limit`].
    #[tracing::instrument(name = "keeper.llm.count", skip_all, fields(provider = %provider))]
    pub async fn count_request(
        &self,
        a: &Authorized,
        provider: &str,
        global_rpm: Option<u32>,
    ) -> Result<Counted, BrokerError> {
        let to_i32 = |r: u32| i32::try_from(r).unwrap_or(i32::MAX);
        let (tenant_rpm, global_rpm) = (a.tenant_limits.rpm.map(to_i32), global_rpm.map(to_i32));
        if tenant_rpm.is_none() && global_rpm.is_none() {
            return Ok(Counted::default());
        }
        let c = self.store.count_requests(&a.grant.tenant, provider, window_of(a.at), tenant_rpm, global_rpm).await?;
        let retry_after_secs = retry_after(a.at);
        if !c.tenant_passed {
            return Err(BrokerError::Limit(LimitRefusal {
                level: LimitLevel::Tenant,
                kind: LimitKind::Rate,
                message: format!(
                    "rate limit of the tenant exceeded ({} requests per minute), retry after {retry_after_secs}s",
                    tenant_rpm.unwrap_or_default()
                ),
                retry_after_secs: Some(retry_after_secs),
                budget: None,
            }));
        }
        if !c.global_passed {
            return Err(BrokerError::Limit(LimitRefusal {
                level: LimitLevel::Global,
                kind: LimitKind::Rate,
                message: format!("rate limit of provider {provider} exceeded, retry after {retry_after_secs}s"),
                retry_after_secs: Some(retry_after_secs),
                budget: None,
            }));
        }
        let count = |limit: Option<i32>, n: Option<i32>| {
            limit.map(|l| RateCount { limit: i64::from(l), count: i64::from(n.unwrap_or(0)) })
        };
        Ok(Counted { tenant: count(tenant_rpm, c.tenant_count), global: count(global_rpm, c.global_count) })
    }

    /// Reserves `tokens` and `micro_usd` on every budget of the request's
    /// tenant and of `provider` (`global` holds the provider's limits), in
    /// the periods the request was authorized in. All or nothing: a budget
    /// that is used up, reservations of requests in flight included,
    /// refuses the request ([`BrokerError::Limit`], naming the lowest level
    /// that refused) and nothing stays reserved. A refusal of the global
    /// level does not show the provider's numbers.
    #[tracing::instrument(name = "keeper.llm.reserve", skip_all, fields(provider = %provider))]
    pub async fn reserve(
        &self,
        a: &Authorized,
        provider: &str,
        global: &Limits,
        tokens: i64,
        micro_usd: i64,
    ) -> Result<Reserved, BrokerError> {
        let mut claims = Vec::new();
        for (scope, limits) in
            [(LimitScope::tenant(&a.grant.tenant), &a.tenant_limits), (LimitScope::global(provider), global)]
        {
            for period in limits.budget_periods() {
                claims.push(BudgetClaim {
                    scope: scope.clone(),
                    period,
                    period_start: period.start(a.at),
                    limit_tokens: limits.tokens(period),
                    limit_micro_usd: limits.micro_usd(period),
                    tokens,
                    micro_usd,
                });
            }
        }
        if claims.is_empty() {
            return Ok(Reserved::default());
        }
        match self.store.reserve(&claims).await? {
            Ok(rows) => {
                let reservations = claims
                    .into_iter()
                    .map(|c| Reservation {
                        level: c.scope.level,
                        tenant: c.scope.tenant,
                        provider: c.scope.provider,
                        period: c.period,
                        period_start: c.period_start,
                        tokens: c.tokens.max(0),
                        micro_usd: c.micro_usd.max(0),
                    })
                    .collect();
                Ok(Reserved { reservations, rows })
            }
            Err(denied) => {
                let Some(claim) = denied.refused.iter().map(|i| &claims[*i]).min_by_key(|c| (c.scope.level, c.period))
                else {
                    return Err(BrokerError::Internal("a refused reservation names no budget".into()));
                };
                let spend = denied
                    .rows
                    .iter()
                    .find(|r| r.is(&claim.scope, claim.period) && r.period_start == claim.period_start)
                    .map(SpendRow::spend)
                    .unwrap_or_default();
                Err(BrokerError::Limit(budget_refusal(claim, &spend, provider)))
            }
        }
    }

    /// Gives back what a request reserved when it ends before it reaches
    /// the provider. Not to be repeated after [`BrokerError::CommitUnknown`].
    pub async fn release(&self, reservations: &[Reservation]) -> Result<(), BrokerError> {
        self.store.release(reservations).await
    }

    /// Post-accounting of one proxied request that holds reservations: in
    /// one transaction, the reservations are given back and the usage is
    /// added to the token, to the budgets the reservations were taken on
    /// (in the periods the request was authorized in) and to the usage log.
    /// Not to be repeated after [`BrokerError::CommitUnknown`].
    pub async fn record_usage_settling(&self, row: &NewUsageRow, settle: &[Reservation]) -> Result<(), BrokerError> {
        self.store.record_usage_settling(row, settle).await
    }

    /// The keyed digest of a presented LLM token; `None` for anything that
    /// cannot be one.
    pub fn llm_token_digest(&self, presented: &str) -> Option<TokenDigest> {
        self.hasher.parse(TokenKind::Llm, presented)
    }

    /// Reads a valid LLM token by its digest without counting a request,
    /// with the limits of its tenant.
    #[tracing::instrument(name = "keeper.llm.inspect", skip_all)]
    pub async fn inspect_llm_token(&self, digest: &TokenDigest) -> Result<Inspected, BrokerError> {
        let now = self.clock.now();
        let t = self.store.find_llm_token(digest, now).await?.ok_or(BrokerError::Unauthorized)?;
        if !self.verify_llm_mac(&t.id, &t.tenant_id, t.providers.as_deref(), t.expires_at, &t.auth_mac) {
            integrity_failure("llm_tokens", &t.id);
            return Err(BrokerError::Unauthorized);
        }
        let tenant_limits = self.store.get_tenant_limits(&t.tenant_id).await?.map(|r| r.limits()).unwrap_or_default();
        Ok(Inspected { token: t, at: now, tenant_limits })
    }

    // ---------- limits of tenants ----------

    /// Replaces the limits of a tenant (all of them: a limit left out is
    /// removed; no limits at all removes the tenant's entry). Audited.
    #[tracing::instrument(name = "keeper.tenant_limits.set", skip_all, fields(tenant = %tenant))]
    pub async fn set_tenant_limits(
        &self,
        ctx: CallContext<'_>,
        tenant: &str,
        limits: Limits,
    ) -> Result<Option<TenantLimits>, BrokerError> {
        validate::tenant_id(tenant)?;
        limits.validate().map_err(BrokerError::Invalid)?;
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "tenant_limits.set",
            tenant: Some(tenant),
            trace_id: ctx.trace_id,
            detail: Some(serde_json::to_string(&limits).unwrap_or_default()),
            ..AuditEvent::default()
        };
        let row = self.store.set_tenant_limits(tenant, &limits, self.clock.now(), ctx.actor, &audit).await?;
        Ok(row.map(Into::into))
    }

    pub async fn tenant_limits(&self, tenant: &str) -> Result<Option<TenantLimits>, BrokerError> {
        validate::tenant_id(tenant)?;
        Ok(self.store.get_tenant_limits(tenant).await?.map(Into::into))
    }

    /// Every tenant with limits, by id.
    pub async fn all_tenant_limits(&self) -> Result<Vec<TenantLimits>, BrokerError> {
        Ok(self.store.list_tenant_limits().await?.into_iter().map(Into::into).collect())
    }

    /// Request windows and spend of tenants and providers in the day and
    /// month of `at`.
    pub async fn limit_usage(
        &self,
        scopes: &[LimitScope],
        at: Timestamp,
    ) -> Result<(Vec<RpmRow>, Vec<SpendRow>), BrokerError> {
        self.store.limit_usage(scopes, Period::Day.start(at), Period::Month.start(at)).await
    }

    /// The latest expiry of the live tokens of each tenant and label, for at
    /// most `limit` of them.
    pub async fn labelled_token_expiry(&self, limit: i64) -> Result<Vec<LabelledTokenExpiry>, BrokerError> {
        self.store.labelled_token_expiry(self.clock.now(), limit).await
    }

    /// Resolves and decrypts the tenant's API key for `provider`. Writes the
    /// audit row first; the key is used only to build the upstream request.
    #[tracing::instrument(name = "secret.resolve", skip_all, fields(tenant = %grant.tenant, provider = %provider, purpose = "llm.proxy"))]
    pub async fn provider_key(
        &self,
        grant: &LlmGrant,
        provider: &str,
        trace_id: Option<&str>,
    ) -> Result<Secret<String>, BrokerError> {
        let name = provider_key_secret_name(provider);
        let sealed = self.store.get_sealed(&grant.tenant, &name).await?.ok_or_else(|| {
            BrokerError::Forbidden(format!("no API key for provider {provider} is configured for this tenant"))
        })?;
        if sealed.kind != LLM_KEY_KIND {
            return Err(BrokerError::Forbidden(format!("secret {name} is not of kind {LLM_KEY_KIND}")));
        }
        let actor = format!("llm-token:{}", grant.token_id);
        let purpose = format!("llm.proxy:{provider}");
        self.decrypt(&actor, &purpose, trace_id, &sealed).await
    }

    /// Audit, then decrypt. The AAD is rebuilt from the row's own tenant,
    /// name and kind, so a row changed in the database fails here.
    #[tracing::instrument(name = "secret.decrypt", skip_all, fields(tenant = %sealed.tenant, secret = %sealed.name))]
    async fn decrypt(
        &self,
        actor: &str,
        purpose: &str,
        trace_id: Option<&str>,
        sealed: &SealedSecret,
    ) -> Result<Secret<String>, BrokerError> {
        let audit = AuditEvent {
            actor,
            action: "secret.decrypt",
            tenant: Some(&sealed.tenant),
            secret_name: Some(&sealed.name),
            purpose: Some(purpose),
            trace_id,
            detail: Some(json!({ "kek_id": sealed.record.kek_id }).to_string()),
        };
        self.store.audit(self.clock.now(), &audit).await?;
        let context = secret_context(&sealed.tenant, &sealed.name, &sealed.kind);
        let plain = self.envelope.open(&sealed.record, &context).await?;
        let kind = purpose.split(':').next().unwrap_or(purpose).to_owned();
        metrics::counter!("ocb_secret_decrypts_total", "purpose" => kind).increment(1);
        let text = String::from_utf8(plain.expose().clone())
            .map_err(|_| BrokerError::Internal("stored secret is not UTF-8".into()))?;
        Ok(Secret::new(text))
    }

    /// Post-accounting of one proxied request.
    pub async fn record_usage(&self, row: &NewUsageRow) -> Result<(), BrokerError> {
        self.store.record_usage(row).await
    }

    pub async fn list_usage(&self, tenant: &str, filter: &UsageFilter) -> Result<Vec<UsageEntry>, BrokerError> {
        validate::tenant_id(tenant)?;
        self.store.list_usage(tenant, filter).await
    }

    // ---------- job tokens ----------

    #[tracing::instrument(name = "keeper.job_token.issue", skip_all, fields(tenant = %tenant))]
    pub async fn issue_job_token(
        &self,
        ctx: CallContext<'_>,
        tenant: &str,
        req: NewJobToken,
    ) -> Result<Issued<JobTokenInfo>, BrokerError> {
        validate::tenant_id(tenant)?;
        validate::reference("job_id", &req.job_id)?;
        let mut names = req.secrets;
        if names.is_empty() || names.len() > self.settings.max_job_secrets {
            return Err(BrokerError::Invalid(format!(
                "secrets must list between 1 and {} names",
                self.settings.max_job_secrets
            )));
        }
        for n in &names {
            validate::secret_name(n)?;
        }
        names.sort();
        names.dedup();
        let ttl = ttl(req.ttl_secs, self.settings.job_token_default_ttl_secs, self.settings.job_token_max_ttl_secs)?;
        check_traceparent(req.trace_parent.as_deref())?;
        let found = self.store.get_sealed_many(tenant, &names).await?;
        let missing: Vec<&str> =
            names.iter().filter(|n| !found.iter().any(|f| &f.name == *n)).map(String::as_str).collect();
        if !missing.is_empty() {
            return Err(BrokerError::NotFound(format!("secrets {}", missing.join(", "))));
        }
        if found.iter().any(|f| f.kind == LLM_KEY_KIND) {
            return Err(BrokerError::Forbidden(format!("secrets of kind {LLM_KEY_KIND} are never handed out")));
        }
        let token = tokens::generate(TokenKind::Job)?;
        let digest = self.hasher.digest(token.expose());
        let id = uuid::Uuid::new_v4().to_string();
        let now = self.clock.now();
        let expires_at = now.saturating_add(ttl);
        let auth_mac = self.job_row_mac(&id, tenant, &req.job_id, &names, expires_at);
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "job_token.issue",
            tenant: Some(tenant),
            purpose: Some(&req.job_id),
            trace_id: ctx.trace_id,
            detail: Some(json!({ "token_id": id, "secrets": names, "ttl_secs": ttl }).to_string()),
            ..AuditEvent::default()
        };
        let row = NewJobTokenRow {
            id: &id,
            digest: &digest,
            auth_mac: &auth_mac,
            trace_parent: req.trace_parent.as_deref(),
            tenant,
            job_id: &req.job_id,
            secret_names: &names,
            now,
            expires_at,
            actor: ctx.actor,
        };
        let info = self.store.insert_job_token(&row, &audit).await?;
        Ok(Issued { token, info })
    }

    pub async fn list_job_tokens(&self, tenant: &str, limit: i64) -> Result<Vec<JobTokenInfo>, BrokerError> {
        validate::tenant_id(tenant)?;
        self.store.list_job_tokens(tenant, limit).await
    }

    #[tracing::instrument(name = "keeper.job_token.revoke", skip_all, fields(tenant = %tenant))]
    pub async fn revoke_job_token(&self, ctx: CallContext<'_>, tenant: &str, id: &str) -> Result<(), BrokerError> {
        validate::tenant_id(tenant)?;
        let audit = AuditEvent {
            actor: ctx.actor,
            action: "job_token.revoke",
            tenant: Some(tenant),
            trace_id: ctx.trace_id,
            detail: Some(json!({ "token_id": id }).to_string()),
            ..AuditEvent::default()
        };
        if self.store.revoke_job_token(tenant, id, self.clock.now(), &audit).await? {
            Ok(())
        } else {
            Err(BrokerError::NotFound("job token".into()))
        }
    }

    /// Redeems a job token: marks it used (atomically, so it works once across
    /// all replicas), then returns exactly the secrets listed for the job, from
    /// the job's tenant. Any failure after the token was consumed leaves it
    /// consumed (fail closed); the platform issues a new one.
    #[tracing::instrument(name = "keeper.job_token.redeem", skip_all, fields(tenant = tracing::field::Empty, job_id = tracing::field::Empty))]
    pub async fn redeem_job_token(&self, presented: &str, trace_id: Option<&str>) -> Result<RedeemedJob, BrokerError> {
        let digest = self.hasher.parse(TokenKind::Job, presented).ok_or(BrokerError::Unauthorized)?;
        let now = self.clock.now();
        let job: RedeemedJobRow = self.store.redeem_job_token(&digest, now).await?.ok_or(BrokerError::Unauthorized)?;
        if !self.verify_job_row(&job) {
            integrity_failure("job_tokens", &job.id);
            return Err(BrokerError::Unauthorized);
        }
        tracing::Span::current().record("tenant", job.tenant_id.as_str()).record("job_id", job.job_id.as_str());
        // The job's trace (set by the platform) wins over the caller's.
        let trace_id = job.trace_parent.as_deref().and_then(trace_id_of_traceparent).or(trace_id);
        let actor = format!("job-token:{}", job.id);
        let purpose = format!("job:{}", job.job_id);
        self.store
            .audit(
                now,
                &AuditEvent {
                    actor: &actor,
                    action: "job_token.redeem",
                    tenant: Some(&job.tenant_id),
                    purpose: Some(&purpose),
                    trace_id,
                    ..AuditEvent::default()
                },
            )
            .await?;
        let sealed = self.store.get_sealed_many(&job.tenant_id, &job.secret_names).await?;
        let missing: Vec<&str> =
            job.secret_names.iter().filter(|n| !sealed.iter().any(|s| &s.name == *n)).map(String::as_str).collect();
        if !missing.is_empty() {
            return Err(BrokerError::NotFound(format!("secrets {}", missing.join(", "))));
        }
        if sealed.iter().any(|s| s.kind == LLM_KEY_KIND) {
            return Err(BrokerError::Forbidden(format!("secrets of kind {LLM_KEY_KIND} are never handed out")));
        }
        let mut secrets = Vec::with_capacity(sealed.len());
        for s in sealed {
            let value = self.decrypt(&actor, &purpose, trace_id, &s).await?;
            secrets.push(RedeemedSecret { name: s.name, kind: s.kind, value });
        }
        Ok(RedeemedJob {
            trace_parent: job.trace_parent,
            token_id: job.id,
            job_id: job.job_id,
            tenant: job.tenant_id,
            secrets,
        })
    }

    fn llm_row_mac(&self, id: &str, tenant: &str, providers: Option<&[String]>, expires_at: Timestamp) -> Vec<u8> {
        let (scope, list) = match providers {
            Some(p) => ("list", p.join("\0")),
            None => ("all", String::new()),
        };
        self.hasher.row_mac(
            "llm_tokens",
            &[id.as_bytes(), tenant.as_bytes(), scope.as_bytes(), list.as_bytes(), &expires_at.to_be_bytes()],
        )
    }

    fn verify_llm_mac(
        &self,
        id: &str,
        tenant: &str,
        providers: Option<&[String]>,
        expires_at: Timestamp,
        mac: &[u8],
    ) -> bool {
        let (scope, list) = match providers {
            Some(p) => ("list", p.join("\0")),
            None => ("all", String::new()),
        };
        self.hasher.verify_row_mac(
            "llm_tokens",
            &[id.as_bytes(), tenant.as_bytes(), scope.as_bytes(), list.as_bytes(), &expires_at.to_be_bytes()],
            mac,
        )
    }

    fn job_row_mac(&self, id: &str, tenant: &str, job_id: &str, names: &[String], expires_at: Timestamp) -> Vec<u8> {
        let names = names.join("\0");
        self.hasher.row_mac(
            "job_tokens",
            &[id.as_bytes(), tenant.as_bytes(), job_id.as_bytes(), names.as_bytes(), &expires_at.to_be_bytes()],
        )
    }

    fn verify_job_row(&self, r: &RedeemedJobRow) -> bool {
        let names = r.secret_names.join("\0");
        self.hasher.verify_row_mac(
            "job_tokens",
            &[
                r.id.as_bytes(),
                r.tenant_id.as_bytes(),
                r.job_id.as_bytes(),
                names.as_bytes(),
                &r.expires_at.to_be_bytes(),
            ],
            &r.auth_mac,
        )
    }

    // ---------- audit and maintenance ----------

    pub async fn audit_log(&self, tenant: Option<&str>, limit: i64) -> Result<Vec<AuditEntry>, BrokerError> {
        if let Some(t) = tenant {
            validate::tenant_id(t)?;
        }
        self.store.list_audit(tenant, limit).await
    }

    /// Re-wraps up to `limit` DEKs that are not wrapped by the current KEK.
    /// Values are not decrypted; only DEKs are unwrapped and wrapped again.
    #[tracing::instrument(name = "keeper.kek.rewrap", skip_all)]
    pub async fn rewrap(&self, ctx: CallContext<'_>, limit: i64) -> Result<RewrapReport, BrokerError> {
        let current = self.envelope.current_key_id().to_owned();
        let batch = self.store.secrets_to_rewrap(&current, limit.clamp(1, 10_000)).await?;
        let (mut rewrapped, mut skipped) = (0u64, 0u64);
        for s in &batch {
            let Some(new) = self.envelope.rewrap(&s.record, &secret_context(&s.tenant, &s.name, &s.kind)).await? else {
                continue;
            };
            if self.store.store_rewrap(&s.id, &s.record.kek_id, &s.record.wrapped_dek, &new).await? {
                rewrapped += 1;
            } else {
                skipped += 1;
            }
        }
        let remaining = self.store.count_to_rewrap(&current).await?;
        let report = RewrapReport { current_kek_id: current, rewrapped, skipped, remaining };
        self.store
            .audit(
                self.clock.now(),
                &AuditEvent {
                    actor: ctx.actor,
                    action: "kek.rewrap",
                    trace_id: ctx.trace_id,
                    detail: Some(serde_json::to_string(&report).unwrap_or_default()),
                    ..AuditEvent::default()
                },
            )
            .await?;
        Ok(report)
    }
}

fn check_traceparent(tp: Option<&str>) -> Result<(), BrokerError> {
    match tp {
        Some(tp) if !valid_traceparent(tp) => {
            Err(BrokerError::Invalid("traceparent must be a W3C traceparent (version 00)".into()))
        }
        _ => Ok(()),
    }
}

/// The trace id part of a valid `traceparent`.
pub fn trace_id_of_traceparent(tp: &str) -> Option<&str> {
    valid_traceparent(tp).then(|| tp.split('-').nth(1)).flatten()
}

/// The refusal of a budget `claim` whose row stood at `spend`. The tenant
/// sees its numbers; for a provider only the time the budget renews is
/// shown, since its numbers come from every tenant.
fn budget_refusal(claim: &BudgetClaim, spend: &Spend, provider: &str) -> LimitRefusal {
    let tokens_out = claim.limit_tokens.is_some_and(|l| spend.used_tokens() >= l);
    let usd_out = claim.limit_micro_usd.is_some_and(|l| spend.used_micro_usd() >= l);
    let unit = if tokens_out || (!usd_out && claim.limit_tokens.is_some()) { "token" } else { "USD" };
    let period = match claim.period {
        Period::Day => "daily",
        Period::Month => "monthly",
    };
    let renews_at = claim.period.end(claim.period_start);
    let renews = format_utc(renews_at);
    let message = match claim.scope.level {
        LimitLevel::Global => {
            format!("{period} {unit} budget of provider {provider} is used up; it renews at {renews}")
        }
        _ => {
            let used = if unit == "token" {
                format!("{} of {} tokens", spend.used_tokens(), claim.limit_tokens.unwrap_or_default())
            } else {
                format!(
                    "${:.6} of ${:.6}",
                    micro_to_usd(spend.used_micro_usd()),
                    micro_to_usd(claim.limit_micro_usd.unwrap_or_default())
                )
            };
            format!(
                "{period} {unit} budget of the tenant is used up ({used}, requests in flight included); it renews at {renews}"
            )
        }
    };
    let (usd, limit, used) = if unit == "token" {
        (false, claim.limit_tokens.unwrap_or_default(), spend.used_tokens())
    } else {
        (true, claim.limit_micro_usd.unwrap_or_default(), spend.used_micro_usd())
    };
    LimitRefusal {
        level: claim.scope.level,
        kind: LimitKind::Budget,
        message,
        retry_after_secs: None,
        budget: Some(RefusedBudget { period: claim.period, usd, limit, used, renews_at }),
    }
}

/// A token row whose MAC does not verify was changed outside the broker.
fn integrity_failure(table: &'static str, id: &str) {
    tracing::error!(table, id, "token row failed its integrity check; refusing it");
    metrics::counter!("ocb_integrity_failures_total", "table" => table).increment(1);
}

fn not_found_secret(name: &str) -> BrokerError {
    BrokerError::NotFound(format!("secret {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_format() {
        assert!(valid_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        assert!(!valid_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01"));
        assert!(!valid_traceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        assert!(!valid_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"));
        assert!(!valid_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"));
    }

    #[test]
    fn budgets() {
        let price = ModelPrice {
            provider: "a".into(),
            model: "m".into(),
            input: 1.0,
            output: 1.0,
            cache_read: None,
            cache_write: None,
            cache_write_1h: None,
            free: false,
        };
        let mut g = LlmGrant {
            token_id: "t".into(),
            tenant: "x".into(),
            run_id: None,
            budget_micro_usd: None,
            budget_tokens: Some(100),
            spent_micro_usd: 0,
            spent_tokens: 99,
            trace_parent: None,
        };
        assert!(g.check_budget(Some("m"), None).is_ok());
        g.spent_tokens = 100;
        assert!(matches!(g.check_budget(Some("m"), None), Err(BrokerError::BudgetExceeded(_))));
        g.budget_tokens = None;
        g.budget_micro_usd = Some(5);
        assert!(matches!(g.check_budget(Some("unpriced"), None), Err(BrokerError::Invalid(_))));
        assert!(g.check_budget(Some("m"), Some(&price)).is_ok());
        g.spent_micro_usd = 5;
        assert!(matches!(g.check_budget(Some("m"), Some(&price)), Err(BrokerError::BudgetExceeded(_))));
        // Used up whatever the model: nothing to read from the request.
        assert!(matches!(g.check_budget(Some("unpriced"), None), Err(BrokerError::BudgetExceeded(_))));
        assert!(matches!(g.budget_used_up(), Some(BrokerError::BudgetExceeded(_))));
        g.spent_micro_usd = 4;
        assert!(g.budget_used_up().is_none());
        assert_eq!(usd_to_micro(1.5).unwrap(), 1_500_000);
        assert!(usd_to_micro(-1.0).is_err());
        assert!(usd_to_micro(f64::INFINITY).is_err());
    }

    #[test]
    fn a_tenant_budget_used_up_when_the_token_was_found() {
        // 2030-03-17T17:46:40Z.
        let at = 1_900_000_000;
        let mut a = Authorized {
            grant: LlmGrant {
                token_id: "t".into(),
                tenant: "tenant-a".into(),
                run_id: None,
                budget_micro_usd: None,
                budget_tokens: None,
                spent_micro_usd: 0,
                spent_tokens: 0,
                trace_parent: None,
            },
            at,
            token_rpm: RateCount { limit: 10, count: 1 },
            tenant_limits: Limits {
                budget_tokens: PerPeriod { day: Some(100), month: None },
                budget_usd: PerPeriod { day: None, month: Some(1.0) },
                ..Limits::default()
            },
            tenant_spend: PerPeriod::default(),
        };
        assert!(a.tenant_budget_used_up().is_none(), "nothing spent yet");
        // What requests in flight reserved counts.
        a.tenant_spend.day = Some(Spend { spent_tokens: 60, reserved_tokens: 40, ..Spend::default() });
        let Some(BrokerError::Limit(r)) = a.tenant_budget_used_up() else { panic!("not refused") };
        assert_eq!((r.level, r.kind), (LimitLevel::Tenant, LimitKind::Budget));
        assert_eq!(
            r.message,
            "daily token budget of the tenant is used up (100 of 100 tokens, requests in flight included); \
             it renews at 2030-03-18T00:00:00Z"
        );
        a.tenant_spend.day = Some(Spend { spent_tokens: 99, ..Spend::default() });
        a.tenant_spend.month = Some(Spend { spent_micro_usd: 1_000_000, ..Spend::default() });
        let Some(BrokerError::Limit(r)) = a.tenant_budget_used_up() else { panic!("not refused") };
        assert_eq!(r.budget.map(|b| (b.period, b.usd)), Some((Period::Month, true)));
        // A budget of zero lets nothing through, as with a reservation.
        a.tenant_limits = Limits { budget_tokens: PerPeriod { day: Some(0), month: None }, ..Limits::default() };
        a.tenant_spend = PerPeriod::default();
        assert!(a.tenant_budget_used_up().is_some());
        a.tenant_limits = Limits::default();
        assert!(a.tenant_budget_used_up().is_none());
    }

    #[test]
    fn header_safety() {
        assert!(check_header_safe("sk-abc_123").is_ok());
        assert!(check_header_safe("sk abc").is_err());
        assert!(check_header_safe("sk\r\nX-Evil: 1").is_err());
        assert!(check_header_safe("café").is_err());
    }
}
