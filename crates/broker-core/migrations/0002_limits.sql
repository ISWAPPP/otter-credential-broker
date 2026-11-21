-- Limits of tenants and providers (docs/ARCHITECTURE.md, "Limits"). The
-- token level keeps its limits in llm_tokens. On the tenant level
-- `provider` is '', on the global level (a provider, for every tenant)
-- `tenant_id` is ''.

-- Limits of a tenant on every provider, set through the admin API. NULL is
-- no limit; USD is in micro-USD.
CREATE TABLE tenant_limits (
    tenant_id              TEXT PRIMARY KEY,
    rpm                    INTEGER CHECK (rpm IS NULL OR rpm > 0),
    concurrent             INTEGER CHECK (concurrent IS NULL OR concurrent > 0),
    budget_tokens_day      BIGINT CHECK (budget_tokens_day IS NULL OR budget_tokens_day >= 0),
    budget_tokens_month    BIGINT CHECK (budget_tokens_month IS NULL OR budget_tokens_month >= 0),
    budget_micro_usd_day   BIGINT CHECK (budget_micro_usd_day IS NULL OR budget_micro_usd_day >= 0),
    budget_micro_usd_month BIGINT CHECK (budget_micro_usd_month IS NULL OR budget_micro_usd_month >= 0),
    updated_at             BIGINT NOT NULL,
    updated_by             TEXT NOT NULL
);

-- Requests in the current one-minute window of a tenant or a provider, for
-- levels with a requests-per-minute limit.
CREATE TABLE limit_rpm (
    level     TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    provider  TEXT NOT NULL,
    rl_window BIGINT NOT NULL,
    rl_count  INTEGER NOT NULL,
    PRIMARY KEY (level, tenant_id, provider),
    CONSTRAINT limit_rpm_scope CHECK ((level = 'tenant' AND tenant_id <> '' AND provider = '')
                                   OR (level = 'global' AND tenant_id = '' AND provider <> ''))
);

-- Spend of a tenant or a provider per UTC day or month, for levels with a
-- budget. A period is keyed by its start, so a new period is a new row and
-- nothing has to reset counters. A request is counted in the period it was
-- authorized in. reserved_* holds what requests in flight reserved;
-- accounting moves their actual usage to spent_*. limit_* is the limit that
-- was in force when the row last took a reservation.
CREATE TABLE limit_spend (
    level              TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    provider           TEXT NOT NULL,
    period_kind        TEXT NOT NULL CHECK (period_kind IN ('day', 'month')),
    period_start       BIGINT NOT NULL,
    spent_tokens       BIGINT NOT NULL DEFAULT 0,
    spent_micro_usd    BIGINT NOT NULL DEFAULT 0,
    reserved_tokens    BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    reserved_micro_usd BIGINT NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
    limit_tokens       BIGINT,
    limit_micro_usd    BIGINT,
    PRIMARY KEY (level, tenant_id, provider, period_kind, period_start),
    CONSTRAINT limit_spend_scope CHECK ((level = 'tenant' AND tenant_id <> '' AND provider = '')
                                     OR (level = 'global' AND tenant_id = '' AND provider <> ''))
);

-- Live tokens with a label, for their expiry metric.
CREATE INDEX llm_tokens_labelled ON llm_tokens (expires_at) WHERE label IS NOT NULL AND revoked_at IS NULL;
