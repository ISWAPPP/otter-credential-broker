-- otter-credential-broker schema (PostgreSQL).
-- Timestamps are unix seconds (BIGINT). Every tenant-owned row carries
-- tenant_id and every query filters on it.

-- Envelope-encrypted secrets: one random DEK per record, wrapped by the KEK
-- named in kek_id. (tenant_id, name, kind) is bound into the AEAD associated
-- data, so a row moved, renamed or re-kinded in the database fails to decrypt.
CREATE TABLE secrets (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    version     BIGINT NOT NULL CHECK (version >= 1),
    kek_id      TEXT NOT NULL,
    wrapped_dek BYTEA NOT NULL,
    ciphertext  BYTEA NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    created_by  TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    CONSTRAINT secrets_tenant_name UNIQUE (tenant_id, name)
);
CREATE INDEX secrets_kek_id ON secrets (kek_id);

-- Internal LLM tokens. Only a keyed digest (HMAC) of the token is stored;
-- auth_mac authenticates id, tenant, provider list and expiry.
CREATE TABLE llm_tokens (
    id                    TEXT PRIMARY KEY,
    token_hash            BYTEA NOT NULL UNIQUE,
    auth_mac              BYTEA NOT NULL,
    tenant_id             TEXT NOT NULL,
    run_id                TEXT,
    label                 TEXT,
    providers             TEXT[],
    budget_micro_usd      BIGINT CHECK (budget_micro_usd IS NULL OR budget_micro_usd >= 0),
    budget_tokens         BIGINT CHECK (budget_tokens IS NULL OR budget_tokens >= 0),
    spent_micro_usd       BIGINT NOT NULL DEFAULT 0,
    spent_tokens          BIGINT NOT NULL DEFAULT 0,
    request_count         BIGINT NOT NULL DEFAULT 0,
    rate_limit_per_minute INTEGER NOT NULL CHECK (rate_limit_per_minute > 0),
    rl_window             BIGINT NOT NULL DEFAULT 0,
    rl_count              INTEGER NOT NULL DEFAULT 0,
    trace_parent          TEXT,
    created_at            BIGINT NOT NULL,
    expires_at            BIGINT NOT NULL,
    revoked_at            BIGINT,
    last_used_at          BIGINT,
    created_by            TEXT NOT NULL
);
CREATE INDEX llm_tokens_tenant ON llm_tokens (tenant_id, created_at);

-- Single-use job tokens for workers: one tenant, an explicit list of secrets.
-- auth_mac authenticates id, tenant, job id, secret list and expiry.
CREATE TABLE job_tokens (
    id           TEXT PRIMARY KEY,
    token_hash   BYTEA NOT NULL UNIQUE,
    auth_mac     BYTEA NOT NULL,
    tenant_id    TEXT NOT NULL,
    job_id       TEXT NOT NULL,
    secret_names TEXT[] NOT NULL,
    trace_parent TEXT,
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL,
    used_at      BIGINT,
    revoked_at   BIGINT,
    created_by   TEXT NOT NULL
);
CREATE INDEX job_tokens_tenant ON job_tokens (tenant_id, created_at);

-- One row per proxied LLM request (accounting). Never contains bodies or keys.
CREATE TABLE llm_usage (
    id                 BIGSERIAL PRIMARY KEY,
    ts                 BIGINT NOT NULL,
    token_id           TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    run_id             TEXT,
    provider           TEXT NOT NULL,
    endpoint           TEXT NOT NULL,
    model              TEXT,
    response_model     TEXT,
    status             INTEGER NOT NULL,
    input_tokens       BIGINT NOT NULL,
    output_tokens      BIGINT NOT NULL,
    cache_read_tokens  BIGINT NOT NULL,
    cache_write_tokens BIGINT NOT NULL,
    cost_micro_usd     BIGINT NOT NULL,
    usage_source       TEXT NOT NULL CHECK (usage_source IN ('reported', 'estimated', 'none')),
    duration_ms        BIGINT NOT NULL,
    ttft_ms            BIGINT,
    trace_id           TEXT
);
CREATE INDEX llm_usage_tenant ON llm_usage (tenant_id, id);
CREATE INDEX llm_usage_token ON llm_usage (token_id, id);

-- Audit log: every write, every token issue/revoke/redeem, every decrypt.
-- Never contains secret values.
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          BIGINT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    tenant_id   TEXT,
    secret_name TEXT,
    purpose     TEXT,
    trace_id    TEXT,
    detail      TEXT
);
CREATE INDEX audit_log_tenant ON audit_log (tenant_id, id);
