# API

Errors of the admin API and the worker endpoint:
`{"error": "<code>", "message": "..."}`. Errors produced by the proxy on
`/llm/*` use the provider's own error shape so SDKs show the message
(`{"type":"error","error":{"type","message","code"}}` for Anthropic,
`{"error":{"message","type","code"}}` for OpenAI-compatible routes).

## Public listener (`listen`, default `:8080`): agent pods and workers

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/healthz`, `/readyz` | none | liveness; readiness checks PostgreSQL |
| POST | `/llm/anthropic/v1/messages` | LLM token | billable, JSON or SSE |
| POST | `/llm/anthropic/v1/messages/count_tokens` | LLM token | free |
| GET | `/llm/anthropic/v1/models` | LLM token | free |
| POST | `/llm/openai/<provider>/chat/completions` | LLM token | billable, JSON or SSE |
| GET | `/llm/openai/<provider>/models` | LLM token | free |
| POST | `/v1/worker/secrets` | job token (`Bearer`) | returns the job's secrets once |

Anything else under `/llm/` is refused (404), as are query keys other than
`beta`, `limit`, `after_id`, `before_id` (Anthropic) and none (OpenAI).

Proxy status codes: upstream statuses are passed through; the broker's own
are 400 (invalid request, unpriced model with a USD budget, streaming without
usage), 401 (missing, unknown, expired or revoked token), 402
`budget_exceeded`, 403 (provider not allowed for the token, or no key for the
tenant), 404 (unknown provider or endpoint), 413, 429 `rate_limited` (token
rate limit, or too many failed token checks from one address) or
`too_many_in_flight`, both with `Retry-After`, 502 `upstream_unavailable` or
`upstream_bad_encoding` (compressed response refused), 503 `shutting_down`,
504 `upstream_timeout` (the caller stopped waiting; the request still runs to
its end upstream and is accounted).

Worker response: `{"job_id", "tenant", "secrets": [{"name", "kind", "value"}]}`
with `Cache-Control: no-store`. A second redemption, an expired or a revoked
token all get 401.

## Admin listener (`admin_listen`, default `:8081`): the platform core

All routes need `Authorization: Bearer <admin token>`. `{t}` is a tenant id
(`[A-Za-z0-9._-]`, 1-64 chars); tenants are implicit.

| Method | Path | Body / query | Result |
|---|---|---|---|
| GET | `/v1/admin/tenants/{t}/secrets` | | names, kinds, metadata, versions (no values) |
| POST | `/v1/admin/tenants/{t}/secrets` | `{name, kind, value, metadata?}` | 201 metadata; 409 if the name exists |
| GET | `/v1/admin/tenants/{t}/secrets/{name}` | | metadata |
| PATCH | `/v1/admin/tenants/{t}/secrets/{name}` | `{value?, metadata?}` | metadata; a new value bumps `version` |
| DELETE | `/v1/admin/tenants/{t}/secrets/{name}` | | 204 |
| POST | `/v1/admin/tenants/{t}/llm-tokens` | `{run_id?, label?, providers?, budget_usd?, budget_tokens?, ttl_secs?, rate_limit_per_minute?, traceparent?}` | 201 `{token, id, ...}`; the token is shown once |
| GET | `/v1/admin/tenants/{t}/llm-tokens` | `?limit=` | tokens with spend (never the token itself) |
| GET | `/v1/admin/tenants/{t}/llm-tokens/{id}` | | one token with spend |
| POST | `/v1/admin/tenants/{t}/llm-tokens/{id}/revoke` | | 204; effective on the next request |
| POST | `/v1/admin/tenants/{t}/job-tokens` | `{job_id, secrets: [names], ttl_secs?, traceparent?}` | 201 `{token, id, ...}` |
| GET | `/v1/admin/tenants/{t}/job-tokens` | `?limit=` | job tokens (state, never the token) |
| POST | `/v1/admin/tenants/{t}/job-tokens/{id}/revoke` | | 204 |
| GET | `/v1/admin/tenants/{t}/usage` | `?run_id=&token_id=&limit=` | accounted LLM requests |
| GET | `/v1/admin/audit` | `?tenant=&limit=` | audit log, newest first |
| POST | `/v1/admin/kek/rewrap` | `?limit=` | re-wraps DEKs not under the current KEK |

Secret names are `[A-Za-z0-9._-]` (1-128 chars); kinds are `[a-z0-9_]`.
Conventions: a tenant's key for provider `<id>` is the secret `llm.<id>` of
kind `llm_api_key`. Secrets of that kind are used only by the proxy and are
never handed out, not even through job tokens.

## Metrics listener (`metrics_listen`, default `:9090`)

`GET /metrics` (Prometheus text format), `GET /healthz`. Kept off the public
listener because metrics carry tenant labels.
