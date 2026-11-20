# API

Errors of the admin API and the worker endpoint:
`{"error": "<code>", "message": "..."}`. Errors produced by the proxy on
`/llm/*` use the error shape of the provider's kind so SDKs show the
message (`{"type":"error","error":{"type","message","code"}}` for
Anthropic, `{"error":{"message","type","code"}}` for OpenAI-compatible
providers). A request for an unknown provider on `/llm/p/` gets the
OpenAI-compatible shape.

## Public listener (`listen`, default `:8080`): agent pods and workers

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/healthz`, `/readyz` | none | liveness; readiness checks PostgreSQL |
| GET, POST | `/llm/p/<provider>/<endpoint>` | LLM token | any configured provider, by id |
| GET, POST | `/llm/anthropic/<endpoint>` | LLM token | the provider with id `anthropic` |
| GET, POST | `/llm/openai/<provider>/<endpoint>` | LLM token | providers of kind `openai` |
| POST | `/v1/worker/secrets` | job token (`Bearer`) | returns the job's secrets once |

`<endpoint>` is one of the endpoints of the provider's kind:

| Kind | Name | Method | Endpoint | |
|---|---|---|---|---|
| `anthropic` | `messages` | POST | `v1/messages` | billable, JSON or SSE |
| `anthropic` | `count_tokens` | POST | `v1/messages/count_tokens` | free |
| `anthropic` | `models` | GET | `v1/models` | free |
| `openai` | `chat_completions` | POST | `chat/completions` | billable, JSON or SSE |
| `openai` | `models` | GET | `models` | free |

So an Anthropic SDK uses `http://<broker>:8080/llm/p/<provider>` (or
`/llm/anthropic` for the provider `anthropic`) as its base URL, an
OpenAI-compatible SDK `http://<broker>:8080/llm/p/<provider>` (or
`/llm/openai/<provider>`). A provider may serve only some endpoints of its
kind (`endpoints` in its configuration, by name). Provider ids and paths
are compared exactly as sent, without decoding or normalisation; the ids
`p` and `limits` are reserved.

Anything else under `/llm/` is refused (404), as are query keys other than
`beta`, `limit`, `after_id`, `before_id` (Anthropic) and none (OpenAI).

Headers. The caller headers sent upstream are `content-type`, `accept`,
`anthropic-version` and `anthropic-beta` (kind `anthropic`) or
`content-type`, `accept`, `http-referer` and `x-title` (kind `openai`); the
broker sets the provider's auth, `accept-encoding: identity` and
`traceparent` itself. The response headers passed back are `content-type`,
`cache-control`, `retry-after`, `request-id`, `x-request-id` and
`x-should-retry`. A provider can pass more in either direction by name
prefix (`headers` in its configuration). Never passed, whatever the
prefixes: headers with credentials or cookies, routing, framing and
hop-by-hop headers, the ones the broker sets, and on the way back
`set-cookie`, `www-authenticate`, `location`, `alt-svc`, `ratelimit*` and
`ocb-*`.

Server-side tools. A provider of kind `anthropic` with
`body.deny_server_tools = true` refuses, before anything is sent upstream,
a request to any of its POST endpoints (`messages`, `count_tokens`) whose
`mcp_servers` is not empty, or that has a tool whose `type` is anything but
`custom` (web search, web fetch, code execution and the provider's other
tools), unless that type is on the provider's `server_tool_allowlist`
(compared exactly, version date included). The answer is 400 with code
`server_tool_denied` and a message that names the tool:

```json
{"type": "error", "error": {"type": "invalid_request_error", "code": "server_tool_denied",
  "message": "tools[1] has type web_fetch_20260209, which is not allowed: this provider accepts custom tools and only the tool types it is configured to allow"}}
```

A body that cannot be checked (not a JSON object, `tools` or `mcp_servers`
of another shape, or a key given twice) gets 400 `invalid_request`.

Proxy status codes: upstream statuses are passed through; the broker's own
are 400 (invalid request, unpriced model with a USD budget, streaming without
usage; `server_tool_denied`), 401 (missing, unknown, expired or revoked
token), 402 `budget_exceeded`, 403 (provider not allowed for the token: left
out of its `providers` list, or a provider with `access = "explicit"` that
the list does not name; or no key for the tenant), 404 (unknown provider, or an
endpoint the provider does not serve; answered before the token is
checked, so provider ids are not secret), 413, 429 `rate_limited` (token
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
| GET | `/v1/admin/providers` | | the LLM providers this replica uses (read-only, see below) |

Providers come only from the configuration file; the API cannot add or
change them (see DECISIONS.md, D-017). `GET /v1/admin/providers` answers
for the replica that serves the request:

```json
{
  "config_version": 81985529216486,
  "providers": [
    {"id": "gateway", "kind": "anthropic", "host": "gateway.example.internal:8443",
     "endpoints": ["messages", "count_tokens"], "access": "explicit",
     "has_tls": true, "tls_not_after": 1924992000, "pricing_from": "anthropic",
     "headers": {"request_forward_prefixes": ["anthropic-"],
                 "response_forward_prefixes": ["anthropic-ratelimit-"]},
     "body": {"deny_server_tools": true, "server_tool_allowlist": []}}
  ]
}
```

`config_version` identifies the provider configuration (providers, prices
and the content of TLS files); replicas that serve the same configuration
report the same number. `host` is the host and port of the base URL, never
its path or query. `tls_not_after` is the earliest expiry (Unix seconds) of
the provider's CA and client certificates. `headers` and `body` are the
provider's header prefixes and body policy (empty lists and `false` when
not configured). No keys and no file paths are shown.

Secret names are `[A-Za-z0-9._-]` (1-128 chars); kinds are `[a-z0-9_]`.
Conventions: a tenant's key for provider `<id>` is the secret `llm.<id>` of
kind `llm_api_key`. Secrets of that kind are used only by the proxy and are
never handed out, not even through job tokens.

## Metrics listener (`metrics_listen`, default `:9090`)

`GET /metrics` (Prometheus text format), `GET /healthz`. Kept off the public
listener because metrics carry tenant labels.
