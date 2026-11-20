# Decisions

Design decisions and their reasons. Each is marked **accepted**, or **open**
where a part is not decided yet.

## D-001 PostgreSQL, stateless replicas (accepted)

All shared state (secrets, tokens, rate-limit windows, budgets, usage,
audit) is in PostgreSQL, so the service runs as two or more interchangeable
replicas (per-replica load limits are in memory, see D-015).
Correctness-relevant updates are single atomic statements: token validation
plus rate-limit counting, job token redemption, spend accounting.

Queries are literal SQL checked at runtime (no build-time database needed);
timestamps are unix seconds bound from an injectable clock, which keeps
expiry logic testable. Migrations run at startup under sqlx's advisory lock,
or separately (`migrate` command) with a more privileged role.

## D-002 Tenant scoping in the application (accepted; RLS open)

Every query on tenant data filters on `tenant_id`; the tenant of a request
comes from the token row (proxy, worker) or the admin path, never from a
request body. **Open:** add PostgreSQL Row-Level Security as a second line.

## D-003 Write-only secret values (accepted)

No admin route returns a value. Values leave the broker only (a) inside the
proxy as the upstream auth header, (b) to a worker holding a job token for
that secret. Secrets of kind `llm_api_key` are never released to workers,
so provider keys never leave the broker at all.

## D-004 Admin authentication (accepted for now; open: TokenReview)

Static named bearer tokens from a mounted file (`<principal> <token>`),
compared as SHA-256 digests in constant time, behind the `Authenticator`
trait. **Open:** Kubernetes TokenReview of projected, audience-bound
ServiceAccount tokens (no shared secret to distribute); needs RBAC for
`tokenreviews.create`.

## D-005 Envelope encryption with a pluggable KeyProvider (accepted)

Per-record random DEK, XChaCha20-Poly1305 (random 192-bit nonces), DEK
wrapped by a KEK from `KeyProvider`. AAD binds the record to tenant, name
and kind. `kek_id` stored per record; `LocalKeyProvider` holds the current KEK
and retired ones for unwrapping; `POST /v1/admin/kek/rewrap` moves records to
the current KEK without decrypting values. Later: Vault Transit or a cloud
KMS behind the same trait.

## D-006 Tokens: random, prefixed, keyed digests, row MACs (accepted)

`ocb_llm_` / `ocb_job_` + 32 random bytes in hex. Stored as
HMAC-SHA256 under a token key (`token_key_file`), not as a plain hash, so
write access to the database alone cannot plant a row for a token of one's
choosing. Each token row also carries a MAC over its authorization fields
(tenant, provider list or job id and secret list, expiry), so they cannot be
widened in the database. Prefixes let secret scanners find leaked tokens and
make cross-type use impossible. Validation hits the database on every request
(no cache), so revocation is immediate across replicas. Changing the token
key invalidates every token (tokens are short-lived; reissue).

## D-007 Observability (accepted)

JSON logs with span context, OpenTelemetry spans with W3C trace context
always on (export via `OTEL_*` when configured), Prometheus metrics on a
separate port. See OBSERVABILITY.md.

## D-008 License (open)

Not chosen yet; `LICENSE` is a placeholder until it is.

## D-009 LLM proxy: transparent, allowlisted (accepted)

- Request bodies are forwarded byte for byte; the proxy reads only `model`,
  `stream`, `stream_options.include_usage` and `max_tokens` /
  `max_completion_tokens`, and `tools` and `mcp_servers` for a provider
  with a body policy (D-021). No format translation.
- Responses (JSON or SSE) are streamed unchanged, except that the provider
  key is replaced should it ever appear. The proxy asks for uncompressed
  responses and refuses compressed success bodies, which it could neither
  redact nor account.
- Upstream base URLs come only from configuration; endpoints and query keys
  are allowlisted per provider kind (Anthropic Messages, token counting and
  models; OpenAI-compatible chat completions and models), and a provider
  can narrow that to some of its kind's endpoints (`endpoints`). Batches,
  files and everything else are refused: they would bypass accounting or
  expose data unrelated to the agent's job. Redirects are not followed and
  proxy environment variables are ignored.
- Caller headers are allowlisted per kind, and a provider can add more by
  prefix (D-021); the proxy always sets auth itself.
- The token is accepted as `x-api-key` or `Authorization: Bearer`, so stock
  SDKs work by changing only the base URL and the key.
- Proxy errors use the provider's error shape. A used-up budget is 402: the
  common SDKs do not retry it (they retry 429).

## D-010 Usage accounting and budgets (accepted)

- Each upstream exchange runs in its own task, which owns the response and
  the accounting. When the caller hangs up, stops reading or stops waiting,
  the task reads the upstream response to its end, so usage comes from the
  provider's own report (Anthropic `message_start` and cumulative
  `message_delta` usage, OpenAI-compatible `usage` including the final
  streaming chunk) and cannot be avoided by disconnecting. Trade-off: a
  generation the caller abandons still runs to completion and is billed.
  **Open:** an opt-in "abort and charge `max_tokens`" mode.
- Without a report the row is `estimated`: input from the report or the
  request size, output from the generated text; when the provider may have
  billed unseen output (no response, stalled or failed stream, shutdown cut,
  compressed body) at least the request's `max_tokens` /
  `max_completion_tokens`.
- OpenAI-compatible streaming requests must ask for usage
  (`stream_options.include_usage`), because the body is never modified;
  per provider this can be turned off (`require_stream_usage = false`) for
  providers that always send usage.
- Budgets: pre-check before forwarding, atomic and saturating
  post-accounting. Tokens with a USD budget may only use priced models.
  Token budgets count all input (including cache reads and writes) plus
  output.
- Prices are configuration (USD per million tokens, exact model or prefix);
  nothing is hard-coded because prices change. A provider can use another
  provider's prices (`pricing_from`), e.g. a gateway in front of a public
  API. Requests are billed by the
  model the provider reports as having answered; one without a price is
  billed at the provider's highest configured price. Zero prices need
  `free = true`.
- Usage writes are retried a few times. **Open:** a durable outbox, and
  reservations to bound overshoot by concurrent requests.

## D-011 Three listeners (accepted)

Public (`/llm/*`, `/v1/worker/*`), admin (`/v1/admin/*`) and metrics on
separate ports, so network policy can admit agent pods to the proxy only,
the platform core to the admin API only, and monitoring to metrics only
(metrics carry tenant labels).

## D-012 TOML configuration (accepted)

Configuration files are TOML, overridable by environment variables (`OCB_`
prefix, `__` for nesting). YAML was ruled out because the YAML parser
available to the config loader is unmaintained and flagged by `cargo deny`.

## D-013 Provider keys per tenant (accepted; sharing open)

The proxy uses the key stored as `llm.<provider>` in the token's tenant. A
platform that wants several tenants to use one key stores it in each tenant
(rotation means updating each copy). **Open:** an explicit, audited
"shared key" grant if copying becomes a burden; cross-tenant fallback is
deliberately not implemented.

## D-014 Linking LLM calls and jobs to a platform run (accepted)

An LLM token may carry the run's `traceparent`; the proxy then parents its
`llm.request` spans on it, so LLM calls appear in the run's trace even when
the agent does not propagate trace context. Issuing one token per run also
gives per-run budgets and usage (`run_id`). A job token may carry the job's
`traceparent`, which then becomes the trace id of its redemption and decrypt
audit rows.

## D-015 Connection handling and per-replica limits (accepted)

The broker runs its own HTTP/1.1 accept loop (hyper) instead of the default
server helper, to get a header read timeout, a connection cap per listener
and the client address on every request. Limits that only bound one
replica's load are kept in memory: requests in flight per LLM token and in
total, and failed token checks per client address and minute (refused
without a database lookup once over the limit). Limits that must hold across
replicas (rate limit, budgets) stay in PostgreSQL. Shutdown is staged: stop
accepting, give in-flight requests a grace period, then cut them and account
conservatively.

## D-016 Caller trace context is untrusted on the public listener (accepted)

Agent pods are untrusted, so on the public listener a caller's `traceparent`
is recorded only as a span link (`caller_trace_id`); spans, audit rows and
usage rows use the broker's own trace or the trace given by the platform at
token issuance (D-014). `http.trust_caller_trace_context = true` makes the
caller's context the parent, for deployments that trust their agents' trace
propagation. The admin listener always honours it.

## D-017 Providers come only from configuration (accepted)

The admin API lists providers (`GET /v1/admin/providers`) but cannot create
or change them. A provider's base URL and TLS trust decide where tenants'
keys are sent. An API that could change them would let anyone holding an
admin token point a provider at a host of their choosing and collect every
tenant's key on the next requests, although the broker otherwise never
releases provider keys, not even to admins (D-003). Provider changes go
through the config file instead, which is reviewed and deployed like code
and reloaded without a restart (D-019). The list shows only the host of a
base URL, so a path that carries account details stays out of the API.

## D-018 One route for every provider; explicit access (accepted)

`/llm/p/<id>/...` reaches any configured provider, so several providers of
one kind (a public API and a gateway in front of it, say) need no routes of
their own; `/llm/anthropic/...` and `/llm/openai/<id>/...` stay as they
were. The new route has its own prefix, so no provider id can shadow an
older route. The ids `p` and `limits` are reserved anyway, so that no
provider id reads like a path of the broker itself: `p` is the prefix of
the route, and `limits` is kept for a later endpoint. Reserving names
before a first release costs little, and giving them back later breaks
nothing, while reserving them later would. It does turn away a
configuration that used either id for an `openai` provider, which loaded
before: rename such a provider, store each tenant's key under the new
`llm.<id>` and reissue tokens whose `providers` list names it.

A token without a `providers` list may use every provider, as before. That
is the wrong default for a provider meant for a few tokens only (one
tenant's gateway, an expensive pool): with `access = "explicit"` a provider
serves only tokens whose list names it. The check uses the token row's
provider list, which the row MAC covers.

Provider ids are not secret. An unknown id, or an endpoint a provider does
not serve, gets 404 before the token is checked, as on the older routes,
so a caller without a token can list the configured ids. Hiding them would
need a token lookup before every 404; access depends on the token check,
not on ids being unknown, so ids should simply not carry confidential
names.

## D-019 Reloading providers and prices (accepted)

Providers, prices and the clients of providers with TLS settings form one
immutable snapshot, and a request keeps the snapshot it started with until
its accounting is done. State that must outlive a reload (exchange tasks,
the shutdown switch, in-flight limits, the failed-token limiter) is not in
the snapshot and is never replaced, so a reload can neither reset limits
nor hide a stream from shutdown.

The config file and the TLS files are polled by content hash
(`reload_interval_secs`) rather than watched through file-system events:
polling needs no extra dependency and sees Kubernetes volume updates, which
swap a `..data` link. A changed file is loaded and validated in full. Only
`llm.providers`, `llm.pricing` and TLS file contents are applied; any other
change is reported as needing a restart and nothing is applied, because
listeners, keys, the database pool and limits are set up once, and half an
applied file would leave the process in a state no file describes. An
invalid file is refused. A file refused only because the TLS files it
names cannot be used yet is looked at again whenever one of them changes:
ConfigMap and Secret volumes are updated independently, and without the
retry such a change would only apply after the next edit of the file or a
restart. `ocb_config_version` is a fingerprint of the
configuration rather than a counter, so replicas that serve the same
configuration report the same value.

## D-020 TLS settings per provider (accepted)

A provider with `tls` gets an HTTP client of its own that trusts only the
CA certificates in `ca_file` (built-in and platform roots off) and presents
its client certificate, if one is configured. The other providers share a
client that never presents one. Trust per provider means a private CA
cannot vouch for public hosts, a public CA cannot vouch for the private
endpoint, and a client certificate only goes to the endpoint it was issued
for. Certificate files are reloaded when they change (D-019); a renewed
certificate that does not match its key is refused until it does.

## D-021 Header and body policy per provider (accepted)

What passes besides the body stays closed by default: caller headers on
the allowlist of the provider's kind, and `content-type`, `cache-control`,
`retry-after`, `request-id`, `x-request-id` and `x-should-retry` back.
`x-should-retry` joined that list because the common SDKs follow it over
their own guess from the status, and it says nothing about the account.

A provider can pass more headers in each direction by name prefix
(`headers.request_forward_prefixes`, `headers.response_forward_prefixes`).
A gateway in front of one owner's account may need every header the SDK
sends, and the owner may want its rate-limit headers to reach the caller.
Opening this by default would show agent pods the account details and
rate-limit use of keys on providers that serve several tenants, and let
agents send headers that change what a provider does, so it is a setting
of the provider, meant for providers whose headers concern one owner.
Prefixes rather than exact names, because a provider's headers come in
families that grow (a rate limit per window, a header per SDK option); a
prefix as long as a whole name serves for one header. Credentials,
cookies, routing, framing, hop-by-hop and the broker's own headers never
pass, nor, on the way back, `set-cookie`, `www-authenticate`, `location`,
`alt-svc` and the `ratelimit*` and `ocb-*` names kept for the broker's own
limit headers. A prefix that could match one of them is refused at load
rather than narrowed in silence, and the list is applied again to each
header forwarded, so neither check depends on the other.

With `body.deny_server_tools`, a provider of kind `anthropic` refuses
requests that would have it act on the network itself: a non-empty
`mcp_servers`, or a tool whose `type` is not `custom`. Agent pods may reach
only the broker; tools the provider runs on its side (web search and
fetch, code execution, MCP connections) would let them fetch and send data
anywhere through it. Any type but `custom` counts, the provider's
client-side tools included: the broker cannot tell where a type runs, and a
new tool should be reviewed before it passes. Allowed types
(`server_tool_allowlist`) are compared exactly, version date included,
since a newer version of a tool can do more. Only `tools` and `mcp_servers`
are read, the body is forwarded unchanged, and a key given twice makes the
body unreadable, so that the broker and the provider cannot read different
values. Token counting is checked like messages because it takes the same
fields. The `openai` kind has no body policy: OpenAI-compatible providers
spell their server-side features in their own ways, and a setting that
checked nothing would only look like protection, so asking for one is a
configuration error.

Both are part of the provider configuration: reloaded like the rest of it
(D-019) and shown by `GET /v1/admin/providers` (D-017).
