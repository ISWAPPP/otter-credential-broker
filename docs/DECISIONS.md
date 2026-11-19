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
  `max_completion_tokens`. No format translation.
- Responses (JSON or SSE) are streamed unchanged, except that the provider
  key is replaced should it ever appear. The proxy asks for uncompressed
  responses and refuses compressed success bodies, which it could neither
  redact nor account.
- Upstream base URLs come only from configuration; endpoints and query keys
  are allowlisted per provider kind (Anthropic Messages, token counting and
  models; OpenAI-compatible chat completions and models). Batches, files and
  everything else are refused: they would bypass accounting or expose data
  unrelated to the agent's job. Redirects are not followed and proxy
  environment variables are ignored.
- Caller headers are allowlisted; the proxy always sets auth itself.
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
  nothing is hard-coded because prices change. Requests are billed by the
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
