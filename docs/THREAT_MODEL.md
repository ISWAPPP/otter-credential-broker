# Threat model

## Assets

1. **KEKs**: decrypt every stored secret together with a database copy.
2. **Token key**: keys the digests of issued tokens and the MACs of token
   rows; with database write access it would allow minting tokens.
3. **Stored secrets**: provider API keys (spend money, read account data),
   SSH keys and passwords of tenant servers.
4. **Admin tokens**: full control (write secrets, issue tokens, read audit).
5. **Internal LLM tokens**: spend a tenant's budget through the proxy.
6. **Job tokens**: one-time access to a job's secrets.
7. **Integrity of accounting and audit**: budgets, usage, who decrypted what.

## Actors and trust

| Actor | Trust | Reaches |
|---|---|---|
| Platform core | trusted (admin) | admin listener |
| Agent pods | **untrusted**: they run LLM agents that read untrusted content and can be steered by prompt injection | public listener, `/llm/*` with their own token |
| Workers | semi-trusted: execute jobs, receive the secrets of one job at a time | public listener, `/v1/worker/secrets` |
| LLM providers | trusted for confidentiality of the key they issued; their responses are not trusted to be free of reflected data | outbound HTTPS from the broker |
| Broker process, its Secrets (KEK, token key, admin tokens) | trusted | |
| Operators or attackers with database access but without the broker's Secrets | not trusted to read secrets or to mint tokens | PostgreSQL |

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Agent asks for or exfiltrates the provider key (prompt injection, reading env/files) | The key never enters the pod: the pod holds only an internal token. The key is decrypted inside the broker for the upstream request only and is never put in a body. Exact-match redaction removes the key should an upstream ever reflect it in a success response. |
| Stolen internal LLM token | Works only through the broker (pods have no other route to providers), only for its tenant and allowed providers, within its budget, rate limit and in-flight cap, until its TTL. Revocation is checked on every request (no cache). |
| Token used against another tenant | The tenant comes from the token row, never from the request, and the row's tenant is covered by its MAC. Provider keys are looked up as `(token tenant, llm.<provider>)`; there is no fallback to another tenant's key. Admin routes for token ids and job tokens filter on the tenant in the path. |
| SSRF / redirecting the key to an attacker host | Upstream URLs are built from configuration plus allowlisted constant paths; the request's Host, `X-Forwarded-*`, `Forwarded`, absolute-form request targets and paths are never used to pick a host. Redirects are not followed; proxy environment variables are ignored. Base URLs must be https unless `allow_http` is set explicitly. Tests prove a trap host is never contacted. |
| Header smuggling (hop-by-hop `Connection`, duplicate auth headers, provider org headers, method override) | The upstream request is built from scratch with an allowlist of caller headers; auth is always set by the broker; ambiguous credentials are refused. CL/TE conflicts are rejected by the HTTP server. |
| Avoiding accounting by hanging up (before the response head or mid-stream), reading slowly or making the caller time out | The upstream exchange runs in its own task, which owns accounting and reads the upstream response to its end regardless of the caller; usage comes from the provider's report. Tested for each case. |
| Avoiding accounting with hidden reasoning (billed but not streamed) on aborted responses | Aborted responses are drained (above). Where no report can be had (stalled or failed stream, no response, shutdown cut, compressed body) output is charged at least at the request's `max_tokens` / `max_completion_tokens`. |
| Avoiding accounting via other endpoints (batches, files) or streaming without usage | Only allowlisted endpoints are reachable; OpenAI-compatible streams must request usage (configurable). |
| Paying a cheap model's price for an expensive one (provider-side routing and fallbacks) | Cost uses the model the provider reports as having answered; a model without a price is billed at the provider's highest configured price. |
| Forgotten zero price disabling USD budgets | Zero input or output prices are rejected unless the entry sets `free = true`. |
| Budget overshoot | Pre-check before forwarding, atomic post-accounting, at most `max_concurrent_per_token` requests in flight per token and replica. |
| Key leaks via errors | Provider error bodies are scrubbed (exact key, caller token, credential-like runs) before they are cut to size, so a key at the cut is still removed. Broker errors never contain values or echo caller input; JSON parse errors of the admin API are generic. Internal errors are logged without details sent to the caller. |
| Key leaks via logs, traces, metrics | `Secret<T>` hides values in `Debug`/`Display` and zeroizes on drop; provider auth header values are marked sensitive; incoming `Authorization`, `x-api-key`, `Cookie`, `Proxy-Authorization` are marked sensitive; bodies are never logged; SQL logging carries statements, not bound values; metric labels are bounded (route templates, a fixed set of methods, configured model names, tenant ids). An adversarial test runs many flows with TRACE logging of every crate and checks that no key fragment appears. |
| Database backup or replica leaked | Values are envelope-encrypted; KEKs are not in the database. Tokens are stored as keyed digests (HMAC) of 256-bit random values. |
| Database write access used to read secrets or gain access | Planting a job or LLM token row does not work without the token key (keyed digests). Widening a token row (tenant, secret list, provider list, expiry) fails its MAC. Moving, renaming or re-kinding a sealed secret fails to decrypt (tenant, name and kind are bound as AAD). |
| KEK or token key compromise | Out of scope for file-based keys; use a KMS-backed `KeyProvider` (Vault Transit, cloud KMS) to keep KEKs out of the process. KEK rotation and re-wrap are supported; a new token key invalidates all tokens. |
| Worker over-reach | A job token lists explicit secret names of one tenant, works once, expires quickly (default 5 minutes). Provider keys (kind `llm_api_key`) are never released to workers. |
| Job token replay / race | Single atomic `UPDATE ... WHERE used_at IS NULL`; tested with concurrent redemptions. |
| Stolen admin token | Admin API on its own port, reachable only from the platform core (NetworkPolicy). Tokens are compared in constant time on digests; principals are named for the audit trail. Moving to Kubernetes TokenReview removes long-lived shared tokens. |
| Cross-tenant information via metrics | Metrics are on a separate port reachable only by monitoring. |
| Untrusted callers choosing trace ids (misattributing audit and usage rows, injecting spans into other traces) | On the public listener a caller's `traceparent` is only linked; audit and usage rows carry the broker's trace id or the trace set by the platform at token issuance. |
| Resource exhaustion: slow or many connections, slow request bodies, floods of bad tokens, many concurrent requests, unbounded metric labels | Header read timeout and connection cap per listener; request body read timeout and size limit; failed token checks per address are capped before any database lookup; in-flight caps per token and replica; upstream connect, idle and total timeouts are enforced by the exchange regardless of the caller; method labels from a fixed set. |
| Supply chain | `Cargo.lock` committed, pinned toolchain, `cargo deny` (advisories, licenses, bans incl. OpenSSL, sources), `cargo audit` in CI, new dependency versions at least 14 days old, no `unsafe` in our code. |

## Residual risks and follow-ups

- **Plaintext inside the cluster.** The listeners speak HTTP; rely on
  NetworkPolicy and a mesh or add TLS on the listeners. PostgreSQL supports
  TLS (`sslmode=verify-full`, `sslrootcert=`).
- **Abandoned generations are paid for.** Because the exchange drains the
  upstream response for accounting, a request the caller cancels still runs
  to completion at the provider (bounded by its `max_tokens`) and is billed.
  An "abort and charge `max_tokens`" mode would save that cost.
- **Estimates.** When no usage report exists, output is charged at least at
  the request's `max_tokens`. OpenAI-compatible requests may omit it; then
  hidden reasoning in a stalled or failed stream is not covered.
- **Budget overshoot** by requests already in flight when a budget runs out,
  bounded by `max_concurrent_per_token` × replicas and the cost per request.
  A reservation step (reserve `max_tokens` up front) would close it.
- **Per-replica limits.** In-flight caps and the failed-token limiter are
  kept in memory per replica, so cluster-wide they scale with the number of
  replicas. The limiter is keyed by client address.
- **Prices are configuration.** Wrong prices give wrong USD accounting;
  tiered pricing (long context, server tools such as web search, service
  tiers) is not modelled. Token budgets are exact for what the provider
  reports.
- **Lost accounting writes.** A usage write is retried three times and then
  dropped (counted in `ocb_llm_accounting_failures_total`); a durable outbox
  would remove that window.
- **Exact-match redaction** only catches the key as one contiguous byte
  sequence. A key split across separately encoded fragments would not be
  caught; the model never sees the key, so only a reflecting upstream could
  produce it.
- **Provider-side egress.** Request bodies are forwarded unchanged, so
  provider server-side tools (web fetch, MCP connectors, code execution) are
  available to agents if the provider and the request enable them. Policy for
  that belongs to the agent platform, or to a future body policy in the
  proxy.
- **Revocation does not stop a stream already in progress.** New requests
  are refused immediately.
- **What database write access still allows**: deleting rows, resetting
  spend or raising budgets, replaying an older ciphertext of the same
  tenant, name and kind, and clearing `revoked_at` or `used_at` of a token
  whose value the attacker already has. The audit log is only as strong as
  the database role (see below).
- **No Row-Level Security yet.** Tenant scoping is enforced in every query
  of the application; PostgreSQL RLS would be a second line.
- **Recommended database roles:** a migration role that owns the schema, and
  a runtime role with `SELECT, INSERT, UPDATE, DELETE` on the tables but only
  `INSERT, SELECT` on `audit_log`, so the running service cannot rewrite its
  audit trail.
- **Retention.** `llm_usage`, `audit_log` and spent tokens grow without
  bound; add retention jobs before high volume.
- **Memory hygiene** is best effort: `Secret<T>` zeroizes, but copies made
  by serde, HTTP header values, TLS buffers and the keyed HMAC state are not
  zeroized.
