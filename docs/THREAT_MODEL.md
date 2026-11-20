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
8. **Provider configuration and its TLS files**: base URLs and CA files
   decide where keys are sent and which servers are trusted; client
   certificate keys identify the broker to a provider.

## Actors and trust

| Actor | Trust | Reaches |
|---|---|---|
| Platform core | trusted (admin) | admin listener |
| Agent pods | **untrusted**: they run LLM agents that read untrusted content and can be steered by prompt injection | public listener, `/llm/*` with their own token |
| Workers | semi-trusted: execute jobs, receive the secrets of one job at a time | public listener, `/v1/worker/secrets` |
| LLM providers | trusted for confidentiality of the key they issued; their responses are not trusted to be free of reflected data | outbound HTTPS from the broker |
| Broker process, its Secrets (KEK, token key, admin tokens) | trusted | |
| Operators or attackers with database access but without the broker's Secrets | not trusted to read secrets or to mint tokens | PostgreSQL |
| Whoever can change the config file or the providers' TLS files | trusted like whoever deploys the broker: decides where requests and keys go | ConfigMap and Secrets of the broker |

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Agent asks for or exfiltrates the provider key (prompt injection, reading env/files) | The key never enters the pod: the pod holds only an internal token. The key is decrypted inside the broker for the upstream request only and is never put in a body. Exact-match redaction removes the key should an upstream ever reflect it in a success response. |
| Stolen internal LLM token | Works only through the broker (pods have no other route to providers), only for its tenant and allowed providers, within its budget, rate limit and in-flight cap, until its TTL. Revocation is checked on every request (no cache). |
| Token used against another tenant | The tenant comes from the token row, never from the request, and the row's tenant is covered by its MAC. Provider keys are looked up as `(token tenant, llm.<provider>)`; there is no fallback to another tenant's key. Admin routes for token ids and job tokens filter on the tenant in the path. |
| SSRF / redirecting the key to an attacker host | Upstream URLs are built from configuration plus allowlisted constant paths; the request's Host, `X-Forwarded-*`, `Forwarded`, absolute-form request targets and paths are never used to pick a host. Redirects are not followed; proxy environment variables are ignored. Base URLs must be https unless `allow_http` is set explicitly. Tests prove a trap host is never contacted. |
| An admin token used to send tenants' keys elsewhere (changing a provider's base URL or TLS trust) | Providers come only from the config file; the admin API can list them and nothing else. The list shows the host and port of a base URL, not its path, and no keys or file paths. |
| A token without a provider list reaching a provider meant for a few tokens | With `access = "explicit"` a provider serves only tokens whose `providers` list names it. The list is covered by the token row's MAC and checked on every request. |
| Impersonating a provider that is reached over a private network (a gateway with its own CA) | A provider with `tls` trusts only its `ca_file`; built-in and platform roots are off, so a certificate from a public CA or from another provider's CA is refused before anything, the key included, is sent. Tested with a server whose certificate comes from another CA. |
| A client certificate offered to the wrong host | Each provider with `tls` has a client of its own; providers without `tls` use one shared client, which is built without a client certificate. Tested: a provider with `tls` but no client certificate presents none, even to a server that asks, and only providers with `tls` get a client of their own. |
| A bad configuration while the broker runs | A changed config file is validated in full before anything is applied; an invalid one is refused and the running one stays. Changes outside `llm.providers` and `llm.pricing` are not applied until a restart. TLS files that do not fit together (a renewed certificate with the old key) are refused. A change refused only because TLS files it names are missing or do not fit together is tried again whenever one of those files changes, so a change whose Secret is updated after the config file, a stricter `access` say, is not silently left unapplied. Requests in flight keep the configuration they started with; a reload resets neither the in-flight limits nor the failed-token limiter, and shutdown still waits for every stream. |
| Header smuggling (hop-by-hop `Connection`, duplicate auth headers, provider org headers, method override) | The upstream request is built from scratch with an allowlist of caller headers; auth is always set by the broker; ambiguous credentials are refused. CL/TE conflicts are rejected by the HTTP server. A provider can pass more caller headers by prefix, but never credentials, cookies, routing, framing or hop-by-hop headers, nor those the broker sets: a prefix that could match one makes the configuration invalid, and every header forwarded by prefix is checked against the list again. Tested with prefixes that validation would refuse. |
| Response headers that act on the caller or show what is not the caller's (cookies, credential challenges, redirects, account ids, rate limits of a key) | A fixed set of response headers comes back by default. A provider can pass more by prefix, meant for a provider whose headers concern one owner; `set-cookie`, `www-authenticate`, `location`, `alt-svc` and the names kept for the broker's own limit headers (`ratelimit*`, `ocb-*`) never pass, whatever the prefixes. |
| An agent reaching the network through tools the provider runs itself (web search and fetch, code execution, MCP servers named in the request), past the rule that agent pods reach only the broker | `body.deny_server_tools` on a provider of kind `anthropic` refuses, before anything is sent, a request with a non-empty `mcp_servers` or with a tool whose `type` is not `custom` and not on the provider's allowlist (exact types, version date included). Any type but `custom` counts, so a new provider tool is refused until it is reviewed and listed. A key given twice makes the body unreadable, so the broker cannot check one `tools` or `type` while the provider uses another. Off by default; see residual risks for what it does not cover. |
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
- **Write access to the config file or the TLS files** is as powerful as
  deploying the broker: it decides where keys are sent and which servers
  are trusted, and a change applies within seconds, without a restart.
  Protect the ConfigMap and Secrets with RBAC and review changes.
- **Replicas reload independently.** For up to the kubelet's sync delay
  plus `reload_interval_secs`, replicas can serve different provider
  configurations; `ocb_config_version` shows each replica's.
- **Configuration changes affect new requests only.** Removing a provider
  or making it explicit does not stop a stream that is already running.
- **Provider ids are visible without a token.** An unknown provider, or an
  endpoint a provider does not serve, gets 404 before the token is
  checked, so a caller without a token can find out which ids are
  configured and which endpoints each one serves, explicit providers
  included. Ids are not secret: access is enforced by the token check
  (`access = "explicit"` included), not by hiding ids, so an id should not
  carry a confidential name such as a customer's.
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
- **Provider-side egress.** Request bodies are forwarded unchanged. On a
  provider of kind `anthropic` with `body.deny_server_tools`, tools the
  provider would run itself and MCP servers are refused; on any other
  provider an agent can use them if the provider and the request enable
  them. The policy does not cover content the provider fetches by URL
  (image or document blocks with a `url` source), server-side features of
  OpenAI-compatible providers (each spells them its own way, so the
  `openai` kind has no body policy), or features a provider adds outside
  `tools` and `mcp_servers`. Restricting those belongs to the agent
  platform or the provider account.
- **Headers passed by prefix are not inspected.** A prefix passes whatever
  the caller or the provider puts in matching headers. On a provider that
  serves several tenants, a broad response prefix shows one tenant's
  agents the account details and rate-limit use of that tenant's key, and
  a broad request prefix lets agents send headers that change what the
  provider does. This is why the defaults stay closed: the shared
  providers of a default configuration serve tenants with their own keys,
  and the header allowlist is what keeps account details away from agent
  pods. Prefixes are meant for providers whose headers concern one owner,
  and should be as narrow as the use needs.
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
