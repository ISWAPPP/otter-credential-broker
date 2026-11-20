# Observability

The binary emits JSON logs, OpenTelemetry spans and Prometheus metrics. None
of them ever contains a secret value, a provider key, a token or a request or
response body (see THREAT_MODEL.md; an adversarial test checks logs at TRACE
level and the full metrics output).

## Logs

JSON lines on stdout, level via `RUST_LOG` (default `info`; e.g.
`RUST_LOG=info,broker_core=debug`). Every line carries the current span and
the span list. The request span `http.request` records `method` (from a fixed
set; anything else is `other`), `route` (the route template, never the raw
path), `status` and `trace_id`, so all lines of one request can be
correlated, also with the platform's traces.

A request refused by a provider's body policy (a tool the provider would
run itself, or MCP servers) is logged at warn, `request refused by the
body policy of the provider`, with the provider, tenant, token id and what
was refused (the tool's index and type); never the body.

Refusals by limits are counted (`ocb_limit_denials_total`), not logged. A
reservation that could not be given back after its retries is logged at
error (`failed to give back a reservation; it stays until its period
ends`) and counted in `ocb_llm_accounting_failures_total`; reading the
limit gauges from the database is logged at warn when it fails.

## Traces

A tracer provider always exists, so spans have real W3C trace and span ids.
Where trace context comes from:

- **admin listener**: an incoming `traceparent` / `tracestate` becomes the
  parent of `http.request` (the platform core is trusted);
- **public listener**: callers are untrusted, so by default their
  `traceparent` is only recorded as a span link and as `caller_trace_id`;
  `http.trust_caller_trace_context = true` makes it the parent instead;
- **tokens**: an LLM token issued with `traceparent` (the platform's run)
  parents every `llm.request` made with that token; a job token issued with
  `traceparent` records its redemption in that trace;
- **outgoing**: the upstream request carries a `traceparent` for the
  `llm.request` span (per provider `propagate_trace_context`, default on).

Export is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` (or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set and `OTEL_SDK_DISABLED` is not
`true`; the protocol is OTLP/HTTP protobuf (port 4318).

```yaml
env:
  - { name: OTEL_EXPORTER_OTLP_ENDPOINT, value: "http://otel-collector.monitoring:4318" }
  - { name: OTEL_SERVICE_NAME, value: "otter-credential-broker" }   # default
  - { name: OTEL_TRACES_SAMPLER, value: "parentbased_traceidratio" }
  - { name: OTEL_TRACES_SAMPLER_ARG, value: "0.25" }
```

Spans:

| Span | Fields | Level |
|---|---|---|
| `http.request` | method, route, status, trace_id, caller_trace_id (public listener) | info |
| `llm.request` | provider, endpoint, model (requested), response_model (reported by the provider), tenant, run_id, token_id, stream, status, input_tokens (all prompt tokens incl. cache), output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, ttft_ms (time to first generated content), duration_ms (until the upstream response ends), usage_source, outcome | info |
| `keeper.llm.authorize` | provider | info |
| `keeper.llm.count`, `keeper.llm.reserve` (windows and budgets of the tenant and the provider) | provider | info |
| `llm.limits`, `keeper.llm.inspect` (`GET /llm/_/limits`) | | info |
| `secret.resolve` | tenant, provider, purpose | info |
| `secret.decrypt` | tenant, secret | info |
| `keeper.job_token.redeem` | tenant, job_id | info |
| `admin.*`, `keeper.*` (secret, token and maintenance operations) | tenant | info |
| `worker.redeem` | | info |
| `db.*` (every query), `crypto.seal` / `crypto.open` / `crypto.rewrap` | | debug |

`llm.request` lives as long as the upstream exchange, which can outlast the
caller's connection. Its `outcome`:

| Outcome | Meaning |
|---|---|
| `complete` | response delivered to the caller to the end |
| `client_gone` | caller hung up, stopped reading or stopped waiting; the upstream response was still read to the end and accounted from its usage report |
| `stream_error` | the upstream body failed or stalled past the idle timeout |
| `upstream_status` | non-2xx from the provider |
| `timeout` | no response head within the total time limit |
| `connect` | no connection to the provider (nothing billed) |
| `send_error` | the request failed after connecting |
| `bad_encoding` | compressed response body, refused |
| `shutdown` | cut at the end of the shutdown grace period |

## Metrics

Served on the metrics listener (`metrics_listen`, default `:9090`) at
`GET /metrics`. Histograms use buckets from 5 ms to 30 min.

| Metric | Type | Labels |
|---|---|---|
| `http_request_duration_seconds` | histogram | method (fixed set or `other`), route, status |
| `ocb_auth_failures_total` | counter | realm = admin, llm, job |
| `ocb_llm_request_duration_seconds` | histogram | provider, model, status |
| `ocb_llm_time_to_first_token_seconds` | histogram | provider, model |
| `ocb_llm_tokens_total` | counter | tenant, provider, model, type = input, output, cache_read, cache_write |
| `ocb_llm_cost_microdollars_total` | counter | tenant, provider, model |
| `ocb_llm_budget_denials_total` | counter | tenant, kind = tokens, usd, unpriced_model (refusals by the token's budget, and of unpriced models under a USD budget of any level) |
| `ocb_limit_denials_total` | counter | level = token, tenant, global; kind = rpm, concurrent, budget; provider (empty when the replica's total of requests in flight refused); tenant (the tenant of the refused request, whatever the level) |
| `ocb_limit_quota` | gauge | level = tenant, global; tenant (empty for global); provider (empty for tenant); kind = tokens_day, tokens_month, usd_day, usd_month (the budget, USD in dollars) |
| `ocb_limit_remaining` | gauge | same as `ocb_limit_quota`: what is left of the budget in the current period, reservations of requests in flight counted as used; NaN once the budget is removed |
| `ocb_llm_token_expiry_timestamp` | gauge | tenant, label (live tokens with a label: the latest expiry per tenant and label, Unix seconds; NaN once none is left) |
| `ocb_llm_rate_limited_total` | counter | tenant |
| `ocb_llm_rejected_total` | counter | reason (error code of a request the proxy refused or could not complete, e.g. `unauthorized`, `rate_limited`, `too_many_in_flight`, `budget_exceeded`, `server_tool_denied`, `upstream_timeout`, `upstream_unavailable`, `upstream_bad_encoding`, `shutting_down`) |
| `ocb_llm_errors_total` | counter | provider, kind = an `outcome` other than `complete` |
| `ocb_llm_usage_estimated_total` | counter | provider |
| `ocb_llm_unpriced_response_model_total` | counter | provider (billed at the highest configured price) |
| `ocb_llm_inflight_requests` | gauge | provider |
| `ocb_llm_accounting_failures_total` | counter | (usage write failed after retries) |
| `ocb_llm_key_redactions_total` | counter | provider (the provider key redacted from a success body, or a response header dropped because it held the key or the caller's token) |
| `ocb_integrity_failures_total` | counter | table = llm_tokens, job_tokens (row MAC check failed) |
| `ocb_secret_decrypts_total` | counter | purpose = llm.proxy, job |
| `ocb_job_redemptions_total` | counter | result = ok, unauthorized, error |
| `ocb_config_version` | gauge | (version of the provider configuration in use: the first 48 bits of a SHA-256 over providers, prices and TLS file contents; equal on replicas that serve the same configuration) |
| `ocb_config_reload_total` | counter | result = applied, unchanged, invalid, restart_required (one per change looked at: a changed config file, a changed set of TLS files in use, or a refused config file looked at again because a TLS file it names changed) |
| `ocb_config_reload_pending` | gauge | (1 while the config file or the TLS files in use hold a change that is not applied: refused, waiting for a restart, or the config file cannot be read; 0 otherwise) |
| `ocb_upstream_tls_cert_expiry_timestamp` | gauge | provider (providers with `tls`: earliest `notAfter` of the CA and client certificates, Unix seconds; NaN once a reload removed the provider's TLS settings) |

Label cardinality is bounded: `model` is the configured price entry (prefix
patterns without `*`), `max` for the highest-price fallback, or `other`,
never a caller's string; `method` comes from a fixed set; `route` is the
route template; `provider` is a configured provider id; `level` and `kind`
come from fixed sets; `tenant` grows with the number of tenants. `label` of
`ocb_llm_token_expiry_timestamp` is chosen by the platform when it issues
a token: give tokens labels that name a role (`agent`, `probe`), not a run,
since every tenant and label pair is a series. At most 1000 pairs are
exported (a warning says when there are more).

`ocb_limit_quota`, `ocb_limit_remaining` and
`ocb_llm_token_expiry_timestamp` are read from the database every 30
seconds on each replica, so every replica exports the same values (take
`max` across them), and a budget's values are right as soon as a new
period starts, before any request touches it.

A configuration reload logs one line per change it looks at: `provider
configuration reloaded` (info, with the new and previous version), a note
that the file changed but not its providers or prices (info, `unchanged`),
or a warning that names the problem (a validation error, TLS files that
cannot be used, or the keys that need a restart; never their values). The
first look after start, which finds the file the process started with, is
neither logged nor counted.

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: otter-credential-broker
    metrics_path: /metrics
    kubernetes_sd_configs:
      - role: endpoints
        namespaces: { names: [credential-broker] }
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        regex: credential-broker-metrics
        action: keep
```

### Prometheus Operator

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: credential-broker
  namespace: credential-broker
spec:
  selector:
    matchLabels: { app.kubernetes.io/name: credential-broker }
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

The NetworkPolicy in `deploy/k8s/broker.yaml` admits the `monitoring`
namespace to port 9090 only.

## Suggested alerts

```yaml
groups:
  - name: otter-credential-broker
    rules:
      - alert: CredentialBrokerIntegrityFailures
        expr: increase(ocb_integrity_failures_total[10m]) > 0
        annotations: { summary: "A token row failed its MAC check: the database was changed outside the broker" }
      - alert: CredentialBrokerAuthFailures
        expr: sum by (realm) (rate(ocb_auth_failures_total[5m])) > 1
        for: 5m
      - alert: CredentialBrokerAccountingFailures
        expr: increase(ocb_llm_accounting_failures_total[10m]) > 0
        annotations: { summary: "LLM usage could not be recorded; budgets may be undercounted" }
      - alert: CredentialBrokerKeyReflected
        expr: increase(ocb_llm_key_redactions_total[10m]) > 0
        annotations: { summary: "An upstream response contained the provider key (redacted)" }
      - alert: CredentialBrokerUnpricedModels
        expr: increase(ocb_llm_unpriced_response_model_total[1h]) > 0
        annotations: { summary: "Provider answered with a model that has no price; add it to llm.pricing" }
      - alert: CredentialBrokerUpstreamErrors
        expr: sum by (provider) (rate(ocb_llm_errors_total{kind=~"timeout|connect|send_error|stream_error"}[10m])) > 0.05
        for: 10m
      - alert: CredentialBrokerBudgetDenials
        expr: sum by (tenant) (increase(ocb_llm_budget_denials_total[1h])) > 0
        annotations: { summary: "Tenant {{ $labels.tenant }} hit an LLM budget" }
      - alert: CredentialBrokerTenantBudgetLow
        expr: max by (tenant, kind) (ocb_limit_remaining{level="tenant"} / ocb_limit_quota{level="tenant"}) < 0.1
        annotations: { summary: "Less than a tenth left of the {{ $labels.kind }} budget of tenant {{ $labels.tenant }}" }
      - alert: CredentialBrokerProviderBudgetLow
        expr: max by (provider, kind) (ocb_limit_remaining{level="global"} / ocb_limit_quota{level="global"}) < 0.1
        annotations: { summary: "Less than a tenth left of the {{ $labels.kind }} budget of provider {{ $labels.provider }}" }
      - alert: CredentialBrokerLimitDenials
        expr: sum by (level, tenant) (increase(ocb_limit_denials_total{level!="token"}[15m])) > 0
        annotations: { summary: "Requests of tenant {{ $labels.tenant }} refused by a {{ $labels.level }} limit" }
      - alert: CredentialBrokerLabelledTokenExpiring
        expr: max by (tenant, label) (ocb_llm_token_expiry_timestamp) - time() < 86400
        annotations: { summary: "The {{ $labels.label }} token of tenant {{ $labels.tenant }} expires within a day" }
      - alert: CredentialBrokerSlowFirstToken
        expr: histogram_quantile(0.95, sum by (le, provider) (rate(ocb_llm_time_to_first_token_seconds_bucket[10m]))) > 20
        for: 15m
      - alert: CredentialBrokerConfigNotApplied
        expr: max(ocb_config_reload_pending) > 0
        for: 5m
        annotations: { summary: "The config file or a provider's TLS files hold a change that is refused or needs a restart; see the broker's log" }
      - alert: CredentialBrokerConfigDiverged
        expr: count(count_values("version", ocb_config_version)) > 1
        for: 15m
        annotations: { summary: "Replicas serve different provider configurations" }
      - alert: CredentialBrokerUpstreamCertExpiring
        expr: ocb_upstream_tls_cert_expiry_timestamp - time() < 14 * 86400
        annotations: { summary: "A TLS certificate of provider {{ $labels.provider }} expires within 14 days" }
```
