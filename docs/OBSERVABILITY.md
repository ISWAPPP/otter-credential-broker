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
| `ocb_llm_budget_denials_total` | counter | tenant, kind = tokens, usd, unpriced_model |
| `ocb_llm_rate_limited_total` | counter | tenant |
| `ocb_llm_rejected_total` | counter | reason (error code of a request the proxy refused or could not complete, e.g. `unauthorized`, `rate_limited`, `too_many_in_flight`, `budget_exceeded`, `upstream_timeout`, `upstream_unavailable`, `upstream_bad_encoding`, `shutting_down`) |
| `ocb_llm_errors_total` | counter | provider, kind = an `outcome` other than `complete` |
| `ocb_llm_usage_estimated_total` | counter | provider |
| `ocb_llm_unpriced_response_model_total` | counter | provider (billed at the highest configured price) |
| `ocb_llm_inflight_requests` | gauge | provider |
| `ocb_llm_accounting_failures_total` | counter | (usage write failed after retries) |
| `ocb_llm_key_redactions_total` | counter | provider |
| `ocb_integrity_failures_total` | counter | table = llm_tokens, job_tokens (row MAC check failed) |
| `ocb_secret_decrypts_total` | counter | purpose = llm.proxy, job |
| `ocb_job_redemptions_total` | counter | result = ok, unauthorized, error |

Label cardinality is bounded: `model` is the configured price entry (prefix
patterns without `*`), `max` for the highest-price fallback, or `other`,
never a caller's string; `method` comes from a fixed set; `route` is the
route template; `tenant` grows with the number of tenants.

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
      - alert: CredentialBrokerSlowFirstToken
        expr: histogram_quantile(0.95, sum by (le, provider) (rate(ocb_llm_time_to_first_token_seconds_bucket[10m]))) > 20
        for: 15m
```
