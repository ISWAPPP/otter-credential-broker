//! Logging and tracing: JSON logs (every line carries the span list with
//! `trace_id`), W3C trace context, optional OTLP export.

use anyhow::Context;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Keeps the trace pipeline alive; flushes on drop.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(p) = self.provider.take()
            && let Err(e) = p.shutdown()
        {
            eprintln!("otel shutdown: {e}");
        }
    }
}

/// OTLP export is enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` (or the
/// traces-specific variant) is set and `OTEL_SDK_DISABLED` is not `true`.
/// Service name, resource attributes and sampler come from the standard
/// `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER(_ARG)`.
fn otlp_enabled() -> bool {
    let disabled = std::env::var("OTEL_SDK_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true"));
    let endpoint = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some();
    endpoint && !disabled
}

pub fn init(default_service: &str) -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt::layer().json().with_current_span(true).with_span_list(true).with_target(true);

    // A tracer provider always exists, so spans get real W3C trace and span
    // ids: incoming `traceparent` headers are honoured, outgoing ones are
    // sent, and log lines carry the trace id even when nothing is exported.
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| default_service.to_owned()))
        .build();
    let mut builder = SdkTracerProvider::builder().with_resource(resource);
    let exporting = otlp_enabled();
    if exporting {
        let exporter = opentelemetry_otlp::SpanExporter::builder().with_http().build().context("OTLP exporter")?;
        builder = builder.with_batch_exporter(exporter);
    }
    let provider = builder.build();
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("otter-credential-broker"));

    tracing_subscriber::registry().with(otel_layer).with(fmt.with_filter(filter)).try_init().context("init tracing")?;
    if exporting {
        tracing::info!("OTLP trace export enabled");
    }
    Ok(TelemetryGuard { provider: Some(provider) })
}
