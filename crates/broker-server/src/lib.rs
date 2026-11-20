//! HTTP layer of `otter-credential-broker`.
//!
//! Three listeners, so network policy can separate who reaches what:
//! - public (`listen`): `/llm/*` proxy for agent pods (and `/llm/_/limits`,
//!   where they see their limits) and `/v1/worker/*` for workers;
//! - admin (`admin_listen`): `/v1/admin/*` for the platform core;
//! - metrics (`metrics_listen`): Prometheus `/metrics`.
//!
//! All three also answer `/healthz`; public and admin answer `/readyz`.
#![forbid(unsafe_code)]

pub mod admin;
mod caller_limits;
pub mod config;
pub mod error;
pub mod limit_metrics;
mod limit_view;
pub mod limits;
pub mod observe;
mod policy;
pub mod proxy;
pub mod registry;
pub mod reload;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Router, middleware};
use broker_core::auth::{Authenticator, StaticTokenAuthenticator};
use broker_core::clock::SystemClock;
use broker_core::crypto::{Envelope, LocalKeyProvider};
use broker_core::store::Store;
use broker_core::tokens::TokenHasher;
use broker_core::{Keeper, Secret};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub use config::ServerConfig;
use limits::AuthFailureLimiter;
pub use proxy::LlmProxy;
use reload::Reloader;

#[derive(Clone)]
pub struct AppState {
    pub keeper: Arc<Keeper>,
    pub admin_auth: Arc<dyn Authenticator>,
    pub proxy: Arc<LlmProxy>,
    /// Failed token checks per client address (LLM proxy and worker endpoint).
    pub limiter: Arc<AuthFailureLimiter>,
}

/// Request headers whose values must never appear in logs or traces.
fn sensitive_headers() -> SetSensitiveRequestHeadersLayer {
    SetSensitiveRequestHeadersLayer::new([
        header::AUTHORIZATION,
        header::PROXY_AUTHORIZATION,
        header::COOKIE,
        header::HeaderName::from_static("x-api-key"),
    ])
}

fn observed(router: Router, trust_caller_trace_context: bool) -> Router {
    router
        .layer(middleware::from_fn(observe::track_metrics))
        .layer(TraceLayer::new_for_http().make_span_with(move |req: &axum::http::Request<axum::body::Body>| {
            observe::make_span(req, trust_caller_trace_context)
        }))
        .layer(sensitive_headers())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(st): State<AppState>) -> Response {
    match st.keeper.store().ping().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

/// Admin API: `/v1/admin/*` behind the admin authenticator. The platform
/// core is trusted, so its trace context is honoured.
pub fn admin_router(state: AppState, timeout: Duration, body_limit: usize) -> Router {
    let t = "/v1/admin/tenants/{tenant}";
    let api = Router::new()
        .route(&format!("{t}/secrets"), get(admin::list_secrets).post(admin::create_secret))
        .route(
            &format!("{t}/secrets/{{name}}"),
            get(admin::get_secret).patch(admin::update_secret).delete(admin::delete_secret),
        )
        .route(&format!("{t}/llm-tokens"), get(admin::list_llm_tokens).post(admin::issue_llm_token))
        .route(&format!("{t}/llm-tokens/{{id}}"), get(admin::get_llm_token))
        .route(&format!("{t}/llm-tokens/{{id}}/revoke"), post(admin::revoke_llm_token))
        .route(&format!("{t}/job-tokens"), get(admin::list_job_tokens).post(admin::issue_job_token))
        .route(&format!("{t}/job-tokens/{{id}}/revoke"), post(admin::revoke_job_token))
        .route(&format!("{t}/limits"), get(admin::get_tenant_limits).put(admin::put_tenant_limits))
        .route(&format!("{t}/usage"), get(admin::usage))
        .route("/v1/admin/audit", get(admin::audit))
        .route("/v1/admin/providers", get(admin::list_providers))
        .route("/v1/admin/limits", get(admin::list_limits))
        .route("/v1/admin/kek/rewrap", post(admin::rewrap))
        .route_layer(middleware::from_fn_with_state(state.clone(), admin::require_admin))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout));
    observed(
        Router::new().route("/healthz", get(healthz)).route("/readyz", get(readyz)).merge(api).with_state(state),
        true,
    )
}

/// Options of the public listener's router.
#[derive(Debug, Clone, Copy)]
pub struct PublicOptions {
    /// Worker endpoint request timeout.
    pub timeout: Duration,
    /// Worker endpoint body limit.
    pub body_limit: usize,
    /// LLM request body limit.
    pub llm_body_limit: usize,
    pub trust_caller_trace_context: bool,
}

/// Public listener: LLM proxy and worker endpoint.
pub fn public_router(state: AppState, o: PublicOptions) -> Router {
    let worker = Router::new()
        .route("/v1/worker/secrets", post(admin::worker_secrets))
        .layer(DefaultBodyLimit::max(o.body_limit))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, o.timeout));
    // No global timeout here: responses stream for minutes. Upstream timeouts
    // (connect, response, idle, total) are enforced by the proxy itself.
    let llm = Router::new()
        .route("/llm/_/limits", get(caller_limits::view))
        .route("/llm/p/{*path}", any(proxy::by_id))
        .route("/llm/anthropic/{*path}", any(proxy::anthropic))
        .route("/llm/openai/{*path}", any(proxy::openai))
        .layer(DefaultBodyLimit::max(o.llm_body_limit));
    observed(
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .merge(worker)
            .merge(llm)
            .with_state(state),
        o.trust_caller_trace_context,
    )
}

/// Metrics listener.
pub fn metrics_router(handle: Option<PrometheusHandle>) -> Router {
    Router::new().route("/healthz", get(healthz)).route(
        "/metrics",
        get(move || {
            let handle = handle.clone();
            async move {
                match handle {
                    Some(h) => ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], h.render()).into_response(),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }),
    )
}

/// Connection handling of one listener.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// Complete request headers must arrive within this time (slow clients
    /// cannot hold connections open by trickling headers).
    pub header_read_timeout: Duration,
    /// Open connections; further clients wait in the listen backlog.
    pub max_connections: usize,
}

/// Serves `app` on `listener` (HTTP/1.1) until `stop` is cancelled, then
/// finishes in-flight requests and returns. Each request carries the
/// client's address as `ConnectInfo<SocketAddr>`.
pub async fn serve_listener(listener: TcpListener, app: Router, opts: ServeOptions, stop: CancellationToken) {
    let slots = Arc::new(Semaphore::new(opts.max_connections.max(1)));
    let conns = TaskTracker::new();
    loop {
        let slot = tokio::select! {
            s = slots.clone().acquire_owned() => match s {
                Ok(s) => s,
                Err(_) => break,
            },
            () = stop.cancelled() => break,
        };
        let (stream, remote) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = stop.cancelled() => break,
        };
        let _ = stream.set_nodelay(true);
        let svc = app.clone().map_request(move |mut req: axum::http::Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo::<SocketAddr>(remote));
            req
        });
        let svc = TowerToHyperService::new(svc);
        let stop = stop.clone();
        let header_read_timeout = opts.header_read_timeout;
        conns.spawn(async move {
            let _slot = slot;
            let mut builder = http1::Builder::new();
            builder.timer(TokioTimer::new()).header_read_timeout(header_read_timeout);
            let conn = builder.serve_connection(TokioIo::new(stream), svc);
            let mut conn = std::pin::pin!(conn);
            let res = tokio::select! {
                res = conn.as_mut() => res,
                () = stop.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    conn.as_mut().await
                }
            };
            if let Err(e) = res {
                tracing::debug!(error = %e, "connection closed with an error");
            }
        });
    }
    conns.close();
    conns.wait().await;
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! { () = ctrl_c => {}, () = term => {} }
}

/// Reads the database URL from `url` or `url_file`.
pub fn database_url(cfg: &ServerConfig) -> anyhow::Result<Secret<String>> {
    match (&cfg.database.url, &cfg.database.url_file) {
        (Some(url), _) => Ok(Secret::new(url.trim().to_owned())),
        (None, Some(f)) => {
            let raw = Secret::new(std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?);
            Ok(Secret::new(raw.expose().trim().to_owned()))
        }
        (None, None) => anyhow::bail!("database.url or database.url_file must be set"),
    }
}

pub async fn connect_store(cfg: &ServerConfig) -> anyhow::Result<Store> {
    let url = database_url(cfg)?;
    Store::connect(&url, cfg.database.max_connections, Duration::from_secs(cfg.database.acquire_timeout_secs))
        .await
        .context("connect to PostgreSQL")
}

fn key_provider(cfg: &ServerConfig) -> anyhow::Result<LocalKeyProvider> {
    let mut kp = LocalKeyProvider::from_file(cfg.kek.id.clone(), &cfg.kek.file).context("load current KEK")?;
    for p in &cfg.kek.previous {
        let key = LocalKeyProvider::read_key_file(&p.file).with_context(|| format!("load previous KEK {}", p.id))?;
        kp = kp.with_previous(p.id.clone(), key).context("previous KEK")?;
    }
    Ok(kp)
}

/// Waits for all listeners to finish and then for every exchange task
/// (each ends with its accounting).
async fn drain(servers: &mut tokio::task::JoinSet<()>, proxy: &LlmProxy) {
    while servers.join_next().await.is_some() {}
    proxy.tracker().close();
    proxy.tracker().wait().await;
}

/// Staged shutdown: cancels `stop` so the listeners in `servers` stop
/// accepting, lets in-flight requests (LLM streams included) finish within
/// `grace`, then cuts what is left and waits for its accounting.
pub async fn shutdown(
    stop: &CancellationToken,
    servers: &mut tokio::task::JoinSet<()>,
    proxy: &LlmProxy,
    grace: Duration,
) {
    stop.cancel();
    if tokio::time::timeout(grace, drain(servers, proxy)).await.is_err() {
        tracing::warn!("shutdown grace period over; cutting in-flight LLM requests");
        proxy.abort_all();
        // Cut exchanges are accounted conservatively before the process exits.
        if tokio::time::timeout(Duration::from_secs(15), drain(servers, proxy)).await.is_err() {
            tracing::error!("timed out waiting for usage accounting to finish");
        }
    }
}

/// Builds all components from config and serves until a shutdown signal.
/// `config_file` is where `cfg` came from; it is checked for changes every
/// `reload_interval_secs` (see [`reload`]).
pub async fn serve(cfg: ServerConfig, config_file: Option<PathBuf>) -> anyhow::Result<()> {
    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_buckets(observe::LATENCY_BUCKETS)
        .context("metrics buckets")?
        .install_recorder()
        .context("install metrics recorder")?;
    let kek = key_provider(&cfg)?;
    let hasher = TokenHasher::from_file(&cfg.token_key_file).context("load token key")?;
    let admin = StaticTokenAuthenticator::from_file(&cfg.admin_tokens_file).context("load admin tokens")?;
    tracing::info!(principals = admin.len(), kek_id = %cfg.kek.id, previous_keks = cfg.kek.previous.len(), "keys loaded");
    let proxy = Arc::new(LlmProxy::new(&cfg.llm).map_err(|e| anyhow::anyhow!("invalid llm config: {e}"))?);
    let store = connect_store(&cfg).await?;
    if cfg.database.run_migrations {
        store.migrate().await.context("apply migrations")?;
    }
    let keeper = Keeper::new(store, Envelope::new(Arc::new(kek)), hasher, Arc::new(SystemClock), cfg.keeper.clone());
    let state = AppState {
        keeper: Arc::new(keeper),
        admin_auth: Arc::new(admin),
        proxy: proxy.clone(),
        limiter: Arc::new(AuthFailureLimiter::new(cfg.http.auth_failures_per_minute)),
    };

    let timeout = Duration::from_secs(cfg.http.request_timeout_secs);
    let public = public_router(
        state.clone(),
        PublicOptions {
            timeout,
            body_limit: cfg.http.body_limit_bytes,
            llm_body_limit: cfg.llm.max_request_bytes,
            trust_caller_trace_context: cfg.http.trust_caller_trace_context,
        },
    );
    let admin = admin_router(state.clone(), timeout, cfg.http.body_limit_bytes);
    let metrics_app = metrics_router(Some(metrics));
    let opts = ServeOptions {
        header_read_timeout: Duration::from_secs(cfg.http.header_read_timeout_secs.max(1)),
        max_connections: cfg.http.max_connections,
    };

    let stop = CancellationToken::new();
    let gauges = limit_metrics::LimitGauges::new(state.keeper.clone(), proxy.clone());
    tokio::spawn(gauges.run(limit_metrics::REFRESH_EVERY, stop.clone()));
    if cfg.reload_interval_secs > 0 {
        let reloader = Reloader::new(config_file, cfg.clone(), proxy.clone());
        tokio::spawn(reloader.run(Duration::from_secs(cfg.reload_interval_secs), stop.clone()));
    }
    let mut servers = tokio::task::JoinSet::new();
    for (name, addr, app) in [
        ("public", cfg.listen, public),
        ("admin", cfg.admin_listen, admin),
        ("metrics", cfg.metrics_listen, metrics_app),
    ] {
        let listener = TcpListener::bind(addr).await.with_context(|| format!("bind {name} {addr}"))?;
        tracing::info!(listener = name, %addr, "listening");
        servers.spawn(serve_listener(listener, app, opts, stop.clone()));
    }
    tokio::select! {
        () = shutdown_signal() => tracing::info!("shutdown requested"),
        Some(res) = servers.join_next() => tracing::error!(?res, "a listener stopped unexpectedly"),
    }
    shutdown(&stop, &mut servers, &proxy, Duration::from_secs(cfg.http.shutdown_grace_secs)).await;
    tracing::info!("shutdown complete");
    Ok(())
}
