#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Configuration reload: providers and prices change for new requests while
//! requests in flight, in-flight limits and shutdown are unaffected; invalid
//! configurations and changes that need a restart are refused, and a change
//! refused for TLS files that are not in place yet applies once they are.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use broker_core::llm::ProviderAccess;
use broker_server::reload::{ReloadResult, Reloader};
use broker_server::{LlmProxy, ServeOptions, ServerConfig, serve_listener, shutdown};
use common::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// A configuration with one Anthropic provider on `upstream`.
struct Cfg {
    upstream: SocketAddr,
    /// Multiplies the prices of `test-model` (3.0 input, 15.0 output). The
    /// fake upstream reports that model for every Anthropic answer, so its
    /// price is what gets billed.
    price_factor: f64,
    max_concurrent_total: u32,
    /// `access` of the Anthropic provider.
    access: &'static str,
    /// Appended at the end (more providers or prices).
    extra: String,
}

impl Cfg {
    fn new(upstream: SocketAddr) -> Self {
        Self { upstream, price_factor: 1.0, max_concurrent_total: 1024, access: "implicit", extra: String::new() }
    }

    fn toml(&self) -> String {
        let Self { upstream, price_factor, max_concurrent_total, access, extra } = self;
        let (input, output) = (3.0 * price_factor, 15.0 * price_factor);
        format!(
            r#"
            [llm]
            response_timeout_secs = 5
            idle_timeout_secs = 5
            max_concurrent_per_token = 1
            max_concurrent_total = {max_concurrent_total}

            [llm.providers.anthropic]
            kind = "anthropic"
            base_url = "http://{upstream}"
            allow_http = true
            access = "{access}"

            [[llm.pricing]]
            provider = "anthropic"
            model = "test-model"
            input = {input:?}
            output = {output:?}
            {extra}
            "#
        )
    }
}

/// Replaces the file the way a ConfigMap update does: all at once.
fn write(path: &Path, content: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn counter(series: &str) -> u64 {
    let text = telemetry().metrics.render();
    text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse::<f64>().ok())).map_or(0, |v| v as u64)
}

/// A proxy and a reloader for the config file at `path`, without a database.
fn proxy_and_reloader(path: &Path) -> (Arc<LlmProxy>, Reloader) {
    telemetry();
    let cfg = ServerConfig::load(Some(path)).unwrap();
    let proxy = Arc::new(LlmProxy::new(&cfg.llm).unwrap());
    let reloader = Reloader::new(Some(path.to_owned()), cfg, proxy.clone());
    (proxy, reloader)
}

#[tokio::test]
async fn reload_during_a_stream_then_shutdown_drains_and_accounts_the_stream() {
    let (upstream, addr) = start_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Cfg::new(addr);
    write(&path, &cfg.toml());
    let server_cfg = ServerConfig::load(Some(&path)).unwrap();
    let Some(env) = Env::with_llm(EnvOptions::default(), server_cfg.llm.clone(), (upstream, addr)).await else {
        return;
    };
    let proxy = env.state.proxy.clone();
    let mut reloader = Reloader::new(Some(path.clone()), server_cfg, proxy.clone());
    assert_eq!(reloader.check(), None, "the file is the one loaded at start");
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;

    // The public listener, run and stopped the way `serve` does it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let mut servers = tokio::task::JoinSet::new();
    let opts = ServeOptions { header_read_timeout: Duration::from_secs(10), max_connections: 64 };
    servers.spawn(serve_listener(listener, env.public.clone(), opts, stop.clone()));

    // A stream of about two seconds.
    let body = anthropic_body("long-stream", true);
    let mut sock = tokio::net::TcpStream::connect(public).await.unwrap();
    let req = format!(
        "POST /llm/anthropic/v1/messages HTTP/1.1\r\nhost: broker\r\nx-api-key: {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(26).any(|w| w == b"event: content_block_delta") {
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }

    // Reload mid-stream: new prices and a new provider.
    let before = proxy.snapshot().version();
    cfg.price_factor = 2.0;
    cfg.extra =
        format!("[llm.providers.second]\nkind = \"anthropic\"\nbase_url = \"http://{addr}\"\nallow_http = true");
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_ne!(proxy.snapshot().version(), before);
    assert!(proxy.has_provider("second"));

    // In-flight limits are process state: the token's only slot is still
    // taken by the stream.
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.text());
    assert_eq!(r.json()["error"]["code"], "too_many_in_flight");

    // Shutdown waits for the stream that started before the reload.
    let reader = tokio::spawn(async move {
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), sock.read_to_end(&mut rest)).await;
        rest
    });
    tokio::time::timeout(Duration::from_secs(30), shutdown(&stop, &mut servers, &proxy, Duration::from_secs(20)))
        .await
        .expect("shutdown finished within the grace period");
    assert!(proxy.tracker().is_empty(), "every exchange finished with its accounting");
    got.extend_from_slice(&reader.await.unwrap());
    let text = String::from_utf8_lossy(&got);
    assert!(text.contains("message_stop"), "the stream ran to its end");

    // Its usage row is there, priced as when the stream started:
    // 120 input and 1000 cache reads at 3.0, 5000 output at 15.0.
    let (s, rows) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/usage", None).await;
    assert_eq!(s, StatusCode::OK);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["usage_source"], "reported");
    assert_eq!(rows[0]["output_tokens"].as_i64(), Some(5000));
    assert_eq!(rows[0]["cost_micro_usd"].as_i64(), Some(78_360), "{}", rows[0]);
    env.cleanup().await;
}

#[tokio::test]
async fn new_requests_use_the_reloaded_prices() {
    let (upstream, addr) = start_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Cfg::new(addr);
    write(&path, &cfg.toml());
    let server_cfg = ServerConfig::load(Some(&path)).unwrap();
    let Some(env) = Env::with_llm(EnvOptions::default(), server_cfg.llm.clone(), (upstream, addr)).await else {
        return;
    };
    let mut reloader = Reloader::new(Some(path.clone()), server_cfg, env.state.proxy.clone());
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let h = [("x-api-key", token.as_str())];
    cfg.price_factor = 2.0;
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("long-stream", true))).await;
    assert_eq!(r.status, StatusCode::OK);
    env.settle().await;
    let (_, rows) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/usage", None).await;
    assert_eq!(rows[0]["cost_micro_usd"].as_i64(), Some(156_720), "{rows}");
    env.cleanup().await;
}

#[tokio::test]
async fn an_invalid_configuration_is_refused_and_the_current_one_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let cfg = Cfg::new("127.0.0.1:9".parse().unwrap());
    write(&path, &cfg.toml());
    let (proxy, mut reloader) = proxy_and_reloader(&path);
    let version = proxy.snapshot().version();
    let invalid = counter("ocb_config_reload_total{result=\"invalid\"}");
    for broken in [
        "[llm\nthis is not TOML".to_owned(),
        cfg.toml().replace("kind = \"anthropic\"", "kind = \"unknown\""),
        cfg.toml().replace("http://127.0.0.1:9", "ftp://127.0.0.1:9"),
        format!("{}\n[[llm.pricing]]\nprovider = \"nowhere\"\nmodel = \"m\"\ninput = 1.0\noutput = 1.0\n", cfg.toml()),
        format!("{}\n[llm.providers.p]\nkind = \"anthropic\"\nbase_url = \"https://p.example\"\n", cfg.toml()),
    ] {
        write(&path, &broken);
        assert_eq!(reloader.check(), Some(ReloadResult::Invalid), "{broken}");
        assert_eq!(reloader.check(), None, "the same content is looked at once");
        assert_eq!(proxy.snapshot().version(), version);
    }
    assert!(counter("ocb_config_reload_total{result=\"invalid\"}") >= invalid + 5);

    // A file that cannot be read is reported once, too.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid));
    assert_eq!(reloader.check(), None);
    // Back to the content in use: nothing to apply.
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Unchanged));
    assert_eq!(proxy.snapshot().version(), version);
}

#[tokio::test]
async fn changes_outside_providers_and_pricing_need_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Cfg::new("127.0.0.1:9".parse().unwrap());
    write(&path, &cfg.toml());
    let (proxy, mut reloader) = proxy_and_reloader(&path);
    let version = proxy.snapshot().version();
    let restart = counter("ocb_config_reload_total{result=\"restart_required\"}");

    // A price change together with a limit that is only read at start:
    // neither is applied.
    cfg.price_factor = 5.0;
    cfg.max_concurrent_total = 8;
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::RestartRequired));
    assert_eq!(proxy.snapshot().version(), version);
    let price = |p: &LlmProxy| p.snapshot().prices().lookup("anthropic", "test-model").unwrap().input;
    assert_eq!(price(&proxy), 3.0);
    for other in ["reload_interval_secs = 1\n", "[http]\nshutdown_grace_secs = 1\n", "listen = \"127.0.0.1:1\"\n"] {
        cfg.max_concurrent_total = 1024;
        write(&path, &format!("{other}{}", cfg.toml()));
        assert_eq!(reloader.check(), Some(ReloadResult::RestartRequired), "{other}");
    }
    assert!(counter("ocb_config_reload_total{result=\"restart_required\"}") >= restart + 4);

    // Without the other changes, the price applies.
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_eq!(price(&proxy), 15.0);
    assert!(telemetry().metrics.render().contains("ocb_config_version "));
}

/// A provider with its own TLS settings; nothing connects to it here.
fn gateway(tls: &str) -> String {
    format!("[llm.providers.gateway]\nkind = \"anthropic\"\nbase_url = \"https://127.0.0.1:9\"\ntls = {{ {tls} }}\n")
}

#[tokio::test]
async fn a_change_refused_for_missing_tls_files_applies_once_they_arrive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Cfg::new("127.0.0.1:9".parse().unwrap());
    write(&path, &cfg.toml());
    let (proxy, mut reloader) = proxy_and_reloader(&path);
    let version = proxy.snapshot().version();

    // A change that is invalid as written is not looked at again when a TLS
    // file it names appears: the file would not make it valid.
    let other_ca = dir.path().join("other-ca.crt");
    cfg.extra = format!(
        "{}[[llm.pricing]]\nprovider = \"nowhere\"\nmodel = \"m\"\ninput = 1.0\noutput = 1.0\n",
        gateway(&format!("ca_file = {}", lit(&other_ca)))
    );
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid));
    replace(&other_ca, &tls_fixture("ca.pem"));
    assert_eq!(reloader.check(), None, "invalid as written");

    // A new provider whose CA file is not there yet (its Secret is updated
    // after the config file), and explicit access for the existing one.
    let ca = dir.path().join("ca.crt");
    cfg.access = "explicit";
    cfg.extra = gateway(&format!("ca_file = {}", lit(&ca)));
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid));
    assert_eq!(reloader.check(), None, "refused once while the file is missing");
    assert_eq!(proxy.snapshot().version(), version);

    // A file that cannot be used: looked at again and refused again, once.
    write(&ca, "not a certificate");
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid));
    assert_eq!(reloader.check(), None);
    assert!(!proxy.has_provider("gateway"));
    assert_eq!(proxy.snapshot().provider("anthropic").unwrap().access, ProviderAccess::Implicit);

    // The CA arrives: the whole change applies.
    replace(&ca, &tls_fixture("ca.pem"));
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert!(proxy.has_provider("gateway"));
    assert_eq!(proxy.snapshot().provider("anthropic").unwrap().access, ProviderAccess::Explicit);
    assert_eq!(reloader.check(), None);
}

#[tokio::test]
async fn a_price_change_made_during_a_certificate_rotation_applies_with_the_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, cert, key) = (dir.path().join("ca.crt"), dir.path().join("tls.crt"), dir.path().join("tls.key"));
    replace(&ca, &tls_fixture("ca.pem"));
    replace(&cert, &tls_fixture("client-a.pem"));
    replace(&key, &tls_fixture("client-a.key"));
    let path = dir.path().join("config.toml");
    let mut cfg = Cfg::new("127.0.0.1:9".parse().unwrap());
    cfg.extra = gateway(&format!("ca_file = {}, client_cert = {}, client_key = {}", lit(&ca), lit(&cert), lit(&key)));
    write(&path, &cfg.toml());
    let (proxy, mut reloader) = proxy_and_reloader(&path);
    assert_eq!(reloader.check(), None);
    let price = |p: &LlmProxy| p.snapshot().prices().lookup("anthropic", "test-model").unwrap().input;

    // The certificate is renewed before its key, and the prices change
    // meanwhile. The new configuration and the renewed files of the running
    // one are each refused once.
    replace(&cert, &tls_fixture("client-b.pem"));
    cfg.price_factor = 2.0;
    write(&path, &cfg.toml());
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid), "the new configuration");
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid), "the renewed files of the running configuration");
    assert_eq!(reloader.check(), None);
    assert_eq!(price(&proxy), 3.0);
    assert_eq!(proxy.snapshot().tls_not_after("gateway"), Some(4_904_409_600));

    // With the new key in place, the new prices apply together with the new
    // certificate.
    replace(&key, &tls_fixture("client-b.key"));
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_eq!(price(&proxy), 6.0);
    assert_eq!(proxy.snapshot().tls_not_after("gateway"), Some(4_912_358_400));
    assert_eq!(reloader.check(), None);
}

#[tokio::test]
async fn the_reload_loop_applies_changes_on_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Cfg::new("127.0.0.1:9".parse().unwrap());
    write(&path, &cfg.toml());
    let (proxy, reloader) = proxy_and_reloader(&path);
    let version = proxy.snapshot().version();
    let stop = CancellationToken::new();
    let task = tokio::spawn(reloader.run(Duration::from_millis(20), stop.clone()));
    cfg.extra = "[llm.providers.later]\nkind = \"openai\"\nbase_url = \"https://later.example/v1\"".into();
    write(&path, &cfg.toml());
    for _ in 0..250 {
        if proxy.has_provider("later") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(proxy.has_provider("later"));
    assert_ne!(proxy.snapshot().version(), version);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
}
