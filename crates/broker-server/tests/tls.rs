#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Providers reached over TLS with a private CA and client certificates:
//! each such provider has a client of its own that trusts only its CA and
//! presents only its own certificate, and rotated files are picked up
//! without a restart. Certificates: tests/fixtures/tls.

mod common;

use std::path::Path;

use axum::http::StatusCode;
use broker_server::ServerConfig;
use broker_server::reload::{ReloadResult, Reloader};
use common::*;
use serde_json::json;

/// A fixture path as a TOML literal string.
fn lit(p: &Path) -> String {
    format!("'{}'", p.display())
}

fn gauge(series: &str) -> Option<f64> {
    telemetry().metrics.render().lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse().ok()))
}

/// Replaces a file all at once, as a Secret volume update does.
fn replace(dst: &Path, src: &Path) {
    let tmp = dst.with_extension("new");
    std::fs::copy(src, &tmp).unwrap();
    std::fs::rename(&tmp, dst).unwrap();
}

async fn call(env: &Env, token: &str, provider: &str) -> TestResponse {
    let uri = format!("/llm/p/{provider}/v1/messages");
    env.llm("POST", &uri, &[("x-api-key", token)], Some(anthropic_body("test-model", false))).await
}

#[tokio::test]
async fn each_provider_presents_only_its_own_client_certificate() {
    let server = start_tls_upstream("server.pem", "server.key", Some("ca.pem")).await;
    let (plain, plain_addr) = start_upstream().await;
    let port = server.addr.port();
    let (ca, cert, key) = (tls_fixture("ca.pem"), tls_fixture("client-a.pem"), tls_fixture("client-a.key"));
    let llm = llm_config(&format!(
        r#"
        [llm.providers.anthropic]
        kind = "anthropic"
        base_url = "http://{plain_addr}"
        allow_http = true

        [llm.providers.gateway]
        kind = "anthropic"
        base_url = "https://127.0.0.1:{port}"
        tls = {{ ca_file = {}, client_cert = {}, client_key = {} }}

        [llm.providers.gateway-ca]
        kind = "anthropic"
        base_url = "https://127.0.0.1:{port}"
        tls = {{ ca_file = {} }}
        "#,
        lit(&ca),
        lit(&cert),
        lit(&key),
        lit(&ca)
    ));
    let Some(env) = Env::with_llm(EnvOptions::default(), llm, (plain.clone(), plain_addr)).await else { return };
    env.put_secret("tenant-a", "llm.anthropic", "llm_api_key", KEY_A).await;
    env.put_secret("tenant-a", "llm.gateway", "llm_api_key", "sk-gateway-FAKE-1").await;
    env.put_secret("tenant-a", "llm.gateway-ca", "llm_api_key", "sk-gateway-FAKE-2").await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;

    let r = call(&env, &token, "gateway").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(server.upstream.last().headers.get("x-api-key").unwrap(), "sk-gateway-FAKE-1");
    assert_eq!(server.last_client_cert(), Some(fixture_cert("client-a.pem")));

    // Same server and CA, no client certificate configured: none is sent.
    let r = call(&env, &token, "gateway-ca").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(server.last_client_cert(), None);
    assert_eq!(server.connections(), 2, "one client per provider");

    // Providers without TLS settings are unaffected.
    let r = call(&env, &token, "anthropic").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(plain.count(), 1);

    let snapshot = env.state.proxy.snapshot();
    assert_eq!(snapshot.tls_not_after("gateway"), Some(4_904_409_600), "client-a expires before the CA");
    assert_eq!(snapshot.tls_not_after("gateway-ca"), Some(4_922_899_200));
    assert_eq!(snapshot.tls_not_after("anthropic"), None);
    assert_eq!(gauge("ocb_upstream_tls_cert_expiry_timestamp{provider=\"gateway-ca\"}"), Some(4_922_899_200.0));

    let (_, v) = env.admin_call("GET", "/v1/admin/providers", None).await;
    let view = |id: &str| v["providers"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap().clone();
    assert_eq!(
        (view("gateway")["has_tls"].as_bool(), view("gateway")["tls_not_after"].as_i64()),
        (Some(true), Some(4_904_409_600))
    );
    assert_eq!(
        (view("anthropic")["has_tls"].as_bool(), view("anthropic")["tls_not_after"].as_i64()),
        (Some(false), None)
    );
    assert!(!v.to_string().contains("fixtures"), "file paths are not shown");
    env.cleanup().await;
}

#[tokio::test]
async fn servers_outside_the_configured_ca_are_refused() {
    let foreign = start_tls_upstream("other-server.pem", "other-server.key", None).await;
    let server = start_tls_upstream("server.pem", "server.key", None).await;
    let (plain, plain_addr) = start_upstream().await;
    let (ca, other_ca) = (lit(&tls_fixture("ca.pem")), lit(&tls_fixture("other-ca.pem")));
    let llm = llm_config(&format!(
        r#"
        [llm.providers.elsewhere]
        kind = "anthropic"
        base_url = "https://127.0.0.1:{}"
        tls = {{ ca_file = {ca} }}

        [llm.providers.wrong-ca]
        kind = "anthropic"
        base_url = "https://127.0.0.1:{}"
        tls = {{ ca_file = {other_ca} }}

        [llm.providers.right-ca]
        kind = "anthropic"
        base_url = "https://127.0.0.1:{}"
        tls = {{ ca_file = {ca} }}
        "#,
        foreign.addr.port(),
        server.addr.port(),
        server.addr.port()
    ));
    let Some(env) = Env::with_llm(EnvOptions::default(), llm, (plain, plain_addr)).await else { return };
    for id in ["elsewhere", "wrong-ca", "right-ca"] {
        env.put_secret("tenant-a", &format!("llm.{id}"), "llm_api_key", &format!("sk-{id}-FAKE")).await;
    }
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    for id in ["elsewhere", "wrong-ca"] {
        let r = call(&env, &token, id).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{id}: {}", r.text());
        assert_eq!(r.json()["error"]["code"], "upstream_unavailable");
    }
    assert_eq!((foreign.upstream.count(), server.upstream.count()), (0, 0), "no request went out");
    let r = call(&env, &token, "right-ca").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(server.upstream.last().headers.get("x-api-key").unwrap(), "sk-right-ca-FAKE");
    env.cleanup().await;
}

#[tokio::test]
async fn rotated_certificates_are_used_by_new_requests() {
    let server = start_tls_upstream("server.pem", "server.key", Some("ca.pem")).await;
    let (plain, plain_addr) = start_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let (ca, cert, key) = (dir.path().join("ca.crt"), dir.path().join("tls.crt"), dir.path().join("tls.key"));
    replace(&ca, &tls_fixture("ca.pem"));
    replace(&cert, &tls_fixture("client-a.pem"));
    replace(&key, &tls_fixture("client-a.key"));
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
            [llm.providers.rotating]
            kind = "anthropic"
            base_url = "https://127.0.0.1:{}"
            access = "explicit"
            tls = {{ ca_file = {}, client_cert = {}, client_key = {} }}
            "#,
            server.addr.port(),
            lit(&ca),
            lit(&cert),
            lit(&key)
        ),
    )
    .unwrap();
    let cfg = ServerConfig::load(Some(&config_path)).unwrap();
    let Some(env) = Env::with_llm(EnvOptions::default(), cfg.llm.clone(), (plain, plain_addr)).await else {
        return;
    };
    let proxy = env.state.proxy.clone();
    let mut reloader = Reloader::new(Some(config_path.clone()), cfg, proxy.clone());
    assert_eq!(reloader.check(), None);
    env.put_secret("tenant-a", "llm.rotating", "llm_api_key", "sk-rotating-FAKE").await;
    let (token, _) = env.llm_token("tenant-a", json!({"providers": ["rotating"]})).await;
    let expiry = || gauge("ocb_upstream_tls_cert_expiry_timestamp{provider=\"rotating\"}");

    assert_eq!(call(&env, &token, "rotating").await.status, StatusCode::OK);
    assert_eq!(server.last_client_cert(), Some(fixture_cert("client-a.pem")));
    assert_eq!(expiry(), Some(4_904_409_600.0));
    let version = proxy.snapshot().version();

    // Half a rotation: the new certificate does not match the old key.
    // Nothing changes, and the failure is reported once.
    replace(&cert, &tls_fixture("client-b.pem"));
    assert_eq!(reloader.check(), Some(ReloadResult::Invalid));
    assert_eq!(reloader.check(), None);
    assert_eq!(proxy.snapshot().version(), version);
    assert_eq!(call(&env, &token, "rotating").await.status, StatusCode::OK);
    assert_eq!(server.last_client_cert(), Some(fixture_cert("client-a.pem")));

    // With the new key in place the rotation applies to new requests.
    replace(&key, &tls_fixture("client-b.key"));
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert_ne!(proxy.snapshot().version(), version);
    let connections = server.connections();
    assert_eq!(call(&env, &token, "rotating").await.status, StatusCode::OK);
    assert_eq!(server.connections(), connections + 1, "a new client, a new connection");
    assert_eq!(server.last_client_cert(), Some(fixture_cert("client-b.pem")));
    assert_eq!(expiry(), Some(4_912_358_400.0));
    assert_eq!(proxy.snapshot().tls_not_after("rotating"), Some(4_912_358_400));

    // A provider removed by a reload leaves no expiry behind.
    std::fs::write(&config_path, "[llm.providers.other]\nkind = \"openai\"\nbase_url = \"https://other.example/v1\"\n")
        .unwrap();
    assert_eq!(reloader.check(), Some(ReloadResult::Applied));
    assert!(proxy.snapshot().tls_files().is_empty());
    assert!(expiry().unwrap().is_nan());
    env.cleanup().await;
}
