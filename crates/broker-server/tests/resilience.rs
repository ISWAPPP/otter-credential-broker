#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Accounting and resource limits under hostile or broken clients and
//! upstreams: early disconnects, slow readers, stalled or compressed
//! upstreams, concurrency caps, slow headers, connection caps, repeated bad
//! tokens, routed models, shutdown.

mod common;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use broker_server::ServeOptions;
use common::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn usage(env: &Env, tenant: &str) -> Vec<Value> {
    let (s, v) = env.admin_call("GET", &format!("/v1/admin/tenants/{tenant}/usage"), None).await;
    assert_eq!(s, StatusCode::OK);
    v.as_array().unwrap().clone()
}

/// Polls until `n` usage rows exist (the exchange accounts on its own).
async fn wait_rows(env: &Env, tenant: &str, n: usize) -> Vec<Value> {
    for _ in 0..300 {
        let rows = usage(env, tenant).await;
        if rows.len() >= n {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("expected {n} usage rows");
}

fn raw_request(token: &str, body: &str) -> String {
    format!(
        "POST /llm/anthropic/v1/messages HTTP/1.1\r\nhost: broker\r\nx-api-key: {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn hanging_up_before_the_response_head_does_not_avoid_accounting() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, token_id) = env.llm_token("tenant-a", json!({})).await;
    let addr = env.serve_public().await;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(raw_request(&token, &anthropic_body("slow-json", false)).as_bytes()).await.unwrap();
    // The upstream needs 1.5 s; hang up long before that.
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(sock);
    let rows = wait_rows(&env, "tenant-a", 1).await;
    assert_eq!(rows[0]["usage_source"], "reported", "{:?}", rows[0]);
    assert_eq!((rows[0]["input_tokens"].as_i64(), rows[0]["output_tokens"].as_i64()), (Some(200), Some(50)));
    let (_, t) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{token_id}"), None).await;
    assert_eq!(t["spent_tokens"].as_i64(), Some(250));
    env.cleanup().await;
}

#[tokio::test]
async fn a_reader_that_stops_reading_cannot_hold_the_exchange_or_its_accounting() {
    let Some(env) = Env::with(EnvOptions { idle_timeout_secs: 1, ..EnvOptions::default() }).await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let addr = env.serve_public().await;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    // About 13 MB of SSE; this client never reads a byte.
    sock.write_all(raw_request(&token, &anthropic_body("huge-stream", true)).as_bytes()).await.unwrap();
    let started = Instant::now();
    let rows = wait_rows(&env, "tenant-a", 1).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(rows[0]["usage_source"], "reported", "{:?}", rows[0]);
    assert_eq!(rows[0]["output_tokens"].as_i64(), Some(7777));
    // The exchange is over (and its permit released) while the socket is
    // still open: it stopped feeding this client and drained the upstream.
    env.settle().await;
    let token_id = rows[0]["token_id"].as_str().unwrap().to_owned();
    let closed = telemetry()
        .logs
        .contents()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| {
            v["span"]["name"] == "llm.request"
                && v["fields"]["message"] == "close"
                && v["span"]["token_id"] == token_id.as_str()
        })
        .expect("llm.request closed");
    assert_eq!(closed["span"]["outcome"], "client_gone", "{closed}");
    assert_eq!(env.state.proxy.inflight().count(&token_id), 0);
    drop(sock);
    env.cleanup().await;
}

#[tokio::test]
async fn compressed_upstream_responses_are_refused_and_charged_conservatively() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("gzip-body", false)))
        .await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert_eq!(r.json()["error"]["code"], "upstream_bad_encoding");
    env.settle().await;
    let rows = usage(&env, "tenant-a").await;
    assert_eq!(rows[0]["usage_source"], "estimated");
    assert_eq!(rows[0]["output_tokens"].as_i64(), Some(64), "max_tokens of the request");
    env.cleanup().await;
}

#[tokio::test]
async fn error_bodies_are_scrubbed_before_they_are_cut() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("error-long", false)))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.len() <= 4096);
    let text = r.text();
    // Not even the part of the key before the cut survives.
    let random = &KEY_A[KEY_A.len() - 28..];
    for frag in [&KEY_A[..12], &random[..8], "FAKE-tenant"] {
        assert!(!text.contains(frag), "{frag} leaked: ...{}", &text[text.len().saturating_sub(120)..]);
    }
    env.cleanup().await;
}

#[tokio::test]
async fn requests_in_flight_are_capped_per_token() {
    let Some(env) = Env::with(EnvOptions { max_concurrent_per_token: 1, ..EnvOptions::default() }).await else {
        return;
    };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let (other, _) = env.llm_token("tenant-a", json!({})).await;
    let addr = env.serve_public().await;
    // First request holds the token's only slot for 1.5 s.
    let slow = {
        let token = token.clone();
        tokio::spawn(async move {
            reqwest::Client::new()
                .post(format!("http://{addr}/llm/anthropic/v1/messages"))
                .header("x-api-key", token)
                .body(anthropic_body("slow-json", false))
                .send()
                .await
                .unwrap()
                .status()
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.json()["error"]["code"], "too_many_in_flight");
    assert_eq!(r.headers.get("retry-after").unwrap(), "1");
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &other)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::OK, "other tokens are not affected");
    assert_eq!(slow.await.unwrap().as_u16(), 200);
    env.settle().await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::OK, "the slot is free again");
    env.cleanup().await;
}

#[tokio::test]
async fn slow_headers_are_cut_and_connections_are_capped() {
    let Some(env) = Env::new().await else { return };
    let opts = ServeOptions { header_read_timeout: Duration::from_secs(1), max_connections: 1 };
    let addr = serve_on_socket(env.public.clone(), opts).await;
    // A client that trickles headers holds the only connection slot...
    let mut slowloris = tokio::net::TcpStream::connect(addr).await.unwrap();
    slowloris.write_all(b"GET /healthz HTTP/1.1\r\nhost: broker\r\nx-slow: ").await.unwrap();
    let started = Instant::now();
    let mut probe = tokio::net::TcpStream::connect(addr).await.unwrap();
    probe.write_all(b"GET /healthz HTTP/1.1\r\nhost: broker\r\nconnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), probe.read_to_end(&mut out)).await.unwrap().unwrap();
    // ...but only until the header read timeout, then the next client is served.
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&out));
    assert!(started.elapsed() >= Duration::from_millis(800), "served while the slot was taken");
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), slowloris.read_to_end(&mut rest)).await.unwrap().unwrap_or(0);
    let closed = String::from_utf8_lossy(&rest[..n]).to_string();
    assert!(closed.is_empty() || closed.starts_with("HTTP/1.1 408"), "{closed}");
    env.cleanup().await;
}

#[tokio::test]
async fn repeated_bad_tokens_from_one_address_are_refused_early() {
    let Some(env) = Env::with(EnvOptions { auth_failures_per_minute: 3, ..EnvOptions::default() }).await else {
        return;
    };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let addr = env.serve_public().await;
    let client = reqwest::Client::new();
    let send = |t: String| {
        let client = client.clone();
        async move {
            client
                .post(format!("http://{addr}/llm/anthropic/v1/messages"))
                .header("x-api-key", t)
                .body(anthropic_body("test-model", false))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    let bad = format!("ocb_llm_{}", "0".repeat(64));
    let mut codes = Vec::new();
    for _ in 0..5 {
        codes.push(send(bad.clone()).await);
    }
    // Minute windows: unless the test straddles a minute boundary, the 4th
    // and later attempts are refused without a database lookup.
    let boundary = codes.iter().filter(|c| **c == 401).count() > 3;
    if !boundary {
        assert_eq!(codes, [401, 401, 401, 429, 429]);
        assert_eq!(send(token.clone()).await, 429, "the address is blocked for this window");
    }
    // In-process callers (no address) are unaffected.
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    env.cleanup().await;
}

#[tokio::test]
async fn the_model_that_answered_is_what_gets_billed() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({"budget_usd": 10.0})).await;
    // Asked for a cheap model, the provider routed to an expensive one.
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("cheap-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // ... and to a model without a price: billed at the highest known price.
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[("x-api-key", &token)],
            Some(anthropic_body("cheap-model-2", false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    env.settle().await;
    let rows = usage(&env, "tenant-a").await;
    let by = |m: &str| rows.iter().find(|u| u["model"] == m).cloned().unwrap();
    let routed = by("cheap-model");
    assert_eq!(routed["response_model"], "expensive-model");
    assert_eq!(routed["cost_micro_usd"].as_i64(), Some(1000 * 50 + 1000 * 100));
    let unknown = by("cheap-model-2");
    assert_eq!(unknown["response_model"], "unknown-model");
    assert_eq!(unknown["cost_micro_usd"].as_i64(), Some(1000 * 50 + 1000 * 100));
    env.cleanup().await;
}

#[tokio::test]
async fn shutdown_cuts_streams_and_still_accounts_them() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let addr = env.serve_public().await;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(raw_request(&token, &anthropic_body("long-stream", true)).as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(26).any(|w| w == b"event: content_block_delta") {
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    env.state.proxy.abort_all();
    // The caller's response ends abnormally (no clean chunked terminator).
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut rest)).await;
    got.extend_from_slice(&rest);
    let text = String::from_utf8_lossy(&got);
    assert!(!text.contains("message_stop"));
    assert!(!text.ends_with("0\r\n\r\n"), "aborted, not completed");
    let rows = wait_rows(&env, "tenant-a", 1).await;
    assert_eq!(rows[0]["usage_source"], "estimated");
    assert!(rows[0]["output_tokens"].as_i64().unwrap() >= 64, "{:?}", rows[0]);
    env.cleanup().await;
}
