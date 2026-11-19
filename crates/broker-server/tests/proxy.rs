#![allow(clippy::unwrap_used, clippy::expect_used)]
//! LLM proxy behaviour against a fake upstream: transparent forwarding,
//! streaming, usage accounting, budgets, rate limits, timeouts, tracing.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn usage(env: &Env, tenant: &str) -> Vec<Value> {
    env.settle().await;
    let (s, v) = env.admin_call("GET", &format!("/v1/admin/tenants/{tenant}/usage"), None).await;
    assert_eq!(s, StatusCode::OK);
    v.as_array().unwrap().clone()
}

#[tokio::test]
async fn anthropic_json_is_forwarded_unchanged_with_tenant_key() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, token_id) = env.llm_token("tenant-a", json!({"run_id": "run-1"})).await;
    let body = anthropic_body("test-model", false);
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[("x-api-key", &token), ("anthropic-version", "2023-06-01"), ("anthropic-beta", "b1,b2")],
            Some(body.clone()),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.text(), ANTHROPIC_JSON, "response body must be unchanged");
    assert!(r.headers.get("set-cookie").is_none(), "upstream cookies are not forwarded");

    let seen = env.upstream.last();
    assert_eq!(seen.uri, "/v1/messages");
    assert_eq!(seen.body, body.as_bytes(), "request body must be unchanged");
    assert_eq!(seen.headers.get("x-api-key").unwrap(), KEY_A);
    assert_eq!(seen.headers.get("anthropic-version").unwrap(), "2023-06-01");
    assert_eq!(seen.headers.get("anthropic-beta").unwrap(), "b1,b2");
    assert_eq!(seen.headers.get("accept-encoding").unwrap(), "identity");
    assert!(seen.headers.get("authorization").is_none());

    let u = usage(&env, "tenant-a").await;
    assert_eq!(u.len(), 1);
    assert_eq!((u[0]["input_tokens"].as_i64(), u[0]["output_tokens"].as_i64()), (Some(200), Some(50)));
    // 200 * 3.0 + 50 * 15.0 = 1350 micro-USD
    assert_eq!(u[0]["cost_micro_usd"].as_i64(), Some(1350));
    assert_eq!((u[0]["run_id"].as_str(), u[0]["usage_source"].as_str()), (Some("run-1"), Some("reported")));
    let (_, t) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{token_id}"), None).await;
    assert_eq!((t["spent_tokens"].as_i64(), t["request_count"].as_i64()), (Some(250), Some(1)));
    env.cleanup().await;
}

#[tokio::test]
async fn anthropic_sse_streams_byte_for_byte_and_is_accounted() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-b", json!({})).await;
    // Bearer works as well as x-api-key.
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[("authorization", &format!("Bearer {token}")), ("anthropic-version", "2023-06-01")],
            Some(anthropic_body("test-model", true)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/event-stream"));
    assert_eq!(r.text(), ANTHROPIC_SSE);
    assert_eq!(env.upstream.last().headers.get("x-api-key").unwrap(), KEY_B);

    let u = usage(&env, "tenant-b").await;
    assert_eq!(
        (u[0]["input_tokens"].as_i64(), u[0]["cache_read_tokens"].as_i64(), u[0]["output_tokens"].as_i64()),
        (Some(120), Some(1000), Some(30))
    );
    // 120*3 + 1000*0.3 + 30*15 = 360 + 300 + 450
    assert_eq!(u[0]["cost_micro_usd"].as_i64(), Some(1110));
    assert!(u[0]["ttft_ms"].as_i64().is_some());
    env.cleanup().await;
}

#[tokio::test]
async fn openai_compatible_json_and_stream() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({"providers": ["deepseek"]})).await;
    let auth = format!("Bearer {token}");

    let body = openai_body("deepseek-chat", false, false);
    let r =
        env.llm("POST", "/llm/openai/deepseek/chat/completions", &[("authorization", &auth)], Some(body.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.text(), OPENAI_JSON);
    let seen = env.upstream.last();
    assert_eq!(seen.uri, "/v1/chat/completions");
    assert_eq!(seen.body, body.as_bytes());
    assert_eq!(seen.headers.get("authorization").unwrap(), &format!("Bearer {DS_KEY_A}"));
    assert!(seen.headers.get("x-api-key").is_none());

    let r = env
        .llm(
            "POST",
            "/llm/openai/deepseek/chat/completions",
            &[("authorization", &auth)],
            Some(openai_body("deepseek-chat", true, true)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), OPENAI_SSE_WITH_USAGE);

    // Streaming without include_usage is refused before anything is sent.
    let before = env.upstream.count();
    let r = env
        .llm(
            "POST",
            "/llm/openai/deepseek/chat/completions",
            &[("authorization", &auth)],
            Some(openai_body("deepseek-chat", true, false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.json()["error"]["message"].as_str().unwrap().contains("include_usage"));
    assert_eq!(env.upstream.count(), before);

    // The token is limited to deepseek.
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.json()["error"]["type"], "permission_error");
    // No deepseek key in tenant-b: refused, never another tenant's key.
    let (tb, _) = env.llm_token("tenant-b", json!({})).await;
    let r = env
        .llm(
            "POST",
            "/llm/openai/deepseek/chat/completions",
            &[("authorization", &format!("Bearer {tb}"))],
            Some(openai_body("deepseek-chat", false, false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let u = usage(&env, "tenant-a").await;
    assert_eq!(u.len(), 2);
    // stream: prompt 70 (20 cached), completion 9: 50*0.5 + 20*0.1 + 9*2.0 = 25 + 2 + 18
    assert_eq!(u[0]["cost_micro_usd"].as_i64(), Some(45));
    assert_eq!((u[0]["input_tokens"].as_i64(), u[0]["cache_read_tokens"].as_i64()), (Some(50), Some(20)));
    // json: 40*0.5 + 10*2 = 40
    assert_eq!(u[1]["cost_micro_usd"].as_i64(), Some(40));
    env.cleanup().await;
}

#[tokio::test]
async fn free_endpoints_and_query_passthrough() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({"budget_tokens": 0})).await;
    // Free endpoints work even with an exhausted budget.
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages/count_tokens",
            &[("x-api-key", &token)],
            Some("{\"model\":\"m\"}".into()),
        )
        .await;
    assert_eq!((r.status, r.text().as_str()), (StatusCode::OK, r#"{"input_tokens":42}"#));
    let r = env.llm("GET", "/llm/anthropic/v1/models?limit=5", &[("x-api-key", &token)], None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(env.upstream.last().uri, "/v1/models?limit=5");
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages?beta=true",
            &[("x-api-key", &token)],
            Some(anthropic_body("test-model", false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYMENT_REQUIRED);
    let u = usage(&env, "tenant-a").await;
    assert!(u.iter().all(|e| e["usage_source"] == "none" && e["cost_micro_usd"] == 0));
    env.cleanup().await;
}

#[tokio::test]
async fn budgets_are_enforced_with_clear_errors() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    // Token budget: the first request passes the pre-check, post-accounting
    // records 250 tokens, the next one is refused with 402.
    let (token, _) = env.llm_token("tenant-a", json!({"budget_tokens": 100})).await;
    let h = [("x-api-key", token.as_str())];
    let ok = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(ok.status, StatusCode::OK);
    env.settle().await;
    let before = env.upstream.count();
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(r.status, StatusCode::PAYMENT_REQUIRED);
    let v = r.json();
    assert_eq!(v["type"], "error");
    assert_eq!(v["error"]["type"], "billing_error");
    assert_eq!(v["error"]["code"], "budget_exceeded");
    assert!(v["error"]["message"].as_str().unwrap().contains("250 of 100 tokens"), "{v}");
    assert_eq!(env.upstream.count(), before, "nothing forwarded after the budget is used up");

    // USD budget, OpenAI-shaped error.
    let (t2, _) = env.llm_token("tenant-a", json!({"budget_usd": 0.00003})).await;
    let h2 = format!("Bearer {t2}");
    let b = openai_body("deepseek-chat", false, false);
    let r = env.llm("POST", "/llm/openai/deepseek/chat/completions", &[("authorization", &h2)], Some(b.clone())).await;
    assert_eq!(r.status, StatusCode::OK);
    env.settle().await;
    let r = env.llm("POST", "/llm/openai/deepseek/chat/completions", &[("authorization", &h2)], Some(b)).await;
    assert_eq!(r.status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(r.json()["error"]["code"], "budget_exceeded");
    assert_eq!(r.json()["error"]["type"], "insufficient_quota");

    // A USD budget cannot be checked against an unpriced model: refused.
    let (t3, _) = env.llm_token("tenant-a", json!({"budget_usd": 10.0})).await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &t3)], Some(anthropic_body("unpriced-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.json()["error"]["message"].as_str().unwrap().contains("no configured price"));
    env.cleanup().await;
}

#[tokio::test]
async fn rate_limit_per_token() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    env.clock.set(T0 - T0 % 60 + 10);
    let (token, _) = env.llm_token("tenant-a", json!({"rate_limit_per_minute": 2})).await;
    let (other, _) = env.llm_token("tenant-a", json!({"rate_limit_per_minute": 2})).await;
    let h = [("x-api-key", token.as_str())];
    for _ in 0..2 {
        let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers.get("retry-after").unwrap(), "50");
    assert_eq!(r.json()["error"]["type"], "rate_limit_error");
    // Limits are per token.
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &other)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    env.clock.advance(60);
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(r.status, StatusCode::OK);
    env.cleanup().await;
}

#[tokio::test]
async fn upstream_errors_are_passed_through_scrubbed() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("error-401", false)))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let text = r.text();
    assert!(!text.contains(KEY_A) && !text.contains("FAKE") && !text.contains("ab****"), "{text}");
    assert!(text.contains("[REDACTED]") && text.contains("authentication_error"), "{text}");
    assert!(r.headers.get("set-cookie").is_none());
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("error-529", false)))
        .await;
    assert_eq!(r.status.as_u16(), 529);
    assert_eq!(r.json()["error"]["type"], "overloaded_error");
    let u = usage(&env, "tenant-a").await;
    assert_eq!(u.len(), 2);
    assert!(u.iter().all(|e| e["cost_micro_usd"] == 0));
    env.cleanup().await;
}

#[tokio::test]
async fn timeouts() {
    let Some(env) =
        Env::with(EnvOptions { response_timeout_secs: 1, idle_timeout_secs: 1, ..EnvOptions::default() }).await
    else {
        return;
    };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let started = std::time::Instant::now();
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[("x-api-key", &token)],
            Some(anthropic_body("slow-headers", false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(r.json()["error"]["code"], "upstream_timeout");
    assert!(started.elapsed() < Duration::from_secs(4));

    // Stalled stream: the body ends early (idle timeout). Usage is estimated
    // with the request's max_tokens as the output floor (hidden reasoning
    // could have been billed).
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(anthropic_body("stall-stream", true)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text().contains("message_start"));
    assert!(!r.text().contains("message_stop"));
    // The caller gave up on slow-headers, but the exchange kept waiting and
    // accounts the provider's own report.
    let rows = usage(&env, "tenant-a").await;
    let by_model = |m: &str| rows.iter().find(|u| u["model"] == m).cloned().unwrap_or_default();
    let stall = by_model("stall-stream");
    assert_eq!(stall["usage_source"], "estimated");
    assert_eq!((stall["input_tokens"].as_i64(), stall["output_tokens"].as_i64()), (Some(120), Some(64)));
    let slow = by_model("slow-headers");
    assert_eq!(slow["usage_source"], "reported", "{rows:?}");
    assert_eq!((slow["input_tokens"].as_i64(), slow["output_tokens"].as_i64()), (Some(200), Some(50)));
    env.cleanup().await;
}

#[tokio::test]
async fn client_disconnect_mid_stream_is_still_accounted() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, token_id) = env.llm_token("tenant-a", json!({})).await;
    let addr = env.serve_public().await;
    let body = anthropic_body("long-stream", true);
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /llm/anthropic/v1/messages HTTP/1.1\r\nhost: broker\r\nx-api-key: {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await.unwrap();
    // Read a few deltas, then hang up before the final usage event.
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.windows(26).filter(|w| w == b"event: content_block_delta").count() < 3 {
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    drop(sock);
    // Accounting happens when the proxy notices the disconnect.
    let mut rows = Vec::new();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        rows = usage(&env, "tenant-a").await;
        if !rows.is_empty() {
            break;
        }
    }
    // The exchange read the upstream to its end after the caller left, so
    // the provider's final report is what gets accounted.
    assert_eq!(rows.len(), 1, "usage row for the abandoned stream");
    assert_eq!(rows[0]["usage_source"], "reported", "{:?}", rows[0]);
    assert_eq!(rows[0]["output_tokens"].as_i64(), Some(5000));
    let (_, t) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{token_id}"), None).await;
    assert_eq!(t["spent_tokens"].as_i64(), Some(120 + 1000 + 5000));
    env.cleanup().await;
}

#[tokio::test]
async fn trace_context_propagates_in_and_out() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({"run_id": "run-77"})).await;
    let incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[("x-api-key", &token), ("traceparent", incoming)],
            Some(anthropic_body("test-model", true)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // Callers on the public listener are untrusted: their trace context is
    // only linked, so it never becomes the trace of the upstream call, the
    // usage row or the audit row.
    let out = env.upstream.last().headers.get("traceparent").unwrap().to_str().unwrap().to_owned();
    assert!(out.starts_with("00-") && !out.contains("4bf92f3577b34da6a3ce929d0e0e4736"), "{out}");
    let own_trace = out.split('-').nth(1).unwrap().to_owned();
    let u = usage(&env, "tenant-a").await;
    assert_eq!(u[0]["trace_id"], own_trace.as_str());
    let (_, audit) = env.admin_call("GET", "/v1/admin/audit?tenant=tenant-a", None).await;
    let d = audit.as_array().unwrap().iter().find(|e| e["action"] == "secret.decrypt").unwrap().clone();
    assert_eq!(d["trace_id"], own_trace.as_str());
    // ... but kept for correlation.
    let logs = telemetry().logs.contents();
    assert!(logs.contains("\"caller_trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));

    // The llm.request span carries the accounting fields.
    let logs = telemetry().logs.contents();
    let span_close = logs
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| {
            v["span"]["name"] == "llm.request" && v["fields"]["message"] == "close" && v["span"]["run_id"] == "run-77"
        })
        .expect("llm.request span closed");
    let s = &span_close["span"];
    assert_eq!(s["provider"], "anthropic");
    assert_eq!(s["model"], "test-model");
    assert_eq!(s["tenant"], "tenant-a");
    assert_eq!(s["run_id"], "run-77");
    assert_eq!((s["input_tokens"].as_u64(), s["output_tokens"].as_u64()), (Some(1120), Some(30)));
    assert_eq!(s["cost_usd"].as_f64(), Some(0.00111));
    assert!(s["ttft_ms"].is_number() && s["duration_ms"].is_number());

    // A token issued with the run's traceparent puts LLM calls into that trace.
    let run_trace = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let (t2, _) = env.llm_token("tenant-a", json!({"traceparent": run_trace})).await;
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &t2)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let out = env.upstream.last().headers.get("traceparent").unwrap().to_str().unwrap().to_owned();
    assert!(out.starts_with("00-0af7651916cd43dd8448eb211c80319c-"), "{out}");
    env.cleanup().await;
}

#[tokio::test]
async fn request_body_limit() {
    let Some(env) = Env::with(EnvOptions { max_request_bytes: 1024, ..EnvOptions::default() }).await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let big = json!({"model": "test-model", "messages": [{"role": "user", "content": "x".repeat(4096)}]}).to_string();
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(big)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(env.upstream.count(), 0);
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some("not json".into())).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(env.upstream.count(), 0);
    env.cleanup().await;
}

#[tokio::test]
async fn caller_trace_context_is_followed_when_trusted() {
    let Some(env) = Env::with(EnvOptions { trust_caller_trace_context: true, ..EnvOptions::default() }).await else {
        return;
    };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[("x-api-key", &token), ("traceparent", incoming)],
            Some(anthropic_body("test-model", false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let out = env.upstream.last().headers.get("traceparent").unwrap().to_str().unwrap().to_owned();
    assert!(out.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"), "{out}");
    assert!(!out.contains("00f067aa0ba902b7"), "a new span id for the upstream call");
    let u = usage(&env, "tenant-a").await;
    assert_eq!(u[0]["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    env.cleanup().await;
}
