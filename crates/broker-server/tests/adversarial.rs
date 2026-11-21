#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Adversarial tests: key leakage, revocation, tenant isolation, token reuse,
//! header and request smuggling.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Every fake key, plus long fragments of them (a leak of half a key is a leak).
fn key_fragments() -> Vec<String> {
    let mut out = Vec::new();
    for k in [KEY_A, KEY_B, DS_KEY_A] {
        out.push(k.to_owned());
        let random = &k[k.len() - 28..];
        out.push(random[..14].to_owned());
        out.push(random[14..].to_owned());
    }
    out
}

fn assert_no_leak(what: &str, text: &str, extra: &[&str]) {
    for f in key_fragments().iter().map(String::as_str).chain(extra.iter().copied()) {
        assert!(!text.contains(f), "{what} contains secret material {f:?}");
    }
}

type Flow = (String, &'static str, Vec<(String, String)>, Option<String>);

async fn raw_http(addr: SocketAddr, request: &str) -> String {
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), sock.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// A server that must never be contacted.
async fn trap() -> (Upstream, SocketAddr) {
    start_upstream().await
}

#[tokio::test]
async fn keys_never_leak_into_responses_errors_logs_metrics_or_audit() {
    let Some(env) =
        Env::with(EnvOptions { response_timeout_secs: 1, idle_timeout_secs: 1, ..EnvOptions::default() }).await
    else {
        return;
    };
    env.seed_keys().await;
    let (ta, _) = env.llm_token("tenant-a", json!({"budget_tokens": 1_000_000})).await;
    let (tb, _) = env.llm_token("tenant-b", json!({})).await;
    let (tiny, _) = env.llm_token("tenant-a", json!({"budget_tokens": 1})).await;
    let mut bodies = Vec::new();
    let anth = |token: &str| {
        vec![("x-api-key".to_owned(), token.to_owned()), ("anthropic-version".into(), "2023-06-01".into())]
    };
    let flows: Vec<Flow> = vec![
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&ta), Some(anthropic_body("test-model", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&ta), Some(anthropic_body("test-model", true))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&tb), Some(anthropic_body("test-model", true))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&ta), Some(anthropic_body("error-401", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&tb), Some(anthropic_body("error-401", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&ta), Some(anthropic_body("echo-key", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&tb), Some(anthropic_body("echo-key", true))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&ta), Some(anthropic_body("slow-headers", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&ta), Some(anthropic_body("stall-stream", true))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&tiny), Some(anthropic_body("test-model", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(&tiny), Some(anthropic_body("test-model", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth("ocb_llm_0000"), Some(anthropic_body("test-model", false))),
        ("POST".into(), "/llm/anthropic/v1/messages", anth(KEY_A), Some(anthropic_body("test-model", false))),
        (
            "POST".into(),
            "/llm/openai/deepseek/chat/completions",
            vec![("authorization".into(), format!("Bearer {ta}"))],
            Some(openai_body("deepseek-chat", true, true)),
        ),
        (
            "POST".into(),
            "/llm/openai/deepseek/chat/completions",
            vec![("authorization".into(), format!("Bearer {ta}"))],
            Some(openai_body("deepseek-chat", false, false)),
        ),
    ];
    env.settle().await;
    for (method, uri, headers, body) in flows {
        let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let r = env.llm(&method, uri, &h, body).await;
        let mut dump = format!("{} {:?} ", r.status, r.headers);
        dump.push_str(&r.text());
        bodies.push(dump);
        env.settle().await;
    }
    for b in &bodies {
        assert_no_leak("proxy response", b, &[]);
    }
    // The reflected key was replaced, not dropped silently.
    assert!(bodies.iter().filter(|b| b.contains("[REDACTED]")).count() >= 4, "{bodies:#?}");

    // Admin views: usage, token info, audit, secrets.
    for uri in [
        "/v1/admin/tenants/tenant-a/usage",
        "/v1/admin/tenants/tenant-b/usage",
        "/v1/admin/tenants/tenant-a/llm-tokens",
        "/v1/admin/tenants/tenant-a/secrets",
        "/v1/admin/tenants/tenant-a/secrets/llm.anthropic",
        "/v1/admin/audit?limit=1000",
    ] {
        let (s, v) = env.admin_call("GET", uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert_no_leak(uri, &v.to_string(), &[]);
    }

    // Raw database: values are encrypted, tokens are digests.
    let pool = env.state.keeper.store().pool().clone();
    let dump: Vec<(String,)> = sqlx::query_as(
        "SELECT row_to_json(t)::text FROM (SELECT * FROM secrets) t UNION ALL
         SELECT row_to_json(t)::text FROM (SELECT * FROM llm_tokens) t UNION ALL
         SELECT row_to_json(t)::text FROM (SELECT * FROM llm_usage) t UNION ALL
         SELECT row_to_json(t)::text FROM (SELECT * FROM audit_log) t",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let dump: String = dump.into_iter().map(|(s,)| s).collect::<Vec<_>>().join("\n");
    assert_no_leak("database", &dump, &[&ta[8..], &tb[8..]]);

    env.settle().await;
    // Logs of the whole test binary (TRACE, all crates) and all metrics.
    let logs = telemetry().logs.contents();
    assert!(logs.contains("llm.request"), "log capture is working");
    assert_no_leak("logs", &logs, &[&ta[8..], &tb[8..], &tiny[8..], ADMIN_TOKEN]);
    let metrics = telemetry().metrics.render();
    assert!(metrics.contains("ocb_llm_tokens_total"), "metrics capture is working");
    assert_no_leak("metrics", &metrics, &[&ta[8..], &tb[8..]]);
    env.cleanup().await;
}

#[tokio::test]
async fn prompt_asking_for_the_key_gets_nothing() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    for stream in [false, true] {
        let body = anthropic_body("echo-key", stream);
        let r = env.llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &token)], Some(body.clone())).await;
        assert_eq!(r.status, StatusCode::OK);
        let seen = env.upstream.last();
        // The key travels only in the auth header, never in the body.
        assert_eq!(seen.body, body.as_bytes());
        assert_eq!(seen.headers.get("x-api-key").unwrap(), KEY_A);
        // Even an upstream that reflects the key cannot hand it to the caller.
        assert_no_leak("response", &r.text(), &[]);
        assert!(r.text().contains("[REDACTED]"), "{}", r.text());
    }
    env.cleanup().await;
}

#[tokio::test]
async fn revoked_and_expired_tokens_are_rejected_immediately() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (token, id) = env.llm_token("tenant-a", json!({"ttl_secs": 300})).await;
    let h = [("x-api-key", token.as_str())];
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(r.status, StatusCode::OK);
    let (s, _) = env.admin_call("POST", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{id}/revoke"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let before = env.upstream.count();
    let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.json()["error"]["type"], "authentication_error");
    assert_eq!(r.headers.get("www-authenticate").unwrap(), "Bearer");
    assert_eq!(env.upstream.count(), before, "nothing forwarded with a revoked token");

    let (t2, _) = env.llm_token("tenant-a", json!({"ttl_secs": 60})).await;
    env.clock.advance(60);
    let r = env
        .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", &t2)], Some(anthropic_body("test-model", false)))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    env.cleanup().await;
}

#[tokio::test]
async fn cross_tenant_access_is_denied_everywhere() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    env.put_secret("tenant-a", "pw", "password", "secret-of-a").await;
    env.put_secret("tenant-b", "pw", "password", "secret-of-b").await;
    let (ta, ta_id) = env.llm_token("tenant-a", json!({})).await;
    let (tb, _) = env.llm_token("tenant-b", json!({})).await;

    // Proxy: each token uses its own tenant's key; no fallback across tenants.
    for (t, key) in [(&ta, KEY_A), (&tb, KEY_B)] {
        let r = env
            .llm("POST", "/llm/anthropic/v1/messages", &[("x-api-key", t)], Some(anthropic_body("test-model", false)))
            .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(env.upstream.last().headers.get("x-api-key").unwrap(), key);
    }
    let r = env
        .llm(
            "POST",
            "/llm/openai/deepseek/chat/completions",
            &[("authorization", &format!("Bearer {tb}"))],
            Some(openai_body("deepseek-chat", false, false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "tenant-b has no deepseek key; tenant-a's must not be used");

    // Admin API: a token id or job token of tenant-a is invisible under tenant-b.
    for (method, uri) in [
        ("GET", format!("/v1/admin/tenants/tenant-b/llm-tokens/{ta_id}")),
        ("POST", format!("/v1/admin/tenants/tenant-b/llm-tokens/{ta_id}/revoke")),
    ] {
        let (s, _) = env.admin_call(method, &uri, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
    }
    let (_, v) = env
        .admin_call("POST", "/v1/admin/tenants/tenant-a/job-tokens", Some(json!({"job_id": "j", "secrets": ["pw"]})))
        .await;
    let (job_token, job_id) = (v["token"].as_str().unwrap().to_owned(), v["id"].as_str().unwrap().to_owned());
    let (s, _) = env.admin_call("POST", &format!("/v1/admin/tenants/tenant-b/job-tokens/{job_id}/revoke"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = env.admin_call("GET", "/v1/admin/tenants/tenant-b/job-tokens", None).await;
    assert_eq!(list, json!([]));
    let (_, usage_b) = env.admin_call("GET", "/v1/admin/tenants/tenant-b/usage", None).await;
    assert!(usage_b.as_array().unwrap().iter().all(|u| u["tenant"] == "tenant-b"));
    let (_, audit_b) = env.admin_call("GET", "/v1/admin/audit?tenant=tenant-b", None).await;
    assert!(audit_b.as_array().unwrap().iter().all(|e| e["tenant"] == "tenant-b"));

    // Path tricks cannot reach another tenant.
    for uri in [
        "/v1/admin/tenants/tenant-a/../tenant-b/secrets",
        "/v1/admin/tenants/tenant-a%2F..%2Ftenant-b/secrets",
        "/v1/admin/tenants/tenant-b%00/secrets",
        "/v1/admin/tenants/%2A/secrets",
    ] {
        let (s, v) = env.admin_call("GET", uri, None).await;
        assert!(s == StatusCode::NOT_FOUND || s == StatusCode::BAD_REQUEST, "{uri}: {s} {v}");
    }

    // Worker: the job of tenant-a gets tenant-a's value, never tenant-b's.
    let r =
        raw_call(&env.public, "POST", "/v1/worker/secrets", &[("authorization", &format!("Bearer {job_token}"))], None)
            .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["secrets"][0]["value"], "secret-of-a");
    assert!(!r.text().contains("secret-of-b"));
    env.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_token_reuse_is_rejected_even_concurrently() {
    let Some(env) = Env::new().await else { return };
    env.put_secret("tenant-a", "pw", "password", "hunter2").await;
    let (_, v) = env
        .admin_call("POST", "/v1/admin/tenants/tenant-a/job-tokens", Some(json!({"job_id": "j", "secrets": ["pw"]})))
        .await;
    let auth = format!("Bearer {}", v["token"].as_str().unwrap());
    let addr = env.serve_public().await;
    let client = reqwest::Client::new();
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let (client, auth) = (client.clone(), auth.clone());
        tasks.push(tokio::spawn(async move {
            client
                .post(format!("http://{addr}/v1/worker/secrets"))
                .header("authorization", auth)
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut codes = Vec::new();
    for t in tasks {
        codes.push(t.await.unwrap().as_u16());
    }
    assert_eq!(codes.iter().filter(|c| **c == 200).count(), 1, "{codes:?}");
    assert_eq!(codes.iter().filter(|c| **c == 401).count(), 11, "{codes:?}");
    env.cleanup().await;
}

#[tokio::test]
async fn header_smuggling_cannot_redirect_or_leak() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (evil, evil_addr) = trap().await;
    let evil_host = evil_addr.to_string();
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let forwarded = format!("for=1.2.3.4;host={evil_host};proto=http");
    let evil_url = format!("http://{evil_host}/");
    let r = env
        .llm(
            "POST",
            "/llm/anthropic/v1/messages",
            &[
                ("x-api-key", &token),
                ("host", &evil_host),
                ("x-forwarded-host", &evil_host),
                ("x-forwarded-proto", "http"),
                ("x-forwarded-for", "1.2.3.4"),
                ("forwarded", &forwarded),
                ("x-original-url", &evil_url),
                ("x-rewrite-url", &evil_url),
                ("x-http-method-override", "DELETE"),
                ("proxy-authorization", "Basic ZXZpbDpldmls"),
                ("cookie", "session=abc"),
                ("connection", "x-api-key, keep-alive"),
                ("api-key", "azure-style-key"),
                ("x-goog-api-key", "google-style-key"),
                ("openai-organization", "org-evil"),
                ("anthropic-organization", "org-evil"),
                ("x-stainless-os", "evil"),
            ],
            Some(anthropic_body("test-model", false)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let seen = env.upstream.last();
    assert_eq!(seen.headers.get("host").unwrap().to_str().unwrap(), env.upstream_addr.to_string());
    assert_eq!(seen.headers.get("x-api-key").unwrap(), KEY_A, "the hop-by-hop trick did not strip our key");
    let allowed = [
        "content-type",
        "accept",
        "accept-encoding",
        "x-api-key",
        "user-agent",
        "host",
        "content-length",
        "traceparent",
    ];
    for name in seen.headers.keys() {
        assert!(allowed.contains(&name.as_str()), "unexpected header forwarded upstream: {name}");
    }
    assert_eq!(evil.count(), 0);

    // Absolute-form request target and evil Host on a real socket.
    let addr = env.serve_public().await;
    let body = anthropic_body("test-model", false);
    let before = env.upstream.count();
    let resp = raw_http(
        addr,
        &format!(
            "POST http://{evil_host}/llm/anthropic/v1/messages HTTP/1.1\r\nhost: {evil_host}\r\nx-api-key: {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(env.upstream.count(), before + 1);
    assert_eq!(evil.count(), 0, "the evil host was contacted");

    // Request smuggling: conflicting Content-Length and Transfer-Encoding.
    let before = env.upstream.count();
    let resp = raw_http(
        addr,
        &format!(
            "POST /llm/anthropic/v1/messages HTTP/1.1\r\nhost: broker\r\nx-api-key: {token}\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n0\r\n\r\nPOST /llm/anthropic/v1/files HTTP/1.1\r\nhost: broker\r\n\r\n"
        ),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    assert_eq!(env.upstream.count(), before);
    assert_eq!(evil.count(), 0);
    env.cleanup().await;
}

#[tokio::test]
async fn only_allowlisted_endpoints_and_providers_are_reachable() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (_, evil_addr) = trap().await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let bearer = format!("Bearer {token}");
    let cases: Vec<(&str, String)> = vec![
        ("POST", "/llm/anthropic/v1/messages/batches".into()),
        ("POST", "/llm/anthropic/v1/files".into()),
        ("GET", "/llm/anthropic/v1/organizations/me".into()),
        ("POST", "/llm/anthropic/v1/messages/".into()),
        ("POST", "/llm/anthropic/V1/messages".into()),
        ("POST", "/llm/anthropic/v1%2Fmessages".into()),
        ("POST", "/llm/anthropic/v1/messages/../files".into()),
        ("POST", "/llm/anthropic/v1/./messages".into()),
        ("POST", "/llm/anthropic//v1/messages".into()),
        ("POST", format!("/llm/anthropic//{evil_addr}/v1/messages")),
        ("POST", format!("/llm/anthropic/http://{evil_addr}/v1/messages")),
        ("PUT", "/llm/anthropic/v1/messages".into()),
        ("DELETE", "/llm/anthropic/v1/messages".into()),
        ("GET", "/llm/anthropic/v1/messages".into()),
        ("POST", "/llm/anthropic/v1/messages?url=http://evil.example".into()),
        ("POST", "/llm/anthropic/v1/messages?beta=true&target=x".into()),
        ("POST", "/llm/openai/evil/chat/completions".into()),
        ("POST", "/llm/openai/anthropic/v1/messages".into()),
        ("POST", "/llm/openai/../anthropic/v1/messages".into()),
        ("POST", format!("/llm/openai/{evil_addr}/chat/completions")),
        ("POST", "/llm/openai/http:%2F%2Fevil.example/chat/completions".into()),
        ("POST", "/llm/openai/deepseek/v1/chat/completions".into()),
        ("POST", "/llm/openai/deepseek/chat/completions/../../files".into()),
        ("POST", "/llm/openai/deepseek/files".into()),
        ("POST", "/llm/openai/deepseek/embeddings".into()),
        ("POST", "/llm/openai/DEEPSEEK/chat/completions".into()),
        ("POST", "/llm/openai/deepseek/chat/completions?api-version=1".into()),
        ("POST", "/llm/deepseek/chat/completions".into()),
        ("POST", "/llm/".into()),
        ("POST", "/llm/p/evil/v1/messages".into()),
        ("POST", "/llm/p/anthropic/v1/files".into()),
        ("POST", "/llm/p/anthropic/chat/completions".into()),
        ("POST", "/llm/p/deepseek/v1/messages".into()),
        ("POST", "/llm/p/anthropic%2Fv1/messages".into()),
        ("POST", "/llm/p/../anthropic/v1/messages".into()),
        ("POST", format!("/llm/p/{evil_addr}/v1/messages")),
        ("POST", "/llm/p/http:%2F%2Fevil.example/v1/messages".into()),
    ];
    for (method, uri) in &cases {
        let r = env
            .llm(
                method,
                uri,
                &[("x-api-key", &token), ("authorization", &bearer)],
                Some(anthropic_body("test-model", false)),
            )
            .await;
        assert!(matches!(r.status.as_u16(), 400 | 404 | 405), "{method} {uri} -> {} {}", r.status, r.text());
        assert_no_leak(uri, &r.text(), &[]);
    }
    assert_eq!(
        env.upstream.count(),
        0,
        "nothing may reach the upstream: {:?}",
        env.upstream.requests().iter().map(|s| s.uri.clone()).collect::<Vec<_>>()
    );
    env.cleanup().await;
}

#[tokio::test]
async fn wrong_or_ambiguous_credentials_never_reach_upstream() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    env.put_secret("tenant-a", "pw", "password", "hunter2").await;
    let (token, _) = env.llm_token("tenant-a", json!({})).await;
    let (other, _) = env.llm_token("tenant-b", json!({})).await;
    let (_, v) = env
        .admin_call("POST", "/v1/admin/tenants/tenant-a/job-tokens", Some(json!({"job_id": "j", "secrets": ["pw"]})))
        .await;
    let job = v["token"].as_str().unwrap().to_owned();
    let bearer = |t: &str| format!("Bearer {t}");
    let cases: Vec<Vec<(&str, String)>> = vec![
        vec![],
        vec![("x-api-key", KEY_A.to_owned())],
        vec![("authorization", bearer(KEY_A))],
        vec![("x-api-key", ADMIN_TOKEN.to_owned())],
        vec![("x-api-key", job.clone())],
        vec![("x-api-key", token.clone()), ("authorization", bearer(&other))],
        vec![("x-api-key", token.clone()), ("x-api-key", token.clone())],
        vec![("authorization", format!("Basic {token}"))],
        vec![("x-api-key", format!("{token} "))],
        vec![("x-api-key", token.to_uppercase())],
        vec![("x-api-key", token[..token.len() - 2].to_owned())],
    ];
    for headers in &cases {
        let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = env.llm("POST", "/llm/anthropic/v1/messages", &h, Some(anthropic_body("test-model", false))).await;
        // A trailing space is trimmed by HTTP itself; that one is a valid token.
        if headers.len() == 1 && headers[0].1 == format!("{token} ") {
            continue;
        }
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{headers:?}");
    }
    assert!(env.upstream.requests().iter().all(|s| s.headers.get("x-api-key").unwrap() == KEY_A));
    env.cleanup().await;
}

#[tokio::test]
async fn admin_and_metrics_are_not_on_the_public_listener() {
    let Some(env) = Env::new().await else { return };
    let auth = format!("Bearer {ADMIN_TOKEN}");
    for uri in ["/metrics", "/v1/admin/audit", "/v1/admin/tenants/tenant-a/secrets"] {
        let (s, _) = call(&env.public, "GET", uri, &[("authorization", &auth)], None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
    }
    for uri in ["/llm/anthropic/v1/messages", "/v1/worker/secrets"] {
        let (s, _) = call(&env.admin, "POST", uri, &[("authorization", &auth)], Some("{}".into())).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
    }
    let m = broker_server::metrics_router(None, Default::default());
    let (s, _) = call(&m, "GET", "/v1/admin/audit", &[("authorization", &auth)], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let _: Value = Value::Null;
    env.cleanup().await;
}

#[tokio::test]
async fn arbitrary_methods_do_not_create_metric_labels() {
    let Some(env) = Env::new().await else { return };
    let addr = env.serve_public().await;
    for uri in ["/healthz", "/llm/anthropic/v1/messages", "/nowhere"] {
        let method = format!("XEVIL{}", "Q".repeat(200));
        let resp =
            raw_http(addr, &format!("{method} {uri} HTTP/1.1\r\nhost: broker\r\nconnection: close\r\n\r\n")).await;
        assert!(resp.starts_with("HTTP/1.1 "), "{resp}");
    }
    let metrics = telemetry().metrics.render();
    assert!(!metrics.contains("XEVIL"), "a caller-chosen method became a metric label");
    assert!(metrics.contains("method=\"other\""));
    assert!(!telemetry().logs.contents().contains("XEVILQQQQ"), "nor a log field");
    env.cleanup().await;
}
