#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Admin API and worker endpoint over HTTP.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};

#[tokio::test]
async fn probes_and_admin_authentication() {
    let Some(env) = Env::new().await else { return };
    for app in [&env.admin, &env.public] {
        assert_eq!(call(app, "GET", "/healthz", &[], None).await.0, StatusCode::OK);
        assert_eq!(call(app, "GET", "/readyz", &[], None).await.0, StatusCode::OK);
    }
    let (_, job) = {
        env.put_secret("tenant-a", "pw", "password", "hunter2").await;
        env.admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/job-tokens",
            Some(json!({"job_id": "j1", "secrets": ["pw"]})),
        )
        .await
    };
    let (llm, _) = env.llm_token("tenant-a", json!({})).await;
    let job = job["token"].as_str().unwrap().to_owned();
    let uri = "/v1/admin/tenants/tenant-a/secrets";
    for auth in [
        None,
        Some("Bearer wrong".to_owned()),
        Some(format!("Basic {ADMIN_TOKEN}")),
        Some(format!("Bearer {llm}")),
        Some(format!("Bearer {job}")),
        Some(format!("Bearer {ADMIN_TOKEN}x")),
    ] {
        let headers: Vec<(&str, &str)> = auth.as_deref().map(|a| vec![("authorization", a)]).unwrap_or_default();
        let (s, v) = call(&env.admin, "GET", uri, &headers, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(v["error"], "unauthorized");
    }
    // Two Authorization headers are ambiguous.
    let a = format!("Bearer {ADMIN_TOKEN}");
    let (s, _) = call(&env.admin, "GET", uri, &[("authorization", &a), ("authorization", &a)], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The admin API is not served on the public listener.
    let (s, _) = call(&env.public, "GET", uri, &[("authorization", &a)], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    env.cleanup().await;
}

#[tokio::test]
async fn secrets_crud_never_returns_values() {
    let Some(env) = Env::new().await else { return };
    let value = "pve-api-token=SECRET-VALUE-0123456789";
    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/secrets",
            Some(json!({"name": "proxmox.api", "kind": "password", "value": value, "metadata": {"host": "pve-1"}})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!((v["name"].as_str(), v["version"].as_i64()), (Some("proxmox.api"), Some(1)));
    assert_eq!(v["created_by"], "core");
    let mut seen = vec![v];

    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/secrets",
            Some(json!({"name": "proxmox.api", "kind": "password", "value": "x"})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");

    let (s, v) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/secrets/proxmox.api", None).await;
    assert_eq!(s, StatusCode::OK);
    seen.push(v);
    let (s, v) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/secrets", None).await;
    assert_eq!((s, v.as_array().unwrap().len()), (StatusCode::OK, 1));
    seen.push(v);
    let (s, v) = env
        .admin_call(
            "PATCH",
            "/v1/admin/tenants/tenant-a/secrets/proxmox.api",
            Some(json!({"value": "pve-api-token=ROTATED-0987654321"})),
        )
        .await;
    assert_eq!((s, v["version"].as_i64()), (StatusCode::OK, Some(2)), "{v}");
    seen.push(v);
    let (_, audit) = env.admin_call("GET", "/v1/admin/audit?tenant=tenant-a", None).await;
    seen.push(audit);
    for v in &seen {
        let t = v.to_string();
        assert!(!t.contains("SECRET-VALUE") && !t.contains("ROTATED"), "value leaked: {t}");
    }

    // Unknown fields and malformed input are rejected without echoing values.
    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/secrets",
            Some(json!({"name": "x", "kind": "password", "value": "v", "tenant": "tenant-b"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/llm-tokens",
            Some(json!({"budget_usd": "sk-misplaced-secret-value"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(!v.to_string().contains("misplaced"), "{v}");
    let (s, _) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/bad%20tenant/secrets",
            Some(json!({"name": "x", "kind": "password", "value": "v"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/secrets",
            Some(json!({"name": "x", "kind": "password", "value": "v".repeat(300 * 1024)})),
        )
        .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    let (s, _) = env.admin_call("DELETE", "/v1/admin/tenants/tenant-a/secrets/proxmox.api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = env.admin_call("DELETE", "/v1/admin/tenants/tenant-a/secrets/proxmox.api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    env.cleanup().await;
}

#[tokio::test]
async fn token_issuance_shapes_and_tenant_isolation() {
    let Some(env) = Env::new().await else { return };
    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/llm-tokens",
            Some(json!({"run_id": "run-9", "providers": ["anthropic"], "budget_usd": 2.5, "budget_tokens": 1000,
                        "ttl_secs": 600, "rate_limit_per_minute": 10})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let token = v["token"].as_str().unwrap().to_owned();
    let id = v["id"].as_str().unwrap().to_owned();
    assert!(token.starts_with("ocb_llm_"));
    assert_eq!((v["budget_usd"].as_f64(), v["budget_tokens"].as_i64()), (Some(2.5), Some(1000)));
    assert_eq!(v["expires_at"].as_i64(), Some(T0 + 600));

    // Listing and reading never show the token again.
    let (_, list) = env.admin_call("GET", "/v1/admin/tenants/tenant-a/llm-tokens", None).await;
    let (_, one) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-a/llm-tokens/{id}"), None).await;
    for v in [&list, &one] {
        assert!(!v.to_string().contains(&token[8..]), "token shown again");
    }
    // Other tenants cannot see or revoke it.
    let (s, _) = env.admin_call("GET", &format!("/v1/admin/tenants/tenant-b/llm-tokens/{id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = env.admin_call("POST", &format!("/v1/admin/tenants/tenant-b/llm-tokens/{id}/revoke"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list_b) = env.admin_call("GET", "/v1/admin/tenants/tenant-b/llm-tokens", None).await;
    assert_eq!(list_b, json!([]));

    // Unknown providers are refused at issuance.
    let (s, v) =
        env.admin_call("POST", "/v1/admin/tenants/tenant-a/llm-tokens", Some(json!({"providers": ["evil"]}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    // Responses carrying tokens must not be cached.
    let r = raw_call(
        &env.admin,
        "POST",
        "/v1/admin/tenants/tenant-a/llm-tokens",
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        Some("{}".into()),
    )
    .await;
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    env.cleanup().await;
}

#[tokio::test]
async fn worker_redeems_job_secrets_exactly_once() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    env.put_secret("tenant-a", "ssh.vm-1", "ssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAA").await;
    env.put_secret("tenant-a", "pw", "password", "hunter2").await;
    env.put_secret("tenant-b", "pw", "password", "tenant-b-password").await;

    // LLM keys are never handed out; secrets of another tenant do not exist here.
    for secrets in [json!(["llm.anthropic"]), json!(["pw", "llm.deepseek"])] {
        let (s, _) = env
            .admin_call(
                "POST",
                "/v1/admin/tenants/tenant-a/job-tokens",
                Some(json!({"job_id": "j", "secrets": secrets})),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
    env.put_secret("tenant-b", "only-b", "password", "x").await;
    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/job-tokens",
            Some(json!({"job_id": "j", "secrets": ["only-b"]})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");

    let (s, v) = env
        .admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/job-tokens",
            Some(json!({"job_id": "vm-create-42", "secrets": ["ssh.vm-1", "pw"], "ttl_secs": 120})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let token = v["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("ocb_job_"));

    let auth = format!("Bearer {token}");
    let r = raw_call(&env.public, "POST", "/v1/worker/secrets", &[("authorization", &auth)], None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    let v = r.json();
    assert_eq!((v["job_id"].as_str(), v["tenant"].as_str()), (Some("vm-create-42"), Some("tenant-a")));
    let got: Vec<(String, String)> = v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["name"].as_str().unwrap().to_owned(), s["value"].as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(
        got,
        [
            ("pw".to_owned(), "hunter2".to_owned()),
            ("ssh.vm-1".into(), "-----BEGIN OPENSSH PRIVATE KEY-----\nAAA".into())
        ]
    );
    let all = r.text();
    assert!(!all.contains("tenant-b-password") && !all.contains(KEY_A) && !all.contains(DS_KEY_A));

    // Reuse is rejected.
    let (s, v) = call(&env.public, "POST", "/v1/worker/secrets", &[("authorization", &auth)], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    // Job endpoint is not on the admin listener, and other credentials do not work.
    let (s, _) = call(&env.admin, "POST", "/v1/worker/secrets", &[("authorization", &auth)], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (llm, _) = env.llm_token("tenant-a", json!({})).await;
    for bad in [format!("Bearer {llm}"), format!("Bearer {ADMIN_TOKEN}"), "Bearer ".into(), String::new()] {
        let headers: Vec<(&str, &str)> = if bad.is_empty() { vec![] } else { vec![("authorization", &bad)] };
        let (s, _) = call(&env.public, "POST", "/v1/worker/secrets", &headers, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{bad}");
    }

    // Expiry (manual clock) and revocation.
    let issue = |secrets: Value| {
        env.admin_call(
            "POST",
            "/v1/admin/tenants/tenant-a/job-tokens",
            Some(json!({"job_id": "j2", "secrets": secrets, "ttl_secs": 30})),
        )
    };
    let (_, v) = issue(json!(["pw"])).await;
    let expiring = format!("Bearer {}", v["token"].as_str().unwrap());
    env.clock.advance(31);
    let (s, _) = call(&env.public, "POST", "/v1/worker/secrets", &[("authorization", &expiring)], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, v) = issue(json!(["pw"])).await;
    let revoked = format!("Bearer {}", v["token"].as_str().unwrap());
    let id = v["id"].as_str().unwrap();
    let (s, _) = env.admin_call("POST", &format!("/v1/admin/tenants/tenant-b/job-tokens/{id}/revoke"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = env.admin_call("POST", &format!("/v1/admin/tenants/tenant-a/job-tokens/{id}/revoke"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&env.public, "POST", "/v1/worker/secrets", &[("authorization", &revoked)], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // The audit log shows who decrypted what, for which job.
    let (_, audit) = env.admin_call("GET", "/v1/admin/audit?tenant=tenant-a&limit=100", None).await;
    let decrypts: Vec<&Value> = audit.as_array().unwrap().iter().filter(|e| e["action"] == "secret.decrypt").collect();
    assert_eq!(decrypts.len(), 2);
    assert!(decrypts.iter().all(|e| e["purpose"] == "job:vm-create-42"));
    assert!(!audit.to_string().contains("hunter2"));
    env.cleanup().await;
}

#[tokio::test]
async fn kek_rewrap_endpoint() {
    let Some(env) = Env::new().await else { return };
    env.put_secret("tenant-a", "pw", "password", "hunter2").await;
    let (s, v) = env.admin_call("POST", "/v1/admin/kek/rewrap", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!((v["rewrapped"].as_u64(), v["remaining"].as_i64()), (Some(0), Some(0)));
    assert_eq!(v["current_kek_id"], "test-1");
    env.cleanup().await;
}

#[tokio::test]
async fn providers_are_listed_read_only() {
    let Some(env) = Env::new().await else { return };
    env.seed_keys().await;
    let (s, v) = env.admin_call("GET", "/v1/admin/providers", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["config_version"].as_u64(), Some(env.state.proxy.snapshot().version()));
    let providers = v["providers"].as_array().unwrap();
    let ids: Vec<&str> = providers.iter().map(|p| p["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["anthropic", "deepseek", "openrouter"]);
    assert_eq!(
        providers[0],
        json!({"id": "anthropic", "kind": "anthropic", "host": env.upstream_addr.to_string(),
               "endpoints": ["messages", "count_tokens", "models"], "access": "implicit",
               "has_tls": false, "tls_not_after": null, "pricing_from": null,
               "headers": {"request_forward_prefixes": [], "response_forward_prefixes": []}})
    );
    // Only the host of a base URL is shown (openrouter's has the path /v1/).
    assert_eq!(providers[2]["host"], env.upstream_addr.to_string());
    assert_eq!(providers[2]["endpoints"], json!(["chat_completions", "models"]));
    let text = v.to_string();
    assert!(!text.contains("/v1") && !text.contains(KEY_A) && !text.contains(DS_KEY_A), "{text}");

    // Read-only, admin only, and not on the public listener.
    let auth = format!("Bearer {ADMIN_TOKEN}");
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let (s, _) =
            call(&env.admin, method, "/v1/admin/providers", &[("authorization", &auth)], Some("{}".into())).await;
        assert!(s == StatusCode::METHOD_NOT_ALLOWED || s == StatusCode::NOT_FOUND, "{method}: {s}");
    }
    let (s, _) = call(&env.admin, "GET", "/v1/admin/providers", &[], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&env.public, "GET", "/v1/admin/providers", &[("authorization", &auth)], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    env.cleanup().await;
}
