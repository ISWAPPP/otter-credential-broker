#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Keeper behaviour against a real PostgreSQL database: tenant scoping,
//! write-only values, audit of every decrypt, single-use job tokens, LLM token
//! validation, accounting and KEK rotation.

use std::sync::Arc;

use broker_core::clock::{Clock, ManualClock};
use broker_core::crypto::{Envelope, KEY_LEN, LocalKeyProvider, random_bytes};
use broker_core::keeper::{NewJobToken, NewLlmToken, NewSecret, SecretUpdate};
use broker_core::store::{NewUsageRow, Store, UsageFilter};
use broker_core::testing::TestDb;
use broker_core::tokens::TokenHasher;
use broker_core::{BrokerError, CallContext, Keeper, KeeperSettings, Secret};
use serde_json::json;

const T0: i64 = 1_900_000_000;
const ADMIN: CallContext<'static> = CallContext { actor: "core", trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736") };
const KEY_A: &str = "sk-ant-fake-tenant-a-0000000000000000";
const KEY_B: &str = "sk-ant-fake-tenant-b-1111111111111111";

struct Fx {
    keeper: Keeper,
    clock: Arc<ManualClock>,
    store: Store,
    kek: Secret<Vec<u8>>,
    token_key: Secret<Vec<u8>>,
    db: TestDb,
}

fn kek() -> Secret<Vec<u8>> {
    Secret::new(random_bytes(KEY_LEN).unwrap())
}

async fn fixture() -> Option<Fx> {
    let db = TestDb::create().await?;
    let store = db.store().await;
    let clock = Arc::new(ManualClock::new(T0));
    let kek = kek();
    let token_key = self::kek();
    let envelope = Envelope::new(Arc::new(LocalKeyProvider::new("k1", kek.clone()).unwrap()));
    let hasher = TokenHasher::new(token_key.clone()).unwrap();
    let keeper = Keeper::new(store.clone(), envelope, hasher, clock.clone(), KeeperSettings::default());
    Some(Fx { keeper, clock, store, kek, token_key, db })
}

fn secret(name: &str, kind: &str, value: &str) -> NewSecret {
    NewSecret { name: name.into(), kind: kind.into(), value: Secret::new(value.into()), metadata: None }
}

async fn put_llm_key(k: &Keeper, tenant: &str, provider: &str, key: &str) {
    k.create_secret(ADMIN, tenant, secret(&format!("llm.{provider}"), "llm_api_key", key)).await.unwrap();
}

#[tokio::test]
async fn secrets_are_tenant_scoped_write_only_and_audited() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let mut s = secret("ssh.vm-1", "ssh_private_key", "-----BEGIN KEY-----\nAAAA\n-----END KEY-----");
    s.metadata = Some(json!({"host": "vm-1"}));
    let meta = k.create_secret(ADMIN, "tenant-a", s).await.unwrap();
    assert_eq!((meta.version, meta.kind.as_str(), meta.kek_id.as_str()), (1, "ssh_private_key", "k1"));
    let shown = serde_json::to_string(&meta).unwrap() + &format!("{meta:?}");
    assert!(!shown.contains("BEGIN KEY"), "metadata must not include the value");

    // Same name in another tenant is a different secret; duplicates conflict.
    k.create_secret(ADMIN, "tenant-b", secret("ssh.vm-1", "ssh_private_key", "other")).await.unwrap();
    assert!(matches!(
        k.create_secret(ADMIN, "tenant-a", secret("ssh.vm-1", "ssh_private_key", "x")).await,
        Err(BrokerError::Conflict(_))
    ));
    assert_eq!(k.list_secrets("tenant-a").await.unwrap().len(), 1);
    assert!(k.list_secrets("tenant-c").await.unwrap().is_empty());
    assert!(matches!(k.get_secret("tenant-c", "ssh.vm-1").await, Err(BrokerError::NotFound(_))));

    // Value update bumps the version; metadata-only update does not.
    let m = k
        .update_secret(
            ADMIN,
            "tenant-a",
            "ssh.vm-1",
            SecretUpdate { value: Some(Secret::new("v2".into())), metadata: None },
        )
        .await
        .unwrap();
    assert_eq!(m.version, 2);
    let m = k
        .update_secret(ADMIN, "tenant-a", "ssh.vm-1", SecretUpdate { value: None, metadata: Some(json!({"a": 1})) })
        .await
        .unwrap();
    assert_eq!((m.version, m.metadata["a"].as_i64()), (2, Some(1)));
    assert!(matches!(
        k.update_secret(
            ADMIN,
            "tenant-c",
            "ssh.vm-1",
            SecretUpdate { value: Some(Secret::new("x".into())), metadata: None }
        )
        .await,
        Err(BrokerError::NotFound(_))
    ));

    // Deleting in tenant-c does nothing to tenant-a.
    assert!(matches!(k.delete_secret(ADMIN, "tenant-c", "ssh.vm-1").await, Err(BrokerError::NotFound(_))));
    k.delete_secret(ADMIN, "tenant-a", "ssh.vm-1").await.unwrap();
    assert_eq!(k.list_secrets("tenant-b").await.unwrap().len(), 1);

    let audit = k.audit_log(Some("tenant-a"), 100).await.unwrap();
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["secret.delete", "secret.update", "secret.update", "secret.create"]);
    assert!(audit.iter().all(|e| e.actor == "core" && e.trace_id.as_deref() == ADMIN.trace_id));
    let dump = format!("{audit:?}");
    assert!(!dump.contains("BEGIN KEY") && !dump.contains("v2"));

    // The value is stored encrypted.
    let raw: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT ciphertext FROM secrets").fetch_all(fx.store.pool()).await.unwrap();
    assert!(raw.iter().all(|(c,)| !String::from_utf8_lossy(c).contains("other")));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn input_validation() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    for (tenant, name, kind, value) in [
        ("bad tenant", "n", "generic", "v"),
        ("t", "../n", "generic", "v"),
        ("t", "n", "Bad", "v"),
        ("t", "n", "generic", ""),
        ("t", "llm.x", "llm_api_key", "sk with space"),
        ("t", "llm.x", "llm_api_key", "sk\r\nInjected: 1"),
    ] {
        assert!(matches!(
            k.create_secret(ADMIN, tenant, secret(name, kind, value)).await,
            Err(BrokerError::Invalid(_))
        ));
    }
    let big = "x".repeat(KeeperSettings::default().max_secret_bytes + 1);
    assert!(matches!(k.create_secret(ADMIN, "t", secret("n", "generic", &big)).await, Err(BrokerError::TooLarge(_))));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn provider_keys_resolve_only_within_the_token_tenant() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    put_llm_key(k, "tenant-a", "anthropic", KEY_A).await;
    put_llm_key(k, "tenant-b", "anthropic", KEY_B).await;
    let ta = k.issue_llm_token(ADMIN, "tenant-a", NewLlmToken::default()).await.unwrap();
    let tb = k.issue_llm_token(ADMIN, "tenant-b", NewLlmToken::default()).await.unwrap();
    assert!(ta.token.expose().starts_with("ocb_llm_"));

    let ga = k.authorize_llm(ta.token.expose(), "anthropic").await.unwrap();
    let gb = k.authorize_llm(tb.token.expose(), "anthropic").await.unwrap();
    assert_eq!(k.provider_key(&ga, "anthropic", Some("trace-1")).await.unwrap().expose(), KEY_A);
    assert_eq!(k.provider_key(&gb, "anthropic", None).await.unwrap().expose(), KEY_B);
    // No key for this provider in the tenant: refused, never another tenant's key.
    assert!(matches!(k.provider_key(&ga, "deepseek", None).await, Err(BrokerError::Forbidden(_))));

    // Every decrypt left an audit row with actor, purpose and trace id.
    let audit = k.audit_log(Some("tenant-a"), 10).await.unwrap();
    let d = audit.iter().find(|e| e.action == "secret.decrypt").unwrap();
    assert_eq!(d.actor, format!("llm-token:{}", ta.info.id));
    assert_eq!(d.secret_name.as_deref(), Some("llm.anthropic"));
    assert_eq!(d.purpose.as_deref(), Some("llm.proxy:anthropic"));
    assert_eq!(d.trace_id.as_deref(), Some("trace-1"));
    assert!(!format!("{audit:?}").contains(KEY_A));

    // A sealed record copied into another tenant's row does not decrypt (AAD).
    sqlx::query(
        "UPDATE secrets SET wrapped_dek = a.wrapped_dek, ciphertext = a.ciphertext FROM
         (SELECT wrapped_dek, ciphertext FROM secrets WHERE tenant_id = 'tenant-a') a WHERE tenant_id = 'tenant-b'",
    )
    .execute(fx.store.pool())
    .await
    .unwrap();
    assert!(matches!(k.provider_key(&gb, "anthropic", None).await, Err(BrokerError::Crypto(_))));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn llm_tokens_validate_revoke_expire_and_rate_limit() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let t = k
        .issue_llm_token(
            ADMIN,
            "tenant-a",
            NewLlmToken {
                run_id: Some("run-1".into()),
                providers: Some(vec!["anthropic".into()]),
                ttl_secs: Some(600),
                rate_limit_per_minute: Some(3),
                ..NewLlmToken::default()
            },
        )
        .await
        .unwrap();
    let tok = t.token.expose();
    // Rate limit: 3 per minute window.
    fx.clock.set(T0 - T0 % 60);
    for _ in 0..3 {
        k.authorize_llm(tok, "anthropic").await.unwrap();
    }
    match k.authorize_llm(tok, "anthropic").await {
        Err(BrokerError::RateLimited { retry_after_secs }) => assert_eq!(retry_after_secs, 60),
        other => panic!("expected rate limit, got {other:?}"),
    }
    fx.clock.advance(60);
    let g = k.authorize_llm(tok, "anthropic").await.unwrap();
    assert_eq!(g.run_id.as_deref(), Some("run-1"));
    // Provider allowlist.
    assert!(matches!(k.authorize_llm(tok, "deepseek").await, Err(BrokerError::Forbidden(_))));
    // Garbage, other token types and look-alikes are rejected without a DB hit.
    for bad in ["", "Bearer x", &tok[..tok.len() - 1], &tok.replace("ocb_llm_", "ocb_job_")] {
        assert!(matches!(k.authorize_llm(bad, "anthropic").await, Err(BrokerError::Unauthorized)));
    }
    // Revocation is effective immediately, and only within the token's tenant.
    assert!(matches!(k.revoke_llm_token(ADMIN, "tenant-b", &t.info.id).await, Err(BrokerError::NotFound(_))));
    k.authorize_llm(tok, "anthropic").await.unwrap();
    k.revoke_llm_token(ADMIN, "tenant-a", &t.info.id).await.unwrap();
    assert!(matches!(k.authorize_llm(tok, "anthropic").await, Err(BrokerError::Unauthorized)));
    assert!(k.get_llm_token("tenant-a", &t.info.id).await.unwrap().revoked_at.is_some());
    assert!(matches!(k.get_llm_token("tenant-b", &t.info.id).await, Err(BrokerError::NotFound(_))));

    // Expiry.
    let t2 = k
        .issue_llm_token(ADMIN, "tenant-a", NewLlmToken { ttl_secs: Some(10), ..NewLlmToken::default() })
        .await
        .unwrap();
    k.authorize_llm(t2.token.expose(), "anthropic").await.unwrap();
    fx.clock.advance(10);
    assert!(matches!(k.authorize_llm(t2.token.expose(), "anthropic").await, Err(BrokerError::Unauthorized)));

    // Issuance limits.
    for bad in [
        NewLlmToken { ttl_secs: Some(0), ..NewLlmToken::default() },
        NewLlmToken { ttl_secs: Some(i64::MAX), ..NewLlmToken::default() },
        NewLlmToken { budget_usd: Some(-1.0), ..NewLlmToken::default() },
        NewLlmToken { budget_usd: Some(f64::NAN), ..NewLlmToken::default() },
        NewLlmToken { budget_tokens: Some(-5), ..NewLlmToken::default() },
        NewLlmToken { providers: Some(vec![]), ..NewLlmToken::default() },
        NewLlmToken { providers: Some(vec!["Evil.Host".into()]), ..NewLlmToken::default() },
        NewLlmToken { rate_limit_per_minute: Some(0), ..NewLlmToken::default() },
        NewLlmToken { run_id: Some("run 1".into()), ..NewLlmToken::default() },
        NewLlmToken { trace_parent: Some("garbage".into()), ..NewLlmToken::default() },
    ] {
        assert!(matches!(k.issue_llm_token(ADMIN, "tenant-a", bad).await, Err(BrokerError::Invalid(_))));
    }
    fx.db.cleanup().await;
}

#[tokio::test]
async fn usage_accounting_feeds_budgets() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let t = k
        .issue_llm_token(ADMIN, "tenant-a", NewLlmToken { budget_tokens: Some(1000), ..NewLlmToken::default() })
        .await
        .unwrap();
    let g = k.authorize_llm(t.token.expose(), "anthropic").await.unwrap();
    g.check_budget(Some("m"), None).unwrap();
    let row = NewUsageRow {
        ts: fx.clock.now(),
        token_id: g.token_id.clone(),
        tenant: g.tenant.clone(),
        run_id: None,
        provider: "anthropic".into(),
        endpoint: "v1/messages".into(),
        model: Some("m".into()),
        response_model: None,
        status: 200,
        input_tokens: 900,
        output_tokens: 150,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        cost_micro_usd: 4200,
        usage_source: "reported",
        duration_ms: 12,
        ttft_ms: Some(3),
        trace_id: None,
        billable_tokens: 1050,
    };
    k.record_usage(&row).await.unwrap();
    let info = k.get_llm_token("tenant-a", &t.info.id).await.unwrap();
    assert_eq!((info.spent_tokens, info.spent_micro_usd, info.request_count), (1050, 4200, 1));
    let g = k.authorize_llm(t.token.expose(), "anthropic").await.unwrap();
    assert!(matches!(g.check_budget(Some("m"), None), Err(BrokerError::BudgetExceeded(_))));
    let usage = k.list_usage("tenant-a", &UsageFilter { limit: 10, ..UsageFilter::default() }).await.unwrap();
    assert_eq!(usage.len(), 1);
    assert!(k.list_usage("tenant-b", &UsageFilter { limit: 10, ..UsageFilter::default() }).await.unwrap().is_empty());
    fx.db.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_tokens_are_single_use_tenant_scoped_and_exclude_llm_keys() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    k.create_secret(ADMIN, "tenant-a", secret("ssh.vm-1", "ssh_private_key", "ssh-a")).await.unwrap();
    k.create_secret(ADMIN, "tenant-a", secret("proxmox.api", "password", "pve-a")).await.unwrap();
    k.create_secret(ADMIN, "tenant-a", secret("unrelated", "password", "nope")).await.unwrap();
    k.create_secret(ADMIN, "tenant-b", secret("only-in-b", "password", "b-secret")).await.unwrap();
    put_llm_key(k, "tenant-a", "anthropic", KEY_A).await;

    let job = |secrets: &[&str]| NewJobToken {
        trace_parent: None,
        job_id: "job-7".into(),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        ttl_secs: Some(60),
    };
    // Names must exist in this tenant; LLM keys are never handed out.
    assert!(matches!(k.issue_job_token(ADMIN, "tenant-a", job(&["only-in-b"])).await, Err(BrokerError::NotFound(_))));
    assert!(matches!(
        k.issue_job_token(ADMIN, "tenant-a", job(&["llm.anthropic"])).await,
        Err(BrokerError::Forbidden(_))
    ));
    assert!(matches!(k.issue_job_token(ADMIN, "tenant-a", job(&[])).await, Err(BrokerError::Invalid(_))));

    let issued = k.issue_job_token(ADMIN, "tenant-a", job(&["ssh.vm-1", "proxmox.api", "ssh.vm-1"])).await.unwrap();
    assert_eq!(issued.info.secret_names, ["proxmox.api", "ssh.vm-1"]);
    let tok = issued.token.expose().to_owned();

    // Concurrent redemption: exactly one wins.
    let k = Arc::new(fx.keeper);
    let mut handles = Vec::new();
    for _ in 0..16 {
        let (k, tok) = (k.clone(), tok.clone());
        handles.push(tokio::spawn(async move { k.redeem_job_token(&tok, Some("trace-job")).await }));
    }
    let mut ok = Vec::new();
    for h in handles {
        match h.await.unwrap() {
            Ok(j) => ok.push(j),
            Err(e) => assert!(matches!(e, BrokerError::Unauthorized), "{e:?}"),
        }
    }
    assert_eq!(ok.len(), 1);
    let j = &ok[0];
    let got: Vec<(&str, &str)> = j.secrets.iter().map(|s| (s.name.as_str(), s.value.expose().as_str())).collect();
    assert_eq!(got, [("proxmox.api", "pve-a"), ("ssh.vm-1", "ssh-a")]);
    assert_eq!((j.tenant.as_str(), j.job_id.as_str()), ("tenant-a", "job-7"));
    assert!(matches!(k.redeem_job_token(&tok, None).await, Err(BrokerError::Unauthorized)));

    // One audit row per decrypt, with the job as purpose.
    let audit = k.audit_log(Some("tenant-a"), 50).await.unwrap();
    let decrypts: Vec<_> = audit.iter().filter(|e| e.action == "secret.decrypt").collect();
    assert_eq!(decrypts.len(), 2);
    assert!(decrypts.iter().all(|e| e.purpose.as_deref() == Some("job:job-7")
        && e.trace_id.as_deref() == Some("trace-job")
        && e.actor == format!("job-token:{}", issued.info.id)));

    // Expired and revoked tokens are rejected.
    let t2 = k.issue_job_token(ADMIN, "tenant-a", job(&["ssh.vm-1"])).await.unwrap();
    fx.clock.advance(61);
    assert!(matches!(k.redeem_job_token(t2.token.expose(), None).await, Err(BrokerError::Unauthorized)));
    let t3 = k.issue_job_token(ADMIN, "tenant-a", job(&["ssh.vm-1"])).await.unwrap();
    assert!(matches!(k.revoke_job_token(ADMIN, "tenant-b", &t3.info.id).await, Err(BrokerError::NotFound(_))));
    k.revoke_job_token(ADMIN, "tenant-a", &t3.info.id).await.unwrap();
    assert!(matches!(k.redeem_job_token(t3.token.expose(), None).await, Err(BrokerError::Unauthorized)));
    // A secret deleted after issuance fails the job, and the token stays used.
    let t4 = k.issue_job_token(ADMIN, "tenant-a", job(&["proxmox.api"])).await.unwrap();
    k.delete_secret(ADMIN, "tenant-a", "proxmox.api").await.unwrap();
    assert!(matches!(k.redeem_job_token(t4.token.expose(), None).await, Err(BrokerError::NotFound(_))));
    assert!(matches!(k.redeem_job_token(t4.token.expose(), None).await, Err(BrokerError::Unauthorized)));
    // An LLM token is not a job token and vice versa.
    let lt = k.issue_llm_token(ADMIN, "tenant-a", NewLlmToken::default()).await.unwrap();
    assert!(matches!(k.redeem_job_token(lt.token.expose(), None).await, Err(BrokerError::Unauthorized)));
    let t5 = k.issue_job_token(ADMIN, "tenant-a", job(&["ssh.vm-1"])).await.unwrap();
    assert!(matches!(k.authorize_llm(t5.token.expose(), "anthropic").await, Err(BrokerError::Unauthorized)));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn kek_rotation_rewraps_without_changing_values() {
    let Some(fx) = fixture().await else { return };
    put_llm_key(&fx.keeper, "tenant-a", "anthropic", KEY_A).await;
    fx.keeper.create_secret(ADMIN, "tenant-b", secret("pw", "password", "hunter2")).await.unwrap();

    // Restart with a new current KEK, keeping the old one for unwrapping.
    let provider = LocalKeyProvider::new("k2", kek()).unwrap().with_previous("k1", fx.kek.clone()).unwrap();
    let rotated = Keeper::new(
        fx.store.clone(),
        Envelope::new(Arc::new(provider)),
        TokenHasher::new(fx.token_key.clone()).unwrap(),
        fx.clock.clone(),
        KeeperSettings::default(),
    );
    let report = rotated.rewrap(ADMIN, 1).await.unwrap();
    assert_eq!((report.rewrapped, report.remaining), (1, 1));
    let report = rotated.rewrap(ADMIN, 100).await.unwrap();
    assert_eq!((report.rewrapped, report.remaining, report.current_kek_id.as_str()), (1, 0, "k2"));
    assert!(rotated.list_secrets("tenant-b").await.unwrap().iter().all(|m| m.kek_id == "k2"));

    let t = rotated.issue_llm_token(ADMIN, "tenant-a", NewLlmToken::default()).await.unwrap();
    let g = rotated.authorize_llm(t.token.expose(), "anthropic").await.unwrap();
    assert_eq!(rotated.provider_key(&g, "anthropic", None).await.unwrap().expose(), KEY_A);
    assert!(rotated.audit_log(None, 10).await.unwrap().iter().any(|e| e.action == "kek.rewrap"));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn database_write_access_cannot_mint_tokens_or_widen_them() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let pool = fx.store.pool().clone();
    k.create_secret(ADMIN, "tenant-a", secret("pw", "password", "a-password")).await.unwrap();
    k.create_secret(ADMIN, "tenant-b", secret("pw", "password", "b-password")).await.unwrap();
    put_llm_key(k, "tenant-a", "anthropic", KEY_A).await;
    let job = |names: &[&str]| NewJobToken {
        trace_parent: None,
        job_id: "j".into(),
        secrets: names.iter().map(|n| (*n).to_owned()).collect(),
        ttl_secs: Some(60),
    };

    // 1. Plant a job token row for a token of one's choosing: without the
    //    token key its digest cannot be computed, so it never matches.
    let chosen = format!("ocb_job_{}", "ab".repeat(32));
    use sha2::Digest as _;
    let plain_sha: Vec<u8> = sha2::Sha256::digest(chosen.as_bytes()).to_vec();
    let attacker = TokenHasher::new(kek()).unwrap();
    for (i, digest) in [plain_sha, attacker.digest(&chosen).to_vec()].into_iter().enumerate() {
        sqlx::query(
            "INSERT INTO job_tokens (id, token_hash, auth_mac, tenant_id, job_id, secret_names, created_at, expires_at, created_by)
             VALUES ($1, $2, $3, 'tenant-b', 'evil', ARRAY['pw'], 0, 9999999999, 'attacker')",
        )
        .bind(format!("planted-{i}"))
        .bind(digest)
        .bind(vec![0u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(matches!(k.redeem_job_token(&chosen, None).await, Err(BrokerError::Unauthorized)));

    // 2. Widen an existing job token in the database: the row MAC fails and
    //    nothing is released.
    let issued = k.issue_job_token(ADMIN, "tenant-a", job(&["pw"])).await.unwrap();
    sqlx::query("UPDATE job_tokens SET tenant_id = 'tenant-b' WHERE id = $1")
        .bind(&issued.info.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(k.redeem_job_token(issued.token.expose(), None).await, Err(BrokerError::Unauthorized)));
    let issued = k.issue_job_token(ADMIN, "tenant-a", job(&["pw"])).await.unwrap();
    sqlx::query("UPDATE job_tokens SET expires_at = expires_at + 86400 WHERE id = $1")
        .bind(&issued.info.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(k.redeem_job_token(issued.token.expose(), None).await, Err(BrokerError::Unauthorized)));

    // 3. Re-kind a provider key to release it to a worker: the AAD binds the
    //    kind, so it no longer decrypts.
    sqlx::query("UPDATE secrets SET kind = 'password' WHERE name = 'llm.anthropic'").execute(&pool).await.unwrap();
    let issued = k.issue_job_token(ADMIN, "tenant-a", job(&["llm.anthropic"])).await.unwrap();
    assert!(matches!(k.redeem_job_token(issued.token.expose(), None).await, Err(BrokerError::Crypto(_))));

    // 4. Move an LLM token to another tenant: refused.
    let t = k.issue_llm_token(ADMIN, "tenant-a", NewLlmToken::default()).await.unwrap();
    k.authorize_llm(t.token.expose(), "anthropic").await.unwrap();
    sqlx::query("UPDATE llm_tokens SET tenant_id = 'tenant-b' WHERE id = $1")
        .bind(&t.info.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(k.authorize_llm(t.token.expose(), "anthropic").await, Err(BrokerError::Unauthorized)));
    // ... or lift its provider restriction.
    let t = k
        .issue_llm_token(
            ADMIN,
            "tenant-a",
            NewLlmToken { providers: Some(vec!["deepseek".into()]), ..NewLlmToken::default() },
        )
        .await
        .unwrap();
    sqlx::query("UPDATE llm_tokens SET providers = NULL WHERE id = $1").bind(&t.info.id).execute(&pool).await.unwrap();
    assert!(matches!(k.authorize_llm(t.token.expose(), "anthropic").await, Err(BrokerError::Unauthorized)));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn job_trace_parent_is_recorded() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    k.create_secret(ADMIN, "tenant-a", secret("pw", "password", "x")).await.unwrap();
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let issued = k
        .issue_job_token(
            ADMIN,
            "tenant-a",
            NewJobToken {
                trace_parent: Some(tp.into()),
                job_id: "j".into(),
                secrets: vec!["pw".into()],
                ttl_secs: None,
            },
        )
        .await
        .unwrap();
    let j = k.redeem_job_token(issued.token.expose(), Some("caller-chosen-trace")).await.unwrap();
    assert_eq!(j.trace_parent.as_deref(), Some(tp));
    let audit = k.audit_log(Some("tenant-a"), 10).await.unwrap();
    assert!(
        audit
            .iter()
            .filter(|e| e.action == "secret.decrypt" || e.action == "job_token.redeem")
            .all(|e| e.trace_id.as_deref() == Some("0af7651916cd43dd8448eb211c80319c"))
    );
    assert!(matches!(
        k.issue_job_token(
            ADMIN,
            "tenant-a",
            NewJobToken {
                trace_parent: Some("bogus".into()),
                job_id: "j".into(),
                secrets: vec!["pw".into()],
                ttl_secs: None
            },
        )
        .await,
        Err(BrokerError::Invalid(_))
    ));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn spend_accounting_saturates_instead_of_overflowing() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let t = k.issue_llm_token(ADMIN, "tenant-a", NewLlmToken::default()).await.unwrap();
    let row = NewUsageRow {
        ts: fx.clock.now(),
        token_id: t.info.id.clone(),
        tenant: "tenant-a".into(),
        run_id: None,
        provider: "anthropic".into(),
        endpoint: "v1/messages".into(),
        model: None,
        response_model: None,
        status: 200,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        cost_micro_usd: i64::MAX,
        usage_source: "estimated",
        duration_ms: 0,
        ttft_ms: None,
        trace_id: None,
        billable_tokens: i64::MAX,
    };
    k.record_usage(&row).await.unwrap();
    k.record_usage(&row).await.unwrap();
    let info = k.get_llm_token("tenant-a", &t.info.id).await.unwrap();
    assert_eq!((info.spent_micro_usd, info.spent_tokens, info.request_count), (i64::MAX, i64::MAX, 2));
    fx.db.cleanup().await;
}
