#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Limits of tenants and providers against a real PostgreSQL database:
//! request windows counted level by level, reservations taken all or
//! nothing, and usage settled in the period a request was authorized in.

use std::sync::Arc;

use broker_core::clock::{Clock, ManualClock};
use broker_core::crypto::{Envelope, KEY_LEN, LocalKeyProvider, random_bytes};
use broker_core::keeper::{Authorized, NewLlmToken};
use broker_core::limits::{LimitKind, LimitLevel, LimitRefusal, Limits, PerPeriod, Period};
use broker_core::llm::ProviderAccess::Implicit;
use broker_core::store::{LimitScope, NewUsageRow, SpendRow};
use broker_core::testing::TestDb;
use broker_core::tokens::TokenHasher;
use broker_core::{BrokerError, CallContext, Keeper, KeeperSettings, Secret};

/// 2030-03-17T17:46:40Z.
const T0: i64 = 1_900_000_000;
const DAY0: i64 = 1_899_936_000;
const ADMIN: CallContext<'static> = CallContext { actor: "core", trace_id: None };

struct Fx {
    keeper: Keeper,
    clock: Arc<ManualClock>,
    db: TestDb,
}

async fn fixture() -> Option<Fx> {
    let db = TestDb::create().await?;
    let clock = Arc::new(ManualClock::new(T0));
    let key = || Secret::new(random_bytes(KEY_LEN).unwrap());
    let keeper = Keeper::new(
        db.store().await,
        Envelope::new(Arc::new(LocalKeyProvider::new("k1", key()).unwrap())),
        TokenHasher::new(key()).unwrap(),
        clock.clone(),
        KeeperSettings::default(),
    );
    Some(Fx { keeper, clock, db })
}

async fn token(k: &Keeper, tenant: &str, rpm: i32) -> String {
    let t = NewLlmToken { rate_limit_per_minute: Some(rpm), ..NewLlmToken::default() };
    k.issue_llm_token(ADMIN, tenant, t).await.unwrap().token.expose().to_owned()
}

fn refusal(r: Result<impl std::fmt::Debug, BrokerError>) -> LimitRefusal {
    match r {
        Err(BrokerError::Limit(l)) => l,
        other => panic!("expected a limit refusal, got {other:?}"),
    }
}

fn tokens_per_day(day: u64) -> Limits {
    Limits { budget_tokens: PerPeriod { day: Some(day), month: None }, ..Limits::default() }
}

/// The spend row of `scope` in `period` starting at `start`, if any.
async fn row(k: &Keeper, scope: &LimitScope, period: Period, at: i64) -> Option<SpendRow> {
    let (_, rows) = k.limit_usage(std::slice::from_ref(scope), at).await.unwrap();
    rows.into_iter().find(|r| r.is(scope, period))
}

fn usage(a: &Authorized, tokens: i64, cost: i64, ts: i64) -> NewUsageRow {
    NewUsageRow {
        ts,
        token_id: a.grant.token_id.clone(),
        tenant: a.grant.tenant.clone(),
        run_id: None,
        provider: "anthropic".into(),
        endpoint: "v1/messages".into(),
        model: Some("m".into()),
        response_model: None,
        status: 200,
        input_tokens: tokens,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        cost_micro_usd: cost,
        usage_source: "reported",
        duration_ms: 1,
        ttft_ms: None,
        trace_id: None,
        billable_tokens: tokens,
    }
}

#[tokio::test]
async fn windows_count_a_request_only_where_the_lower_levels_let_it_through() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    fx.clock.set(T0 - T0 % 60 + 1);
    k.set_tenant_limits(ADMIN, "tenant-a", Limits { rpm: Some(3), ..Limits::default() }).await.unwrap();
    let (a, b) = (token(k, "tenant-a", 100).await, token(k, "tenant-b", 100).await);
    let send = |t: &str, global: Option<u32>| {
        let t = t.to_owned();
        async move {
            let auth = k.authorize(&t, "anthropic", Implicit).await.unwrap();
            k.count_request(&auth, "anthropic", global).await
        }
    };
    for n in 1..=3 {
        let c = send(&a, Some(5)).await.unwrap();
        assert_eq!(c.tenant.unwrap().count, n);
        assert_eq!((c.global.unwrap().limit, c.global.unwrap().count), (5, n));
    }
    // The tenant is at its limit: refused there, and the provider's window
    // does not count the request.
    for _ in 0..5 {
        let r = refusal(send(&a, Some(5)).await);
        assert_eq!((r.level, r.kind, r.retry_after_secs), (LimitLevel::Tenant, LimitKind::Rate, Some(59)));
        assert!(r.message.contains("3 requests per minute"), "{}", r.message);
    }
    // So another tenant still has the rest of the provider's window.
    for n in 4..=5 {
        assert_eq!(send(&b, Some(5)).await.unwrap().global.unwrap().count, n);
    }
    let r = refusal(send(&b, Some(5)).await);
    assert_eq!(r.level, LimitLevel::Global);
    assert_eq!(r.message, "rate limit of provider anthropic exceeded, retry after 59s", "no numbers of the provider");
    // A provider without a limit keeps no window.
    assert!(send(&b, None).await.unwrap().global.is_none());
    // The next minute is a new window on both levels.
    fx.clock.advance(60);
    let c = send(&a, Some(5)).await.unwrap();
    assert_eq!((c.tenant.unwrap().count, c.global.unwrap().count), (1, 1));
    // Without limits on either level nothing is written.
    let fresh = token(k, "tenant-c", 100).await;
    assert!(send(&fresh, None).await.unwrap().tenant.is_none());
    let (rpm, _) = k.limit_usage(&[LimitScope::tenant("tenant-c")], fx.clock.now()).await.unwrap();
    assert!(rpm.is_empty());
    fx.db.cleanup().await;
}

#[tokio::test]
async fn reservations_are_all_or_nothing_and_settled_in_the_authorizing_period() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    k.set_tenant_limits(ADMIN, "tenant-a", tokens_per_day(100)).await.unwrap();
    let global = Limits { budget_tokens: PerPeriod { day: Some(1000), month: Some(150) }, ..Limits::default() };
    let t = token(k, "tenant-a", 100).await;
    let tenant = LimitScope::tenant("tenant-a");
    let provider = LimitScope::global("anthropic");

    // Two requests in flight: each reserves 64 although nothing is spent yet.
    let a1 = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let r1 = k.reserve(&a1, "anthropic", &global, 64, 0).await.unwrap();
    assert_eq!(r1.reservations.len(), 3, "tenant day, provider day and month");
    let a2 = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let r2 = k.reserve(&a2, "anthropic", &global, 64, 0).await.unwrap();
    let tenant_day = row(k, &tenant, Period::Day, T0).await.unwrap();
    assert_eq!((tenant_day.spent_tokens, tenant_day.reserved_tokens, tenant_day.limit_tokens), (0, 128, Some(100)));

    // A third is refused by the tenant, whose budget the reservations fill:
    // nothing is reserved anywhere for it.
    let a3 = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let r = refusal(k.reserve(&a3, "anthropic", &global, 64, 0).await);
    assert_eq!((r.level, r.kind), (LimitLevel::Tenant, LimitKind::Budget));
    assert!(r.message.starts_with("daily token budget of the tenant is used up (128 of 100 tokens"), "{}", r.message);
    assert!(r.message.ends_with("it renews at 2030-03-18T00:00:00Z"), "{}", r.message);
    assert_eq!(row(k, &provider, Period::Month, T0).await.unwrap().reserved_tokens, 128);

    // Accounting gives the reservation back and counts what was used.
    k.record_usage_settling(&usage(&a1, 30, 7, T0), &r1.reservations).await.unwrap();
    let tenant_day = row(k, &tenant, Period::Day, T0).await.unwrap();
    assert_eq!((tenant_day.spent_tokens, tenant_day.reserved_tokens, tenant_day.spent_micro_usd), (30, 64, 7));
    let month = row(k, &provider, Period::Month, T0).await.unwrap();
    assert_eq!((month.spent_tokens, month.reserved_tokens), (30, 64));

    // The provider's monthly budget refuses next, with no numbers shown.
    k.set_tenant_limits(ADMIN, "tenant-a", Limits::default()).await.unwrap();
    let a4 = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let r4 = k.reserve(&a4, "anthropic", &global, 64, 0).await.unwrap();
    assert_eq!(r4.reservations.len(), 2, "the tenant has no budget now");
    let a5 = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let r = refusal(k.reserve(&a5, "anthropic", &global, 64, 0).await);
    assert_eq!(r.level, LimitLevel::Global);
    assert_eq!(r.message, "monthly token budget of provider anthropic is used up; it renews at 2030-04-01T00:00:00Z");

    // A request authorized before midnight and accounted after it is
    // counted in the day it was authorized in.
    fx.clock.set(DAY0 + 86_399);
    k.set_tenant_limits(ADMIN, "tenant-a", tokens_per_day(1_000_000)).await.unwrap();
    let late = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let held = k.reserve(&late, "anthropic", &Limits::default(), 10, 0).await.unwrap();
    fx.clock.advance(5);
    k.record_usage_settling(&usage(&late, 400, 0, fx.clock.now()), &held.reservations).await.unwrap();
    let before = row(k, &tenant, Period::Day, DAY0).await.unwrap();
    assert_eq!((before.spent_tokens, before.reserved_tokens), (30 + 400, 64));
    assert!(row(k, &tenant, Period::Day, DAY0 + 86_400).await.is_none(), "nothing in the new day");

    // Released reservations go back without spend; settling twice cannot
    // take a row below zero.
    k.release(&r2.reservations).await.unwrap();
    k.release(&r2.reservations).await.unwrap();
    assert_eq!(row(k, &tenant, Period::Day, DAY0).await.unwrap().reserved_tokens, 0);
    fx.db.cleanup().await;
}

#[tokio::test]
async fn zero_and_usd_budgets() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let t = token(k, "tenant-a", 100).await;
    // A budget of zero lets nothing billable through, even on a fresh row.
    k.set_tenant_limits(ADMIN, "tenant-a", tokens_per_day(0)).await.unwrap();
    let a = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let r = refusal(k.reserve(&a, "anthropic", &Limits::default(), 1, 0).await);
    assert!(r.message.contains("(0 of 0 tokens"), "{}", r.message);
    // USD: what is reserved counts like what is spent.
    let usd = Limits { budget_usd: PerPeriod { day: None, month: Some(0.001) }, ..Limits::default() };
    k.set_tenant_limits(ADMIN, "tenant-a", usd).await.unwrap();
    let a = k.authorize(&t, "anthropic", Implicit).await.unwrap();
    let held = k.reserve(&a, "anthropic", &Limits::default(), 10, 1500).await.unwrap();
    let r = refusal(k.reserve(&a, "anthropic", &Limits::default(), 10, 1).await);
    assert!(
        r.message.starts_with("monthly USD budget of the tenant is used up ($0.001500 of $0.001000"),
        "{}",
        r.message
    );
    k.record_usage_settling(&usage(&a, 10, 200, T0), &held.reservations).await.unwrap();
    let row = row(k, &LimitScope::tenant("tenant-a"), Period::Month, T0).await.unwrap();
    assert_eq!((row.spent_micro_usd, row.reserved_micro_usd), (200, 0));
    assert!(k.reserve(&a, "anthropic", &Limits::default(), 10, 1).await.is_ok());
    fx.db.cleanup().await;
}

#[tokio::test]
async fn tenant_limits_are_validated_audited_and_cleared() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    let limits = Limits {
        rpm: Some(600),
        concurrent: Some(8),
        budget_tokens: PerPeriod { day: Some(2_000_000), month: Some(50_000_000) },
        budget_usd: PerPeriod { day: None, month: Some(150.5) },
    };
    let set = k.set_tenant_limits(ADMIN, "tenant-a", limits).await.unwrap().unwrap();
    assert_eq!((set.limits, set.updated_by.as_str(), set.updated_at), (limits, "core", T0));
    assert_eq!(k.tenant_limits("tenant-a").await.unwrap().unwrap().limits, limits);
    assert!(k.tenant_limits("tenant-b").await.unwrap().is_none());
    k.set_tenant_limits(ADMIN, "tenant-b", tokens_per_day(5)).await.unwrap();
    let all: Vec<String> = k.all_tenant_limits().await.unwrap().into_iter().map(|t| t.tenant).collect();
    assert_eq!(all, ["tenant-a", "tenant-b"]);

    // No limits at all removes the entry; every change is audited.
    assert!(k.set_tenant_limits(ADMIN, "tenant-a", Limits::default()).await.unwrap().is_none());
    assert!(k.tenant_limits("tenant-a").await.unwrap().is_none());
    let audit = k.audit_log(Some("tenant-a"), 10).await.unwrap();
    assert_eq!(audit.iter().filter(|e| e.action == "tenant_limits.set").count(), 2);
    assert!(audit[1].detail.as_deref().unwrap().contains("\"rpm\":600"), "{audit:?}");

    for bad in [Limits { rpm: Some(0), ..Limits::default() }, Limits { concurrent: Some(0), ..Limits::default() }] {
        assert!(matches!(k.set_tenant_limits(ADMIN, "tenant-a", bad).await, Err(BrokerError::Invalid(_))));
    }
    assert!(matches!(k.set_tenant_limits(ADMIN, "bad tenant", limits).await, Err(BrokerError::Invalid(_))));
    fx.db.cleanup().await;
}

#[tokio::test]
async fn a_token_is_inspected_without_counting_a_request() {
    let Some(fx) = fixture().await else { return };
    let k = &fx.keeper;
    fx.clock.set(T0 - T0 % 60 + 1);
    let t = token(k, "tenant-a", 2).await;
    k.set_tenant_limits(ADMIN, "tenant-a", tokens_per_day(9)).await.unwrap();
    let digest = k.llm_token_digest(&t).unwrap();
    for _ in 0..5 {
        let seen = k.inspect_llm_token(&digest).await.unwrap();
        assert_eq!((seen.token.tenant_id.as_str(), seen.token.rl_count), ("tenant-a", 0));
        assert_eq!(seen.tenant_limits.tokens(Period::Day), Some(9));
    }
    // The token's window is untouched: both requests of the minute pass.
    for _ in 0..2 {
        k.authorize_llm(&t, "anthropic", Implicit).await.unwrap();
    }
    assert!(matches!(k.authorize_llm(&t, "anthropic", Implicit).await, Err(BrokerError::RateLimited { .. })));
    assert!(k.llm_token_digest("sk-not-a-token").is_none());
    let other = k.llm_token_digest(&format!("ocb_llm_{}", "0".repeat(64))).unwrap();
    assert!(matches!(k.inspect_llm_token(&other).await, Err(BrokerError::Unauthorized)));
    fx.db.cleanup().await;
}
