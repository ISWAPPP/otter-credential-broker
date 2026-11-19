//! Test support: a throwaway PostgreSQL database per test.
//!
//! Set `OCB_TEST_DATABASE_URL` to a server URL whose user may create
//! databases, e.g. `postgres://postgres@127.0.0.1:5432/postgres`. Without it
//! the tests fail with instructions, unless `OCB_SKIP_DB_TESTS=1` explicitly
//! opts out (then they return early).
#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use sqlx::Connection;
use sqlx::postgres::{PgConnectOptions, PgConnection};

use crate::store::Store;

pub struct TestDb {
    admin: PgConnectOptions,
    name: String,
}

impl TestDb {
    /// Creates a fresh, migrated database. `None` only when DB tests are
    /// explicitly skipped.
    pub async fn create() -> Option<Self> {
        let Ok(url) = std::env::var("OCB_TEST_DATABASE_URL") else {
            if std::env::var("OCB_SKIP_DB_TESTS").is_ok_and(|v| v == "1") {
                eprintln!("OCB_SKIP_DB_TESTS=1: skipping a PostgreSQL test");
                return None;
            }
            panic!(
                "OCB_TEST_DATABASE_URL is not set. Point it at a PostgreSQL server where the user can create \
                 databases (see README, Development), or set OCB_SKIP_DB_TESTS=1 to skip database tests."
            );
        };
        let admin: PgConnectOptions = url.parse().expect("OCB_TEST_DATABASE_URL must be a PostgreSQL URL");
        let name = format!("ocb_test_{}", uuid::Uuid::new_v4().simple());
        let mut conn = PgConnection::connect_with(&admin).await.expect("connect to OCB_TEST_DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut conn)
            .await
            .expect("create test database");
        conn.close().await.ok();
        Some(Self { admin, name })
    }

    pub fn options(&self) -> PgConnectOptions {
        self.admin.clone().database(&self.name)
    }

    /// Connects and applies migrations.
    pub async fn store(&self) -> Store {
        let store = Store::connect_with(self.options(), 8, Duration::from_secs(10)).await.expect("connect test db");
        store.migrate().await.expect("migrate test db");
        store
    }

    /// Drops the database (best effort; a failed test leaves it behind).
    pub async fn cleanup(self) {
        if let Ok(mut conn) = PgConnection::connect_with(&self.admin).await {
            let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name)))
                .execute(&mut conn)
                .await;
            conn.close().await.ok();
        }
    }
}
