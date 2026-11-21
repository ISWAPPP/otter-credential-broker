//! Core domain logic for `otter-credential-broker`.
//!
//! The broker is the only component that holds provider API keys and other
//! secrets in plain text. Everything else receives either secret names or
//! short-lived tokens: internal LLM tokens for the proxy, single-use job tokens
//! for workers.
#![forbid(unsafe_code)]

pub mod auth;
pub mod clock;
pub mod crypto;
pub mod error;
pub mod keeper;
pub mod limits;
pub mod llm;
pub mod secret;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;
pub mod tokens;
pub mod validate;

pub use error::BrokerError;
pub use keeper::{CallContext, Keeper, KeeperSettings};
pub use secret::Secret;
