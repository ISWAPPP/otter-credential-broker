//! Authentication of admin callers (the platform core).
//!
//! Today: static bearer tokens from a file. The [`Authenticator`] trait allows
//! swapping in Kubernetes TokenReview of projected ServiceAccount tokens later
//! without touching the API layer (see docs/DECISIONS.md).

use std::collections::HashSet;
use std::path::Path;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::secret::Secret;
use crate::validate;

/// Minimum length of a static admin token.
pub const MIN_TOKEN_LEN: usize = 32;

fn digest(token: &str) -> [u8; 32] {
    let out = Sha256::digest(token.as_bytes());
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// An authenticated admin caller. `name` is recorded as the actor in audit rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, bearer: &str) -> Option<Principal>;
}

/// Static tokens, one `<principal-name> <token>` per line, `#` comments.
/// Tokens are kept only as SHA-256 digests and compared in constant time; every
/// entry is visited so timing does not reveal which one matched.
pub struct StaticTokenAuthenticator {
    entries: Vec<(String, [u8; 32])>,
}

impl StaticTokenAuthenticator {
    pub fn parse(content: &str) -> Result<Self, std::io::Error> {
        let bad = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
        let mut entries = Vec::new();
        let mut names = HashSet::new();
        let mut digests = HashSet::new();
        for (n, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some(name), Some(token), None) if token.len() >= MIN_TOKEN_LEN => {
                    validate::reference("principal name", name)
                        .map_err(|_| bad(format!("tokens line {}: invalid principal name", n + 1)))?;
                    let d = digest(token);
                    if !names.insert(name.to_owned()) || !digests.insert(d) {
                        return Err(bad(format!("tokens line {}: duplicate name or token", n + 1)));
                    }
                    entries.push((name.to_owned(), d));
                }
                _ => {
                    return Err(bad(format!(
                        "tokens line {}: expected `<name> <token>` with a token of at least {MIN_TOKEN_LEN} chars",
                        n + 1
                    )));
                }
            }
        }
        if entries.is_empty() {
            return Err(bad("no tokens configured".into()));
        }
        Ok(Self { entries })
    }

    pub fn from_file(path: &Path) -> Result<Self, std::io::Error> {
        let content = Secret::new(std::fs::read_to_string(path)?);
        Self::parse(content.expose())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[async_trait]
impl Authenticator for StaticTokenAuthenticator {
    async fn authenticate(&self, bearer: &str) -> Option<Principal> {
        let d = digest(bearer);
        let mut found: Option<&str> = None;
        for (name, h) in &self.entries {
            if bool::from(h.ct_eq(&d)) {
                found = Some(name);
            }
        }
        found.map(|n| Principal { name: n.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const T2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[tokio::test]
    async fn static_tokens() {
        let a = StaticTokenAuthenticator::parse(&format!("# c\ncore {T1}\nops {T2}\n")).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a.authenticate(T1).await, Some(Principal { name: "core".into() }));
        assert_eq!(a.authenticate(T2).await, Some(Principal { name: "ops".into() }));
        assert_eq!(a.authenticate("x").await, None);
        assert_eq!(a.authenticate(&T1[1..]).await, None);
    }

    #[test]
    fn rejects_bad_files() {
        assert!(StaticTokenAuthenticator::parse("core short").is_err());
        assert!(StaticTokenAuthenticator::parse("").is_err());
        assert!(StaticTokenAuthenticator::parse(&format!("core {T1}\ncore {T2}")).is_err());
        assert!(StaticTokenAuthenticator::parse(&format!("a {T1}\nb {T1}")).is_err());
        assert!(StaticTokenAuthenticator::parse(&format!("bad\x07name {T1}")).is_err());
        assert!(StaticTokenAuthenticator::parse(&format!("core {T1} extra")).is_err());
    }
}
