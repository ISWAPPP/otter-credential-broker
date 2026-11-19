//! Bearer tokens issued by the broker. A token is a type prefix followed by 64
//! hex characters (32 random bytes). The prefix makes leaked tokens easy to
//! find with secret scanners and stops a token of one type from being accepted
//! as another.
//!
//! Only a keyed digest (HMAC-SHA256 under the broker's token key) is stored.
//! Someone with write access to the database but without the token key can
//! therefore neither recover a token nor plant a row for a token they chose.
//! The same key authenticates the authorization fields of token rows (tenant,
//! secret list, expiry), so they cannot be edited in the database either.

use std::path::Path;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::crypto::{CryptoError, KEY_LEN, random_bytes};
use crate::secret::Secret;

const RANDOM_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Internal LLM token: authenticates calls to the `/llm/*` proxy.
    Llm,
    /// Job token: redeems the secrets of one job, once.
    Job,
}

impl TokenKind {
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Llm => "ocb_llm_",
            Self::Job => "ocb_job_",
        }
    }
}

pub type TokenDigest = [u8; 32];

/// Creates a new random token of the given kind.
pub fn generate(kind: TokenKind) -> Result<Secret<String>, CryptoError> {
    let bytes = Secret::new(random_bytes(RANDOM_BYTES)?);
    Ok(Secret::new(format!("{}{}", kind.prefix(), hex::encode(bytes.expose()))))
}

fn well_formed(kind: TokenKind, presented: &str) -> bool {
    presented.strip_prefix(kind.prefix()).is_some_and(|rest| {
        rest.len() == RANDOM_BYTES * 2 && rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Keyed digests of tokens and MACs over token rows. `Debug` is not
/// implemented, so the keyed state cannot end up in logs.
pub struct TokenHasher {
    keyed: Hmac<Sha256>,
}

impl TokenHasher {
    pub fn new(key: Secret<Vec<u8>>) -> Result<Self, CryptoError> {
        if key.expose().len() != KEY_LEN {
            return Err(CryptoError::InvalidKey(format!("token key must be {KEY_LEN} bytes")));
        }
        let keyed = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose())
            .map_err(|_| CryptoError::InvalidKey("token key".into()))?;
        Ok(Self { keyed })
    }

    /// Reads a file containing 64 hex characters (as written by `keygen`).
    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {
        let raw = Secret::new(
            std::fs::read_to_string(path).map_err(|e| CryptoError::Io(format!("{}: {e}", path.display())))?,
        );
        let bytes = hex::decode(raw.expose().trim())
            .map_err(|_| CryptoError::InvalidKey("token key file must contain hex".into()))?;
        Self::new(Secret::new(bytes))
    }

    fn hmac(&self) -> Hmac<Sha256> {
        self.keyed.clone()
    }

    /// Digest stored for a token.
    pub fn digest(&self, token: &str) -> TokenDigest {
        let mut m = self.hmac();
        m.update(b"ocb.token.v1\0");
        m.update(token.as_bytes());
        m.finalize().into_bytes().into()
    }

    /// Checks the shape of a presented token and returns its digest for
    /// lookup. Returns `None` for anything that cannot be a token of this
    /// kind, so garbage never reaches the database.
    pub fn parse(&self, kind: TokenKind, presented: &str) -> Option<TokenDigest> {
        well_formed(kind, presented).then(|| self.digest(presented))
    }

    fn row_mac_inner(&self, label: &str, fields: &[&[u8]]) -> Hmac<Sha256> {
        let mut m = self.hmac();
        m.update(b"ocb.row.v1\0");
        m.update(label.as_bytes());
        for f in fields {
            m.update(&(f.len() as u64).to_be_bytes());
            m.update(f);
        }
        m
    }

    /// MAC over the authorization fields of a token row (length-prefixed).
    pub fn row_mac(&self, label: &str, fields: &[&[u8]]) -> Vec<u8> {
        self.row_mac_inner(label, fields).finalize().into_bytes().to_vec()
    }

    /// Constant-time check of a row MAC.
    pub fn verify_row_mac(&self, label: &str, fields: &[&[u8]], mac: &[u8]) -> bool {
        self.row_mac_inner(label, fields).verify_slice(mac).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher(seed: u8) -> TokenHasher {
        TokenHasher::new(Secret::new(vec![seed; KEY_LEN])).unwrap()
    }

    #[test]
    fn generate_and_parse() {
        let h = hasher(1);
        let t = generate(TokenKind::Llm).unwrap();
        assert!(t.expose().starts_with("ocb_llm_"));
        assert_eq!(t.expose().len(), 8 + 64);
        assert_eq!(h.parse(TokenKind::Llm, t.expose()), Some(h.digest(t.expose())));
        // Wrong type, wrong length, uppercase hex, garbage.
        assert_eq!(h.parse(TokenKind::Job, t.expose()), None);
        assert_eq!(h.parse(TokenKind::Llm, &t.expose()[..40]), None);
        assert_eq!(h.parse(TokenKind::Llm, &t.expose().to_uppercase()), None);
        assert_eq!(h.parse(TokenKind::Llm, "sk-ant-api03-xxxx"), None);
        assert_ne!(generate(TokenKind::Llm).unwrap().expose(), t.expose());
    }

    #[test]
    fn digests_are_keyed() {
        let t = generate(TokenKind::Job).unwrap();
        assert_ne!(hasher(1).digest(t.expose()), hasher(2).digest(t.expose()));
        // Not a plain SHA-256 of the token.
        use sha2::Digest;
        let plain: [u8; 32] = Sha256::digest(t.expose().as_bytes()).into();
        assert_ne!(hasher(1).digest(t.expose()), plain);
        assert!(TokenHasher::new(Secret::new(vec![0; 16])).is_err());
    }

    #[test]
    fn row_macs() {
        let h = hasher(3);
        let mac = h.row_mac("job", &[b"id", b"tenant-a", b"a\0b"]);
        assert!(h.verify_row_mac("job", &[b"id", b"tenant-a", b"a\0b"], &mac));
        assert!(!h.verify_row_mac("job", &[b"id", b"tenant-b", b"a\0b"], &mac));
        assert!(!h.verify_row_mac("llm", &[b"id", b"tenant-a", b"a\0b"], &mac));
        // Length prefixes: moving bytes between fields changes the MAC.
        assert!(!h.verify_row_mac("job", &[b"idt", b"enant-a", b"a\0b"], &mac));
        assert!(!hasher(4).verify_row_mac("job", &[b"id", b"tenant-a", b"a\0b"], &mac));
    }
}
