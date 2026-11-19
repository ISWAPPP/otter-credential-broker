//! Envelope encryption: each record gets a random data-encryption key (DEK),
//! the DEK is wrapped by a key-encryption key (KEK) owned by a [`KeyProvider`].
//! Cipher: XChaCha20-Poly1305 (192-bit random nonces, safe to generate randomly).
//! Each record stores the id of the KEK that wrapped it, so KEKs can be rotated.

use std::path::Path;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::secret::Secret;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong key, wrong context or tampered data)")]
    Decrypt,
    #[error("unknown key id {0}")]
    UnknownKey(String),
    #[error("randomness unavailable")]
    Rng,
    #[error("key provider I/O: {0}")]
    Io(String),
}

/// Source of the KEK. Implementations: local files (here), Vault Transit or a
/// cloud KMS (future).
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Identifier of the KEK currently used for wrapping (stored next to each record).
    fn key_id(&self) -> &str;
    async fn wrap(&self, dek: &Secret<Vec<u8>>, aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
    async fn unwrap(&self, key_id: &str, wrapped: &[u8], aad: &[u8]) -> Result<Secret<Vec<u8>>, CryptoError>;
}

pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey("key must be 32 bytes".into()))
}

/// Returns `nonce || ciphertext`.
fn seal_raw(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = random_bytes(NONCE_LEN)?;
    let nonce = XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::Encrypt)?;
    let ct = cipher(key)?.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| CryptoError::Encrypt)?;
    let mut out = nonce_bytes;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_raw(key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| CryptoError::Decrypt)?;
    cipher(key)?.decrypt(&nonce, Payload { msg: ct, aad }).map_err(|_| CryptoError::Decrypt)
}

/// KEKs held in process memory, loaded from hex-encoded files (e.g. a mounted
/// Kubernetes Secret). One key is current and wraps new DEKs; previous keys
/// are kept for unwrapping only, so records can be re-wrapped after rotation.
pub struct LocalKeyProvider {
    id: String,
    kek: Secret<Vec<u8>>,
    previous: Vec<(String, Secret<Vec<u8>>)>,
}

impl LocalKeyProvider {
    pub fn new(id: impl Into<String>, kek: Secret<Vec<u8>>) -> Result<Self, CryptoError> {
        let id = id.into();
        check_key(&id, &kek)?;
        Ok(Self { id, kek, previous: Vec::new() })
    }

    /// Adds a retired KEK that can still unwrap existing records.
    pub fn with_previous(mut self, id: impl Into<String>, kek: Secret<Vec<u8>>) -> Result<Self, CryptoError> {
        let id = id.into();
        check_key(&id, &kek)?;
        if id == self.id || self.previous.iter().any(|(p, _)| *p == id) {
            return Err(CryptoError::InvalidKey(format!("duplicate KEK id {id}")));
        }
        self.previous.push((id, kek));
        Ok(self)
    }

    /// Reads a file containing 64 hex characters (surrounding whitespace ignored).
    pub fn read_key_file(path: &Path) -> Result<Secret<Vec<u8>>, CryptoError> {
        let raw = Secret::new(
            std::fs::read_to_string(path).map_err(|e| CryptoError::Io(format!("{}: {e}", path.display())))?,
        );
        let bytes = hex::decode(raw.expose().trim())
            .map_err(|_| CryptoError::InvalidKey("KEK file must contain hex".into()))?;
        Ok(Secret::new(bytes))
    }

    pub fn from_file(id: impl Into<String>, path: &Path) -> Result<Self, CryptoError> {
        Self::new(id, Self::read_key_file(path)?)
    }

    pub fn generate_hex() -> Result<Secret<String>, CryptoError> {
        Ok(Secret::new(hex::encode(random_bytes(KEY_LEN)?)))
    }

    fn key_for(&self, key_id: &str) -> Option<&Secret<Vec<u8>>> {
        if key_id == self.id {
            return Some(&self.kek);
        }
        self.previous.iter().find(|(id, _)| id == key_id).map(|(_, k)| k)
    }
}

fn check_key(id: &str, kek: &Secret<Vec<u8>>) -> Result<(), CryptoError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(CryptoError::InvalidKey("KEK id must be 1-64 chars of [A-Za-z0-9._-]".into()));
    }
    if kek.expose().len() != KEY_LEN {
        return Err(CryptoError::InvalidKey(format!("KEK must be {KEY_LEN} bytes")));
    }
    Ok(())
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    fn key_id(&self) -> &str {
        &self.id
    }
    async fn wrap(&self, dek: &Secret<Vec<u8>>, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        seal_raw(self.kek.expose(), dek.expose(), aad)
    }
    async fn unwrap(&self, key_id: &str, wrapped: &[u8], aad: &[u8]) -> Result<Secret<Vec<u8>>, CryptoError> {
        let kek = self.key_for(key_id).ok_or_else(|| CryptoError::UnknownKey(key_id.to_owned()))?;
        open_raw(kek.expose(), wrapped, aad).map(Secret::new)
    }
}

/// Encrypted record as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord {
    pub kek_id: String,
    pub wrapped_dek: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Envelope encryption helper. `context` is bound as AAD on both layers so a
/// record cannot be moved to another tenant or name without failing to decrypt.
pub struct Envelope {
    provider: std::sync::Arc<dyn KeyProvider>,
}

impl Envelope {
    pub fn new(provider: std::sync::Arc<dyn KeyProvider>) -> Self {
        Self { provider }
    }

    /// Id of the KEK that wraps new records.
    pub fn current_key_id(&self) -> &str {
        self.provider.key_id()
    }

    #[tracing::instrument(name = "crypto.seal", level = "debug", skip_all)]
    pub async fn seal(&self, plaintext: &[u8], context: &str) -> Result<SealedRecord, CryptoError> {
        let dek = Secret::new(random_bytes(KEY_LEN)?);
        let aad = context.as_bytes();
        let ciphertext = seal_raw(dek.expose(), plaintext, aad)?;
        let wrapped_dek = self.provider.wrap(&dek, aad).await?;
        Ok(SealedRecord { kek_id: self.provider.key_id().to_owned(), wrapped_dek, ciphertext })
    }

    #[tracing::instrument(name = "crypto.open", level = "debug", skip_all)]
    pub async fn open(&self, record: &SealedRecord, context: &str) -> Result<Secret<Vec<u8>>, CryptoError> {
        let aad = context.as_bytes();
        let dek = self.provider.unwrap(&record.kek_id, &record.wrapped_dek, aad).await?;
        open_raw(dek.expose(), &record.ciphertext, aad).map(Secret::new)
    }

    /// Re-wraps the record's DEK with the current KEK. The ciphertext is not
    /// touched. Returns `None` when the record already uses the current KEK.
    #[tracing::instrument(name = "crypto.rewrap", level = "debug", skip_all)]
    pub async fn rewrap(&self, record: &SealedRecord, context: &str) -> Result<Option<SealedRecord>, CryptoError> {
        if record.kek_id == self.provider.key_id() {
            return Ok(None);
        }
        let aad = context.as_bytes();
        let dek = self.provider.unwrap(&record.kek_id, &record.wrapped_dek, aad).await?;
        // Prove the DEK still opens the payload before committing to the new wrap.
        open_raw(dek.expose(), &record.ciphertext, aad)?;
        let wrapped_dek = self.provider.wrap(&dek, aad).await?;
        Ok(Some(SealedRecord {
            kek_id: self.provider.key_id().to_owned(),
            wrapped_dek,
            ciphertext: record.ciphertext.clone(),
        }))
    }
}

/// AAD context for a stored secret: binds the record to its tenant, name and
/// kind. Length-prefixed so different triples can never collide.
pub fn secret_context(tenant: &str, name: &str, kind: &str) -> String {
    format!("ocb.secret.v2:{}:{}:{}:{}:{}:{}", tenant.len(), tenant, name.len(), name, kind.len(), kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn envelope() -> Envelope {
        let kek = Secret::new(random_bytes(KEY_LEN).unwrap());
        Envelope::new(Arc::new(LocalKeyProvider::new("k1", kek).unwrap()))
    }

    #[tokio::test]
    async fn roundtrip() {
        let env = envelope();
        let rec = env.seal(b"hello credentials", "acct-1").await.unwrap();
        assert_ne!(rec.ciphertext, b"hello credentials");
        let pt = env.open(&rec, "acct-1").await.unwrap();
        assert_eq!(pt.expose().as_slice(), b"hello credentials");
    }

    #[tokio::test]
    async fn wrong_context_fails() {
        let env = envelope();
        let rec = env.seal(b"x", "acct-1").await.unwrap();
        assert!(matches!(env.open(&rec, "acct-2").await, Err(CryptoError::Decrypt)));
    }

    #[tokio::test]
    async fn tamper_fails() {
        let env = envelope();
        let mut rec = env.seal(b"payload", "a").await.unwrap();
        let last = rec.ciphertext.len() - 1;
        rec.ciphertext[last] ^= 1;
        assert!(env.open(&rec, "a").await.is_err());
    }

    #[tokio::test]
    async fn wrong_kek_fails() {
        let rec = envelope().seal(b"payload", "a").await.unwrap();
        assert!(envelope().open(&rec, "a").await.is_err());
    }

    #[tokio::test]
    async fn rotation_and_rewrap() {
        let old = Secret::new(random_bytes(KEY_LEN).unwrap());
        let new = Secret::new(random_bytes(KEY_LEN).unwrap());
        let before = Envelope::new(Arc::new(LocalKeyProvider::new("k1", old.clone()).unwrap()));
        let rec = before.seal(b"payload", "ctx").await.unwrap();
        assert_eq!(rec.kek_id, "k1");

        // New KEK current, old one kept for unwrapping.
        let after = Envelope::new(Arc::new(
            LocalKeyProvider::new("k2", new.clone()).unwrap().with_previous("k1", old).unwrap(),
        ));
        assert_eq!(after.open(&rec, "ctx").await.unwrap().expose().as_slice(), b"payload");
        let re = after.rewrap(&rec, "ctx").await.unwrap().unwrap();
        assert_eq!(re.kek_id, "k2");
        assert_eq!(re.ciphertext, rec.ciphertext);
        assert!(after.rewrap(&re, "ctx").await.unwrap().is_none());
        assert!(after.rewrap(&rec, "other").await.is_err());

        // Once the old KEK is dropped, only re-wrapped records open.
        let only_new = Envelope::new(Arc::new(LocalKeyProvider::new("k2", new).unwrap()));
        assert!(matches!(only_new.open(&rec, "ctx").await, Err(CryptoError::UnknownKey(_))));
        assert_eq!(only_new.open(&re, "ctx").await.unwrap().expose().as_slice(), b"payload");
    }

    #[test]
    fn key_ids_validated() {
        let k = || Secret::new(vec![7u8; KEY_LEN]);
        assert!(LocalKeyProvider::new("", k()).is_err());
        assert!(LocalKeyProvider::new("a b", k()).is_err());
        assert!(LocalKeyProvider::new("k1", k()).unwrap().with_previous("k1", k()).is_err());
    }

    #[test]
    fn contexts_do_not_collide() {
        assert_ne!(secret_context("a:1", "b", "k"), secret_context("a", "1:b", "k"));
        assert_ne!(secret_context("t", "n", "k"), secret_context("t", "n2", "k"));
        assert_ne!(secret_context("t", "n", "password"), secret_context("t", "n", "llm_api_key"));
    }

    #[test]
    fn rejects_short_kek() {
        assert!(LocalKeyProvider::new("k", Secret::new(vec![0; 16])).is_err());
    }

    #[test]
    fn kek_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kek");
        std::fs::write(&p, format!("{}\n", LocalKeyProvider::generate_hex().unwrap().expose())).unwrap();
        assert!(LocalKeyProvider::from_file("k", &p).is_ok());
    }
}
