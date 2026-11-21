//! TLS files of upstream providers: reading them, the expiry of their
//! certificates and the HTTP client that uses them.
//!
//! Certificate parsing here is limited to what the broker reports (PEM
//! blocks and the `notAfter` of each certificate); verification is done by
//! rustls through reqwest.

use std::path::{Path, PathBuf};
use std::time::Duration;

use broker_core::Secret;
use sha2::{Digest, Sha256};

use crate::config::ProviderTls;

/// Labels of PEM blocks that hold an unencrypted private key.
const KEY_LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

/// The TLS files of one provider, read once.
pub(crate) struct TlsMaterial {
    /// CA certificates (DER); the only trust anchors of the provider.
    ca: Vec<Vec<u8>>,
    /// Client certificate chain followed by its key (PEM).
    identity: Option<Secret<Vec<u8>>>,
    /// Earliest `notAfter` of the CA and client certificates (Unix seconds).
    pub not_after: Option<i64>,
    /// Over the content of all files: equal material, equal client.
    pub digest: [u8; 32],
    /// SHA-256 of each file's content, to notice changes.
    pub files: Vec<(PathBuf, [u8; 32])>,
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Reads a file into memory that is wiped when dropped (it may be a key).
pub(crate) fn read_file(path: &Path) -> std::io::Result<Secret<Vec<u8>>> {
    std::fs::read(path).map(Secret::new)
}

/// Reads and checks the files of `tls`. Errors name the file, never its
/// content.
pub(crate) fn load(tls: &ProviderTls) -> Result<TlsMaterial, String> {
    let read = |what: &str, path: &Path| read_file(path).map_err(|e| format!("{what} {}: {e}", path.display()));
    let mut digest = Sha256::new();
    let mut files = Vec::new();
    let mut add = |path: &Path, content: &[u8]| {
        digest.update((content.len() as u64).to_be_bytes());
        digest.update(content);
        files.push((path.to_owned(), sha256(content)));
    };

    let ca_pem = read("ca_file", &tls.ca_file)?;
    add(&tls.ca_file, ca_pem.expose());
    let ca = certificates(ca_pem.expose())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| format!("ca_file {}: no PEM certificate", tls.ca_file.display()))?;
    let mut not_after = earliest(&ca);

    let identity = match (&tls.client_cert, &tls.client_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = read("client_cert", cert)?;
            let key_pem = read("client_key", key)?;
            add(cert, cert_pem.expose());
            add(key, key_pem.expose());
            let chain = certificates(cert_pem.expose())
                .filter(|c| !c.is_empty())
                .ok_or_else(|| format!("client_cert {}: no PEM certificate", cert.display()))?;
            if !labels(key_pem.expose()).iter().any(|l| KEY_LABELS.contains(l)) {
                return Err(format!("client_key {}: no unencrypted PEM private key", key.display()));
            }
            not_after = [not_after, earliest(&chain)].into_iter().flatten().min();
            let mut pem = Vec::with_capacity(cert_pem.expose().len() + key_pem.expose().len() + 1);
            pem.extend_from_slice(cert_pem.expose());
            pem.push(b'\n');
            pem.extend_from_slice(key_pem.expose());
            Some(Secret::new(pem))
        }
        _ => None,
    };
    Ok(TlsMaterial { ca, identity, not_after, digest: digest.finalize().into(), files })
}

/// Settings of every upstream HTTP client; they only change with a restart.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientSettings {
    pub connect_timeout: Duration,
    /// Bounds a whole upstream exchange, streamed body included.
    pub total_timeout: Duration,
}

/// An upstream client. Without `tls` it trusts the platform's roots and has
/// no client certificate; with it, it trusts only the given CA certificates
/// and presents the given client certificate, if any.
pub(crate) fn http_client(s: ClientSettings, tls: Option<&TlsMaterial>) -> Result<reqwest::Client, String> {
    // No read timeout on the client: it would also cut the wait for the
    // response headers, which for non-streaming requests lasts the whole
    // generation. The idle timeout is applied between body chunks by the
    // exchange; the total timeout bounds everything.
    let mut b = reqwest::Client::builder()
        .connect_timeout(s.connect_timeout)
        .timeout(s.total_timeout)
        // Never follow redirects: the key must only ever go to the configured host.
        .redirect(reqwest::redirect::Policy::none())
        // Never route through proxies from the environment either.
        .no_proxy()
        .user_agent(concat!("otter-credential-broker/", env!("CARGO_PKG_VERSION")));
    if let Some(m) = tls {
        let roots =
            m.ca.iter()
                .map(|der| reqwest::Certificate::from_der(der))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("ca_file: {}", chain(&e)))?;
        // Built-in and platform roots are off: only these CAs are trusted.
        b = b.tls_certs_only(roots).https_only(true);
        if let Some(pem) = &m.identity {
            let identity =
                reqwest::Identity::from_pem(pem.expose()).map_err(|e| format!("client certificate: {}", chain(&e)))?;
            b = b.identity(identity);
        }
    }
    b.build().map_err(|e| format!("HTTP client: {}", chain(&e)))
}

/// An error and its sources on one line.
fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

fn earliest(certs: &[Vec<u8>]) -> Option<i64> {
    certs.iter().filter_map(|c| not_after(c)).min()
}

/// The certificates (DER) of a PEM file; `None` if it is not valid PEM.
fn certificates(pem: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for (label, body) in pem_blocks(pem)? {
        if label == "CERTIFICATE" {
            out.push(base64_decode(&body?)?);
        }
    }
    Some(out)
}

/// The labels of the PEM blocks in `pem`.
fn labels(pem: &[u8]) -> Vec<&str> {
    pem_blocks(pem).map(|b| b.into_iter().map(|(label, _)| label).collect()).unwrap_or_default()
}

/// PEM blocks as (label, base64 body). Only certificate bodies are kept;
/// other blocks (keys) are skipped, so no copy of a key is made here.
fn pem_blocks(pem: &[u8]) -> Option<Vec<(&str, Option<String>)>> {
    let text = std::str::from_utf8(pem).ok()?;
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else { continue };
        let keep = label == "CERTIFICATE";
        let mut body = String::new();
        loop {
            let l = lines.next()?;
            if l.strip_prefix("-----END ").and_then(|l| l.strip_suffix("-----")) == Some(label) {
                break;
            }
            if keep {
                body.push_str(l);
            }
        }
        out.push((label, keep.then_some(body)));
    }
    Some(out)
}

/// Standard base64 with optional padding.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// One DER element: tag, contents and what follows it.
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (len, rest) = rest.split_at(n);
        (len.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b)), rest)
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

const SEQUENCE: u8 = 0x30;
const VERSION: u8 = 0xa0;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

/// `notAfter` of an X.509 certificate (DER) in Unix seconds.
pub(crate) fn not_after(cert: &[u8]) -> Option<i64> {
    let (SEQUENCE, cert, _) = der(cert)? else { return None };
    let (SEQUENCE, tbs, _) = der(cert)? else { return None };
    // [0] version (optional), serial number, signature algorithm, issuer, validity.
    let (tag, _, rest) = der(tbs)?;
    let rest = if tag == VERSION { der(rest)?.2 } else { rest };
    let rest = der(rest)?.2;
    let rest = der(rest)?.2;
    let (SEQUENCE, validity, _) = der(rest)? else { return None };
    let (_, _, rest) = der(validity)?;
    let (tag, time, _) = der(rest)?;
    asn1_time(tag, time)
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`), the
/// forms RFC 5280 allows in certificates, in Unix seconds.
fn asn1_time(tag: u8, t: &[u8]) -> Option<i64> {
    let num = |s: &[u8]| s.iter().try_fold(0i64, |acc, &b| b.is_ascii_digit().then(|| acc * 10 + i64::from(b - b'0')));
    let (year, rest) = match (tag, t.len()) {
        (UTC_TIME, 13) => {
            let yy = num(&t[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &t[2..])
        }
        (GENERALIZED_TIME, 15) => (num(&t[..4])?, &t[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let [month, day, hour, minute, second] =
        [&rest[0..2], &rest[2..4], &rest[4..6], &rest[6..8], &rest[8..10]].map(num);
    let (month, day, hour, minute, second) = (month?, day?, hour?, minute?, second?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls").join(name)
    }

    fn cert(name: &str) -> Vec<u8> {
        certificates(&std::fs::read(fixture(name)).unwrap()).unwrap().remove(0)
    }

    // See tests/fixtures/tls/README.md.
    const Y2126: i64 = 4_922_899_200;
    const JUNE_2125: i64 = 4_904_409_600;
    const SEPT_2125: i64 = 4_912_358_400;

    #[test]
    fn certificate_expiry() {
        assert_eq!(not_after(&cert("ca.pem")), Some(Y2126));
        assert_eq!(not_after(&cert("client-a.pem")), Some(JUNE_2125));
        assert_eq!(not_after(&cert("client-b.pem")), Some(SEPT_2125));
        assert_eq!(not_after(&cert("server.pem")), Some(Y2126));
        let c = cert("client-a.pem");
        for broken in [&c[..0], &c[..10], &c[..c.len() / 2], b"\x30\x84\xff\xff\xff\xff".as_slice()] {
            assert_eq!(not_after(broken), None);
        }
    }

    #[test]
    fn certificate_times() {
        assert_eq!(asn1_time(UTC_TIME, b"260101000000Z"), Some(1_767_225_600));
        assert_eq!(asn1_time(UTC_TIME, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(asn1_time(UTC_TIME, b"500101000000Z"), Some(-631_152_000));
        assert_eq!(asn1_time(UTC_TIME, b"700101000000Z"), Some(0));
        assert_eq!(asn1_time(GENERALIZED_TIME, b"21260101000000Z"), Some(Y2126));
        assert_eq!(asn1_time(GENERALIZED_TIME, b"20240229120000Z"), Some(1_709_208_000));
        for (tag, bad) in [
            (UTC_TIME, b"2601010000Z".as_slice()),
            (UTC_TIME, b"260101000000+"),
            (UTC_TIME, b"261301000000Z"),
            (UTC_TIME, b"26010100000aZ"),
            (GENERALIZED_TIME, b"260101000000Z"),
            (SEQUENCE, b"260101000000Z"),
        ] {
            assert_eq!(asn1_time(tag, bad), None, "{bad:?}");
        }
    }

    #[test]
    fn pem_and_base64() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8gd29ybGQ").unwrap(), b"hello world");
        assert!(base64_decode("a b").is_none());
        let key = std::fs::read(fixture("client-a.key")).unwrap();
        assert_eq!(labels(&key), ["PRIVATE KEY"]);
        assert_eq!(certificates(&key).unwrap().len(), 0);
        let both = [std::fs::read(fixture("ca.pem")).unwrap(), std::fs::read(fixture("server.pem")).unwrap()].concat();
        assert_eq!(certificates(&both).unwrap().len(), 2);
        assert!(certificates(b"-----BEGIN CERTIFICATE-----\nAAAA\n").is_none(), "unterminated");
        assert!(certificates(b"\xff\xfe").is_none());
        assert_eq!(certificates(b"no pem here").unwrap().len(), 0);
    }

    fn tls(ca: &str, client: Option<(&str, &str)>) -> ProviderTls {
        ProviderTls {
            ca_file: fixture(ca),
            client_cert: client.map(|c| fixture(c.0)),
            client_key: client.map(|c| fixture(c.1)),
        }
    }

    #[test]
    fn loading_provider_files() {
        let a = load(&tls("ca.pem", Some(("client-a.pem", "client-a.key")))).unwrap();
        assert_eq!(a.ca.len(), 1);
        assert!(a.identity.is_some());
        assert_eq!(a.not_after, Some(JUNE_2125), "the client certificate expires first");
        assert_eq!(a.files.len(), 3);
        let b = load(&tls("ca.pem", Some(("client-b.pem", "client-b.key")))).unwrap();
        assert_ne!(a.digest, b.digest);
        assert_eq!(load(&tls("ca.pem", Some(("client-a.pem", "client-a.key")))).unwrap().digest, a.digest);
        let ca_only = load(&tls("ca.pem", None)).unwrap();
        assert!(ca_only.identity.is_none());
        assert_eq!(ca_only.not_after, Some(Y2126));

        for bad in [
            tls("missing.pem", None),
            tls("client-a.key", None),
            tls("ca.pem", Some(("client-a.key", "client-a.key"))),
            tls("ca.pem", Some(("client-a.pem", "client-a.pem"))),
            tls("ca.pem", Some(("client-a.pem", "missing.key"))),
        ] {
            let e = load(&bad).err().unwrap();
            assert!(!e.contains("BEGIN"), "errors never carry file content: {e}");
        }
    }

    #[test]
    fn clients_check_their_material() {
        let s = ClientSettings { connect_timeout: Duration::from_secs(1), total_timeout: Duration::from_secs(1) };
        http_client(s, None).unwrap();
        http_client(s, Some(&load(&tls("ca.pem", None)).unwrap())).unwrap();
        http_client(s, Some(&load(&tls("ca.pem", Some(("client-a.pem", "client-a.key")))).unwrap())).unwrap();
        // A key that does not belong to the certificate.
        let mismatched = load(&tls("ca.pem", Some(("client-a.pem", "client-b.key")))).unwrap();
        assert!(http_client(s, Some(&mismatched)).is_err());
    }
}
