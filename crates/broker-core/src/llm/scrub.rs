//! Removing key-like material from data that leaves the proxy.
//!
//! - [`scrub_error_body`]: provider error bodies are passed through to the
//!   caller only after redacting known secrets and anything that looks like a
//!   credential (providers sometimes echo a full or partially masked key).
//! - [`StreamRedactor`]: success bodies are streamed unchanged except that any
//!   occurrence of the provider key is replaced. Real providers never send it
//!   back; this is defence in depth against a reflecting upstream. It holds
//!   back only a chunk tail that could be the start of the key, so streaming
//!   latency is unaffected in practice.

use crate::secret::Secret;

pub const REDACTED: &[u8] = b"[REDACTED]";

/// Prefixes of common credential formats (API keys, OAuth and VCS tokens,
/// this broker's own tokens).
const KEY_PREFIXES: &[&[u8]] =
    &[b"sk-", b"sk_", b"rk-", b"rk_", b"pk-", b"ak-", b"AIza", b"ghp_", b"gho_", b"ghs_", b"xox", b"ocb_", b"eyJ"];

/// Runs at least this long are treated as credentials when they mix letters
/// and digits.
const LONG_RUN: usize = 24;

fn run_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'*' | b'.' | b'+' | b'/' | b'=')
}

fn looks_like_key(run: &[u8]) -> bool {
    if run.len() < 8 {
        return false;
    }
    if KEY_PREFIXES.iter().any(|p| run.starts_with(p)) {
        return true;
    }
    if run.windows(3).any(|w| w == b"***") {
        return true;
    }
    let letters = run.iter().filter(|b| b.is_ascii_alphabetic()).count();
    let digits = run.iter().filter(|b| b.is_ascii_digit()).count();
    run.len() >= LONG_RUN && letters > 0 && digits > 0
}

/// Replaces every occurrence of each non-empty needle.
pub fn redact_exact(data: &[u8], needles: &[&[u8]]) -> Vec<u8> {
    let mut out = data.to_vec();
    for needle in needles.iter().filter(|n| !n.is_empty()) {
        if find(&out, needle).is_none() {
            continue;
        }
        let mut next = Vec::with_capacity(out.len());
        let mut i = 0;
        while let Some(pos) = find(&out[i..], needle) {
            next.extend_from_slice(&out[i..i + pos]);
            next.extend_from_slice(REDACTED);
            i += pos + needle.len();
        }
        next.extend_from_slice(&out[i..]);
        out = next;
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Scrubs an upstream error body: exact secrets first, then every run of
/// token characters that looks like a credential. Only ASCII runs are
/// replaced, so UTF-8 text stays valid and JSON structure is preserved.
pub fn scrub_error_body(body: &[u8], secrets: &[&[u8]]) -> Vec<u8> {
    let exact = redact_exact(body, secrets);
    let mut out = Vec::with_capacity(exact.len());
    let mut i = 0;
    while i < exact.len() {
        if run_char(exact[i]) {
            let start = i;
            while i < exact.len() && run_char(exact[i]) {
                i += 1;
            }
            let run = &exact[start..i];
            if looks_like_key(run) {
                out.extend_from_slice(REDACTED);
            } else {
                out.extend_from_slice(run);
            }
        } else {
            out.push(exact[i]);
            i += 1;
        }
    }
    out
}

/// Streaming exact-match redaction of one secret.
/// `Debug` never shows the needle.
#[derive(Debug)]
pub struct StreamRedactor {
    needle: Secret<Vec<u8>>,
    carry: Vec<u8>,
    redactions: u64,
}

impl StreamRedactor {
    pub fn new(needle: &[u8]) -> Self {
        Self { needle: Secret::new(needle.to_vec()), carry: Vec::new(), redactions: 0 }
    }

    /// Number of occurrences replaced so far.
    pub fn redactions(&self) -> u64 {
        self.redactions
    }

    /// Processes one chunk and returns what can be emitted now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let needle = self.needle.expose();
        if needle.is_empty() {
            return chunk.to_vec();
        }
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while let Some(pos) = find(&data[i..], needle) {
            out.extend_from_slice(&data[i..i + pos]);
            out.extend_from_slice(REDACTED);
            self.redactions += 1;
            i += pos + needle.len();
        }
        // Hold back the longest tail that is a proper prefix of the needle.
        let rest = &data[i..];
        let max = rest.len().min(needle.len() - 1);
        let hold = (1..=max).rev().find(|&k| rest[rest.len() - k..] == needle[..k]).unwrap_or(0);
        out.extend_from_slice(&rest[..rest.len() - hold]);
        self.carry = rest[rest.len() - hold..].to_vec();
        out
    }

    /// Flushes what was held back at the end of the stream.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.carry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "sk-ant-api03-FAKEFAKEFAKE0123456789abcdefXYZ";

    #[test]
    fn error_bodies_are_scrubbed() {
        let body = format!(
            r#"{{"type":"error","error":{{"type":"authentication_error","message":"invalid x-api-key {KEY}; key sk-proj-ab************************wxyz rejected; token ocb_llm_{}"}},"request_id":"req_011CSHoEeqs5"}}"#,
            "a".repeat(64)
        );
        let out = String::from_utf8(scrub_error_body(body.as_bytes(), &[KEY.as_bytes()])).unwrap();
        assert!(!out.contains("FAKEFAKE"));
        assert!(!out.contains("sk-proj"));
        assert!(!out.contains("wxyz"));
        assert!(!out.contains("ocb_llm"));
        assert!(out.contains("authentication_error"));
        assert!(out.contains("req_011CSHoEeqs5"), "short ids survive: {out}");
        // Still valid JSON with the same structure.
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["error"]["type"], "authentication_error");
    }

    #[test]
    fn scrub_keeps_utf8_and_plain_text() {
        let body = "Café error: key sk-abcdefghijkl is invalid — overloaded_error ✓".as_bytes();
        let out = String::from_utf8(scrub_error_body(body, &[])).unwrap();
        assert_eq!(out, "Café error: key [REDACTED] is invalid — overloaded_error ✓");
        let plain = br#"{"error":{"message":"Rate limit reached for requests","type":"requests","code":"rate_limit_exceeded"}}"#;
        assert_eq!(scrub_error_body(plain, &[]), plain.to_vec());
    }

    #[test]
    fn stream_redaction_at_every_split_point() {
        let body = format!("data: {{\"text\":\"leak {KEY} and again {KEY}!\"}}\n\n");
        let expected = "data: {\"text\":\"leak [REDACTED] and again [REDACTED]!\"}\n\n".to_owned();
        let b = body.as_bytes();
        for split in 0..=b.len() {
            for split2 in split..=b.len() {
                let mut r = StreamRedactor::new(KEY.as_bytes());
                let mut out = r.push(&b[..split]);
                out.extend(r.push(&b[split..split2]));
                out.extend(r.push(&b[split2..]));
                out.extend(r.finish());
                assert_eq!(String::from_utf8(out).unwrap(), expected, "{split}/{split2}");
                assert_eq!(r.redactions(), 2);
            }
        }
    }

    #[test]
    fn stream_redaction_does_not_hold_back_unrelated_tails() {
        let mut r = StreamRedactor::new(KEY.as_bytes());
        assert_eq!(r.push(b"data: {}\n\n"), b"data: {}\n\n".to_vec());
        // A tail that might start the key is held until disproved.
        assert_eq!(r.push(b"abc s"), b"abc ".to_vec());
        assert_eq!(r.push(b"ome text"), b"some text".to_vec());
        assert!(r.finish().is_empty());
    }
}
