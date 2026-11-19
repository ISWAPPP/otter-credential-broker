//! Validation of identifiers that end up in SQL rows, URL paths, log lines,
//! audit rows and metric labels. Restrictive character sets keep them safe in
//! all of those places. Error messages never echo the rejected input.

use serde_json::Value;

use crate::error::BrokerError;

fn invalid(what: &str, rule: &str) -> BrokerError {
    BrokerError::Invalid(format!("{what} must be {rule}"))
}

fn check(s: &str, max: usize, first: fn(u8) -> bool, rest: fn(u8) -> bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= max && first(b[0]) && b.iter().all(|&c| rest(c))
}

fn name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')
}

/// Tenant identifier: 1-64 chars of `[A-Za-z0-9._-]`, starting with a letter or digit.
pub fn tenant_id(s: &str) -> Result<(), BrokerError> {
    if check(s, 64, |c| c.is_ascii_alphanumeric(), name_char) {
        Ok(())
    } else {
        Err(invalid("tenant id", "1-64 chars of [A-Za-z0-9._-] starting with a letter or digit"))
    }
}

/// Secret name: 1-128 chars of `[A-Za-z0-9._-]`, starting with a letter or digit.
pub fn secret_name(s: &str) -> Result<(), BrokerError> {
    if check(s, 128, |c| c.is_ascii_alphanumeric(), name_char) {
        Ok(())
    } else {
        Err(invalid("secret name", "1-128 chars of [A-Za-z0-9._-] starting with a letter or digit"))
    }
}

/// Secret kind: 1-32 chars of `[a-z0-9_]`, starting with a letter.
pub fn secret_kind(s: &str) -> Result<(), BrokerError> {
    if check(s, 32, |c| c.is_ascii_lowercase(), |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
        Ok(())
    } else {
        Err(invalid("kind", "1-32 chars of [a-z0-9_] starting with a letter"))
    }
}

/// Provider identifier: 1-32 chars of `[a-z0-9_-]`, starting with a letter or digit.
pub fn provider_id(s: &str) -> Result<(), BrokerError> {
    let rest = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-';
    if check(s, 32, |c| c.is_ascii_lowercase() || c.is_ascii_digit(), rest) {
        Ok(())
    } else {
        Err(invalid("provider id", "1-32 chars of [a-z0-9_-] starting with a letter or digit"))
    }
}

/// Free-form reference chosen by the platform (run id, job id, label):
/// 1-128 chars of `[A-Za-z0-9._:@/-]`, starting with a letter or digit.
pub fn reference(what: &str, s: &str) -> Result<(), BrokerError> {
    let rest = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'@' | b'/' | b'-');
    if check(s, 128, |c| c.is_ascii_alphanumeric(), rest) {
        Ok(())
    } else {
        Err(invalid(what, "1-128 chars of [A-Za-z0-9._:@/-] starting with a letter or digit"))
    }
}

/// Non-secret metadata attached to a secret: a JSON object of bounded size.
pub fn metadata(v: &Value, max_bytes: usize) -> Result<String, BrokerError> {
    if !v.is_object() {
        return Err(invalid("metadata", "a JSON object"));
    }
    let s = serde_json::to_string(v).map_err(|e| BrokerError::Internal(format!("encode metadata: {e}")))?;
    if s.len() > max_bytes {
        return Err(BrokerError::TooLarge(format!("metadata exceeds {max_bytes} bytes")));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identifiers() {
        assert!(tenant_id("t-1").is_ok());
        assert!(tenant_id("Tenant_A.prod").is_ok());
        for bad in ["", "-x", ".x", "a b", "a/b", "a\nb", "ä", &"x".repeat(65)] {
            assert!(tenant_id(bad).is_err(), "{bad:?}");
        }
        assert!(secret_name("llm.anthropic").is_ok());
        assert!(secret_name("ssh.vm-12").is_ok());
        assert!(secret_name("../etc").is_err());
        assert!(secret_name("a/b").is_err());
        assert!(secret_kind("llm_api_key").is_ok());
        assert!(secret_kind("LLM").is_err());
        assert!(secret_kind("1x").is_err());
        assert!(provider_id("deepseek").is_ok());
        assert!(provider_id("open-router_2").is_ok());
        assert!(provider_id("OpenAI").is_err());
        assert!(provider_id("evil.example").is_err());
        assert!(reference("run id", "run:42/step-1@a").is_ok());
        assert!(reference("run id", "run 42").is_err());
        assert!(reference("run id", "run\r\n").is_err());
    }

    #[test]
    fn metadata_rules() {
        assert!(metadata(&json!({"a": 1}), 100).is_ok());
        assert!(metadata(&json!([1]), 100).is_err());
        assert!(matches!(metadata(&json!({"a": "x".repeat(200)}), 100), Err(BrokerError::TooLarge(_))));
    }
}
