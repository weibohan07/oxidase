//! One shared, deliberately narrow file format for Admin bearer credentials.

use std::fmt;

use http::HeaderValue;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// Maximum normalized bearer credential length shared by server and `ctl`.
pub const MAX_ADMIN_BEARER_TOKEN_BYTES: usize = 8192;

/// Opaque normalized Admin credential. Generic Secret bytes remain unchanged.
#[derive(Clone)]
pub struct AdminBearerToken(Zeroizing<Vec<u8>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminBearerTokenError;

impl fmt::Display for AdminBearerTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Admin bearer token must contain 1..=8192 visible ASCII bytes, with at most one final LF or CRLF")
    }
}

impl std::error::Error for AdminBearerTokenError {}

impl AdminBearerToken {
    /// Normalize one optional final LF or CRLF. No other trimming is allowed.
    pub fn parse_file_bytes(bytes: &[u8]) -> Result<Self, AdminBearerTokenError> {
        let normalized = bytes
            .strip_suffix(b"\r\n")
            .or_else(|| bytes.strip_suffix(b"\n"))
            .unwrap_or(bytes);
        if normalized.is_empty()
            || normalized.len() > MAX_ADMIN_BEARER_TOKEN_BYTES
            || normalized.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        {
            return Err(AdminBearerTokenError);
        }
        Ok(Self(Zeroizing::new(normalized.to_vec())))
    }

    #[must_use]
    pub fn constant_time_eq(&self, candidate: &[u8]) -> bool {
        self.0.len() == candidate.len() && bool::from(self.0.as_slice().ct_eq(candidate))
    }

    #[must_use]
    pub fn same_credential(&self, other: &Self) -> bool {
        self.constant_time_eq(&other.0)
    }

    /// The resulting HeaderValue is marked sensitive to redact HTTP debug output.
    #[must_use]
    pub fn authorization_header(&self) -> HeaderValue {
        let mut value = Zeroizing::new(Vec::with_capacity(7 + self.0.len()));
        value.extend_from_slice(b"Bearer ");
        value.extend_from_slice(&self.0);
        let mut header = HeaderValue::from_bytes(&value).expect("normalized token is Header safe");
        header.set_sensitive(true);
        header
    }
}

impl fmt::Debug for AdminBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminBearerToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::{AdminBearerToken, MAX_ADMIN_BEARER_TOKEN_BYTES};

    #[test]
    fn one_line_ending_and_exact_size_are_shared() {
        for bytes in [b"test-token".as_slice(), b"test-token\n", b"test-token\r\n"] {
            let token = AdminBearerToken::parse_file_bytes(bytes).expect("valid token");
            assert!(token.constant_time_eq(b"test-token"));
            assert!(token.authorization_header().is_sensitive());
            assert!(!format!("{token:?}").contains("test-token"));
        }
        assert!(
            AdminBearerToken::parse_file_bytes(&vec![b'a'; MAX_ADMIN_BEARER_TOKEN_BYTES]).is_ok()
        );
        assert!(
            AdminBearerToken::parse_file_bytes(&vec![b'a'; MAX_ADMIN_BEARER_TOKEN_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn whitespace_control_and_multiple_line_endings_fail() {
        for bytes in [
            b"".as_slice(),
            b"\n",
            b"token\n\n",
            b"token \n",
            b"token\t",
            b"to ken",
            b"token\r",
            b"token\0",
            b"token\x7f",
            b"token\xff",
        ] {
            assert!(AdminBearerToken::parse_file_bytes(bytes).is_err());
        }
    }
}
