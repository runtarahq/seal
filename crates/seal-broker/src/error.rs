//! Errors from the broker.
//!
//! An error carries a code and identifiers only: never a value, a query string, a
//! header value, a body fragment or an upstream error's text.

use std::fmt;

/// The interface callers program against. Stable within `seal.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The caller may not use this keyset.
    CallerDenied,
    /// The request is malformed.
    BadRequest,
    /// A sealed value did not open.
    OpenFailed,
    /// The keyset does not exist.
    KeysetUnknown,
    /// The keys could not be loaded. May be retried.
    KeysUnavailable,
    /// No rule allows this request.
    PolicyDenied,
    /// The destination's address is refused.
    DestinationRefused,
    /// Rules conflict, or the caller set something an injection sets.
    Conflict,
    /// A body that has to be buffered is over the cap.
    BodyTooLarge,
    /// A response that has to be sealed is over the cap.
    ResponseTooLarge,
    /// A response that has to be sealed could not be parsed, or a response repeats a
    /// credential seal sent.
    ResponseUnparseable,
    /// Could not connect to the provider. May be retried.
    UpstreamConnect,
    /// TLS with the provider failed. May be retried.
    UpstreamTls,
    /// The provider or caller made no progress in time. May be retried.
    UpstreamTimeout,
    /// The provider's connection failed. May be retried.
    UpstreamReset,
    /// A Postgres login failed. The server's message is not passed on.
    PgAuthFailed,
    /// A concurrency limit was reached. May be retried.
    LimitExceeded,
    /// seal failed, or could not write an audit record.
    Internal,
}

impl ErrorCode {
    /// The code's name on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallerDenied => "CALLER_DENIED",
            Self::BadRequest => "BAD_REQUEST",
            Self::OpenFailed => "OPEN_FAILED",
            Self::KeysetUnknown => "KEYSET_UNKNOWN",
            Self::KeysUnavailable => "KEYS_UNAVAILABLE",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::DestinationRefused => "DESTINATION_REFUSED",
            Self::Conflict => "CONFLICT",
            Self::BodyTooLarge => "BODY_TOO_LARGE",
            Self::ResponseTooLarge => "RESPONSE_TOO_LARGE",
            Self::ResponseUnparseable => "RESPONSE_UNPARSEABLE",
            Self::UpstreamConnect => "UPSTREAM_CONNECT",
            Self::UpstreamTls => "UPSTREAM_TLS",
            Self::UpstreamTimeout => "UPSTREAM_TIMEOUT",
            Self::UpstreamReset => "UPSTREAM_RESET",
            Self::PgAuthFailed => "PG_AUTH_FAILED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::Internal => "INTERNAL",
        }
    }
}

/// A refusal or failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerError {
    code: ErrorCode,
    detail: String,
}

impl BrokerError {
    /// An error with static text.
    #[must_use]
    pub fn new(code: ErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail: detail.to_owned(),
        }
    }

    /// An error naming a field. A field name is an identifier, not a value.
    #[must_use]
    pub fn for_field(
        code: ErrorCode,
        detail: &'static str,
        field: &seal_format::FieldName,
    ) -> Self {
        Self {
            code,
            detail: format!("{detail}: {field}"),
        }
    }

    /// The code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Identifiers and static text only.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for BrokerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_the_code_and_detail() {
        let error = BrokerError::new(ErrorCode::PolicyDenied, "no rule matches");
        assert_eq!(error.to_string(), "POLICY_DENIED: no rule matches");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn can_name_a_field() {
        let field = seal_format::FieldName::new("api_key").unwrap();
        let error = BrokerError::for_field(ErrorCode::OpenFailed, "did not open", &field);
        assert_eq!(error.detail(), "did not open: api_key");
    }
}
