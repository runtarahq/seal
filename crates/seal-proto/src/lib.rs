//! gRPC protocol definitions, generated from `proto/seal/v1/seal.proto`.

#![forbid(unsafe_code)]

/// Package `seal.v1`.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
pub mod v1 {
    tonic::include_proto!("seal.v1");
}

/// The metadata key that carries an [`v1::ErrorCode`]'s name on a refusal.
pub const ERROR_CODE_METADATA: &str = "seal-error-code";

/// The largest body chunk in either direction.
pub const MAX_BODY_CHUNK: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::v1::ErrorCode;

    #[test]
    fn error_code_names_are_the_wire_names() {
        assert_eq!(ErrorCode::PolicyDenied.as_str_name(), "POLICY_DENIED");
        assert_eq!(
            ErrorCode::from_str_name("LIMIT_EXCEEDED"),
            Some(ErrorCode::LimitExceeded)
        );
        assert_eq!(ErrorCode::from_str_name("NOT_A_CODE"), None);
    }
}
