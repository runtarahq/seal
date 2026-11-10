//! Errors from sealing, opening and validation.

use std::fmt;

/// Why a format operation failed.
///
/// Errors carry static text only. They never include a value, a secret or a
/// fragment of the input, so they are safe to log and return to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// An identifier is not valid. Names the kind of identifier.
    InvalidIdentifier(&'static str),
    /// An envelope is malformed. Says what is wrong with it.
    InvalidEnvelope(&'static str),
    /// A policy is not valid. Says which rule it breaks.
    InvalidPolicy(&'static str),
    /// A public or private key is malformed.
    InvalidKey,
    /// The secret and policy together are too large to seal.
    PlaintextTooLarge,
    /// The operating system's random source failed, or encryption did.
    SealFailed,
    /// The envelope's keyset is not the one it was presented for.
    KeysetMismatch,
    /// The value did not decrypt under this key and binding, or its contents
    /// are not valid. The two are not distinguished.
    OpenFailed,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(kind) => write!(f, "invalid {kind}"),
            Self::InvalidEnvelope(reason) => write!(f, "invalid envelope: {reason}"),
            Self::InvalidPolicy(reason) => write!(f, "invalid policy: {reason}"),
            Self::InvalidKey => f.write_str("invalid key"),
            Self::PlaintextTooLarge => f.write_str("secret and policy too large to seal"),
            Self::SealFailed => f.write_str("sealing failed"),
            Self::KeysetMismatch => f.write_str("envelope is for a different keyset"),
            Self::OpenFailed => f.write_str("sealed value did not open"),
        }
    }
}

impl std::error::Error for FormatError {}
