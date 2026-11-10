//! Validated identifiers.
//!
//! Keysets, kids and items: `[A-Za-z0-9._:-]{1,128}`. Field and policy names:
//! `[A-Za-z0-9._-]{1,64}`. None may start with `.`, which rules out `.` and
//! `..`, so every identifier is safe as a path segment.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::FormatError;

fn is_valid(value: &str, max_len: usize, allow_colon: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.starts_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
                || (allow_colon && byte == b':')
        })
}

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident, $kind:literal, $max_len:literal, $allow_colon:literal) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates an identifier.
            ///
            /// # Errors
            ///
            /// Returns [`FormatError::InvalidIdentifier`] if the value breaks
            /// the identifier rules.
            pub fn new(value: impl Into<String>) -> Result<Self, FormatError> {
                let value = value.into();
                if is_valid(&value, $max_len, $allow_colon) {
                    Ok(Self(value))
                } else {
                    Err(FormatError::InvalidIdentifier($kind))
                }
            }

            /// The identifier as a string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = FormatError;

            fn try_from(value: String) -> Result<Self, FormatError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl FromStr for $name {
            type Err = FormatError;

            fn from_str(value: &str) -> Result<Self, FormatError> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier!(
    /// Identifies a group of keys that values are sealed to.
    KeysetId,
    "keyset",
    128,
    true
);
identifier!(
    /// Identifies one key in a keyset.
    KeyId,
    "kid",
    128,
    true
);
identifier!(
    /// The application's identifier for the record a value belongs to.
    ItemId,
    "item",
    128,
    true
);
identifier!(
    /// The name of a secret field on a record.
    FieldName,
    "field name",
    64,
    false
);
identifier!(
    /// The name of an entry in a policy's `definitions`.
    PolicyName,
    "policy name",
    64,
    false
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_full_alphabet() {
        assert!(KeysetId::new("Az09._:-").is_ok());
        assert!(KeyId::new("k3").is_ok());
        assert!(ItemId::new("c_123:v2").is_ok());
        assert!(FieldName::new("access_token.v1-a").is_ok());
        assert!(PolicyName::new("refresh").is_ok());
    }

    #[test]
    fn refuses_values_that_could_escape_a_path() {
        for value in [".", "..", ".hidden", "a/b", "a\\b", "a\0b"] {
            assert!(KeysetId::new(value).is_err(), "keyset {value:?}");
            assert!(KeyId::new(value).is_err(), "kid {value:?}");
            assert!(ItemId::new(value).is_err(), "item {value:?}");
            assert!(FieldName::new(value).is_err(), "field {value:?}");
            assert!(PolicyName::new(value).is_err(), "policy {value:?}");
        }
    }

    #[test]
    fn allows_dots_after_the_first_character() {
        assert!(KeysetId::new("a..b").is_ok());
        assert!(FieldName::new("a.").is_ok());
    }

    #[test]
    fn refuses_empty_values_and_other_characters() {
        for value in ["", "a b", "a+b", "é", "a\n"] {
            assert!(KeysetId::new(value).is_err(), "{value:?}");
            assert!(FieldName::new(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn enforces_length_limits_at_the_boundary() {
        assert!(KeysetId::new("a".repeat(128)).is_ok());
        assert!(KeysetId::new("a".repeat(129)).is_err());
        assert!(KeyId::new("a".repeat(129)).is_err());
        assert!(ItemId::new("a".repeat(129)).is_err());
        assert!(FieldName::new("a".repeat(64)).is_ok());
        assert!(FieldName::new("a".repeat(65)).is_err());
        assert!(PolicyName::new("a".repeat(65)).is_err());
    }

    #[test]
    fn field_and_policy_names_refuse_colons() {
        assert!(FieldName::new("a:b").is_err());
        assert!(PolicyName::new("a:b").is_err());
    }

    #[test]
    fn errors_name_the_kind_and_not_the_value() {
        let error = KeysetId::new("bad/SECRET").unwrap_err();
        assert_eq!(error, FormatError::InvalidIdentifier("keyset"));
        assert!(!error.to_string().contains("SECRET"));
    }

    #[test]
    fn serde_applies_the_same_rules() {
        let parsed: KeysetId = serde_json::from_str("\"acme\"").unwrap();
        assert_eq!(parsed.as_str(), "acme");
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"acme\"");
        assert!(serde_json::from_str::<KeysetId>("\"..\"").is_err());
    }

    #[test]
    fn parses_and_displays() {
        let item: ItemId = "c_123".parse().unwrap();
        assert_eq!(item.to_string(), "c_123");
        assert!("..".parse::<ItemId>().is_err());
    }
}
