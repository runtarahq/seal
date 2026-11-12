//! Keyring, key sources and key wrapping.
//!
//! seal holds private keys in memory only. Where the wrapped keys are stored, and what
//! unwraps them, is pluggable: [`KeySource`] and [`KeyWrap`].

#![forbid(unsafe_code)]

mod files;
pub mod http_source;
mod https;
pub mod keyring;
pub mod ovh_kms;
pub mod source;
pub mod wrap;

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey, PublicKey};
use tokio::sync::OwnedSemaphorePermit;

pub use http_source::{HttpKeySource, HttpKeySourceConfig};
pub use keyring::{Keyring, KeyringConfig, PublicKeyInfo};
pub use ovh_kms::{OvhKmsAuth, OvhKmsConfig, OvhKmsWrap};
pub use source::{DirKeySource, KeySource, WrappedKey, rewrap};
pub use wrap::{FileKeyWrap, KeyWrap};

/// Why keys could not be found or changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The keyset does not exist.
    UnknownKeyset,
    /// The keyset exists, but has no key with this id.
    UnknownKey,
    /// The keys could not be loaded. May be retried.
    Unavailable,
    /// The keyset or key already exists.
    AlreadyExists,
    /// The key source is read-only.
    Unsupported,
    /// The keyset has as many keys as it may.
    TooManyKeys,
    /// Something is malformed or misconfigured. Says what, never with a value.
    Invalid(&'static str),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKeyset => f.write_str("the keyset does not exist"),
            Self::UnknownKey => f.write_str("the keyset has no such key"),
            Self::Unavailable => f.write_str("the keys could not be loaded"),
            Self::AlreadyExists => f.write_str("it already exists"),
            Self::Unsupported => f.write_str("the key source is read-only"),
            Self::TooManyKeys => f.write_str("the keyset has as many keys as it may"),
            Self::Invalid(what) => write!(f, "not valid: {what}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A private key in memory. It counts against the limit on live keys until the last
/// reference to it goes, including references a request still holds after the key was
/// evicted or replaced.
pub struct LiveKey {
    key: PrivateKey,
    _permit: Option<OwnedSemaphorePermit>,
}

impl LiveKey {
    /// A key that counts against no limit, for library mode and tests.
    #[must_use]
    pub fn unlimited(key: PrivateKey) -> Self {
        Self { key, _permit: None }
    }

    pub(crate) fn counted(key: PrivateKey, permit: OwnedSemaphorePermit) -> Self {
        Self {
            key,
            _permit: Some(permit),
        }
    }
}

impl Deref for LiveKey {
    type Target = PrivateKey;

    fn deref(&self) -> &PrivateKey {
        &self.key
    }
}

impl fmt::Debug for LiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LiveKey([REDACTED])")
    }
}

/// The keys a broker uses.
///
/// A caller holds a private key only while opening values: never across network
/// activity or while streaming.
#[async_trait]
pub trait Keys: Send + Sync {
    /// The private key an envelope names.
    async fn private_key(&self, keyset: &KeysetId, kid: &KeyId) -> Result<Arc<LiveKey>, KeyError>;

    /// The keyset's current public key, for sealing.
    async fn current_public_key(&self, keyset: &KeysetId) -> Result<(KeyId, PublicKey), KeyError>;
}

/// A fixed set of keys.
#[derive(Debug, Default)]
pub struct StaticKeys {
    keysets: BTreeMap<KeysetId, Vec<(KeyId, Arc<LiveKey>, PublicKey)>>,
}

impl StaticKeys {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key, which becomes the keyset's current key.
    ///
    /// # Errors
    ///
    /// Returns [`seal_format::FormatError`] if the private key is malformed.
    pub fn add(
        &mut self,
        keyset: KeysetId,
        kid: KeyId,
        key: PrivateKey,
    ) -> Result<(), seal_format::FormatError> {
        let public = key.public_key()?;
        self.keysets.entry(keyset).or_default().push((
            kid,
            Arc::new(LiveKey::unlimited(key)),
            public,
        ));
        Ok(())
    }
}

#[async_trait]
impl Keys for StaticKeys {
    async fn private_key(&self, keyset: &KeysetId, kid: &KeyId) -> Result<Arc<LiveKey>, KeyError> {
        let keys = self.keysets.get(keyset).ok_or(KeyError::UnknownKeyset)?;
        keys.iter()
            .find(|(id, _, _)| id == kid)
            .map(|(_, key, _)| Arc::clone(key))
            .ok_or(KeyError::UnknownKey)
    }

    async fn current_public_key(&self, keyset: &KeysetId) -> Result<(KeyId, PublicKey), KeyError> {
        let keys = self.keysets.get(keyset).ok_or(KeyError::UnknownKeyset)?;
        keys.last()
            .map(|(id, _, public)| (id.clone(), *public))
            .ok_or(KeyError::UnknownKeyset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyset() -> KeysetId {
        KeysetId::new("acme").unwrap()
    }

    fn kid(name: &str) -> KeyId {
        KeyId::new(name).unwrap()
    }

    #[tokio::test]
    async fn finds_keys_by_id_and_the_newest_is_current() {
        let (first, first_public) = PrivateKey::generate();
        let (second, second_public) = PrivateKey::generate();
        let mut keys = StaticKeys::new();
        keys.add(keyset(), kid("k1"), first).unwrap();
        keys.add(keyset(), kid("k2"), second).unwrap();

        let found = keys.private_key(&keyset(), &kid("k1")).await.unwrap();
        assert_eq!(found.public_key().unwrap(), first_public);
        assert_eq!(
            keys.current_public_key(&keyset()).await.unwrap(),
            (kid("k2"), second_public)
        );
    }

    #[tokio::test]
    async fn says_what_is_unknown() {
        let (key, _) = PrivateKey::generate();
        let mut keys = StaticKeys::new();
        keys.add(keyset(), kid("k1"), key).unwrap();

        let other = KeysetId::new("other").unwrap();
        assert_eq!(
            keys.private_key(&other, &kid("k1")).await.unwrap_err(),
            KeyError::UnknownKeyset
        );
        assert_eq!(
            keys.current_public_key(&other).await.unwrap_err(),
            KeyError::UnknownKeyset
        );
        assert_eq!(
            keys.private_key(&keyset(), &kid("k9")).await.unwrap_err(),
            KeyError::UnknownKey
        );
    }

    #[test]
    fn debug_does_not_show_keys() {
        let (key, _) = PrivateKey::generate();
        let mut keys = StaticKeys::new();
        keys.add(keyset(), kid("k1"), key).unwrap();
        assert!(format!("{keys:?}").contains("REDACTED"));
    }
}
