//! Wrapping private keys, so that they can be stored outside seal.
//!
//! A wrapped key is bound to its keyset and kid as associated data, so a wrapped key
//! moved to another keyset or kid does not unwrap.

use std::path::Path;

use async_trait::async_trait;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use zeroize::Zeroizing;

use crate::KeyError;

/// What wraps and unwraps private keys: a KMS, or a local key.
#[async_trait]
pub trait KeyWrap: Send + Sync {
    /// Identifies the wrapping key, so that a key wrapped by another is refused.
    fn id(&self) -> &str;

    /// Wraps a private key.
    async fn wrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, KeyError>;

    /// Unwraps a private key.
    async fn unwrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        wrapped: &[u8],
    ) -> Result<PrivateKey, KeyError>;
}

/// The associated data: `"seal/v1/wrap" || lp(keyset) || lp(kid)`.
pub(crate) fn associated_data(keyset: &KeysetId, kid: &KeyId) -> Vec<u8> {
    let mut aad = b"seal/v1/wrap".to_vec();
    for part in [keyset.as_str(), kid.as_str()] {
        // Validated identifiers are at most 128 bytes.
        let length = u16::try_from(part.len()).unwrap_or(u16::MAX);
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
}

/// Wraps with an AES-256-GCM key held in a file readable only by seal's user.
pub struct FileKeyWrap {
    key: LessSafeKey,
    id: String,
    random: SystemRandom,
}

impl std::fmt::Debug for FileKeyWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyWrap")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The length of a wrapping key file: 32 random bytes.
pub const WRAPPING_KEY_BYTES: usize = 32;

impl FileKeyWrap {
    /// Reads the wrapping key. Refuses a file that its group or others can access.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the file cannot be read, is not 32 bytes, or
    /// has permissions that are too open.
    pub fn from_file(path: &Path) -> Result<Self, KeyError> {
        check_private(path)?;
        let bytes = Zeroizing::new(
            std::fs::read(path)
                .map_err(|_| KeyError::Invalid("the wrapping key file cannot be read"))?,
        );
        Self::from_bytes(&bytes)
    }

    /// Uses these bytes as the wrapping key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if there are not 32 of them.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != WRAPPING_KEY_BYTES {
            return Err(KeyError::Invalid("a wrapping key is 32 bytes"));
        }
        let key = UnboundKey::new(&AES_256_GCM, bytes)
            .map_err(|_| KeyError::Invalid("the wrapping key is not valid"))?;
        // The id is a short hash, which identifies the key without revealing it.
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
        let id = format!(
            "file:{}",
            digest.as_ref()[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            key: LessSafeKey::new(key),
            id,
            random: SystemRandom::new(),
        })
    }

    /// Writes a new random wrapping key to a file that only its owner can read. Refuses
    /// to replace an existing file.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the file exists or cannot be written.
    pub fn create_file(path: &Path) -> Result<(), KeyError> {
        let mut bytes = Zeroizing::new([0_u8; WRAPPING_KEY_BYTES]);
        SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| KeyError::Invalid("no random bytes"))?;
        crate::files::write_new_private(path, bytes.as_ref())
            .map_err(|_| KeyError::Invalid("the wrapping key file could not be created"))
    }
}

/// Refuses a file that its group or others can read or write.
pub fn check_private(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            std::fs::metadata(path).map_err(|_| KeyError::Invalid("a key file cannot be read"))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyError::Invalid(
                "a key file is accessible to its group or others",
            ));
        }
    }
    let _ = path;
    Ok(())
}

#[async_trait]
impl KeyWrap for FileKeyWrap {
    fn id(&self) -> &str {
        &self.id
    }

    async fn wrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, KeyError> {
        let mut nonce = [0_u8; NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .map_err(|_| KeyError::Unavailable)?;
        let mut sealed = Zeroizing::new(key.expose(<[u8]>::to_vec));
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(associated_data(keyset, kid)),
                &mut *sealed,
            )
            .map_err(|_| KeyError::Unavailable)?;
        let mut output = nonce.to_vec();
        output.extend_from_slice(&sealed);
        Ok(output)
    }

    async fn unwrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        wrapped: &[u8],
    ) -> Result<PrivateKey, KeyError> {
        if wrapped.len() < NONCE_LEN {
            return Err(KeyError::Unavailable);
        }
        let (nonce, sealed) = wrapped.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| KeyError::Unavailable)?;
        let mut buffer = Zeroizing::new(sealed.to_vec());
        let opened = self
            .key
            .open_in_place(
                nonce,
                Aad::from(associated_data(keyset, kid)),
                buffer.as_mut_slice(),
            )
            .map_err(|_| KeyError::Unavailable)?;
        PrivateKey::from_bytes(opened).map_err(|_| KeyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyset() -> KeysetId {
        KeysetId::new("acme").unwrap()
    }

    fn kid() -> KeyId {
        KeyId::new("k1").unwrap()
    }

    #[tokio::test]
    async fn a_wrapped_key_unwraps_to_the_same_key() {
        let wrap = FileKeyWrap::from_bytes(&[7; 32]).unwrap();
        let (key, public) = PrivateKey::generate();
        let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
        assert!(!key.expose(|bytes| wrapped.windows(32).any(|window| window == bytes)));
        let unwrapped = wrap.unwrap(&keyset(), &kid(), &wrapped).await.unwrap();
        assert_eq!(unwrapped.public_key().unwrap(), public);
    }

    #[tokio::test]
    async fn a_wrapped_key_does_not_unwrap_under_another_keyset_kid_or_key() {
        let wrap = FileKeyWrap::from_bytes(&[7; 32]).unwrap();
        let (key, _) = PrivateKey::generate();
        let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
        let other_keyset = KeysetId::new("other").unwrap();
        let other_kid = KeyId::new("k2").unwrap();
        assert!(wrap.unwrap(&other_keyset, &kid(), &wrapped).await.is_err());
        assert!(wrap.unwrap(&keyset(), &other_kid, &wrapped).await.is_err());
        let other = FileKeyWrap::from_bytes(&[8; 32]).unwrap();
        assert!(other.unwrap(&keyset(), &kid(), &wrapped).await.is_err());
        for index in 0..wrapped.len() {
            let mut changed = wrapped.clone();
            changed[index] ^= 1;
            assert!(wrap.unwrap(&keyset(), &kid(), &changed).await.is_err());
        }
        assert!(wrap.unwrap(&keyset(), &kid(), &wrapped[..5]).await.is_err());
    }

    #[test]
    fn ids_differ_by_key_and_reveal_nothing_of_it() {
        let first = FileKeyWrap::from_bytes(&[7; 32]).unwrap();
        let second = FileKeyWrap::from_bytes(&[8; 32]).unwrap();
        assert_ne!(first.id(), second.id());
        assert!(first.id().starts_with("file:"));
        assert!(!format!("{first:?}").contains("0707"));
        assert!(FileKeyWrap::from_bytes(&[7; 31]).is_err());
    }

    #[test]
    fn a_key_file_is_created_private_and_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kek");
        FileKeyWrap::create_file(&path).unwrap();
        assert!(FileKeyWrap::from_file(&path).is_ok());
        assert!(FileKeyWrap::create_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_that_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kek");
        FileKeyWrap::create_file(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            FileKeyWrap::from_file(&path).unwrap_err(),
            KeyError::Invalid("a key file is accessible to its group or others")
        );
    }
}
