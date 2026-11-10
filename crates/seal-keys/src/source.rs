//! Where wrapped private keys are stored.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seal_format::id::KeyId;
use seal_format::{KeysetId, PublicKey};
use serde::{Deserialize, Serialize};

use crate::KeyError;
use crate::files::{create_private_dir, sync_dir, write_new_private};

/// The largest wrapped key file, or entry in a key source's response.
pub const MAX_WRAPPED_KEY_BYTES: usize = 16 * 1024;

/// A private key, wrapped, with what is needed to use it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    /// The keyset the key belongs to.
    pub keyset: KeysetId,
    /// The key's id.
    pub kid: KeyId,
    /// The public key, in base64url.
    pub public: String,
    /// When the key was made, in seconds since the Unix epoch. The newest is current.
    pub created: u64,
    /// The wrapping key's id.
    pub wrap_id: String,
    /// The wrapped private key, in base64url.
    pub wrapped: String,
}

impl WrappedKey {
    /// The public key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if it is malformed.
    pub fn public_key(&self) -> Result<PublicKey, KeyError> {
        PublicKey::from_base64url(&self.public).map_err(|_| KeyError::Invalid("public key"))
    }

    /// The wrapped bytes.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if they are malformed.
    pub fn wrapped_bytes(&self) -> Result<Vec<u8>, KeyError> {
        URL_SAFE_NO_PAD
            .decode(&self.wrapped)
            .map_err(|_| KeyError::Invalid("wrapped key"))
    }
}

/// Where wrapped private keys are stored.
#[async_trait]
pub trait KeySource: Send + Sync {
    /// A keyset's wrapped keys. An unknown keyset has none.
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError>;

    /// Stores a new wrapped key. A read-only source returns [`KeyError::Unsupported`].
    async fn store(&self, key: &WrappedKey) -> Result<(), KeyError> {
        let _ = key;
        Err(KeyError::Unsupported)
    }
}

/// Stores wrapped keys as `<dir>/<keyset>/<kid>.json`.
///
/// It never replaces a key, and refuses a file whose recorded keyset or kid differs
/// from its path, so that names colliding on a case-insensitive file system fail
/// instead of replacing a key.
#[derive(Clone, Debug)]
pub struct DirKeySource {
    root: PathBuf,
    max_files: usize,
}

impl DirKeySource {
    /// A source rooted at a directory, reading at most `max_files` keys per keyset.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, max_files: usize) -> Self {
        Self {
            root: root.into(),
            max_files,
        }
    }

    fn keyset_dir(&self, keyset: &KeysetId) -> PathBuf {
        // A validated identifier is a single, safe path segment.
        self.root.join(keyset.as_str())
    }
}

fn read_keyset(
    dir: &Path,
    keyset: &KeysetId,
    max_files: usize,
) -> Result<Vec<WrappedKey>, KeyError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(KeyError::Unavailable),
    };
    let mut keys = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| KeyError::Unavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Temporary files start with a dot, as identifiers never do.
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if keys.len() >= max_files {
            return Err(KeyError::Unavailable);
        }
        let metadata = entry.metadata().map_err(|_| KeyError::Unavailable)?;
        if metadata.len() > MAX_WRAPPED_KEY_BYTES as u64 {
            return Err(KeyError::Invalid("a wrapped key file is too large"));
        }
        let bytes = std::fs::read(entry.path()).map_err(|_| KeyError::Unavailable)?;
        let key: WrappedKey = serde_json::from_slice(&bytes)
            .map_err(|_| KeyError::Invalid("a wrapped key file is not valid"))?;
        if key.keyset != *keyset || key.kid.as_str() != stem {
            return Err(KeyError::Invalid(
                "a wrapped key file's keyset or kid differs from its path",
            ));
        }
        keys.push(key);
    }
    Ok(keys)
}

fn store_key(dir: &Path, key: &WrappedKey) -> Result<(), KeyError> {
    create_private_dir(dir).map_err(|_| KeyError::Unavailable)?;
    let json = serde_json::to_vec_pretty(key).map_err(|_| KeyError::Unavailable)?;
    let mut random = [0_u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .map_err(|_| KeyError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = dir.join(format!(".{}.{suffix}.tmp", key.kid));
    let destination = dir.join(format!("{}.json", key.kid));
    write_new_private(&temporary, &json).map_err(|_| KeyError::Unavailable)?;
    // A hard link fails if the destination exists, so a key is never replaced.
    let linked = std::fs::hard_link(&temporary, &destination);
    let _ = std::fs::remove_file(&temporary);
    match linked {
        Ok(()) => sync_dir(dir).map_err(|_| KeyError::Unavailable),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(KeyError::AlreadyExists)
        }
        Err(_) => Err(KeyError::Unavailable),
    }
}

#[async_trait]
impl KeySource for DirKeySource {
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        let (dir, keyset, max) = (self.keyset_dir(keyset), keyset.clone(), self.max_files);
        tokio::task::spawn_blocking(move || read_keyset(&dir, &keyset, max))
            .await
            .map_err(|_| KeyError::Unavailable)?
    }

    async fn store(&self, key: &WrappedKey) -> Result<(), KeyError> {
        let (dir, key) = (self.keyset_dir(&key.keyset), key.clone());
        tokio::task::spawn_blocking(move || store_key(&dir, &key))
            .await
            .map_err(|_| KeyError::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped(keyset: &str, kid: &str) -> WrappedKey {
        WrappedKey {
            keyset: KeysetId::new(keyset).unwrap(),
            kid: KeyId::new(kid).unwrap(),
            public: "x".to_owned(),
            created: 1,
            wrap_id: "file:00".to_owned(),
            wrapped: "y".to_owned(),
        }
    }

    #[tokio::test]
    async fn stores_and_reads_keys() {
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 16);
        let keyset = KeysetId::new("acme").unwrap();
        assert!(source.wrapped_keys(&keyset).await.unwrap().is_empty());
        source.store(&wrapped("acme", "k1")).await.unwrap();
        source.store(&wrapped("acme", "k2")).await.unwrap();
        let mut keys = source.wrapped_keys(&keyset).await.unwrap();
        keys.sort_by(|a, b| a.kid.cmp(&b.kid));
        assert_eq!(keys, [wrapped("acme", "k1"), wrapped("acme", "k2")]);
        let leftovers: Vec<_> = std::fs::read_dir(root.path().join("acme"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 2, "no temporary files are left");
    }

    #[tokio::test]
    async fn never_replaces_a_key() {
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 16);
        source.store(&wrapped("acme", "k1")).await.unwrap();
        let mut changed = wrapped("acme", "k1");
        changed.wrapped = "z".to_owned();
        assert_eq!(source.store(&changed).await, Err(KeyError::AlreadyExists));
        let keys = source
            .wrapped_keys(&KeysetId::new("acme").unwrap())
            .await
            .unwrap();
        assert_eq!(keys[0].wrapped, "y");
    }

    #[tokio::test]
    async fn refuses_a_file_whose_contents_do_not_match_its_path() {
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 16);
        source.store(&wrapped("acme", "k1")).await.unwrap();
        std::fs::rename(
            root.path().join("acme/k1.json"),
            root.path().join("acme/k9.json"),
        )
        .unwrap();
        assert!(matches!(
            source.wrapped_keys(&KeysetId::new("acme").unwrap()).await,
            Err(KeyError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn ignores_temporary_and_other_files_and_bounds_the_count() {
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 2);
        source.store(&wrapped("acme", "k1")).await.unwrap();
        std::fs::write(root.path().join("acme/.k2.abc.tmp"), b"partial").unwrap();
        std::fs::write(root.path().join("acme/notes.txt"), b"x").unwrap();
        let keyset = KeysetId::new("acme").unwrap();
        assert_eq!(source.wrapped_keys(&keyset).await.unwrap().len(), 1);
        source.store(&wrapped("acme", "k2")).await.unwrap();
        source.store(&wrapped("acme", "k3")).await.unwrap();
        assert_eq!(
            source.wrapped_keys(&keyset).await,
            Err(KeyError::Unavailable)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 16);
        source.store(&wrapped("acme", "k1")).await.unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root.path().join("acme")), 0o700);
        assert_eq!(mode(&root.path().join("acme/k1.json")), 0o600);
    }
}
