//! Where wrapped private keys are stored.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seal_format::id::KeyId;
use seal_format::{KeysetId, PublicKey};
use serde::{Deserialize, Serialize};

use crate::KeyError;
use crate::files::{create_private_dir, sync_dir, write_new_private};
use crate::wrap::KeyWraps;

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

    /// Deletes every wrapped key of a keyset, after which nothing sealed to it can be
    /// opened from this source. Copies elsewhere, such as backups, are not touched. A
    /// source that cannot delete returns [`KeyError::Unsupported`].
    async fn delete_keyset(&self, keyset: &KeysetId) -> Result<(), KeyError> {
        let _ = keyset;
        Err(KeyError::Unsupported)
    }

    /// Every keyset that has keys here, in order. A source that cannot list them
    /// returns [`KeyError::Unsupported`].
    async fn keysets(&self) -> Result<Vec<KeysetId>, KeyError> {
        Err(KeyError::Unsupported)
    }

    /// Replaces a stored key with the same key wrapped another way: only `wrap_id` and
    /// `wrapped` may differ. This is the one way a stored key changes, and it is for
    /// [`rewrap`]. If what is stored is no longer `old`, nothing is changed and this
    /// returns [`KeyError::Invalid`]. A source that cannot replace returns
    /// [`KeyError::Unsupported`].
    async fn replace(&self, old: &WrappedKey, new: &WrappedKey) -> Result<(), KeyError> {
        let _ = (old, new);
        Err(KeyError::Unsupported)
    }
}

/// Whether `new` is `old` wrapped another way, and nothing else.
pub(crate) fn is_rewrap_of(old: &WrappedKey, new: &WrappedKey) -> bool {
    (&old.keyset, &old.kid, &old.public, old.created)
        == (&new.keyset, &new.kid, &new.public, new.created)
}

/// Stores wrapped keys as `<dir>/<keyset>/<kid>.json`.
///
/// Storing never replaces a key, and a file whose recorded keyset or kid differs from
/// its path is refused, so that names colliding on a case-insensitive file system fail
/// instead of replacing a key. Only [`KeySource::replace`] changes a file, by renaming
/// a new one over it.
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

/// The keysets that have a directory under `root`.
fn list_keysets(root: &Path) -> Result<Vec<KeysetId>, KeyError> {
    let mut keysets = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| KeyError::Unavailable)? {
        let entry = entry.map_err(|_| KeyError::Unavailable)?;
        if !entry
            .file_type()
            .map_err(|_| KeyError::Unavailable)?
            .is_dir()
        {
            continue;
        }
        let keyset = entry
            .file_name()
            .to_str()
            .and_then(|name| KeysetId::new(name).ok())
            .ok_or(KeyError::Invalid("a directory that is not a keyset's"))?;
        keysets.push(keyset);
    }
    keysets.sort();
    Ok(keysets)
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
        // Read to a bound, not to the size the file had a moment ago.
        let mut bytes = Vec::new();
        std::fs::File::open(entry.path())
            .map_err(|_| KeyError::Unavailable)?
            .take(MAX_WRAPPED_KEY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| KeyError::Unavailable)?;
        if bytes.len() > MAX_WRAPPED_KEY_BYTES {
            return Err(KeyError::Invalid("a wrapped key file is too large"));
        }
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

/// Writes a key to a new temporary file beside where it belongs, and returns both
/// paths. Temporary files start with a dot, so a reader skips them.
fn write_temporary(dir: &Path, key: &WrappedKey) -> Result<(PathBuf, PathBuf), KeyError> {
    let json = serde_json::to_vec_pretty(key).map_err(|_| KeyError::Unavailable)?;
    let mut random = [0_u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .map_err(|_| KeyError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = dir.join(format!(".{}.{suffix}.tmp", key.kid));
    let destination = dir.join(format!("{}.json", key.kid));
    write_new_private(&temporary, &json).map_err(|_| KeyError::Unavailable)?;
    Ok((temporary, destination))
}

/// Renames a new file over a key's, if the key's file still holds `old`. A reader
/// sees the old file or the new one, never part of either.
fn replace_key(dir: &Path, old: &WrappedKey, new: &WrappedKey) -> Result<(), KeyError> {
    if !is_rewrap_of(old, new) {
        return Err(KeyError::Invalid("a key may only be wrapped another way"));
    }
    let stored = read_keyset(dir, &old.keyset, usize::MAX)?
        .into_iter()
        .find(|key| key.kid == old.kid);
    if stored.as_ref() != Some(old) {
        return Err(KeyError::Invalid(
            "a key changed while it was wrapped again",
        ));
    }
    let (temporary, destination) = write_temporary(dir, new)?;
    if std::fs::rename(&temporary, &destination).is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(KeyError::Unavailable);
    }
    sync_dir(dir).map_err(|_| KeyError::Unavailable)
}

fn store_key(dir: &Path, key: &WrappedKey) -> Result<(), KeyError> {
    create_private_dir(dir).map_err(|_| KeyError::Unavailable)?;
    let (temporary, destination) = write_temporary(dir, key)?;
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

/// Removes a keyset's directory and everything in it. Stopped part way, it leaves fewer
/// keys and can be run again.
fn delete_keyset_dir(root: &Path, dir: &Path) -> Result<(), KeyError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(KeyError::Unavailable),
    };
    for entry in entries {
        let entry = entry.map_err(|_| KeyError::Unavailable)?;
        // Only files are ever written here; anything else is not seal's to remove.
        std::fs::remove_file(entry.path()).map_err(|_| KeyError::Unavailable)?;
    }
    std::fs::remove_dir(dir).map_err(|_| KeyError::Unavailable)?;
    sync_dir(root).map_err(|_| KeyError::Unavailable)
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

    async fn delete_keyset(&self, keyset: &KeysetId) -> Result<(), KeyError> {
        let (root, dir) = (self.root.clone(), self.keyset_dir(keyset));
        tokio::task::spawn_blocking(move || delete_keyset_dir(&root, &dir))
            .await
            .map_err(|_| KeyError::Unavailable)?
    }

    async fn keysets(&self) -> Result<Vec<KeysetId>, KeyError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || list_keysets(&root))
            .await
            .map_err(|_| KeyError::Unavailable)?
    }

    async fn replace(&self, old: &WrappedKey, new: &WrappedKey) -> Result<(), KeyError> {
        let (dir, old, new) = (self.keyset_dir(&old.keyset), old.clone(), new.clone());
        tokio::task::spawn_blocking(move || replace_key(&dir, &old, &new))
            .await
            .map_err(|_| KeyError::Unavailable)?
    }
}

/// How [`rewrap`] is to run.
#[derive(Clone, Copy, Debug, Default)]
pub struct RewrapOptions {
    /// Wraps again the keys that are already under the current wrapping key too. For a
    /// KMS that keeps a key's id when it rotates what is behind it, this moves every
    /// key to what is behind it now.
    pub include_current: bool,
    /// Changes nothing, and reports what a run would do.
    pub dry_run: bool,
}

/// What [`rewrap`] did, or with `dry_run` would do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rewrapped {
    /// The keys wrapped again.
    pub rewrapped: usize,
    /// The keys left as they were.
    pub left: usize,
    /// How many keys each wrapping key had before the run, by its id.
    pub before: BTreeMap<String, usize>,
}

/// Wraps again, with the current wrapping key, every key in `source` that an older one
/// wrapped, and puts each in the place of the one it was made from. This is how a
/// wrapping key is replaced: once no key is left under it, it can be taken out of the
/// configuration and destroyed.
///
/// A running seal that has both wrapping keys keeps working throughout: it reads each
/// key in whichever form it finds. A run that stops part way has changed some keys and
/// not others, and can be run again.
///
/// Before anything is changed, every key's wrapping key must be one of `wraps`. Each
/// key is then unwrapped and compared with its public key, wrapped, and unwrapped
/// again from its new form and compared once more, before it replaces the old form.
///
/// # Errors
///
/// Returns [`KeyError::Invalid`] if a key's wrapping key is not one of `wraps`, a key
/// does not match its public key, or a key changed in `source` meanwhile;
/// [`KeyError::Unavailable`] if a key cannot be read, unwrapped or wrapped; and
/// [`KeyError::Unsupported`] if `source` cannot list its keysets or replace a key.
pub async fn rewrap(
    source: &dyn KeySource,
    wraps: &KeyWraps,
    options: RewrapOptions,
) -> Result<Rewrapped, KeyError> {
    let current = wraps.current();
    let mut keys = Vec::new();
    for keyset in source.keysets().await? {
        keys.extend(source.wrapped_keys(&keyset).await?);
    }
    let mut done = Rewrapped::default();
    for key in &keys {
        if wraps.by_id(&key.wrap_id).is_none() {
            return Err(KeyError::Invalid(
                "a key is wrapped with a wrapping key that is not configured",
            ));
        }
        *done.before.entry(key.wrap_id.clone()).or_default() += 1;
    }
    for key in keys {
        if key.wrap_id == current.id() && !options.include_current {
            done.left += 1;
            continue;
        }
        done.rewrapped += 1;
        if options.dry_run {
            continue;
        }
        let old = wraps.by_id(&key.wrap_id).ok_or(KeyError::Unavailable)?;
        let public = key.public_key()?;
        let matches = |private: &seal_format::PrivateKey| {
            private.public_key().is_ok_and(|derived| derived == public)
        };
        let private = old
            .unwrap(&key.keyset, &key.kid, &key.wrapped_bytes()?)
            .await?;
        if !matches(&private) {
            return Err(KeyError::Invalid(
                "a wrapped key does not match its public key",
            ));
        }
        let wrapped = current.wrap(&key.keyset, &key.kid, &private).await?;
        drop(private);
        // What replaces a key must open, or the key would be lost.
        let again = current.unwrap(&key.keyset, &key.kid, &wrapped).await?;
        if !matches(&again) {
            return Err(KeyError::Invalid(
                "a key wrapped again does not match its public key",
            ));
        }
        drop(again);
        let new = WrappedKey {
            wrap_id: current.id().to_owned(),
            wrapped: URL_SAFE_NO_PAD.encode(wrapped),
            ..key.clone()
        };
        source.replace(&key, &new).await?;
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::KeyWrap;

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
    async fn deleting_a_keyset_removes_its_keys_and_no_other() {
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 16);
        let (acme, other) = (
            KeysetId::new("acme").unwrap(),
            KeysetId::new("other").unwrap(),
        );
        source.store(&wrapped("acme", "k1")).await.unwrap();
        source.store(&wrapped("acme", "k2")).await.unwrap();
        source.store(&wrapped("other", "k1")).await.unwrap();

        source.delete_keyset(&acme).await.unwrap();
        assert!(source.wrapped_keys(&acme).await.unwrap().is_empty());
        assert!(!root.path().join("acme").exists());
        assert_eq!(
            source.keysets().await.unwrap(),
            std::slice::from_ref(&other)
        );
        assert_eq!(source.wrapped_keys(&other).await.unwrap().len(), 1);

        // Again, or for a keyset that never was, there is nothing to do.
        source.delete_keyset(&acme).await.unwrap();
        // And the name can be used afresh.
        source.store(&wrapped("acme", "k3")).await.unwrap();
        assert_eq!(source.wrapped_keys(&acme).await.unwrap().len(), 1);
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
    async fn refuses_a_file_over_the_size_limit() {
        let root = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(root.path(), 16);
        source.store(&wrapped("acme", "k1")).await.unwrap();
        let mut large = serde_json::to_vec(&wrapped("acme", "k2")).unwrap();
        large.resize(MAX_WRAPPED_KEY_BYTES + 1, b' ');
        std::fs::write(root.path().join("acme/k2.json"), &large).unwrap();
        assert_eq!(
            source.wrapped_keys(&KeysetId::new("acme").unwrap()).await,
            Err(KeyError::Invalid("a wrapped key file is too large"))
        );
        // At the limit it is read, whitespace and all.
        large.truncate(MAX_WRAPPED_KEY_BYTES);
        std::fs::write(root.path().join("acme/k2.json"), &large).unwrap();
        let keys = source
            .wrapped_keys(&KeysetId::new("acme").unwrap())
            .await
            .unwrap();
        assert_eq!(keys.len(), 2);
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

    /// A key made and wrapped as the keyring does it.
    async fn real_key(wrap: &dyn crate::KeyWrap, keyset: &str, kid: &str) -> WrappedKey {
        let (keyset, kid) = (
            KeysetId::new(keyset).unwrap(),
            KeyId::new(kid.to_owned()).unwrap(),
        );
        let (private, public) = seal_format::PrivateKey::generate();
        let wrapped = wrap.wrap(&keyset, &kid, &private).await.unwrap();
        WrappedKey {
            keyset,
            kid,
            public: public.to_base64url(),
            created: 1,
            wrap_id: wrap.id().to_owned(),
            wrapped: URL_SAFE_NO_PAD.encode(wrapped),
        }
    }

    fn wraps(current: &Arc<dyn KeyWrap>, older: &[&Arc<dyn KeyWrap>]) -> KeyWraps {
        KeyWraps::new(
            Arc::clone(current),
            older.iter().map(|wrap| Arc::clone(wrap)).collect(),
        )
        .unwrap()
    }

    fn file_wrap(byte: u8) -> Arc<dyn KeyWrap> {
        Arc::new(crate::FileKeyWrap::from_bytes(&[byte; 32]).unwrap())
    }

    #[tokio::test]
    async fn rewrapping_moves_every_key_to_the_current_wrapping_key_in_place() {
        let (old, new) = (file_wrap(7), file_wrap(8));
        let dir = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(dir.path(), 16);
        let mut keys = Vec::new();
        for (keyset, kid) in [("acme", "k1"), ("acme", "k2"), ("beta", "k1")] {
            let key = real_key(old.as_ref(), keyset, kid).await;
            source.store(&key).await.unwrap();
            keys.push(key);
        }
        // One key is already under the new wrapping key, as one made meanwhile is.
        let fresh = real_key(new.as_ref(), "beta", "k2").await;
        source.store(&fresh).await.unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        let both = wraps(&new, &[&old]);

        let dry = RewrapOptions {
            dry_run: true,
            ..RewrapOptions::default()
        };
        let would = rewrap(&source, &both, dry).await.unwrap();
        assert_eq!((would.rewrapped, would.left), (3, 1));
        assert_eq!(would.before[old.id()], 3);
        assert_eq!(would.before[new.id()], 1);
        assert_eq!(
            source.wrapped_keys(&keys[0].keyset).await.unwrap().len(),
            2,
            "a dry run changes nothing"
        );
        assert!(
            source
                .wrapped_keys(&keys[0].keyset)
                .await
                .unwrap()
                .iter()
                .all(|key| key.wrap_id == old.id())
        );

        let done = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((done.rewrapped, done.left), (3, 1));
        for key in &keys {
            let moved = source
                .wrapped_keys(&key.keyset)
                .await
                .unwrap()
                .into_iter()
                .find(|moved| moved.kid == key.kid)
                .unwrap();
            assert_eq!(moved.wrap_id, new.id());
            assert_eq!((&moved.public, moved.created), (&key.public, key.created));
            // The new wrapping key opens it, to the same private key; the old cannot.
            let bytes = moved.wrapped_bytes().unwrap();
            let private = new.unwrap(&key.keyset, &key.kid, &bytes).await.unwrap();
            assert_eq!(private.public_key().unwrap(), key.public_key().unwrap());
            assert!(old.unwrap(&key.keyset, &key.kid, &bytes).await.is_err());
        }
        // The key that was current is the same file as before.
        let beta = source.wrapped_keys(&fresh.keyset).await.unwrap();
        assert!(beta.contains(&fresh));
        for keyset in ["acme", "beta"] {
            let names: Vec<_> = std::fs::read_dir(dir.path().join(keyset))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            assert!(
                names.iter().all(|name| !name.starts_with('.')),
                "no temporary files are left: {names:?}"
            );
            #[cfg(unix)]
            for name in &names {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.path().join(keyset).join(name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
        }

        // A second run finds nothing to do, and the old wrapping key can go.
        let again = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((again.rewrapped, again.left), (0, 4));
        assert_eq!(again.before.get(old.id()), None);
        let alone = wraps(&new, &[]);
        let all = RewrapOptions {
            include_current: true,
            ..RewrapOptions::default()
        };
        let refreshed = rewrap(&source, &alone, all).await.unwrap();
        assert_eq!((refreshed.rewrapped, refreshed.left), (4, 0));
    }

    /// A wrapping key that fails to wrap from its second key on.
    struct FailsLater {
        inner: crate::FileKeyWrap,
        wrapped: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl KeyWrap for FailsLater {
        fn id(&self) -> &str {
            self.inner.id()
        }

        async fn wrap(
            &self,
            keyset: &KeysetId,
            kid: &KeyId,
            key: &seal_format::PrivateKey,
        ) -> Result<Vec<u8>, KeyError> {
            if self
                .wrapped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                >= 1
            {
                return Err(KeyError::Unavailable);
            }
            self.inner.wrap(keyset, kid, key).await
        }

        async fn unwrap(
            &self,
            keyset: &KeysetId,
            kid: &KeyId,
            wrapped: &[u8],
        ) -> Result<seal_format::PrivateKey, KeyError> {
            self.inner.unwrap(keyset, kid, wrapped).await
        }
    }

    #[tokio::test]
    async fn a_rewrap_that_stops_part_way_leaves_every_key_readable_and_can_be_run_again() {
        let (old, new) = (file_wrap(7), file_wrap(8));
        let failing: Arc<dyn KeyWrap> = Arc::new(FailsLater {
            inner: crate::FileKeyWrap::from_bytes(&[8; 32]).unwrap(),
            wrapped: std::sync::atomic::AtomicUsize::new(0),
        });
        let dir = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(dir.path(), 16);
        let mut keys = Vec::new();
        for kid in ["k1", "k2", "k3"] {
            let key = real_key(old.as_ref(), "acme", kid).await;
            source.store(&key).await.unwrap();
            keys.push(key);
        }
        assert_eq!(
            rewrap(&source, &wraps(&failing, &[&old]), RewrapOptions::default()).await,
            Err(KeyError::Unavailable)
        );
        let both = wraps(&new, &[&old]);
        let stored = source.wrapped_keys(&keys[0].keyset).await.unwrap();
        assert_eq!(stored.len(), 3);
        assert_eq!(
            stored.iter().filter(|key| key.wrap_id == new.id()).count(),
            1
        );
        for key in &stored {
            let wrap = both.by_id(&key.wrap_id).unwrap();
            let bytes = key.wrapped_bytes().unwrap();
            let private = wrap.unwrap(&key.keyset, &key.kid, &bytes).await.unwrap();
            assert_eq!(private.public_key().unwrap(), key.public_key().unwrap());
        }
        let done = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((done.rewrapped, done.left), (2, 1));
    }

    #[tokio::test]
    async fn rewrapping_refuses_what_it_cannot_vouch_for() {
        let (old, new, other) = (file_wrap(7), file_wrap(8), file_wrap(9));
        let fresh = || {
            let dir = tempfile::tempdir().unwrap();
            let source = DirKeySource::new(dir.path(), 16);
            (dir, source)
        };
        let unchanged = |source: &DirKeySource, key: &WrappedKey| {
            let (source, key) = (source.clone(), key.clone());
            async move {
                assert_eq!(source.wrapped_keys(&key.keyset).await.unwrap(), [key]);
            }
        };

        // A key under a wrapping key that is not configured: nothing is changed, not
        // even the keys that could be.
        let (_dir, source) = fresh();
        let known = real_key(old.as_ref(), "acme", "k1").await;
        let unknown = real_key(other.as_ref(), "beta", "k1").await;
        source.store(&known).await.unwrap();
        source.store(&unknown).await.unwrap();
        assert!(matches!(
            rewrap(&source, &wraps(&new, &[&old]), RewrapOptions::default()).await,
            Err(KeyError::Invalid(_))
        ));
        unchanged(&source, &known).await;
        unchanged(&source, &unknown).await;

        // A key whose stored public key is not its own.
        let (_dir, source) = fresh();
        let mut swapped = real_key(old.as_ref(), "acme", "k1").await;
        swapped.public = seal_format::PrivateKey::generate().1.to_base64url();
        source.store(&swapped).await.unwrap();
        assert!(matches!(
            rewrap(&source, &wraps(&new, &[&old]), RewrapOptions::default()).await,
            Err(KeyError::Invalid(_))
        ));
        unchanged(&source, &swapped).await;

        // A directory that is no keyset's.
        let (dir, source) = fresh();
        std::fs::create_dir(dir.path().join("not a keyset")).unwrap();
        assert!(matches!(
            rewrap(&source, &wraps(&new, &[&old]), RewrapOptions::default()).await,
            Err(KeyError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn a_key_is_replaced_only_by_itself_wrapped_another_way() {
        let (old, new) = (file_wrap(7), file_wrap(8));
        let dir = tempfile::tempdir().unwrap();
        let source = DirKeySource::new(dir.path(), 16);
        let stored = real_key(old.as_ref(), "acme", "k1").await;
        source.store(&stored).await.unwrap();
        let rewrapped = WrappedKey {
            wrap_id: new.id().to_owned(),
            wrapped: "eQ".to_owned(),
            ..stored.clone()
        };

        // Another public key, or another time, is another key.
        for changed in [
            WrappedKey {
                public: "eA".to_owned(),
                ..rewrapped.clone()
            },
            WrappedKey {
                created: stored.created + 1,
                ..rewrapped.clone()
            },
        ] {
            assert!(matches!(
                source.replace(&stored, &changed).await,
                Err(KeyError::Invalid(_))
            ));
        }
        // What is stored is not what the caller read.
        assert!(matches!(
            source.replace(&rewrapped, &rewrapped).await,
            Err(KeyError::Invalid(_))
        ));
        // A key that is not stored at all.
        let missing = WrappedKey {
            kid: KeyId::new("k9").unwrap(),
            ..stored.clone()
        };
        assert!(matches!(
            source.replace(&missing, &missing).await,
            Err(KeyError::Invalid(_))
        ));
        assert_eq!(
            source.wrapped_keys(&stored.keyset).await.unwrap(),
            std::slice::from_ref(&stored)
        );

        source.replace(&stored, &rewrapped).await.unwrap();
        assert_eq!(
            source.wrapped_keys(&stored.keyset).await.unwrap(),
            [rewrapped]
        );
    }
}
