use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use seal_format::policy::builder;
use seal_format::{Binding, FieldName, ItemId, seal};

use super::*;
use crate::wrap::{FileKeyWrap, KeyWrap};

/// A key source in memory, shared by several keyrings as instances share a store.
#[derive(Default)]
struct MemorySource {
    keys: Mutex<HashMap<KeysetId, Vec<WrappedKey>>>,
    fetches: AtomicUsize,
    down: AtomicBool,
}

impl MemorySource {
    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    fn delete(&self, keyset: &KeysetId, kid: &KeyId) {
        self.keys
            .lock()
            .unwrap()
            .get_mut(keyset)
            .unwrap()
            .retain(|key| key.kid != *kid);
    }
}

#[async_trait]
impl KeySource for MemorySource {
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        // Lets concurrent callers pile up, as a real fetch would.
        tokio::time::sleep(Duration::from_millis(10)).await;
        if self.down.load(Ordering::SeqCst) {
            return Err(KeyError::Unavailable);
        }
        Ok(self
            .keys
            .lock()
            .unwrap()
            .get(keyset)
            .cloned()
            .unwrap_or_default())
    }

    async fn store(&self, key: &WrappedKey) -> Result<(), KeyError> {
        let mut keys = self.keys.lock().unwrap();
        let list = keys.entry(key.keyset.clone()).or_default();
        if list.iter().any(|existing| existing.kid == key.kid) {
            return Err(KeyError::AlreadyExists);
        }
        list.push(key.clone());
        Ok(())
    }

    async fn delete_keyset(&self, keyset: &KeysetId) -> Result<(), KeyError> {
        self.keys.lock().unwrap().remove(keyset);
        Ok(())
    }

    async fn keysets(&self) -> Result<Vec<KeysetId>, KeyError> {
        let mut keysets: Vec<_> = self.keys.lock().unwrap().keys().cloned().collect();
        keysets.sort();
        Ok(keysets)
    }

    async fn replace(&self, old: &WrappedKey, new: &WrappedKey) -> Result<(), KeyError> {
        let mut keys = self.keys.lock().unwrap();
        let stored = keys
            .get_mut(&old.keyset)
            .and_then(|list| list.iter_mut().find(|key| *key == old))
            .ok_or(KeyError::Invalid(
                "a key changed while it was wrapped again",
            ))?;
        *stored = new.clone();
        Ok(())
    }
}

/// A source that only reads, as one served over HTTP is.
struct ReadOnlySource(Arc<MemorySource>);

#[async_trait]
impl KeySource for ReadOnlySource {
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        self.0.wrapped_keys(keyset).await
    }
}

/// A wrapping key that can be revoked.
struct RevocableWrap {
    inner: FileKeyWrap,
    revoked: AtomicBool,
}

#[async_trait]
impl KeyWrap for RevocableWrap {
    fn id(&self) -> &str {
        self.inner.id()
    }

    async fn wrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, KeyError> {
        self.inner.wrap(keyset, kid, key).await
    }

    async fn unwrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        wrapped: &[u8],
    ) -> Result<PrivateKey, KeyError> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(KeyError::Unavailable);
        }
        self.inner.unwrap(keyset, kid, wrapped).await
    }
}

fn config() -> KeyringConfig {
    KeyringConfig {
        idle_evict: Duration::from_secs(60),
        refresh_interval: Duration::from_secs(10),
        max_stale: Duration::from_secs(30),
        max_unwrap_age: Duration::from_secs(120),
        negative_ttl: Duration::from_secs(5),
        unknown_kid_refresh: Duration::from_secs(5),
        max_loaded_keysets: 4,
        max_keys_per_keyset: 3,
        max_live_keys: 8,
        max_tracked_keysets: 4,
        unwrap_concurrency: 2,
        fetch_timeout: Duration::from_secs(2),
        maintenance_tick: Duration::from_secs(1),
    }
}

struct Setup {
    source: Arc<MemorySource>,
    wrap: Arc<RevocableWrap>,
}

impl Setup {
    fn new() -> Self {
        Self {
            source: Arc::new(MemorySource::default()),
            wrap: Arc::new(RevocableWrap {
                inner: FileKeyWrap::from_bytes(&[7; 32]).unwrap(),
                revoked: AtomicBool::new(false),
            }),
        }
    }

    fn keyring(&self, config: KeyringConfig) -> Keyring {
        Keyring::new(
            Arc::clone(&self.source) as Arc<dyn KeySource>,
            Arc::clone(&self.wrap) as Arc<dyn KeyWrap>,
            config,
        )
        .unwrap()
    }
}

fn keyset(name: &str) -> KeysetId {
    KeysetId::new(name).unwrap()
}

/// Seals a value to a keyset's current key, and checks the keyring opens it.
async fn opens(keyring: &Keyring, name: &str) -> Result<(), KeyError> {
    let keyset = keyset(name);
    let (kid, public) = keyring.current_public_key(&keyset).await?;
    let (item, field) = (ItemId::new("i").unwrap(), FieldName::new("f").unwrap());
    let binding = Binding {
        keyset: &keyset,
        item: &item,
        field: &field,
    };
    let policy = builder::bearer("https://api.example.com/").unwrap();
    let envelope = seal(&public, &kid, binding, b"secret", &policy).unwrap();
    let key = keyring.private_key(&keyset, &kid).await?;
    assert_eq!(
        seal_format::open(&key, &envelope, binding)
            .unwrap()
            .secret
            .expose(<[u8]>::to_vec),
        b"secret"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_generated_keyset_loads_on_first_use_and_opens_values() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    let created = keyring.generate(&keyset("acme")).await.unwrap();
    assert_eq!(created.wrap_id, setup.wrap.id());
    opens(&keyring, "acme").await.unwrap();
    assert_eq!(keyring.loaded_keysets(), 1);
    assert_eq!(keyring.live_keys(), 1);
}

#[tokio::test(start_paused = true)]
async fn concurrent_first_uses_share_one_fetch() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    let before = setup.source.fetches();
    let acme = keyset("acme");
    let uses = (0..20).map(|_| keyring.current_public_key(&acme));
    for result in futures_util::future::join_all(uses).await {
        result.unwrap();
    }
    assert_eq!(setup.source.fetches() - before, 1);
}

#[tokio::test(start_paused = true)]
async fn an_unknown_keyset_is_remembered_for_a_while() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    let unknown = keyset("nobody");
    assert_eq!(
        keyring.current_public_key(&unknown).await,
        Err(KeyError::UnknownKeyset)
    );
    let after_first = setup.source.fetches();
    for _ in 0..5 {
        assert_eq!(
            keyring.current_public_key(&unknown).await,
            Err(KeyError::UnknownKeyset)
        );
    }
    assert_eq!(
        setup.source.fetches(),
        after_first,
        "a bad caller cannot hammer the source"
    );

    tokio::time::sleep(Duration::from_secs(6)).await;
    keyring.current_public_key(&unknown).await.unwrap_err();
    assert_eq!(setup.source.fetches(), after_first + 1);
}

#[tokio::test(start_paused = true)]
async fn a_new_keyset_appears_once_generated() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring
        .current_public_key(&keyset("acme"))
        .await
        .unwrap_err();
    keyring.generate(&keyset("acme")).await.unwrap();
    opens(&keyring, "acme").await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn acceptance_evicted_keys_are_reloaded_on_next_use() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    opens(&keyring, "acme").await.unwrap();

    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(keyring.loaded_keysets(), 0);
    assert_eq!(keyring.live_keys(), 0, "evicted keys are gone from memory");

    let before = setup.source.fetches();
    opens(&keyring, "acme").await.unwrap();
    assert_eq!(setup.source.fetches(), before + 1);
}

#[tokio::test(start_paused = true)]
async fn acceptance_a_restarted_instance_serves_the_same_values() {
    let setup = Setup::new();
    let first = setup.keyring(config());
    first.generate(&keyset("acme")).await.unwrap();
    let before = first.current_public_key(&keyset("acme")).await.unwrap();
    drop(first);
    let restarted = setup.keyring(config());
    assert_eq!(
        restarted.current_public_key(&keyset("acme")).await.unwrap(),
        before
    );
    opens(&restarted, "acme").await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn acceptance_a_rotation_on_one_instance_reaches_another_in_constant_use() {
    let setup = Setup::new();
    let (one, two) = (setup.keyring(config()), setup.keyring(config()));
    one.generate(&keyset("acme")).await.unwrap();
    let (old_kid, _) = two.current_public_key(&keyset("acme")).await.unwrap();

    let rotated = one.rotate(&keyset("acme")).await.unwrap();
    assert_eq!(
        one.current_public_key(&keyset("acme")).await.unwrap().0,
        rotated.kid,
        "at once on the instance that rotated"
    );

    // The second instance is in use throughout, so idle eviction never reloads it.
    let started = Instant::now();
    loop {
        let (kid, _) = two.current_public_key(&keyset("acme")).await.unwrap();
        if kid == rotated.kid {
            break;
        }
        assert_eq!(kid, old_kid);
        assert!(
            started.elapsed() <= config().max_stale,
            "not seen within max_stale"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(started.elapsed() <= config().refresh_interval + Duration::from_secs(2));
    // Both keys still open, since the old one has not been deleted.
    two.private_key(&keyset("acme"), &old_kid).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_value_sealed_to_a_key_not_yet_seen_opens_at_once() {
    let setup = Setup::new();
    let (one, two) = (setup.keyring(config()), setup.keyring(config()));
    one.generate(&keyset("acme")).await.unwrap();
    two.current_public_key(&keyset("acme")).await.unwrap();
    let rotated = one.rotate(&keyset("acme")).await.unwrap();
    two.private_key(&keyset("acme"), &rotated.kid)
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_unknown_kid_forces_a_refresh_at_most_once_per_interval() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    keyring.current_public_key(&keyset("acme")).await.unwrap();
    let before = setup.source.fetches();
    let bogus = KeyId::new("k-bogus").unwrap();
    for _ in 0..5 {
        assert_eq!(
            keyring
                .private_key(&keyset("acme"), &bogus)
                .await
                .unwrap_err(),
            KeyError::UnknownKey
        );
    }
    assert_eq!(setup.source.fetches(), before + 1);
}

#[tokio::test(start_paused = true)]
async fn acceptance_a_deleted_key_stops_opening_on_every_instance_within_max_stale() {
    let setup = Setup::new();
    let (one, two) = (setup.keyring(config()), setup.keyring(config()));
    one.generate(&keyset("acme")).await.unwrap();
    let rotated = one.rotate(&keyset("acme")).await.unwrap();
    let old = one
        .public_keys(&keyset("acme"))
        .await
        .unwrap()
        .into_iter()
        .find(|key| key.kid != rotated.kid)
        .unwrap()
        .kid;
    two.private_key(&keyset("acme"), &old).await.unwrap();

    setup.source.delete(&keyset("acme"), &old);
    let started = Instant::now();
    while two.private_key(&keyset("acme"), &old).await.is_ok() {
        assert!(started.elapsed() <= config().max_stale);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    two.private_key(&keyset("acme"), &rotated.kid)
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn deleting_every_key_makes_the_keyset_unknown() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    let created = keyring.generate(&keyset("acme")).await.unwrap();
    keyring.current_public_key(&keyset("acme")).await.unwrap();
    setup.source.delete(&keyset("acme"), &created.kid);
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert_eq!(
        keyring.current_public_key(&keyset("acme")).await,
        Err(KeyError::UnknownKeyset)
    );
}

#[tokio::test(start_paused = true)]
async fn an_unreachable_source_stops_a_keyset_after_max_stale_and_it_recovers() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    keyring.current_public_key(&keyset("acme")).await.unwrap();

    setup.source.down.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(20)).await;
    keyring.current_public_key(&keyset("acme")).await.unwrap();

    tokio::time::sleep(Duration::from_secs(15)).await;
    assert_eq!(
        keyring.current_public_key(&keyset("acme")).await,
        Err(KeyError::Unavailable)
    );

    setup.source.down.store(false, Ordering::SeqCst);
    opens(&keyring, "acme").await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_revoked_wrapping_key_takes_effect_within_max_unwrap_age() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    setup.wrap.revoked.store(true, Ordering::SeqCst);
    // Generating unwraps nothing, so revoke afterwards and load fresh.
    setup.wrap.revoked.store(false, Ordering::SeqCst);
    opens(&keyring, "acme").await.unwrap();
    setup.wrap.revoked.store(true, Ordering::SeqCst);

    let started = Instant::now();
    while keyring.current_public_key(&keyset("acme")).await.is_ok() {
        assert!(started.elapsed() <= config().max_unwrap_age + Duration::from_secs(2));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        started.elapsed() > config().max_unwrap_age / 2,
        "kept while the key was fresh"
    );
    assert_eq!(keyring.live_keys(), 0);
}

#[tokio::test(start_paused = true)]
async fn loaded_keysets_are_bounded_and_the_least_recently_used_goes() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    for name in ["a", "b", "c", "d", "e"] {
        keyring.generate(&keyset(name)).await.unwrap();
        keyring.current_public_key(&keyset(name)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(keyring.loaded_keysets(), 4);
    let before = setup.source.fetches();
    keyring.current_public_key(&keyset("e")).await.unwrap();
    assert_eq!(setup.source.fetches(), before, "the newest is still loaded");
    keyring.current_public_key(&keyset("a")).await.unwrap();
    assert_eq!(setup.source.fetches(), before + 1, "the oldest was evicted");
}

#[tokio::test(start_paused = true)]
async fn keys_per_keyset_are_bounded() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    keyring.rotate(&keyset("acme")).await.unwrap();
    keyring.rotate(&keyset("acme")).await.unwrap();
    assert_eq!(
        keyring.rotate(&keyset("acme")).await,
        Err(KeyError::TooManyKeys)
    );

    // A keyset over the limit still loads: rotations on separate instances can leave
    // one there, and it must not become unreadable.
    let other = setup.keyring(KeyringConfig {
        max_keys_per_keyset: 2,
        max_live_keys: 8,
        ..config()
    });
    other.current_public_key(&keyset("acme")).await.unwrap();
    assert_eq!(
        other.rotate(&keyset("acme")).await,
        Err(KeyError::TooManyKeys)
    );

    // A source that holds more than twice the limit is refused, not truncated.
    let other = setup.keyring(KeyringConfig {
        max_keys_per_keyset: 1,
        max_live_keys: 8,
        ..config()
    });
    assert_eq!(
        other.current_public_key(&keyset("acme")).await,
        Err(KeyError::Unavailable)
    );
}

/// A source whose answer is already old when it arrives, as a real one's is: it reads
/// the keys, and only then takes its time.
struct SlowAnswer(Arc<MemorySource>);

#[async_trait]
impl KeySource for SlowAnswer {
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        let keys = self.0.wrapped_keys(keyset).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        keys
    }

    async fn store(&self, key: &WrappedKey) -> Result<(), KeyError> {
        self.0.store(key).await
    }
}

#[tokio::test(start_paused = true)]
async fn rotations_at_once_do_not_pass_the_limit_together() {
    let setup = Setup::new();
    let keyring = Keyring::new(
        Arc::new(SlowAnswer(Arc::clone(&setup.source))) as Arc<dyn KeySource>,
        Arc::clone(&setup.wrap) as Arc<dyn KeyWrap>,
        config(),
    )
    .unwrap();
    keyring.generate(&keyset("acme")).await.unwrap();
    let name = keyset("acme");
    let (a, b, c, d) = tokio::join!(
        keyring.rotate(&name),
        keyring.rotate(&name),
        keyring.rotate(&name),
        keyring.rotate(&name),
    );
    let added = [a, b, c, d].iter().filter(|result| result.is_ok()).count();
    assert_eq!(added, 2, "three keys in all, as the limit says");
}

#[tokio::test(start_paused = true)]
async fn live_keys_are_bounded_including_keys_held_after_eviction() {
    let setup = Setup::new();
    let keyring = setup.keyring(KeyringConfig {
        max_live_keys: 6,
        max_loaded_keysets: 10,
        ..config()
    });
    for name in ["a", "b", "c"] {
        keyring.generate(&keyset(name)).await.unwrap();
        keyring.rotate(&keyset(name)).await.unwrap();
    }
    for name in ["a", "b", "c"] {
        keyring.current_public_key(&keyset(name)).await.unwrap();
    }
    assert_eq!(keyring.live_keys(), 6);

    // Loading a fourth evicts the least recently used to make room.
    keyring.generate(&keyset("d")).await.unwrap();
    keyring.current_public_key(&keyset("d")).await.unwrap();
    assert!(keyring.live_keys() <= 6);
    assert_eq!(keyring.loaded_keysets(), 3);

    // A key a request still holds counts until it is released.
    let (kid, _) = keyring.current_public_key(&keyset("d")).await.unwrap();
    let held = keyring.private_key(&keyset("d"), &kid).await.unwrap();
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(keyring.loaded_keysets(), 0);
    assert_eq!(keyring.live_keys(), 1);
    drop(held);
    assert_eq!(keyring.live_keys(), 0);
}

#[tokio::test(start_paused = true)]
async fn generate_and_rotate_check_what_exists() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    assert_eq!(
        keyring.rotate(&keyset("acme")).await,
        Err(KeyError::UnknownKeyset)
    );
    keyring.generate(&keyset("acme")).await.unwrap();
    assert_eq!(
        keyring.generate(&keyset("acme")).await,
        Err(KeyError::AlreadyExists)
    );
}

#[tokio::test(start_paused = true)]
async fn a_destroyed_keyset_is_unknown_at_once_and_only_it() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    assert_eq!(
        keyring.destroy(&keyset("acme")).await,
        Err(KeyError::UnknownKeyset)
    );
    keyring.generate(&keyset("acme")).await.unwrap();
    keyring.rotate(&keyset("acme")).await.unwrap();
    keyring.generate(&keyset("other")).await.unwrap();
    keyring.current_public_key(&keyset("acme")).await.unwrap();

    keyring.destroy(&keyset("acme")).await.unwrap();
    assert!(
        setup
            .source
            .keys
            .lock()
            .unwrap()
            .get(&keyset("acme"))
            .is_none()
    );
    assert_eq!(
        keyring.current_public_key(&keyset("acme")).await.err(),
        Some(KeyError::UnknownKeyset)
    );
    assert_eq!(
        keyring.destroy(&keyset("acme")).await,
        Err(KeyError::UnknownKeyset)
    );
    keyring.current_public_key(&keyset("other")).await.unwrap();

    // The name can be given to a new keyset, with new keys.
    keyring.generate(&keyset("acme")).await.unwrap();
    keyring.current_public_key(&keyset("acme")).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_source_that_cannot_delete_keeps_the_keyset() {
    let setup = Setup::new();
    setup
        .keyring(config())
        .generate(&keyset("acme"))
        .await
        .unwrap();
    let read_only = Keyring::new(
        Arc::new(ReadOnlySource(Arc::clone(&setup.source))) as Arc<dyn KeySource>,
        Arc::clone(&setup.wrap) as Arc<dyn KeyWrap>,
        config(),
    )
    .unwrap();
    assert_eq!(
        read_only.destroy(&keyset("acme")).await,
        Err(KeyError::Unsupported)
    );
    read_only.current_public_key(&keyset("acme")).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn public_keys_are_listed_oldest_first() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    assert_eq!(
        keyring.public_keys(&keyset("acme")).await,
        Err(KeyError::UnknownKeyset)
    );
    let first = keyring.generate(&keyset("acme")).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = keyring.rotate(&keyset("acme")).await.unwrap();
    let listed = keyring.public_keys(&keyset("acme")).await.unwrap();
    let kids: Vec<&KeyId> = listed.iter().map(|key| &key.kid).collect();
    assert!(kids.contains(&&first.kid) && kids.contains(&&second.kid));
    assert_eq!(listed.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_wrapped_key_that_does_not_match_its_public_key_is_refused() {
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    let mut created = keyring.generate(&keyset("acme")).await.unwrap();
    let (_, other_public) = PrivateKey::generate();
    created.public = other_public.to_base64url();
    setup
        .source
        .keys
        .lock()
        .unwrap()
        .insert(keyset("acme"), vec![created]);
    assert!(matches!(
        keyring.current_public_key(&keyset("acme")).await,
        Err(KeyError::Invalid(_))
    ));
    // Nor is the stored public key published, for someone to seal to.
    assert!(matches!(
        keyring.public_keys(&keyset("acme")).await,
        Err(KeyError::Invalid(_))
    ));
}

#[test]
fn the_configuration_rules_are_checked() {
    config().validate().unwrap();
    KeyringConfig::default().validate().unwrap();
    assert!(
        KeyringConfig {
            max_stale: Duration::from_secs(5),
            ..config()
        }
        .validate()
        .is_err()
    );
    assert!(
        KeyringConfig {
            max_unwrap_age: Duration::from_secs(20),
            ..config()
        }
        .validate()
        .is_err()
    );
    assert!(
        KeyringConfig {
            max_live_keys: 5,
            ..config()
        }
        .validate()
        .is_err()
    );
    assert!(
        KeyringConfig {
            max_loaded_keysets: 0,
            ..config()
        }
        .validate()
        .is_err()
    );
}

/// Two wrapping keys, as while one replaces the other.
fn two_wraps() -> (Arc<dyn KeyWrap>, Arc<dyn KeyWrap>) {
    (
        Arc::new(FileKeyWrap::from_bytes(&[1; 32]).unwrap()),
        Arc::new(FileKeyWrap::from_bytes(&[2; 32]).unwrap()),
    )
}

#[tokio::test(start_paused = true)]
async fn an_older_wrapping_key_still_unwraps_and_new_keys_take_the_current_one() {
    let source = Arc::new(MemorySource::default());
    let (old, new) = two_wraps();
    let before = Keyring::new(
        Arc::clone(&source) as Arc<dyn KeySource>,
        Arc::clone(&old),
        config(),
    )
    .unwrap();
    let first = before.generate(&keyset("acme")).await.unwrap();
    assert_eq!(first.wrap_id, old.id());

    // The new wrapping key is current, and the old one only unwraps.
    let wraps = KeyWraps::new(Arc::clone(&new), vec![Arc::clone(&old)]).unwrap();
    let during = Keyring::new(Arc::clone(&source) as Arc<dyn KeySource>, wraps, config()).unwrap();
    opens(&during, "acme").await.unwrap();
    let second = during.rotate(&keyset("acme")).await.unwrap();
    assert_eq!(second.wrap_id, new.id());
    // A keyset with keys under both opens, to either key.
    opens(&during, "acme").await.unwrap();
    assert_eq!(during.public_keys(&keyset("acme")).await.unwrap().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_key_under_a_wrapping_key_that_is_not_configured_fails_its_keyset() {
    let source = Arc::new(MemorySource::default());
    let (old, new) = two_wraps();
    Keyring::new(
        Arc::clone(&source) as Arc<dyn KeySource>,
        Arc::clone(&old),
        config(),
    )
    .unwrap()
    .generate(&keyset("acme"))
    .await
    .unwrap();
    let after = Keyring::new(Arc::clone(&source) as Arc<dyn KeySource>, new, config()).unwrap();
    assert_eq!(
        after.current_public_key(&keyset("acme")).await.map(|_| ()),
        Err(KeyError::Unavailable)
    );
}

#[test]
fn a_wrapping_key_cannot_be_named_twice() {
    let (old, new) = two_wraps();
    assert!(KeyWraps::new(Arc::clone(&new), vec![Arc::clone(&new)]).is_err());
    assert!(KeyWraps::new(Arc::clone(&new), vec![Arc::clone(&old), Arc::clone(&old)]).is_err());
    assert!(KeyWraps::new(new, vec![old]).is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_running_keyring_reads_keys_wrapped_again_without_being_restarted() {
    let source = Arc::new(MemorySource::default());
    let (old, new) = two_wraps();
    let wraps = KeyWraps::new(Arc::clone(&new), vec![Arc::clone(&old)]).unwrap();
    Keyring::new(
        Arc::clone(&source) as Arc<dyn KeySource>,
        Arc::clone(&old),
        config(),
    )
    .unwrap()
    .generate(&keyset("acme"))
    .await
    .unwrap();

    let running = Keyring::new(
        Arc::clone(&source) as Arc<dyn KeySource>,
        wraps.clone(),
        config(),
    )
    .unwrap();
    opens(&running, "acme").await.unwrap();

    let done = crate::rewrap(source.as_ref(), &wraps, crate::RewrapOptions::default())
        .await
        .unwrap();
    assert_eq!((done.rewrapped, done.left), (1, 0));
    // Before and after it next reads the source, the keyring opens the same values.
    opens(&running, "acme").await.unwrap();
    tokio::time::sleep(config().refresh_interval * 2).await;
    opens(&running, "acme").await.unwrap();
    // And what it now holds came from the new wrapping key: the old one is not needed.
    let after = Keyring::new(Arc::clone(&source) as Arc<dyn KeySource>, new, config()).unwrap();
    opens(&after, "acme").await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_key_whose_time_was_changed_in_the_source_is_refused() {
    // Whoever holds the source could otherwise say which key is the newest, and so
    // which one new values are sealed to.
    let setup = Setup::new();
    let keyring = setup.keyring(config());
    keyring.generate(&keyset("acme")).await.unwrap();
    keyring.rotate(&keyset("acme")).await.unwrap();
    {
        let mut keys = setup.source.keys.lock().unwrap();
        let stored = keys.get_mut(&keyset("acme")).unwrap();
        stored[0].created = u64::MAX;
    }
    let other = setup.keyring(config());
    assert!(matches!(
        other.current_public_key(&keyset("acme")).await,
        Err(KeyError::Invalid(_))
    ));
}

#[test]
fn only_a_name_seal_made_has_a_time_in_it() {
    let kid = |name: &str| KeyId::new(name.to_owned()).unwrap();
    assert_eq!(
        created_in(&kid("k-1700000000-0a1b2c3d")),
        Some(1_700_000_000)
    );
    for name in [
        "k3",
        "k-1",
        "k-1700000000-xyz",
        "k-17x-0a1b2c3d",
        "k--0a1b2c3d",
    ] {
        assert_eq!(created_in(&kid(name)), None, "{name}");
    }
}
