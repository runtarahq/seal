//! The keyring: loads keysets on demand, refreshes them from the key source, and
//! evicts them, within fixed bounds.
//!
//! Instances do not coordinate. Each polls the key source for its loaded keysets, so
//! a key added to or deleted from the source takes effect on every instance within
//! `max_stale`, and revoking the wrapping key within `max_unwrap_age`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey, PublicKey};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::source::{KeySource, WrappedKey};
use crate::wrap::KeyWrap;
use crate::{KeyError, Keys, LiveKey};

/// The keyring's bounds and timings.
#[derive(Clone, Copy, Debug)]
pub struct KeyringConfig {
    /// A keyset unused for this long is dropped.
    pub idle_evict: Duration,
    /// How often a loaded keyset is fetched again.
    pub refresh_interval: Duration,
    /// A keyset not fetched successfully for this long is dropped.
    pub max_stale: Duration,
    /// A key not unwrapped for this long is dropped. It is unwrapped again at half this.
    pub max_unwrap_age: Duration,
    /// How long an unknown keyset is remembered as unknown.
    pub negative_ttl: Duration,
    /// How often an unknown kid may force a refresh of its keyset.
    pub unknown_kid_refresh: Duration,
    /// The most keysets loaded at once.
    pub max_loaded_keysets: usize,
    /// The most keys in one keyset.
    pub max_keys_per_keyset: usize,
    /// The most private keys in memory, including ones still in use after eviction.
    pub max_live_keys: usize,
    /// The most unknown keysets remembered.
    pub max_tracked_keysets: usize,
    /// The most unwraps at once.
    pub unwrap_concurrency: usize,
    /// How long a fetch, or waiting for room for keys, may take.
    pub fetch_timeout: Duration,
    /// How often maintenance runs.
    pub maintenance_tick: Duration,
}

impl Default for KeyringConfig {
    fn default() -> Self {
        Self {
            idle_evict: Duration::from_secs(15 * 60),
            refresh_interval: Duration::from_secs(60),
            max_stale: Duration::from_secs(5 * 60),
            max_unwrap_age: Duration::from_secs(60 * 60),
            negative_ttl: Duration::from_secs(30),
            unknown_kid_refresh: Duration::from_secs(30),
            max_loaded_keysets: 1024,
            max_keys_per_keyset: 16,
            max_live_keys: 4096,
            max_tracked_keysets: 4096,
            unwrap_concurrency: 8,
            fetch_timeout: Duration::from_secs(10),
            maintenance_tick: Duration::from_secs(1),
        }
    }
}

impl KeyringConfig {
    /// Checks the relations between settings that the guarantees depend on.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] naming the rule that is broken.
    pub fn validate(&self) -> Result<(), KeyError> {
        if !(self.refresh_interval < self.max_stale && self.max_stale < self.max_unwrap_age) {
            return Err(KeyError::Invalid(
                "keys need refresh_interval < max_stale < max_unwrap_age",
            ));
        }
        if self.max_live_keys < 2 * self.max_keys_per_keyset {
            return Err(KeyError::Invalid(
                "keys need max_live_keys of at least twice max_keys_per_keyset",
            ));
        }
        let positive = [
            self.max_loaded_keysets,
            self.max_keys_per_keyset,
            self.max_tracked_keysets,
            self.unwrap_concurrency,
        ];
        if positive.contains(&0) || self.maintenance_tick.is_zero() {
            return Err(KeyError::Invalid("a key limit is zero"));
        }
        Ok(())
    }
}

/// A keyset's public key, checked against its private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// The key's id.
    pub kid: KeyId,
    /// The public key.
    pub public: PublicKey,
    /// When it was made, in seconds since the Unix epoch.
    pub created: u64,
}

struct Unwrapped {
    key: Arc<LiveKey>,
    public: PublicKey,
    created: u64,
    /// Identifies the wrapped form, to tell when a key was replaced in the source.
    fingerprint: (String, String),
    unwrapped_at: Instant,
}

/// One keyset's keys, as last loaded.
struct Generation {
    keys: BTreeMap<KeyId, Unwrapped>,
}

impl Generation {
    fn current(&self) -> Option<(KeyId, PublicKey)> {
        self.keys
            .iter()
            .max_by(|(a_kid, a), (b_kid, b)| a.created.cmp(&b.created).then(a_kid.cmp(b_kid)))
            .map(|(kid, key)| (kid.clone(), key.public))
    }
}

struct Loaded {
    generation: Arc<Generation>,
    last_used: Instant,
    last_fetch_ok: Instant,
    last_refresh_attempt: Instant,
    last_forced: Option<Instant>,
}

#[derive(Default)]
struct State {
    loaded: HashMap<KeysetId, Loaded>,
    /// Unknown keysets, until when.
    negative: HashMap<KeysetId, Instant>,
    /// One lock per keyset being loaded, so that concurrent first uses share a fetch.
    loading: HashMap<KeysetId, Arc<tokio::sync::Mutex<()>>>,
}

struct Inner {
    source: Arc<dyn KeySource>,
    wrap: Arc<dyn KeyWrap>,
    config: KeyringConfig,
    state: Mutex<State>,
    live: Arc<Semaphore>,
    unwraps: Semaphore,
}

/// Loads, refreshes and evicts keysets.
#[derive(Clone)]
pub struct Keyring {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("loaded", &self.loaded_keysets())
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// Creates a keyring, and starts its maintenance. Needs a Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the configuration is not valid.
    pub fn new(
        source: Arc<dyn KeySource>,
        wrap: Arc<dyn KeyWrap>,
        config: KeyringConfig,
    ) -> Result<Self, KeyError> {
        config.validate()?;
        let inner = Arc::new(Inner {
            source,
            wrap,
            config,
            state: Mutex::new(State::default()),
            live: Arc::new(Semaphore::new(config.max_live_keys)),
            unwraps: Semaphore::new(config.unwrap_concurrency),
        });
        spawn_maintenance(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    /// How many keysets are loaded.
    #[must_use]
    pub fn loaded_keysets(&self) -> usize {
        self.inner.lock().loaded.len()
    }

    /// How many private keys are in memory, including ones evicted but still in use.
    #[must_use]
    pub fn live_keys(&self) -> usize {
        self.inner.config.max_live_keys - self.inner.live.available_permits()
    }

    /// Makes a keyset's first key pair, wraps the private key and stores it if the
    /// source can. Returns the wrapped key, for the application to store otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::AlreadyExists`] if the keyset has keys.
    pub async fn generate(&self, keyset: &KeysetId) -> Result<WrappedKey, KeyError> {
        let existing = self.inner.fetch(keyset).await?;
        if !existing.is_empty() {
            return Err(KeyError::AlreadyExists);
        }
        self.add_key(keyset, 0).await
    }

    /// Adds a key to an existing keyset, which becomes its current key.
    ///
    /// Wait `max_stale` before resealing, since until then another instance may still
    /// seal responses to the old key, and reseal before deleting the old key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnknownKeyset`] if the keyset has no keys, and
    /// [`KeyError::TooManyKeys`] if it has as many as it may.
    pub async fn rotate(&self, keyset: &KeysetId) -> Result<WrappedKey, KeyError> {
        let existing = self.inner.fetch(keyset).await?;
        if existing.is_empty() {
            return Err(KeyError::UnknownKeyset);
        }
        if existing.len() >= self.inner.config.max_keys_per_keyset {
            return Err(KeyError::TooManyKeys);
        }
        let newest = existing.iter().map(|key| key.created).max().unwrap_or(0);
        let created = self.add_key(keyset, newest + 1).await?;
        // This instance uses the new key at once; others within `max_stale`.
        let _ = self.inner.load(keyset, true).await;
        Ok(created)
    }

    /// Deletes every key of a keyset from the source, so that nothing sealed to it can be
    /// opened again. This cannot be undone.
    ///
    /// This instance stops using the keyset at once; others within `max_stale`.
    /// Copies of the wrapped keys elsewhere, such as backups of the source, still open
    /// its values for as long as the wrapping key exists.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnknownKeyset`] if the keyset has no keys, and
    /// [`KeyError::Unsupported`] if the source cannot delete.
    pub async fn destroy(&self, keyset: &KeysetId) -> Result<(), KeyError> {
        let existing = self.inner.fetch(keyset).await?;
        if existing.is_empty() {
            return Err(KeyError::UnknownKeyset);
        }
        self.inner.source.delete_keyset(keyset).await?;
        let mut state = self.inner.lock();
        state.loaded.remove(keyset);
        self.inner
            .remember_unknown(&mut state, keyset, Instant::now());
        Ok(())
    }

    /// A keyset's public keys, newest last, freshly read from the source.
    ///
    /// Each one has been checked against its private key, which means unwrapping it:
    /// a key source that stored another public key beside a wrapped key would
    /// otherwise have secrets sealed to a key of its own choosing.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnknownKeyset`] if the keyset has no keys, and what loading
    /// the keyset returns if a key cannot be unwrapped or does not match.
    pub async fn public_keys(&self, keyset: &KeysetId) -> Result<Vec<PublicKeyInfo>, KeyError> {
        let generation = self.inner.load(keyset, true).await?;
        let mut keys: Vec<PublicKeyInfo> = generation
            .keys
            .iter()
            .map(|(kid, key)| PublicKeyInfo {
                kid: kid.clone(),
                public: key.public,
                created: key.created,
            })
            .collect();
        if keys.is_empty() {
            return Err(KeyError::UnknownKeyset);
        }
        keys.sort_by(|a, b| a.created.cmp(&b.created).then(a.kid.cmp(&b.kid)));
        Ok(keys)
    }

    /// Adds a key created no earlier than `not_before`, so that a new key is always
    /// the newest, and so current, even within the same second.
    async fn add_key(&self, keyset: &KeysetId, not_before: u64) -> Result<WrappedKey, KeyError> {
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
            .max(not_before);
        let mut random = [0_u8; 4];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| KeyError::Unavailable)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let kid = KeyId::new(format!("k-{created}-{suffix}"))
            .map_err(|_| KeyError::Invalid("generated kid"))?;
        let (private, public) = PrivateKey::generate();
        let wrapped = self.inner.wrap.wrap(keyset, &kid, &private).await?;
        drop(private);
        let key = WrappedKey {
            keyset: keyset.clone(),
            kid,
            public: public.to_base64url(),
            created,
            wrap_id: self.inner.wrap.id().to_owned(),
            wrapped: URL_SAFE_NO_PAD.encode(wrapped),
        };
        match self.inner.source.store(&key).await {
            Ok(()) | Err(KeyError::Unsupported) => {
                self.inner.lock().negative.remove(keyset);
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn fetch(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        tokio::time::timeout(self.config.fetch_timeout, self.source.wrapped_keys(keyset))
            .await
            .map_err(|_| KeyError::Unavailable)?
    }

    /// A loaded keyset that is not stale. Only a caller's use marks it used, never a
    /// refresh, or a keyset in the background would never go idle.
    fn loaded(&self, keyset: &KeysetId, used: bool) -> Result<Option<Arc<Generation>>, KeyError> {
        let now = Instant::now();
        let mut state = self.lock();
        if let Some(until) = state.negative.get(keyset) {
            if *until > now {
                return Err(KeyError::UnknownKeyset);
            }
            state.negative.remove(keyset);
        }
        let max_stale = self.config.max_stale;
        Ok(state.loaded.get_mut(keyset).and_then(|loaded| {
            (now.duration_since(loaded.last_fetch_ok) <= max_stale).then(|| {
                if used {
                    loaded.last_used = now;
                }
                Arc::clone(&loaded.generation)
            })
        }))
    }

    async fn generation(&self, keyset: &KeysetId) -> Result<Arc<Generation>, KeyError> {
        match self.loaded(keyset, true)? {
            Some(generation) => Ok(generation),
            None => self.load(keyset, false).await,
        }
    }

    /// Loads or refreshes a keyset. Concurrent callers share one fetch. Without
    /// `force`, a keyset someone else loaded meanwhile is used as it is.
    async fn load(&self, keyset: &KeysetId, force: bool) -> Result<Arc<Generation>, KeyError> {
        let lock = Arc::clone(self.lock().loading.entry(keyset.clone()).or_default());
        let result = {
            let _guard = lock.lock().await;
            match (force, self.loaded(keyset, false)?) {
                (false, Some(generation)) => Ok(generation),
                _ => self.load_locked(keyset).await,
            }
        };
        let mut state = self.lock();
        if Arc::strong_count(&lock) <= 2 {
            state.loading.remove(keyset);
        }
        result
    }

    async fn load_locked(&self, keyset: &KeysetId) -> Result<Arc<Generation>, KeyError> {
        let now = Instant::now();
        let previous = {
            let mut state = self.lock();
            state.loaded.get_mut(keyset).map(|loaded| {
                loaded.last_refresh_attempt = now;
                Arc::clone(&loaded.generation)
            })
        };
        let built = self.build(keyset, previous.as_deref()).await;
        let mut state = self.lock();
        match built {
            Ok(Some(generation)) => {
                let generation = Arc::new(generation);
                let entry = state
                    .loaded
                    .entry(keyset.clone())
                    .or_insert_with(|| Loaded {
                        generation: Arc::clone(&generation),
                        last_used: now,
                        last_fetch_ok: now,
                        last_refresh_attempt: now,
                        last_forced: None,
                    });
                entry.generation = Arc::clone(&generation);
                // A refresh is not a use: only callers keep a keyset from going idle.
                entry.last_fetch_ok = now;
                metrics::counter!("seal_keyring_loads_total").increment(1);
                self.enforce_loaded_limit(&mut state, keyset);
                Ok(generation)
            }
            Ok(None) => {
                state.loaded.remove(keyset);
                self.remember_unknown(&mut state, keyset, now);
                Err(KeyError::UnknownKeyset)
            }
            Err(error) => {
                metrics::counter!("seal_keyring_failures_total").increment(1);
                let max_stale = self.config.max_stale;
                if state
                    .loaded
                    .get(keyset)
                    .is_some_and(|loaded| now.duration_since(loaded.last_fetch_ok) > max_stale)
                {
                    state.loaded.remove(keyset);
                }
                Err(error)
            }
        }
    }

    /// Fetches and unwraps, reusing keys from `previous` that are unchanged and recent.
    async fn build(
        &self,
        keyset: &KeysetId,
        previous: Option<&Generation>,
    ) -> Result<Option<Generation>, KeyError> {
        let wrapped = self.fetch(keyset).await?;
        if wrapped.is_empty() {
            return Ok(None);
        }
        if wrapped.len() > self.config.max_keys_per_keyset {
            return Err(KeyError::Unavailable);
        }
        let now = Instant::now();
        let fresh_for = self.config.max_unwrap_age / 2;
        let mut keys = BTreeMap::new();
        let mut needed = Vec::new();
        for key in wrapped {
            if key.keyset != *keyset {
                return Err(KeyError::Invalid(
                    "the source returned another keyset's key",
                ));
            }
            let fingerprint = (key.wrap_id.clone(), key.wrapped.clone());
            let reusable = previous
                .and_then(|previous| previous.keys.get(&key.kid))
                .filter(|old| {
                    old.fingerprint == fingerprint
                        && now.duration_since(old.unwrapped_at) < fresh_for
                });
            match reusable {
                Some(old) => {
                    keys.insert(
                        key.kid.clone(),
                        Unwrapped {
                            key: Arc::clone(&old.key),
                            public: old.public,
                            created: old.created,
                            fingerprint,
                            unwrapped_at: old.unwrapped_at,
                        },
                    );
                }
                None => needed.push(key),
            }
        }

        let mut permits = self.room_for(needed.len(), keyset).await?;
        for key in needed {
            let permit = permits
                .as_mut()
                .and_then(|permits| {
                    if permits.num_permits() == 1 {
                        None
                    } else {
                        permits.split(1)
                    }
                })
                .or_else(|| permits.take())
                .ok_or(KeyError::Unavailable)?;
            let unwrapped = self.unwrap(&key, permit).await?;
            keys.insert(key.kid.clone(), unwrapped);
        }
        Ok(Some(Generation { keys }))
    }

    async fn unwrap(
        &self,
        key: &WrappedKey,
        permit: OwnedSemaphorePermit,
    ) -> Result<Unwrapped, KeyError> {
        if key.wrap_id != self.wrap.id() {
            return Err(KeyError::Unavailable);
        }
        let public = key.public_key()?;
        let wrapped = key.wrapped_bytes()?;
        let _slot = self
            .unwraps
            .acquire()
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let started = Instant::now();
        let private = tokio::time::timeout(
            self.config.fetch_timeout,
            self.wrap.unwrap(&key.keyset, &key.kid, &wrapped),
        )
        .await
        .map_err(|_| KeyError::Unavailable)??;
        metrics::histogram!("seal_keyring_unwrap_seconds").record(started.elapsed().as_secs_f64());
        // A wrapped key that does not match its public key is refused.
        if private.public_key().map_err(|_| KeyError::Unavailable)? != public {
            return Err(KeyError::Invalid(
                "a wrapped key does not match its public key",
            ));
        }
        Ok(Unwrapped {
            key: Arc::new(LiveKey::counted(private, permit)),
            public,
            created: key.created,
            fingerprint: (key.wrap_id.clone(), key.wrapped.clone()),
            unwrapped_at: Instant::now(),
        })
    }

    /// Permits for `count` new keys: evicts least recently used keysets if it must,
    /// then waits, then gives up.
    async fn room_for(
        &self,
        count: usize,
        keyset: &KeysetId,
    ) -> Result<Option<OwnedSemaphorePermit>, KeyError> {
        if count == 0 {
            return Ok(None);
        }
        let count = u32::try_from(count).map_err(|_| KeyError::Unavailable)?;
        loop {
            if let Ok(permits) = Arc::clone(&self.live).try_acquire_many_owned(count) {
                return Ok(Some(permits));
            }
            let mut state = self.lock();
            let oldest = state
                .loaded
                .iter()
                .filter(|(name, _)| *name != keyset)
                .min_by_key(|(_, loaded)| loaded.last_used)
                .map(|(name, _)| name.clone());
            match oldest {
                Some(name) => {
                    state.loaded.remove(&name);
                    metrics::counter!("seal_keyring_evictions_total").increment(1);
                }
                None => break,
            }
        }
        // What is left is held by requests, which hold keys only briefly.
        tokio::time::timeout(
            self.config.fetch_timeout,
            Arc::clone(&self.live).acquire_many_owned(count),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(Some)
        .ok_or(KeyError::Unavailable)
    }

    fn enforce_loaded_limit(&self, state: &mut State, keep: &KeysetId) {
        while state.loaded.len() > self.config.max_loaded_keysets {
            let oldest = state
                .loaded
                .iter()
                .filter(|(name, _)| *name != keep)
                .min_by_key(|(_, loaded)| loaded.last_used)
                .map(|(name, _)| name.clone());
            let Some(name) = oldest else { break };
            state.loaded.remove(&name);
            metrics::counter!("seal_keyring_evictions_total").increment(1);
        }
    }

    fn remember_unknown(&self, state: &mut State, keyset: &KeysetId, now: Instant) {
        while state.negative.len() >= self.config.max_tracked_keysets {
            let oldest = state
                .negative
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(name, _)| name.clone());
            let Some(name) = oldest else { break };
            state.negative.remove(&name);
        }
        state
            .negative
            .insert(keyset.clone(), now + self.config.negative_ttl);
    }

    /// Evicts idle keysets, drops keys too long unwrapped, and refreshes what is due.
    async fn maintain(&self) {
        let now = Instant::now();
        let due: Vec<KeysetId> = {
            let mut state = self.lock();
            let config = self.config;
            state
                .loaded
                .retain(|_, loaded| now.duration_since(loaded.last_used) < config.idle_evict);
            state.negative.retain(|_, until| *until > now);
            for loaded in state.loaded.values_mut() {
                let too_old =
                    |key: &Unwrapped| now.duration_since(key.unwrapped_at) >= config.max_unwrap_age;
                if loaded.generation.keys.values().any(too_old) {
                    let keys = loaded
                        .generation
                        .keys
                        .iter()
                        .filter(|(_, key)| !too_old(key))
                        .map(|(kid, key)| {
                            (
                                kid.clone(),
                                Unwrapped {
                                    key: Arc::clone(&key.key),
                                    public: key.public,
                                    created: key.created,
                                    fingerprint: key.fingerprint.clone(),
                                    unwrapped_at: key.unwrapped_at,
                                },
                            )
                        })
                        .collect();
                    loaded.generation = Arc::new(Generation { keys });
                }
            }
            state.loaded.retain(|_, loaded| {
                !loaded.generation.keys.is_empty()
                    && now.duration_since(loaded.last_fetch_ok) <= config.max_stale
            });
            metrics::gauge!("seal_keyring_keysets_loaded").set(state.loaded.len() as f64);
            state
                .loaded
                .iter()
                .filter(|(_, loaded)| {
                    now.duration_since(loaded.last_refresh_attempt) >= config.refresh_interval
                })
                .map(|(name, _)| name.clone())
                .collect()
        };
        for keyset in due {
            let _ = self.load(&keyset, true).await;
        }
    }
}

fn spawn_maintenance(inner: Weak<Inner>) {
    tokio::spawn(async move {
        loop {
            let Some(tick) = inner.upgrade().map(|inner| inner.config.maintenance_tick) else {
                return;
            };
            tokio::time::sleep(tick).await;
            let Some(inner) = inner.upgrade() else {
                return;
            };
            inner.maintain().await;
        }
    });
}

#[async_trait]
impl Keys for Keyring {
    async fn private_key(&self, keyset: &KeysetId, kid: &KeyId) -> Result<Arc<LiveKey>, KeyError> {
        let generation = self.inner.generation(keyset).await?;
        if let Some(key) = generation.keys.get(kid) {
            return Ok(Arc::clone(&key.key));
        }
        // A value sealed to a key this instance has not seen yet forces a refresh, at
        // most once per keyset per interval.
        let may_force = {
            let now = Instant::now();
            let mut state = self.inner.lock();
            let interval = self.inner.config.unknown_kid_refresh;
            state.loaded.get_mut(keyset).is_some_and(|loaded| {
                let due = loaded
                    .last_forced
                    .is_none_or(|last| now.duration_since(last) >= interval);
                if due {
                    loaded.last_forced = Some(now);
                }
                due
            })
        };
        if !may_force {
            return Err(KeyError::UnknownKey);
        }
        let generation = self.inner.load(keyset, true).await?;
        generation
            .keys
            .get(kid)
            .map(|key| Arc::clone(&key.key))
            .ok_or(KeyError::UnknownKey)
    }

    async fn current_public_key(&self, keyset: &KeysetId) -> Result<(KeyId, PublicKey), KeyError> {
        self.inner
            .generation(keyset)
            .await?
            .current()
            .ok_or(KeyError::UnknownKeyset)
    }
}

#[cfg(test)]
mod tests;
