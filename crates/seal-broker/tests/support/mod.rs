//! A broker wired to recording fakes, and a mock provider to send to.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method};
use http_body_util::BodyExt;
use seal_broker::address::NetworkPolicy;
use seal_broker::audit::{AuditFailed, AuditRecord, AuditSink, SystemClock};
use seal_broker::body::empty_body;
use seal_broker::client::{ClientConfig, RequestBody};
use seal_broker::net::{Connect, Resolve, ResolveFailed};
use seal_broker::{
    Broker, BrokerConfig, BrokerError, Environment, Limits, SendRequest, SendResponse,
};
use seal_format::id::KeyId;
use seal_format::{
    Binding, Envelope, FieldName, ItemId, KeysetId, Policy, PrivateKey, PublicKey, seal,
};
use seal_keys::{KeyError, Keys, LiveKey};
use tokio::net::TcpStream;

// Each test file uses a different part of this.
#[allow(unused_imports)]
pub use seal_testkit::mock_provider::{Alpn, CannedResponse, MockProvider, TLS_HOST};

/// The host that resolves to the mock provider.
pub const HOST: &str = "provider.test";

pub fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

pub fn keyset() -> KeysetId {
    KeysetId::new("acme").unwrap()
}

pub fn item() -> ItemId {
    ItemId::new("connection-1").unwrap()
}

pub fn kid() -> KeyId {
    KeyId::new("k1").unwrap()
}

/// Resolves everything to fixed addresses, and counts lookups.
#[derive(Default)]
pub struct RecordingResolve {
    pub lookups: AtomicUsize,
    pub addresses: Mutex<Vec<IpAddr>>,
    pub hang: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl Resolve for RecordingResolve {
    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ResolveFailed> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let addresses = self.addresses.lock().unwrap().clone();
        if addresses.is_empty() {
            Err(ResolveFailed)
        } else {
            Ok(addresses)
        }
    }
}

/// Really connects, and counts and records where.
#[derive(Default)]
pub struct RecordingConnect {
    pub connects: AtomicUsize,
    pub targets: Mutex<Vec<SocketAddr>>,
}

#[async_trait]
impl Connect for RecordingConnect {
    async fn connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        self.targets.lock().unwrap().push(address);
        TcpStream::connect(address).await
    }
}

/// Keeps audit records, and can be told to fail.
#[derive(Default)]
pub struct MemoryAudit {
    pub records: Mutex<Vec<AuditRecord>>,
    pub fail: Mutex<bool>,
}

impl MemoryAudit {
    pub fn all(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }

    pub fn last(&self) -> AuditRecord {
        self.all().pop().expect("an audit record")
    }
}

impl AuditSink for MemoryAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed> {
        self.records.lock().unwrap().push(record.clone());
        if *self.fail.lock().unwrap() {
            Err(AuditFailed)
        } else {
            Ok(())
        }
    }
}

/// One key, counting how often it is fetched.
pub struct RecordingKeys {
    private: Mutex<Arc<LiveKey>>,
    bytes: [u8; 32],
    pub public: PublicKey,
    pub fetches: AtomicUsize,
}

impl RecordingKeys {
    /// The key as loaded now.
    pub fn current(&self) -> Arc<LiveKey> {
        Arc::clone(&self.private.lock().unwrap())
    }

    /// Evicts the key and loads it again, as the keyring does: the same key, held
    /// anew.
    pub fn evict(&self) {
        let key = seal_format::PrivateKey::from_bytes(&self.bytes).unwrap();
        *self.private.lock().unwrap() = Arc::new(LiveKey::unlimited(key));
    }
}

#[async_trait]
impl Keys for RecordingKeys {
    async fn private_key(&self, keyset: &KeysetId, id: &KeyId) -> Result<Arc<LiveKey>, KeyError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        // A platform keyset shares the tenant's key here; only the bindings differ.
        if !matches!(keyset.as_str(), "acme" | "platform") {
            return Err(KeyError::UnknownKeyset);
        }
        if *id != kid() {
            return Err(KeyError::UnknownKey);
        }
        Ok(self.current())
    }

    async fn current_public_key(&self, keyset: &KeysetId) -> Result<(KeyId, PublicKey), KeyError> {
        if keyset.as_str() != "acme" {
            return Err(KeyError::UnknownKeyset);
        }
        Ok((kid(), self.public))
    }
}

/// A broker with recording fakes.
pub struct Harness {
    pub broker: Broker,
    pub resolve: Arc<RecordingResolve>,
    pub connect: Arc<RecordingConnect>,
    pub audit: Arc<MemoryAudit>,
    pub keys: Arc<RecordingKeys>,
    /// Every secret sealed here, which no audit record may hold.
    pub canaries: Mutex<seal_testkit::canary::CanaryRegistry>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let records = serde_json::to_string(&self.audit.all()).unwrap();
        let hits = self.canaries.lock().unwrap().scan("audit", &records);
        assert!(hits.is_empty(), "a sealed secret appeared: {hits:?}");
    }
}

pub struct Options {
    pub network: NetworkPolicy,
    pub limits: Limits,
    pub client: ClientConfig,
    pub addresses: Vec<IpAddr>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // The mock provider is on loopback, which configuration has to allow.
            network: NetworkPolicy {
                allow_private_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
                ..NetworkPolicy::default()
            },
            limits: Limits {
                idle_timeout: Duration::from_secs(10),
                first_byte_timeout: Duration::from_secs(10),
                buffered_total_timeout: Duration::from_secs(10),
                ..Limits::default()
            },
            client: BrokerConfig::default().client,
            addresses: vec!["127.0.0.1".parse().unwrap()],
        }
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with(Options::default())
    }

    pub fn with(options: Options) -> Self {
        let bytes: [u8; 32] =
            std::array::from_fn(|index| u8::try_from(index).unwrap() ^ rand_byte());
        let private = PrivateKey::from_bytes(&bytes).unwrap();
        let public = private.public_key().unwrap();
        let keys = Arc::new(RecordingKeys {
            private: Mutex::new(Arc::new(LiveKey::unlimited(private))),
            bytes,
            public,
            fetches: AtomicUsize::new(0),
        });
        let resolve = Arc::new(RecordingResolve {
            lookups: AtomicUsize::new(0),
            addresses: Mutex::new(options.addresses),
            hang: std::sync::atomic::AtomicBool::new(false),
        });
        let connect = Arc::new(RecordingConnect::default());
        let audit = Arc::new(MemoryAudit::default());
        let broker = Broker::new(
            BrokerConfig {
                network: options.network,
                client: options.client,
                limits: options.limits,
            },
            Arc::clone(&keys) as Arc<dyn Keys>,
            Environment {
                resolve: Arc::clone(&resolve) as Arc<dyn Resolve>,
                connect: Arc::clone(&connect) as Arc<dyn Connect>,
                audit: Arc::clone(&audit) as Arc<dyn AuditSink>,
                clock: Arc::new(SystemClock),
            },
        )
        .unwrap();
        Self {
            broker,
            resolve,
            connect,
            audit,
            keys,
            canaries: Mutex::new(seal_testkit::canary::CanaryRegistry::new()),
        }
    }

    fn register(&self, secret: &[u8]) {
        if let Ok(text) = std::str::from_utf8(secret)
            && text.len() >= 8
        {
            self.canaries
                .lock()
                .unwrap()
                .register(&seal_testkit::canary::Canary::from_value(text));
        }
    }

    pub fn seal(&self, name: &str, secret: &[u8], policy: &Policy) -> Envelope {
        self.register(secret);
        let (keyset, item, field) = (keyset(), item(), field(name));
        seal(
            &self.keys.public,
            &kid(),
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
            secret,
            policy,
        )
        .unwrap()
    }

    /// Seals a value bound to another record.
    pub fn seal_at(
        &self,
        keyset: &str,
        item: &str,
        name: &str,
        secret: &[u8],
        policy: &Policy,
    ) -> Envelope {
        self.register(secret);
        let (keyset, item, field) = (
            KeysetId::new(keyset).unwrap(),
            ItemId::new(item).unwrap(),
            field(name),
        );
        seal(
            &self.keys.public,
            &kid(),
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
            secret,
            policy,
        )
        .unwrap()
    }

    pub fn open(&self, name: &str, envelope: &Envelope) -> Vec<u8> {
        let (keyset, item, field) = (keyset(), item(), field(name));
        seal_format::open(
            &self.keys.current(),
            envelope,
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
        )
        .unwrap()
        .secret
        .expose(<[u8]>::to_vec)
    }

    pub fn open_policy(&self, name: &str, envelope: &Envelope) -> Policy {
        let (keyset, item, field) = (keyset(), item(), field(name));
        seal_format::open(
            &self.keys.current(),
            envelope,
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
        )
        .unwrap()
        .policy
    }

    pub fn lookups(&self) -> usize {
        self.resolve.lookups.load(Ordering::SeqCst)
    }

    pub fn connects(&self) -> usize {
        self.connect.connects.load(Ordering::SeqCst)
    }

    pub fn key_fetches(&self) -> usize {
        self.keys.fetches.load(Ordering::SeqCst)
    }

    /// Sends with these values, and nothing else set.
    pub async fn get(
        &self,
        url: &str,
        sealed: &[(&str, &Envelope)],
    ) -> Result<SendResponse, BrokerError> {
        self.broker.send(request(url, sealed)).await
    }
}

/// A request with these values, and nothing else set.
pub fn request(url: &str, sealed: &[(&str, &Envelope)]) -> SendRequest {
    SendRequest {
        caller: "test-app".to_owned(),
        keyset: keyset(),
        item: item(),
        sealed: sealed
            .iter()
            .map(|(name, envelope)| (field(name), (*envelope).clone().into()))
            .collect::<BTreeMap<_, _>>(),
        plain: BTreeMap::new(),
        method: Method::GET,
        url: url.to_owned(),
        headers: HeaderMap::new(),
        body: empty_body(),
    }
}

/// A policy for one rule, written out.
pub fn rule_policy(rule: &serde_json::Value) -> Policy {
    Policy::from_json(
        serde_json::json!({ "rules": [rule] })
            .to_string()
            .as_bytes(),
    )
    .unwrap()
}

/// A policy for a plain-HTTP destination on the mock provider.
pub fn plain_policy(provider: &MockProvider, inject: &serde_json::Value) -> Policy {
    rule_policy(&plain_rule(provider, inject))
}

pub fn plain_rule(provider: &MockProvider, inject: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "destination": { "scheme": "http", "host": HOST, "port": provider.port() },
        "allow_plain_http": true,
        "inject": inject,
    })
}

pub fn bearer() -> serde_json::Value {
    serde_json::json!({ "header": { "name": "Authorization", "format": "Bearer {}" } })
}

pub fn url(provider: &MockProvider, path: &str) -> String {
    format!("http://{HOST}:{}{path}", provider.port())
}

pub async fn read_body(response: SendResponse) -> Result<Bytes, BrokerError> {
    response
        .body
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
}

pub async fn read_text(response: SendResponse) -> String {
    String::from_utf8(read_body(response).await.unwrap().to_vec()).unwrap()
}

pub fn request_body(bytes: &'static [u8]) -> RequestBody {
    seal_broker::body::full_body(bytes)
}

/// A byte that differs between harnesses.
fn rand_byte() -> u8 {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    u8::try_from((nanos as usize + NEXT.fetch_add(1, Ordering::SeqCst)) % 256).unwrap()
}
