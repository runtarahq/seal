//! Runs seal in each mode for the same tests: in this process, as the `seal` binary on a
//! Unix socket, and as the binary over mutual TLS.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use seal::config::Config;
use seal_broker::{Broker, Environment};
use seal_client::{Body, ClientTls, Mode, SealClient, SealError, SendRequest, SendResponse};
use seal_format::id::KeyId;
use seal_format::{Binding, Envelope, FieldName, ItemId, KeysetId, Policy, PublicKey};
use seal_keys::{Keyring, Keys};
use seal_testkit::canary::{Canary, CanaryRegistry};
use seal_testkit::pki::{Issued, TestPki};

// Each test file uses a different part of this.
#[allow(unused_imports)]
pub use seal_testkit::mock_provider::{CannedResponse, MockProvider};

/// The name the service's certificate is for.
pub const SERVER_NAME: &str = "seal.test";
/// The host that reaches mock providers.
pub const HOST: &str = "localhost";

pub fn keyset() -> KeysetId {
    KeysetId::new("acme").unwrap()
}

/// The keyset of shared platform credentials.
pub fn platform() -> KeysetId {
    KeysetId::new("platform").unwrap()
}

pub fn item() -> ItemId {
    ItemId::new("connection-1").unwrap()
}

pub fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

/// What a test can change about the configuration.
#[derive(Clone)]
pub struct Options {
    /// Extra TOML for the `[limits]` table.
    pub limits: String,
    /// Extra TOML for the `[keys]` table.
    pub keys: String,
    /// Replaces the callers.
    pub callers: Option<String>,
    /// A shared key directory, for several instances.
    pub keys_dir: Option<PathBuf>,
    /// Whether to serve metrics.
    pub metrics: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: "idle_timeout = \"10s\"\nfirst_byte_timeout = \"10s\"\n".to_owned(),
            keys: String::new(),
            callers: None,
            keys_dir: None,
            metrics: false,
        }
    }
}

/// Everything a seal instance needs on disk.
pub struct Setup {
    pub dir: tempfile::TempDir,
    pub keys_dir: PathBuf,
    pub kek: PathBuf,
    pub audit: PathBuf,
    pub pki: Arc<TestPki>,
    pub client: Issued,
    pub provider_cas: Vec<PathBuf>,
    /// Every secret sealed here, scanned for when the instance ends.
    pub canaries: Arc<std::sync::Mutex<CanaryRegistry>>,
}

impl Setup {
    /// A key directory with keysets `acme` and `platform`, and a CA for the service and its caller.
    pub async fn new(keys_dir: Option<&Path>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = keys_dir.map_or_else(|| dir.path().join("keys"), Path::to_owned);
        let kek = keys_dir.with_extension("kek");
        let pki = Arc::new(TestPki::new("seal callers CA"));
        let client = pki.client("test-app");
        let setup = Self {
            audit: dir.path().join("audit.jsonl"),
            dir,
            keys_dir,
            kek,
            pki,
            client,
            provider_cas: Vec::new(),
            canaries: Arc::new(std::sync::Mutex::new(CanaryRegistry::new())),
        };
        if !setup.kek.exists() {
            std::fs::create_dir_all(&setup.keys_dir).unwrap();
            seal::cli::create_wrapping_key(&setup.kek).unwrap();
            let config = setup.config_text(
                Mode::Unix,
                &Options::default(),
                "[listen]\nunix = \"/unused\"\n",
            );
            let config = Config::parse(&config).unwrap();
            for keyset in [keyset(), platform()] {
                seal::cli::keygen(&config, &keyset).await.unwrap();
            }
        }
        setup
    }

    /// Trusts a mock provider's CA.
    pub fn trust(&mut self, provider: &MockProvider) {
        self.trust_ca(&provider.ca().unwrap());
    }

    /// Trusts a CA toward providers.
    pub fn trust_ca(&mut self, ca: &rustls::pki_types::CertificateDer<'_>) {
        let path = self
            .dir
            .path()
            .join(format!("provider-ca-{}.pem", self.provider_cas.len()));
        let pem = pem_of(ca);
        std::fs::write(&path, pem).unwrap();
        self.provider_cas.push(path);
    }

    pub fn config_text(&self, mode: Mode, options: &Options, listen: &str) -> String {
        let uid = nix::unistd::getuid().as_raw();
        let callers = options.callers.clone().unwrap_or_else(|| match mode {
            Mode::Mtls => "[[callers]]\nname = \"test-app\"\ncert_subject = \"CN=test-app\"\nkeysets = [\"acme\", \"platform\"]\nadmin = true\n".to_owned(),
            _ => format!("[[callers]]\nname = \"test-app\"\nunix_uid = {uid}\nkeysets = [\"acme\", \"platform\"]\nadmin = true\n"),
        });
        let cas: Vec<String> = self
            .provider_cas
            .iter()
            .map(|path| format!("{:?}", path.display().to_string()))
            .collect();
        let metrics = if options.metrics {
            "[metrics]\nlisten = \"127.0.0.1:0\"\n"
        } else {
            ""
        };
        format!(
            r#"{listen}
{callers}
[keys]
source = {{ dir = {keys:?} }}
wrap = {{ file = {kek:?} }}
lock_memory = "off"
{extra_keys}

[network]
allow_private_cidrs = ["127.0.0.0/8", "::1/128"]
extra_ca_files = [{cas}]

[limits]
{limits}

[audit]
sink = {{ file = {audit:?} }}

{metrics}"#,
            keys = self.keys_dir.display().to_string(),
            kek = self.kek.display().to_string(),
            audit = self.audit.display().to_string(),
            extra_keys = options.keys,
            limits = options.limits,
            cas = cas.join(", "),
        )
    }

    /// The audit records written so far.
    pub fn audit_records(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.audit)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The keyset's current public key, read from the key directory.
    pub async fn current_key(&self) -> (KeyId, PublicKey) {
        self.current_key_of(&keyset()).await
    }

    /// A keyset's current public key, read from the key directory.
    pub async fn current_key_of(&self, keyset: &KeysetId) -> (KeyId, PublicKey) {
        let config = Config::parse(&self.config_text(
            Mode::Unix,
            &Options::default(),
            "[listen]\nunix = \"/unused\"\n",
        ))
        .unwrap();
        let (source, wrap) = seal::serve::key_parts(&config).unwrap();
        let keyring = Keyring::new(source, wrap, config.keyring()).unwrap();
        keyring.current_public_key(keyset).await.unwrap()
    }

    /// Opens a value bound to this setup's item, with the keys in the key directory.
    pub async fn open(&self, name: &str, envelope: &Envelope) -> (Vec<u8>, Policy) {
        let config = Config::parse(&self.config_text(
            Mode::Unix,
            &Options::default(),
            "[listen]\nunix = \"/unused\"\n",
        ))
        .unwrap();
        let (source, wrap) = seal::serve::key_parts(&config).unwrap();
        let keyring = Keyring::new(source, wrap, config.keyring()).unwrap();
        let key = keyring
            .private_key(&keyset(), envelope.kid())
            .await
            .unwrap();
        let (keyset, item, field) = (keyset(), item(), field(name));
        let opened = seal_format::open(
            &key,
            envelope,
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
        )
        .unwrap();
        (opened.secret.expose(<[u8]>::to_vec), opened.policy)
    }

    /// Seals a value to the keyset's current key.
    pub async fn seal(&self, name: &str, secret: &[u8], policy: &Policy) -> Envelope {
        self.seal_at(&keyset(), &item(), name, secret, policy).await
    }

    /// Seals a value bound to another record.
    pub async fn seal_at(
        &self,
        keyset: &KeysetId,
        item: &ItemId,
        name: &str,
        secret: &[u8],
        policy: &Policy,
    ) -> Envelope {
        // Every secret long enough to be told from ordinary text is a canary.
        if let Ok(text) = std::str::from_utf8(secret)
            && text.len() >= 8
        {
            self.canaries
                .lock()
                .unwrap()
                .register(&Canary::from_value(text));
        }
        let (kid, public) = self.current_key_of(keyset).await;
        let field = field(name);
        seal_format::seal(
            &public,
            &kid,
            Binding {
                keyset,
                item,
                field: &field,
            },
            secret,
            policy,
        )
        .unwrap()
    }
}

fn pem_of(der: &rustls::pki_types::CertificateDer<'_>) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// A running seal binary. Killed when dropped.
pub struct Process {
    child: Child,
    pub stderr: Arc<std::sync::Mutex<String>>,
    pub address: String,
    pub metrics: Option<String>,
}

impl Process {
    /// The process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the binary and waits until it listens.
pub fn spawn(config_path: &Path) -> Process {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seal"))
        .args(["serve", "--config"])
        .arg(config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let collected = Arc::new(std::sync::Mutex::new(String::new()));
    let (sender, receiver) = std::sync::mpsc::channel();
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if let Some(address) = line.strip_prefix("seal: listening on ") {
                let _ = sender.send(address.to_owned());
            }
            sink.lock().unwrap().push_str(&line);
            sink.lock().unwrap().push('\n');
        }
    });
    let address = receiver
        .recv_timeout(Duration::from_secs(30))
        .unwrap_or_else(|_| panic!("seal did not start: {}", collected.lock().unwrap()));
    Process {
        child,
        stderr: collected,
        address,
        metrics: None,
    }
}

/// seal in a mode, with what a test needs to inspect it.
pub struct Instance {
    pub client: Box<dyn SealClient>,
    pub setup: Setup,
    pub process: Option<Process>,
    /// What seal returned to the test, apart from response bodies.
    pub seen: Arc<std::sync::Mutex<Vec<String>>>,
}

/// When a test ends, nothing seal wrote or returned may hold a secret it sealed: not
/// its logs, audit records or metrics, nor an error or a response head. Response
/// bodies are left out, since echo endpoints return what they received: seal does not
/// stop a provider returning a credential.
impl Drop for Instance {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let registry = self.setup.canaries.lock().unwrap();
        let mut hits = Vec::new();
        hits.extend(registry.scan("logs", &self.logs()));
        let audit = std::fs::read_to_string(&self.setup.audit).unwrap_or_default();
        hits.extend(registry.scan("audit", &audit));
        if let Some(address) = self
            .process
            .as_ref()
            .and_then(|process| process.metrics.clone())
        {
            hits.extend(registry.scan("metrics", &fetch_metrics(&address)));
        }
        for text in self.seen.lock().unwrap().iter() {
            hits.extend(registry.scan("returned to the caller", text));
        }
        assert!(hits.is_empty(), "a sealed secret appeared: {hits:?}");
    }
}

/// The metrics text, read with a blocking request.
fn fetch_metrics(address: &str) -> String {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect(address) else {
        return String::new();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: seal\r\nConnection: close\r\n\r\n");
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    text
}

/// A client that keeps what seal returns, apart from response bodies, for the scan.
pub struct ScanningClient {
    inner: Box<dyn SealClient>,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

impl ScanningClient {
    fn keep<T>(&self, result: &Result<T, SealError>) {
        if let Err(error) = result {
            self.seen.lock().unwrap().push(format!("{error:?} {error}"));
        }
    }
}

#[async_trait::async_trait]
impl SealClient for ScanningClient {
    fn mode(&self) -> Mode {
        self.inner.mode()
    }

    async fn send(&self, request: SendRequest) -> Result<SendResponse, SealError> {
        let result = self.inner.send(request).await;
        self.keep(&result);
        if let Ok(response) = &result {
            self.seen
                .lock()
                .unwrap()
                .push(format!("{:?}", response.response.headers()));
        }
        result
    }

    async fn connect_pg(
        &self,
        request: seal_client::ConnectRequest,
    ) -> Result<seal_client::PgStream, SealError> {
        let result = self.inner.connect_pg(request).await;
        self.keep(&result);
        result
    }

    async fn info(&self) -> Result<seal_client::Info, SealError> {
        let result = self.inner.info().await;
        self.keep(&result);
        result
    }

    async fn generate_keyset(
        &self,
        keyset: &KeysetId,
    ) -> Result<seal_client::WrappedKey, SealError> {
        let result = self.inner.generate_keyset(keyset).await;
        self.keep(&result);
        result
    }

    async fn rotate(&self, keyset: &KeysetId) -> Result<seal_client::WrappedKey, SealError> {
        let result = self.inner.rotate(keyset).await;
        self.keep(&result);
        result
    }

    async fn public_keys(
        &self,
        keyset: &KeysetId,
    ) -> Result<Vec<seal_client::PublicKeyInfo>, SealError> {
        let result = self.inner.public_keys(keyset).await;
        self.keep(&result);
        result
    }
}

impl Instance {
    pub fn mode(&self) -> Mode {
        self.client.mode()
    }

    pub fn logs(&self) -> String {
        self.process
            .as_ref()
            .map(|process| process.stderr.lock().unwrap().clone())
            .unwrap_or_default()
    }
}

/// Starts seal in a mode.
pub async fn start(mode: Mode, options: Options, providers: &[&MockProvider]) -> Instance {
    let cas: Vec<_> = providers
        .iter()
        .filter_map(|provider| provider.ca())
        .collect();
    start_trusting(mode, options, &cas).await
}

/// Starts seal in a mode, trusting these CAs toward providers.
pub async fn start_trusting(
    mode: Mode,
    options: Options,
    cas: &[rustls::pki_types::CertificateDer<'static>],
) -> Instance {
    let mut setup = Setup::new(options.keys_dir.as_deref()).await;
    for ca in cas {
        setup.trust_ca(ca);
    }
    let (client, process) = connect(mode, &options, &setup).await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Instance {
        client: Box::new(ScanningClient {
            inner: client,
            seen: Arc::clone(&seen),
        }),
        setup,
        process,
        seen,
    }
}

/// A client for an existing setup, starting a process if the mode needs one.
pub async fn connect(
    mode: Mode,
    options: &Options,
    setup: &Setup,
) -> (Box<dyn SealClient>, Option<Process>) {
    match mode {
        Mode::InProcess => {
            let config =
                Config::parse(&setup.config_text(mode, options, "[listen]\nunix = \"/unused\"\n"))
                    .unwrap();
            let (source, wrap) = seal::serve::key_parts(&config).unwrap();
            let keyring = Keyring::new(source, wrap, config.keyring()).unwrap();
            let audit = Arc::new(seal::sinks::FileSink::open(&setup.audit).unwrap());
            let broker = Broker::new(
                seal::serve::broker_config(&config).unwrap(),
                Arc::new(keyring.clone()),
                Environment::production(audit).unwrap(),
            )
            .unwrap();
            let client = seal_client::in_process(broker, Some(keyring), config.limits.buffer_cap.0);
            (Box::new(client), None)
        }
        Mode::Unix => {
            let socket = setup
                .dir
                .path()
                .join(format!("seal-{}.sock", rand_suffix()));
            let listen = format!("[listen]\nunix = {:?}\n", socket.display().to_string());
            let path = write_config(setup, &setup.config_text(mode, options, &listen));
            let process = spawn(&path);
            let client = seal_client::unix(&[socket]).unwrap();
            (Box::new(client), Some(process))
        }
        Mode::Mtls => {
            let server = setup.pki.server(&[SERVER_NAME]);
            let (cert, key, ca) = write_tls(setup, &server);
            let listen = format!(
                "[listen]\ntcp = \"127.0.0.1:0\"\ntls = {{ cert = {:?}, key = {:?}, client_ca = {:?} }}\nreload_interval = \"100ms\"\n",
                cert.display().to_string(),
                key.display().to_string(),
                ca.display().to_string()
            );
            let path = write_config(setup, &setup.config_text(mode, options, &listen));
            let process = spawn(&path);
            let address = process.address.strip_prefix("tcp:").unwrap().to_owned();
            let client = seal_client::mtls(&[address], &client_tls(setup, &setup.client)).unwrap();
            (Box::new(client), Some(process))
        }
    }
}

pub fn client_tls(setup: &Setup, identity: &Issued) -> ClientTls {
    ClientTls {
        ca_pem: setup.pki.ca_pem.clone(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        server_name: SERVER_NAME.to_owned(),
    }
}

pub fn write_tls(setup: &Setup, server: &Issued) -> (PathBuf, PathBuf, PathBuf) {
    let suffix = rand_suffix();
    let cert = setup.dir.path().join(format!("server-{suffix}.crt"));
    let key = setup.dir.path().join(format!("server-{suffix}.key"));
    let ca = setup.dir.path().join(format!("clients-{suffix}.crt"));
    std::fs::write(&cert, &server.cert_pem).unwrap();
    std::fs::write(&key, &server.key_pem).unwrap();
    std::fs::write(&ca, &setup.pki.ca_pem).unwrap();
    (cert, key, ca)
}

pub fn write_config(setup: &Setup, text: &str) -> PathBuf {
    let path = setup
        .dir
        .path()
        .join(format!("seal-{}.toml", rand_suffix()));
    std::fs::write(&path, text).unwrap();
    // seal refuses a configuration others could change, whatever the umask made it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

pub fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// A request through seal, with an empty body.
pub fn get(url: &str, sealed: &[(&str, &Envelope)]) -> SendRequest {
    request(
        http::Method::GET,
        url,
        sealed,
        Empty::new().map_err(|never| match never {}).boxed_unsync(),
    )
}

pub fn request(
    method: http::Method,
    url: &str,
    sealed: &[(&str, &Envelope)],
    body: Body,
) -> SendRequest {
    SendRequest {
        keyset: keyset(),
        item: item(),
        sealed: sealed
            .iter()
            .map(|(name, envelope)| (field(name), (*envelope).clone().into()))
            .collect::<BTreeMap<_, _>>(),
        plain: BTreeMap::new(),
        request: http::Request::builder()
            .method(method)
            .uri(url)
            .body(body)
            .unwrap(),
    }
}

pub fn body(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub async fn read(response: SendResponse) -> Result<Bytes, SealError> {
    response
        .response
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
}

pub async fn text(response: SendResponse) -> String {
    String::from_utf8(read(response).await.unwrap().to_vec()).unwrap()
}

pub fn plain_rule(provider: &MockProvider, inject: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "destination": { "scheme": "http", "host": HOST, "port": provider.port() },
        "allow_plain_http": true,
        "inject": inject,
    })
}

pub fn policy(value: &serde_json::Value) -> Policy {
    Policy::from_json(value.to_string().as_bytes()).unwrap()
}

pub fn bearer() -> serde_json::Value {
    serde_json::json!({ "header": { "name": "Authorization", "format": "Bearer {}" } })
}

pub fn url(provider: &MockProvider, path: &str) -> String {
    format!("http://{HOST}:{}{path}", provider.port())
}

/// Runs a test body once per mode.
#[macro_export]
macro_rules! mode_matrix {
    ($($name:ident => $body:expr;)*) => {$(
        mod $name {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn in_process() {
                ($body)(seal_client::Mode::InProcess).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn unix() {
                ($body)(seal_client::Mode::Unix).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn mtls() {
                ($body)(seal_client::Mode::Mtls).await;
            }
        }
    )*};
}
