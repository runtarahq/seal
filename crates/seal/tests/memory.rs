//! Measures the cost constants the memory ceiling is computed from, and fails if a
//! committed constant is too low. Linux only; ignored by default and run
//! nightly:
//!
//! ```sh
//! cargo test --release --package seal --test memory -- --ignored --test-threads=1
//! ```

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use seal_client::Mode;
use seal_format::KeysetId;
use seal_keys::{DirKeySource, FileKeyWrap, Keyring, KeyringConfig, Keys};
use support::*;

fn resident_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap();
    line.split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

/// Resident memory of another process.
fn resident_bytes_of(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap();
    line.split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measures memory; runs nightly"]
async fn the_cost_of_a_live_key_is_within_the_constant() {
    const KEYSETS: usize = 2000;
    let directory = tempfile::tempdir().unwrap();
    let wrap = Arc::new(FileKeyWrap::from_bytes(&[7; 32]).unwrap());
    let source = Arc::new(DirKeySource::new(directory.path(), 16));
    let config = KeyringConfig {
        max_loaded_keysets: KEYSETS,
        max_live_keys: 2 * KEYSETS,
        ..KeyringConfig::default()
    };
    let keyring = Keyring::new(source, wrap, config).unwrap();
    let names: Vec<KeysetId> = (0..KEYSETS)
        .map(|index| KeysetId::new(format!("tenant-{index}")).unwrap())
        .collect();
    for name in &names {
        keyring.generate(name).await.unwrap();
    }
    // Warm up allocators and caches with a few loads before measuring.
    for name in names.iter().take(16) {
        keyring.current_public_key(name).await.unwrap();
    }
    let before = resident_bytes();
    for name in &names[16..] {
        keyring.current_public_key(name).await.unwrap();
    }
    let per_key = resident_bytes().saturating_sub(before) / (KEYSETS as u64 - 16);
    println!("a live key costs about {per_key} bytes");
    assert!(
        per_key <= seal::limits::costs::KEY,
        "{per_key} > {}",
        seal::limits::costs::KEY
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures memory; runs nightly"]
async fn the_cost_of_a_stream_and_the_fixed_overhead_are_within_the_constants() {
    const STREAMS: u64 = 200;
    let provider = MockProvider::plain().await;
    let options = Options {
        limits: format!("max_concurrent_streams = {STREAMS}\nidle_timeout = \"60s\"\n"),
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[&provider]).await;
    let pid = instance.process.as_ref().unwrap().pid();
    let token = instance
        .setup
        .seal(
            "token",
            b"x",
            &policy(&serde_json::json!({ "rules": [plain_rule(&provider, &bearer())] })),
        )
        .await;

    // One request warms up the process.
    text(
        instance
            .client
            .send(get(&url(&provider, "/quiet"), &[("token", &token)]))
            .await
            .unwrap(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let idle = resident_bytes_of(pid);
    println!("an idle service uses {} KiB", idle / 1024);
    assert!(
        idle <= seal::limits::costs::FIXED_OVERHEAD,
        "{idle} > fixed overhead"
    );

    let mut held = Vec::new();
    for _ in 0..STREAMS {
        held.push(
            instance
                .client
                .send(get(&url(&provider, "/stall"), &[("token", &token)]))
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let per_stream = resident_bytes_of(pid).saturating_sub(idle) / STREAMS;
    println!("a stalled stream costs about {per_stream} bytes");
    // A stream's buffer is filled only as data arrives, so a stalled one shows its
    // fixed cost, which is what the constant covers.
    assert!(
        per_stream <= seal::limits::costs::STREAM + seal::limits::costs::UPSTREAM_CONNECTION,
        "{per_stream}"
    );
    drop(held);
}

/// Resident memory of a process, sampled until it settles.
async fn settled_resident(pid: u32) -> u64 {
    let mut last = resident_bytes_of(pid);
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = resident_bytes_of(pid);
        if now.abs_diff(last) < 64 * 1024 {
            return now;
        }
        last = now;
    }
    last
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures memory; runs nightly"]
async fn the_cost_of_a_caller_connection_is_within_the_constant() {
    const CONNECTIONS: u64 = 100;
    let options = Options {
        limits: format!("max_caller_connections = {}\n", CONNECTIONS + 10),
        ..Options::default()
    };
    let instance = start(Mode::Unix, options, &[]).await;
    let pid = instance.process.as_ref().unwrap().pid();
    let socket: std::path::PathBuf = instance
        .process
        .as_ref()
        .unwrap()
        .address
        .strip_prefix("unix:")
        .unwrap()
        .into();
    instance.client.info().await.unwrap();
    let before = settled_resident(pid).await;
    let mut clients = Vec::new();
    for _ in 0..CONNECTIONS {
        let client = seal_client::unix(std::slice::from_ref(&socket)).unwrap();
        seal_client::SealClient::info(&client).await.unwrap();
        clients.push(client);
    }
    let per_connection = settled_resident(pid).await.saturating_sub(before) / CONNECTIONS;
    println!("a caller connection costs about {per_connection} bytes");
    assert!(
        per_connection <= seal::limits::costs::CALLER_CONNECTION,
        "{per_connection}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures memory; runs nightly"]
async fn the_cost_of_a_provider_connection_is_within_the_constant() {
    const PROVIDERS: u64 = 60;
    let mut providers = Vec::new();
    for _ in 0..PROVIDERS {
        providers.push(MockProvider::plain().await);
    }
    let instance = start(Mode::Unix, Options::default(), &[]).await;
    let pid = instance.process.as_ref().unwrap().pid();
    let rules: Vec<serde_json::Value> = providers
        .iter()
        .take(16)
        .map(|provider| plain_rule(provider, &bearer()))
        .collect();
    let mut tokens = Vec::new();
    for chunk in providers.chunks(16) {
        let rules: Vec<serde_json::Value> = chunk
            .iter()
            .map(|provider| plain_rule(provider, &bearer()))
            .collect();
        tokens.push(
            instance
                .setup
                .seal(
                    "token",
                    b"x",
                    &policy(&serde_json::json!({ "rules": rules })),
                )
                .await,
        );
    }
    drop(rules);
    // Warm up with one provider.
    text(
        instance
            .client
            .send(get(&url(&providers[0], "/quiet"), &[("token", &tokens[0])]))
            .await
            .unwrap(),
    )
    .await;
    let before = settled_resident(pid).await;
    for (index, provider) in providers.iter().enumerate().skip(1) {
        let token = &tokens[index / 16];
        text(
            instance
                .client
                .send(get(&url(provider, "/quiet"), &[("token", token)]))
                .await
                .unwrap(),
        )
        .await;
    }
    let per_connection = settled_resident(pid).await.saturating_sub(before) / (PROVIDERS - 1);
    println!("an idle provider connection costs about {per_connection} bytes");
    assert!(
        per_connection <= seal::limits::costs::UPSTREAM_CONNECTION,
        "{per_connection}"
    );
}

/// A TLS provider that requires client certificates from `clients`.
async fn client_cert_provider(clients: &seal_testkit::pki::TestPki) -> MockProvider {
    let server = seal_testkit::pki::TestPki::new("provider CA");
    MockProvider::tls_with(
        &server,
        seal_testkit::mock_provider::Alpn::Http1,
        &[HOST],
        Some(&clients.ca_der),
    )
    .await
}

/// A sealed private key whose certificate is in its policy, for a new identity.
async fn identity(
    setup: &Setup,
    clients: &seal_testkit::pki::TestPki,
    provider: &MockProvider,
    index: usize,
) -> seal_format::Envelope {
    let issued = clients.client(&format!("tenant-{index}"));
    let policy = policy(&serde_json::json!({ "rules": [{
        "destination": { "scheme": "https", "host": HOST, "port": provider.port() },
        "inject": { "client_cert": { "cert": { "literal": issued.cert_pem } } },
    }] }));
    setup
        .seal("client_key", issued.key_pem.as_bytes(), &policy)
        .await
}

fn tls_url(provider: &MockProvider) -> String {
    format!("https://{HOST}:{}/quiet", provider.port())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures memory; runs nightly"]
async fn the_cost_of_a_client_certificate_identity_is_within_the_constant() {
    const IDENTITIES: u64 = 100;
    let clients = seal_testkit::pki::TestPki::new("client CA");
    let provider = client_cert_provider(&clients).await;
    let instance = start_trusting(Mode::Unix, Options::default(), &[provider.ca().unwrap()]).await;
    let pid = instance.process.as_ref().unwrap().pid();
    let mut keys = Vec::new();
    for index in 0..=IDENTITIES {
        keys.push(
            identity(
                &instance.setup,
                &clients,
                &provider,
                usize::try_from(index).unwrap(),
            )
            .await,
        );
    }
    // Warm up with one identity.
    let send = |key: &seal_format::Envelope| get(&tls_url(&provider), &[("client_key", key)]);
    text(instance.client.send(send(&keys[0])).await.unwrap()).await;
    let before = settled_resident(pid).await;
    for key in &keys[1..] {
        text(instance.client.send(send(key)).await.unwrap()).await;
    }
    // Each identity keeps a TLS configuration and an idle connection of its own.
    let per_identity = settled_resident(pid).await.saturating_sub(before) / IDENTITIES;
    println!("a client-certificate identity with its connection costs about {per_identity} bytes");
    assert!(
        per_identity <= seal::limits::costs::TLS_CONFIG + seal::limits::costs::UPSTREAM_CONNECTION,
        "{per_identity}"
    );
    assert_eq!(
        provider.client_certificates().len(),
        usize::try_from(IDENTITIES).unwrap() + 1
    );
}

fn sealing_policy(provider: &MockProvider) -> seal_format::Policy {
    let mut rule = plain_rule(
        provider,
        &serde_json::json!({ "form_field": { "name": "secret" } }),
    );
    rule["seal_response"] = serde_json::json!({
        "format": "json",
        "fields": [{ "at": "/token", "as": "token", "policy": "api" }]
    });
    policy(&serde_json::json!({
        "rules": [rule],
        "definitions": { "api": { "rules": [plain_rule(provider, &bearer())] } }
    }))
}

fn post_form(target: &str, envelope: &seal_format::Envelope) -> seal_client::SendRequest {
    let mut request = request(
        http::Method::POST,
        target,
        &[("secret", envelope)],
        body("a=1"),
    );
    request.request.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures memory; runs nightly"]
async fn a_capped_buffer_costs_within_its_term() {
    const BUFFERS: u64 = 16;
    const CAP: u64 = 512 * 1024;
    let provider = MockProvider::plain().await;
    let options = Options {
        limits: format!(
            "max_concurrent_buffered = {BUFFERS}\nbuffer_cap = \"{CAP}\"\nbuffered_total_timeout = \"60s\"\nidle_timeout = \"60s\"\n"
        ),
        ..Options::default()
    };
    let instance = std::sync::Arc::new(start(Mode::Unix, options, &[&provider]).await);
    let pid = instance.process.as_ref().unwrap().pid();
    let secret = instance
        .setup
        .seal(
            "secret",
            b"SEALCANARY-client-secret",
            &sealing_policy(&provider),
        )
        .await;
    // Warm up: a sealed request that completes.
    text(
        instance
            .client
            .send(post_form(&url(&provider, "/quiet"), &secret))
            .await
            .unwrap(),
    )
    .await;
    let before = settled_resident(pid).await;

    // Each request fills a buffer to just under the cap, then waits for more.
    let target = url(&provider, &format!("/json-stall/{}", CAP - 1024));
    let mut held = Vec::new();
    for _ in 0..BUFFERS {
        let (instance, target, secret) = (
            std::sync::Arc::clone(&instance),
            target.clone(),
            secret.clone(),
        );
        held.push(tokio::spawn(async move {
            let _ = instance.client.send(post_form(&target, &secret)).await;
        }));
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let per_buffer = settled_resident(pid).await.saturating_sub(before) / BUFFERS;
    let term = CAP * seal::limits::costs::PARSE_FACTOR + 8 * seal::limits::costs::MAX_ENVELOPE;
    println!("a full capped buffer costs about {per_buffer} bytes, against {term} allowed");
    assert!(
        per_buffer >= CAP / 2,
        "the buffers were not filled: {per_buffer}"
    );
    assert!(per_buffer <= term, "{per_buffer}");
    for task in held {
        task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measures memory; runs nightly"]
async fn the_cost_of_a_tracked_keyset_is_within_the_constant() {
    const UNKNOWN: usize = 4000;
    let directory = tempfile::tempdir().unwrap();
    let wrap = Arc::new(FileKeyWrap::from_bytes(&[7; 32]).unwrap());
    let source = Arc::new(DirKeySource::new(directory.path(), 16));
    let config = KeyringConfig {
        max_tracked_keysets: UNKNOWN + 10,
        ..KeyringConfig::default()
    };
    let keyring = Keyring::new(source, wrap, config).unwrap();
    for index in 0..100 {
        let _ = keyring
            .current_public_key(&KeysetId::new(format!("warm-{index}")).unwrap())
            .await;
    }
    let before = resident_bytes();
    for index in 0..UNKNOWN {
        let _ = keyring
            .current_public_key(&KeysetId::new(format!("unknown-tenant-{index}")).unwrap())
            .await;
    }
    let per_keyset = resident_bytes().saturating_sub(before) / UNKNOWN as u64;
    println!("a remembered unknown keyset costs about {per_keyset} bytes");
    assert!(
        per_keyset <= seal::limits::costs::TRACKED_KEYSET,
        "{per_keyset}"
    );
}

/// The acceptance criterion: with every bound filled at once, resident memory stays
/// under the ceiling the configuration implies.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measures memory; runs nightly"]
async fn acceptance_with_every_bound_filled_memory_stays_under_the_ceiling() {
    const KEYSETS: usize = 300;
    const UNKNOWN: usize = 500;
    const STREAMS: usize = 64;
    const BUFFERED: usize = 8;
    const CALLERS: usize = 60;
    const IDENTITIES: usize = 256;
    let provider = MockProvider::plain().await;
    let uid = nix::unistd::getuid().as_raw();
    let options = Options {
        callers: Some(format!(
            "[[callers]]\nname = \"app\"\nunix_uid = {uid}\nkeysets = [\"*\"]\nadmin = true\n"
        )),
        limits: format!(
            "max_concurrent_streams = {STREAMS}\nmax_concurrent_buffered = {BUFFERED}\nbuffer_cap = \"256KiB\"\nmax_caller_connections = {}\nidle_timeout = \"60s\"\nbuffered_total_timeout = \"60s\"\nrate_per_caller = \"100000/s\"\nrate_per_keyset = \"100000/s\"\n",
            CALLERS + 10
        ),
        keys: format!(
            "max_loaded_keysets = {KEYSETS}\nmax_live_keys = {}\nmax_tracked_keysets = {UNKNOWN}\n",
            2 * KEYSETS
        ),
        ..Options::default()
    };
    let clients = seal_testkit::pki::TestPki::new("client CA");
    let tls_provider = client_cert_provider(&clients).await;
    let mut setup = Setup::new(None).await;
    setup.trust(&tls_provider);
    let config_text = setup.config_text(Mode::Unix, &options, "[listen]\nunix = \"/unused\"\n");
    let config = seal::config::Config::parse(&config_text).unwrap();
    let names: Vec<KeysetId> = (0..KEYSETS)
        .map(|index| KeysetId::new(format!("tenant-{index}")).unwrap())
        .collect();
    for name in &names {
        seal::cli::keygen(&config, name).await.unwrap();
    }
    let (ceiling, _) = seal::limits::ceiling(&config);
    let (client, process) = connect(Mode::Unix, &options, &setup).await;
    let client: Arc<dyn seal_client::SealClient> = Arc::from(client);
    let process = process.unwrap();
    let pid = process.pid();

    // Load every keyset, by opening a value sealed to each.
    let bearer_policy = policy(&serde_json::json!({ "rules": [plain_rule(&provider, &bearer())] }));
    let (source, wrap) = seal::serve::key_parts(&config).unwrap();
    let keyring = Keyring::new(source, wrap, config.keyring()).unwrap();
    for name in &names {
        let (kid, public) = keyring.current_public_key(name).await.unwrap();
        let (item, field) = (item(), field("token"));
        let binding = seal_format::Binding {
            keyset: name,
            item: &item,
            field: &field,
        };
        let token = seal_format::seal(&public, &kid, binding, b"x", &bearer_policy).unwrap();
        let mut send = get(&url(&provider, "/quiet"), &[("token", &token)]);
        send.keyset = name.clone();
        text(client.send(send).await.unwrap()).await;
    }
    // Fill the table of unknown keysets.
    let acme_token = setup
        .seal("token", b"SEALCANARY-token", &bearer_policy)
        .await;
    for index in 0..UNKNOWN {
        let mut send = get(&url(&provider, "/quiet"), &[("token", &acme_token)]);
        send.keyset = KeysetId::new(format!("nobody-{index}")).unwrap();
        let _ = client.send(send).await;
    }
    // Fill the client-certificate identities, each with an idle connection, before
    // every stream is held.
    for index in 0..IDENTITIES {
        let key = identity(&setup, &clients, &tls_provider, index).await;
        let send = get(&tls_url(&tls_provider), &[("client_key", &key)]);
        text(client.send(send).await.unwrap()).await;
    }
    // Hold every stream: most streaming, some holding a full capped buffer.
    let secret = setup
        .seal(
            "secret",
            b"SEALCANARY-client-secret",
            &sealing_policy(&provider),
        )
        .await;
    let mut held = Vec::new();
    for _ in 0..STREAMS - BUFFERED {
        held.push(
            client
                .send(get(&url(&provider, "/stall"), &[("token", &acme_token)]))
                .await
                .unwrap(),
        );
    }
    let mut buffering = Vec::new();
    for _ in 0..BUFFERED {
        let (client, target, secret) = (
            Arc::clone(&client),
            url(&provider, &format!("/json-stall/{}", 255 * 1024)),
            secret.clone(),
        );
        buffering.push(tokio::spawn(async move {
            let _ = client.send(post_form(&target, &secret)).await;
        }));
    }
    // And open the caller connections.
    let socket: std::path::PathBuf = process.address.strip_prefix("unix:").unwrap().into();
    let mut callers = Vec::new();
    for _ in 0..CALLERS {
        let caller = seal_client::unix(std::slice::from_ref(&socket)).unwrap();
        seal_client::SealClient::info(&caller).await.unwrap();
        callers.push(caller);
    }
    let peak = settled_resident(pid).await;
    println!(
        "with every bound filled, seal uses {} MiB of a {} MiB ceiling",
        peak >> 20,
        ceiling >> 20
    );
    assert!(peak <= ceiling, "{peak} > {ceiling}");
    for task in buffering {
        task.abort();
    }
    drop(held);
}

/// Samples another process's resident memory until stopped, keeping the peak.
struct PeakSampler {
    peak: Arc<std::sync::atomic::AtomicU64>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl PeakSampler {
    fn start(pid: u32) -> Self {
        use std::sync::atomic::Ordering;
        let peak = Arc::new(std::sync::atomic::AtomicU64::new(resident_bytes_of(pid)));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (task_peak, task_stop) = (Arc::clone(&peak), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !task_stop.load(Ordering::Relaxed) {
                task_peak.fetch_max(resident_bytes_of(pid), Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Self { peak, stop }
    }

    fn peak(self) -> u64 {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Relaxed);
        self.peak.load(Ordering::Relaxed)
    }
}

/// 1 GB copied into and out of Postgres through seal leaves seal's memory flat.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves a gigabyte through Postgres; runs nightly, with Docker"]
async fn acceptance_a_gigabyte_copy_through_postgres_stays_within_the_limit() {
    use futures_util::{SinkExt, StreamExt};
    const LIMIT: u64 = 64 * 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    let server_pki = seal_testkit::pki::TestPki::new("db server CA");
    let server = server_pki.server(&[HOST]);
    let clients = seal_testkit::pki::TestPki::new("db client CA");
    let container = seal_testkit::containers::postgres(
        17,
        &seal_testkit::containers::PostgresSetup {
            server_cert_pem: &server.cert_pem,
            server_key_pem: &server.key_pem,
            client_ca_pem: &clients.ca_pem,
            hba: "local all all trust\nhostssl all all all scram-sha-256\n",
            init_sql: "CREATE USER app_user PASSWORD 'app-secret';\nCREATE DATABASE app OWNER app_user;\n",
        },
    )
    .await
    .expect("Postgres starts");
    let port = container.port(5432).unwrap();
    let instance = start(Mode::Unix, Options::default(), &[]).await;
    let pid = instance.process.as_ref().unwrap().pid();
    let policy = policy(&serde_json::json!({ "rules": [{
        "destination": {
            "scheme": "postgres", "host": HOST, "port": port,
            "databases": ["app"], "user": { "literal": "app_user" },
            "tls": { "ca": server_pki.ca_pem },
        },
        "inject": { "pg_password": {} },
    }] }));
    let password = instance
        .setup
        .seal("password", b"app-secret", &policy)
        .await;
    let stream = instance
        .client
        .connect_pg(seal_client::ConnectRequest {
            keyset: keyset(),
            item: item(),
            sealed: std::collections::BTreeMap::from([(field("password"), password.into())]),
            plain: std::collections::BTreeMap::new(),
            host: HOST.to_owned(),
            port,
        })
        .await
        .unwrap();
    let (client, connection) = tokio_postgres::Config::new()
        .user("app_user")
        .dbname("app")
        .connect_raw(stream, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
        .batch_execute("CREATE UNLOGGED TABLE big (v text)")
        .await
        .unwrap();
    let before = settled_resident(pid).await;

    // In: rows of 1000 bytes, written as they are made.
    let sampler = PeakSampler::start(pid);
    let row = format!("{}\n", "x".repeat(999));
    let rows_per_chunk = 64;
    let chunk = bytes::Bytes::from(row.repeat(rows_per_chunk));
    let chunks = GIB / chunk.len() as u64;
    let sink = client.copy_in("COPY big FROM STDIN").await.unwrap();
    futures_util::pin_mut!(sink);
    for _ in 0..chunks {
        sink.feed(chunk.clone()).await.unwrap();
    }
    let copied = sink.finish().await.unwrap();
    assert_eq!(copied, chunks * rows_per_chunk as u64);
    let growth_in = sampler.peak().saturating_sub(before);

    // Out: the same gigabyte back.
    let sampler = PeakSampler::start(pid);
    let out = client.copy_out("COPY big TO STDOUT").await.unwrap();
    futures_util::pin_mut!(out);
    let mut received = 0_u64;
    while let Some(data) = out.next().await {
        received += data.unwrap().len() as u64;
    }
    assert_eq!(received, chunks * chunk.len() as u64);
    let growth_out = sampler.peak().saturating_sub(before);

    println!(
        "a 1 GB COPY grew seal's memory by {} KiB in and {} KiB out",
        growth_in / 1024,
        growth_out / 1024
    );
    assert!(growth_in < LIMIT && growth_out < LIMIT);
}
