//! Large transfers stay within a fixed memory limit, whatever their size.
//!
//! These read `/proc` and move many gigabytes, so they are ignored by default and run
//! nightly, and on Linux only:
//!
//! ```sh
//! cargo test --release --package seal-broker --test memory -- --ignored --test-threads=1
//! ```
//!
//! The provider runs in this process, but streams without buffering, so what shows up
//! is seal's own use. `SEAL_MEMORY_TEST_GIB` changes the size of the large transfers.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod support;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Method;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use seal_broker::BrokerError;
use seal_format::Envelope;
use serde_json::Value;
use support::{
    Alpn, Harness, MockProvider, Options, TLS_HOST, bearer, plain_policy, read_text, request, url,
};

/// How much a transfer may add to resident memory, on top of a fixed baseline. One
/// stream's buffers are well under this, and a transfer that buffered would pass it in
/// the first second.
const LIMIT_BYTES: u64 = 64 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

fn large_transfer_bytes() -> u64 {
    std::env::var("SEAL_MEMORY_TEST_GIB")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5)
        * GIB
}

fn resident_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap();
    let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib * 1024
}

/// Samples resident memory while it is alive.
struct Sampler {
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    baseline: u64,
}

impl Sampler {
    fn start() -> Self {
        let baseline = resident_bytes();
        let peak = Arc::new(AtomicU64::new(baseline));
        let stop = Arc::new(AtomicBool::new(false));
        let (task_peak, task_stop) = (Arc::clone(&peak), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !task_stop.load(Ordering::Relaxed) {
                task_peak.fetch_max(resident_bytes(), Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Self {
            peak,
            stop,
            baseline,
        }
    }

    /// Stops, and fails if memory grew by more than the limit.
    fn assert_within_limit(self, name: &str) {
        self.stop.store(true, Ordering::Relaxed);
        let growth = self
            .peak
            .load(Ordering::Relaxed)
            .saturating_sub(self.baseline);
        println!("{name}: resident memory grew by {} KiB", growth / 1024);
        assert!(growth < LIMIT_BYTES, "{name}: grew by {growth} bytes");
    }
}

/// A request body of zeros that holds nothing in memory.
struct ZeroBody {
    remaining: u64,
}

const CHUNK: usize = 64 * 1024;
static ZEROS: [u8; CHUNK] = [0; CHUNK];

impl Body for ZeroBody {
    type Data = Bytes;
    type Error = BrokerError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BrokerError>>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let size = this.remaining.min(CHUNK as u64);
        this.remaining -= size;
        let slice = &ZEROS[..usize::try_from(size).unwrap()];
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(slice)))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

async fn drain(mut response: seal_broker::SendResponse) -> u64 {
    let mut bytes = 0;
    while let Some(frame) = response.body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            bytes += data.len() as u64;
        }
    }
    bytes
}

fn plain_token(provider: &MockProvider, harness: &Harness) -> Envelope {
    harness.seal("token", b"x", &plain_policy(provider, &bearer()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves many gigabytes; runs nightly"]
async fn acceptance_a_large_download_stays_within_the_limit() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = plain_token(&provider, &harness);
    let size = large_transfer_bytes();

    let sampler = Sampler::start();
    let path = format!("/zeros/{size}");
    let response = harness
        .get(&url(&provider, &path), &[("token", &token)])
        .await
        .unwrap();
    assert_eq!(drain(response).await, size);
    sampler.assert_within_limit("download");
    assert_eq!(harness.audit.last().bytes_out, size);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves many gigabytes; runs nightly"]
async fn acceptance_a_large_upload_stays_within_the_limit() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = plain_token(&provider, &harness);
    let size = large_transfer_bytes();

    let sampler = Sampler::start();
    let mut send = request(&url(&provider, "/sink"), &[("token", &token)]);
    send.method = Method::PUT;
    send.body = ZeroBody { remaining: size }.boxed_unsync();
    let response = harness.broker.send(send).await.unwrap();
    let body: Value = serde_json::from_str(&read_text(response).await).unwrap();
    sampler.assert_within_limit("upload");
    assert_eq!(body["bytes"], size);
    assert_eq!(harness.audit.last().bytes_in, size);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves gigabytes; runs nightly"]
async fn a_large_download_over_tls_and_http2_stays_within_the_limit() {
    let provider = MockProvider::tls(Alpn::Both).await;
    let mut options = Options::default();
    options.client.extra_roots = vec![provider.ca().unwrap()];
    let harness = Harness::with(options);
    let policy =
        seal_format::policy::builder::bearer(&format!("https://{TLS_HOST}:{}/", provider.port()))
            .unwrap();
    let token = harness.seal("token", b"x", &policy);
    let size = 2 * GIB;

    let sampler = Sampler::start();
    let target = format!("https://{TLS_HOST}:{}/zeros/{size}", provider.port());
    let response = harness.get(&target, &[("token", &token)]).await.unwrap();
    assert_eq!(drain(response).await, size);
    sampler.assert_within_limit("TLS download");
}

/// With a slow caller, the provider slows down: nothing piles up in seal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "takes a while; runs nightly"]
async fn a_slow_caller_slows_the_provider_instead_of_growing_a_buffer() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = plain_token(&provider, &harness);

    let sampler = Sampler::start();
    // The provider offers 8 GiB far faster than this caller reads it.
    let path = format!("/zeros/{}", 8 * GIB);
    let mut response = harness
        .get(&url(&provider, &path), &[("token", &token)])
        .await
        .unwrap();
    let mut read = 0_u64;
    while read < 16 * 1024 * 1024 {
        if let Ok(data) = response.body.frame().await.unwrap().unwrap().into_data() {
            read += data.len() as u64;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sampler.assert_within_limit("slow caller");
    drop(response);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves gigabytes; runs nightly"]
async fn many_parallel_transfers_stay_within_a_limit_per_stream() {
    const STREAMS: u64 = 32;
    let provider = MockProvider::plain().await;
    let harness = Arc::new(Harness::new());
    let token = plain_token(&provider, &harness);
    let target = url(&provider, &format!("/zeros/{}", 128 * 1024 * 1024));

    let sampler = Sampler::start();
    let mut tasks = Vec::new();
    for _ in 0..STREAMS {
        let (harness, token, target) = (Arc::clone(&harness), token.clone(), target.clone());
        tasks.push(tokio::spawn(async move {
            drain(harness.get(&target, &[("token", &token)]).await.unwrap()).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 128 * 1024 * 1024);
    }
    sampler.stop.store(true, Ordering::Relaxed);
    let growth = sampler
        .peak
        .load(Ordering::Relaxed)
        .saturating_sub(sampler.baseline);
    println!("parallel: resident memory grew by {} KiB", growth / 1024);
    // Each stream's share of the same limit, with room for what they have in common.
    assert!(growth < 4 * LIMIT_BYTES, "grew by {growth} bytes");
}

// 5 GB to and from RustFS, signed with SigV4. Needs Docker as well.

const RUSTFS_HOST: &str = "rustfs.test";

fn rustfs_policy(port: u16, payload: &[&str]) -> seal_format::Policy {
    support::rule_policy(&serde_json::json!({
        "destination": { "scheme": "http", "host": RUSTFS_HOST, "port": port },
        "allow_plain_http": true,
        "inject": { "aws_sigv4": {
            "region": "us-east-1",
            "service": "s3",
            "access_key_id": { "literal": seal_testkit::containers::RUSTFS_ACCESS_KEY },
            "payload": payload,
        } },
    }))
}

fn zeros_sha256(length: u64) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut left = length;
    while left > 0 {
        let size = left.min(CHUNK as u64);
        context.update(&ZEROS[..usize::try_from(size).unwrap()]);
        left -= size;
    }
    seal_broker::inject::sigv4::hex(context.finish().as_ref())
}

/// The text of the first `<name>` element.
fn element(xml: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let start = xml.find(&open).unwrap() + open.len();
    let end = xml[start..].find(&format!("</{name}>")).unwrap() + start;
    xml[start..end].to_owned()
}

struct S3 {
    _container: seal_testkit::containers::Container,
    harness: Harness,
    secret: Envelope,
    port: u16,
    bucket: String,
}

impl S3 {
    async fn start() -> Self {
        let container = seal_testkit::containers::rustfs()
            .await
            .expect("RustFS starts");
        let port = container.port(9000).unwrap();
        let harness = Harness::new();
        let secret = harness.seal(
            "secret_key",
            seal_testkit::containers::RUSTFS_SECRET_KEY.as_bytes(),
            &rustfs_policy(port, &["computed", "caller_hash", "streaming"]),
        );
        let s3 = Self {
            _container: container,
            harness,
            secret,
            port,
            bucket: "large".to_owned(),
        };
        let response = s3.send(Method::PUT, "", None, &[]).await;
        assert_eq!(response.status, 200);
        read_text(response).await;
        s3
    }

    fn url(&self, path: &str) -> String {
        format!("http://{RUSTFS_HOST}:{}/{}{path}", self.port, self.bucket)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<u64>,
        headers: &[(&'static str, String)],
    ) -> seal_broker::SendResponse {
        let mut send = request(&self.url(path), &[("secret_key", &self.secret)]);
        send.method = method;
        if let Some(length) = body {
            send.body = ZeroBody { remaining: length }.boxed_unsync();
        }
        for (name, value) in headers {
            send.headers
                .insert(*name, http::HeaderValue::from_str(value).unwrap());
        }
        self.harness.broker.send(send).await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves many gigabytes through RustFS; runs nightly"]
async fn acceptance_large_s3_uploads_and_downloads_stay_within_the_limit() {
    let s3 = S3::start().await;
    let size = large_transfer_bytes();

    // Chunked signing, which seal frames as the body streams.
    let sampler = Sampler::start();
    let response = s3.send(Method::PUT, "/chunked", Some(size), &[]).await;
    let status = response.status;
    assert_eq!(status, 200, "{}", read_text(response).await);
    sampler.assert_within_limit("S3 chunked upload");

    // The caller's hash.
    let hash = zeros_sha256(size);
    let sampler = Sampler::start();
    let response = s3
        .send(
            Method::PUT,
            "/caller-hash",
            Some(size),
            &[("x-amz-content-sha256", hash)],
        )
        .await;
    let status = response.status;
    assert_eq!(status, 200, "{}", read_text(response).await);
    sampler.assert_within_limit("S3 caller-hash upload");

    // And back.
    let sampler = Sampler::start();
    let response = s3.send(Method::GET, "/chunked", None, &[]).await;
    assert_eq!(response.status, 200);
    assert_eq!(drain(response).await, size);
    sampler.assert_within_limit("S3 download");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves many gigabytes through RustFS; runs nightly"]
async fn acceptance_a_large_s3_multipart_upload_stays_within_the_limit() {
    let s3 = S3::start().await;
    let size = large_transfer_bytes();
    let parts = 5;
    let part_size = size / parts;

    let sampler = Sampler::start();
    let response = s3.send(Method::POST, "/multipart?uploads", None, &[]).await;
    let upload_id = element(&read_text(response).await, "UploadId");
    let hash = zeros_sha256(part_size);
    let mut etags = Vec::new();
    for number in 1..=parts {
        let path = format!("/multipart?partNumber={number}&uploadId={upload_id}");
        let response = s3
            .send(
                Method::PUT,
                &path,
                Some(part_size),
                &[("x-amz-content-sha256", hash.clone())],
            )
            .await;
        assert_eq!(response.status, 200);
        etags.push(
            response.headers[http::header::ETAG]
                .to_str()
                .unwrap()
                .to_owned(),
        );
        read_text(response).await;
    }
    let complete: String = etags
        .iter()
        .enumerate()
        .map(|(index, etag)| {
            format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
                index + 1
            )
        })
        .collect();
    let body = format!("<CompleteMultipartUpload>{complete}</CompleteMultipartUpload>");
    let mut send = request(
        &s3.url(&format!("/multipart?uploadId={upload_id}")),
        &[("secret_key", &s3.secret)],
    );
    send.method = Method::POST;
    send.body = seal_broker::body::full_body(body);
    let response = s3.harness.broker.send(send).await.unwrap();
    let status = response.status;
    assert_eq!(status, 200, "{}", read_text(response).await);
    sampler.assert_within_limit("S3 multipart upload");

    let response = s3.send(Method::HEAD, "/multipart", None, &[]).await;
    assert_eq!(
        response.headers[http::header::CONTENT_LENGTH]
            .to_str()
            .unwrap(),
        (part_size * parts).to_string()
    );
}
