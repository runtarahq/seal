//! Signing against real implementations in containers, in all three modes: RustFS
//! for S3 (SigV4 in each payload mode, multipart uploads) and Azurite for Azure
//! Storage (Blob, Queue and Table). They need Docker, so they are ignored by default;
//! CI's container job runs them with `--ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use http::{HeaderValue, Method, StatusCode, header};
use seal_client::{Mode, SendRequest};
use seal_format::{Envelope, Policy};
use seal_testkit::canary::{Canary, CanaryRegistry};
use seal_testkit::containers::{
    self, AZURITE_ACCOUNT, AZURITE_KEY, Container, RUSTFS_ACCESS_KEY, RUSTFS_SECRET_KEY,
};
use serde_json::{Value, json};
use support::*;

/// Like `mode_matrix!`, but ignored unless asked for, since these need Docker.
macro_rules! container_matrix {
    ($($name:ident => $body:expr;)*) => {$(
        mod $name {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "needs Docker"]
            async fn in_process() {
                ($body)(seal_client::Mode::InProcess).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "needs Docker"]
            async fn unix() {
                ($body)(seal_client::Mode::Unix).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            #[ignore = "needs Docker"]
            async fn mtls() {
                ($body)(seal_client::Mode::Mtls).await;
            }
        }
    )*};
}

fn local(port: u16, path: &str) -> String {
    format!("http://{HOST}:{port}{path}")
}

fn destination(port: u16) -> Value {
    json!({ "scheme": "http", "host": HOST, "port": port })
}

fn send_request(
    method: Method,
    url: &str,
    sealed: &[(&str, &Envelope)],
    body_bytes: Vec<u8>,
    headers: &[(&'static str, &str)],
) -> SendRequest {
    let mut request = request(method, url, sealed, body(body_bytes));
    for (name, value) in headers {
        request
            .request
            .headers_mut()
            .insert(*name, HeaderValue::from_str(value).unwrap());
    }
    request
}

async fn status_and_text(instance: &Instance, request: SendRequest) -> (StatusCode, String) {
    let response = instance.client.send(request).await.unwrap();
    let status = response.response.status();
    (status, text(response).await)
}

/// Uses a presigned URL as its holder would: straight to the server, with no seal and
/// no credentials but the URL. Returns the status, and the response as received: its
/// head, then its body.
async fn fetch_directly(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body_bytes: &[u8],
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://").unwrap();
    let (authority, path) = rest.split_at(rest.find('/').unwrap());
    let port: u16 = authority.rsplit(':').next().unwrap().parse().unwrap();
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body_bytes.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body_bytes).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response.split(' ').nth(1).unwrap().parse().unwrap();
    (status, response)
}

fn presign_request(
    method: Method,
    url: &str,
    sealed: &[(&str, &Envelope)],
    expires_s: u32,
) -> seal_client::PresignRequest {
    seal_client::PresignRequest {
        keyset: keyset(),
        item: item(),
        sealed: sealed
            .iter()
            .map(|(name, envelope)| (field(name), (*envelope).clone().into()))
            .collect(),
        plain: std::collections::BTreeMap::new(),
        method,
        url: url.to_owned(),
        expires_s,
    }
}

// S3, on RustFS.

fn s3_policy(port: u16, payload: &[&str], allow_unsigned: bool) -> Policy {
    policy(&json!({
        "rules": [{
            "destination": destination(port),
            "allow_plain_http": true,
            "inject": { "aws_sigv4": {
                "region": "us-east-1",
                "service": "s3",
                "access_key_id": { "literal": RUSTFS_ACCESS_KEY },
                "payload": payload,
                "allow_unsigned_payload": allow_unsigned,
            } },
        }]
    }))
}

fn sha256_hex(bytes: &[u8]) -> String {
    seal_broker::inject::sigv4::sha256_hex(bytes)
}

fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap() ^ seed)
        .collect()
}

/// The text of the first `<name>` element.
fn element<'a>(xml: &'a str, name: &str) -> &'a str {
    let open = format!("<{name}>");
    let start = xml.find(&open).unwrap() + open.len();
    let end = xml[start..].find(&format!("</{name}>")).unwrap() + start;
    &xml[start..end]
}

async fn rustfs() -> (Container, u16) {
    let container = containers::rustfs().await.expect("RustFS starts");
    let port = container.port(9000).unwrap();
    (container, port)
}

container_matrix! {
    s3_objects_round_trip_in_every_payload_mode => |mode: Mode| async move {
        let (_rustfs, port) = rustfs().await;
        let instance = start(mode, Options::default(), &[]).await;
        let seal = |policy: Policy| {
            let setup = &instance.setup;
            async move { setup.seal("secret_key", RUSTFS_SECRET_KEY.as_bytes(), &policy).await }
        };
        let computed = seal(s3_policy(port, &["computed"], false)).await;
        let caller_hash = seal(s3_policy(port, &["caller_hash"], false)).await;
        let streaming = seal(s3_policy(port, &["computed", "streaming"], false)).await;
        let unsigned = seal(s3_policy(port, &[], true)).await;
        let bucket = format!("bucket-{}", rand_suffix());
        let object = |key: &str| local(port, &format!("/{bucket}/{key}"));

        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &local(port, &format!("/{bucket}")), &[("secret_key", &computed)], Vec::new(), &[])).await;
        assert_eq!(status, StatusCode::OK, "create bucket: {text}");

        // A small object, hashed by seal.
        let small = b"hello from seal".to_vec();
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("small.txt"), &[("secret_key", &computed)], small.clone(), &[("content-type", "text/plain")])).await;
        assert_eq!(status, StatusCode::OK, "{text}");

        // A larger object with the caller's hash, streamed past the buffer cap.
        let large = pattern(3 * 1024 * 1024, 7);
        let hash = sha256_hex(&large);
        let length = large.len().to_string();
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("caller-hash.bin"), &[("secret_key", &caller_hash)], large.clone(), &[("x-amz-content-sha256", &hash), ("content-length", &length)])).await;
        assert_eq!(status, StatusCode::OK, "caller hash: {text}");

        // The same size, signed in chunks.
        let chunked = pattern(3 * 1024 * 1024 + 12_345, 9);
        let length = chunked.len().to_string();
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("chunked.bin"), &[("secret_key", &streaming)], chunked.clone(), &[("content-length", &length)])).await;
        assert_eq!(status, StatusCode::OK, "chunked: {text}");

        // An unsigned payload.
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("unsigned.bin"), &[("secret_key", &unsigned)], b"unsigned".to_vec(), &[("content-length", "8")])).await;
        assert_eq!(status, StatusCode::OK, "unsigned: {text}");

        for (key, expected) in [("small.txt", &small), ("caller-hash.bin", &large), ("chunked.bin", &chunked)] {
            let response = instance.client.send(get(&object(key), &[("secret_key", &computed)])).await.unwrap();
            assert_eq!(response.response.status(), StatusCode::OK, "{key}");
            assert_eq!(&read(response).await.unwrap()[..], &expected[..], "{key}");
        }

        // A range.
        let response = instance.client.send(send_request(Method::GET, &object("caller-hash.bin"), &[("secret_key", &computed)], Vec::new(), &[("range", "bytes=10-19")])).await.unwrap();
        assert_eq!(response.response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&read(response).await.unwrap()[..], &large[10..20]);

        // A listing, with a query.
        let (status, text) = status_and_text(&instance, get(&local(port, &format!("/{bucket}?list-type=2&prefix=c")), &[("secret_key", &computed)])).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("caller-hash.bin") && text.contains("chunked.bin") && !text.contains("small.txt"), "{text}");

        let (status, _) = status_and_text(&instance, send_request(Method::DELETE, &object("small.txt"), &[("secret_key", &computed)], Vec::new(), &[])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let mut registry = CanaryRegistry::new();
        registry.register(&Canary::from_value(RUSTFS_SECRET_KEY));
        assert!(registry.scan("logs", &instance.logs()).is_empty());
        let audit = std::fs::read_to_string(&instance.setup.audit).unwrap_or_default();
        assert!(registry.scan("audit", &audit).is_empty());
    };

    s3_multipart_uploads_complete => |mode: Mode| async move {
        let (_rustfs, port) = rustfs().await;
        let instance = start(mode, Options::default(), &[]).await;
        let secret = instance.setup.seal("secret_key", RUSTFS_SECRET_KEY.as_bytes(), &s3_policy(port, &["computed", "caller_hash", "streaming"], false)).await;
        let sealed = [("secret_key", &secret)];
        let bucket = format!("multipart-{}", rand_suffix());
        let (status, _) = status_and_text(&instance, send_request(Method::PUT, &local(port, &format!("/{bucket}")), &sealed, Vec::new(), &[])).await;
        assert_eq!(status, StatusCode::OK);
        let object = local(port, &format!("/{bucket}/parts.bin"));

        let (status, text) = status_and_text(&instance, send_request(Method::POST, &format!("{object}?uploads"), &sealed, Vec::new(), &[])).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let upload_id = element(&text, "UploadId").to_owned();

        // Every part but the last is at least 5 MiB.
        let parts = [pattern(5 * 1024 * 1024, 1), pattern(1234, 2)];
        let mut etags = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let length = part.len().to_string();
            let url = format!("{object}?partNumber={}&uploadId={upload_id}", index + 1);
            let response = instance.client.send(send_request(Method::PUT, &url, &sealed, part.clone(), &[("content-length", &length)])).await.unwrap();
            assert_eq!(response.response.status(), StatusCode::OK, "part {index}");
            etags.push(response.response.headers()[header::ETAG].to_str().unwrap().to_owned());
            read(response).await.unwrap();
        }
        let complete: String = etags
            .iter()
            .enumerate()
            .map(|(index, etag)| format!("<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>", index + 1))
            .collect();
        let complete = format!("<CompleteMultipartUpload>{complete}</CompleteMultipartUpload>");
        let (status, text) = status_and_text(&instance, send_request(Method::POST, &format!("{object}?uploadId={upload_id}"), &sealed, complete.into_bytes(), &[("content-type", "application/xml")])).await;
        assert_eq!(status, StatusCode::OK, "{text}");

        let response = instance.client.send(get(&object, &sealed)).await.unwrap();
        let body = read(response).await.unwrap();
        assert_eq!(body.len(), parts[0].len() + parts[1].len());
        assert_eq!(&body[..parts[0].len()], &parts[0][..]);
        assert_eq!(&body[parts[0].len()..], &parts[1][..]);
    };

    s3_with_the_wrong_secret_is_the_providers_403 => |mode: Mode| async move {
        let (_rustfs, port) = rustfs().await;
        let instance = start(mode, Options::default(), &[]).await;
        let wrong = instance.setup.seal("secret_key", b"not-the-secret", &s3_policy(port, &["computed"], false)).await;
        let (status, text) = status_and_text(&instance, get(&local(port, "/"), &[("secret_key", &wrong)])).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(text.contains("SignatureDoesNotMatch"), "{text}");
    };
}

container_matrix! {
    s3_metadata_is_stored_and_copies_stay_in_the_bucket => |mode: Mode| async move {
        let (_rustfs, port) = rustfs().await;
        let instance = start(mode, Options::default(), &[]).await;
        let bucket = format!("copies-{}", rand_suffix());
        let admin = instance.setup.seal("secret_key", RUSTFS_SECRET_KEY.as_bytes(), &s3_policy(port, &["computed"], false)).await;
        for name in [&bucket, &format!("{bucket}-other")] {
            let (status, _) = status_and_text(&instance, send_request(Method::PUT, &local(port, &format!("/{name}")), &[("secret_key", &admin)], Vec::new(), &[])).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, _) = status_and_text(&instance, send_request(Method::PUT, &local(port, &format!("/{bucket}-other/secret")), &[("secret_key", &admin)], b"other".to_vec(), &[])).await;
        assert_eq!(status, StatusCode::OK);

        // A secret sent to one bucket's paths.
        let scoped = policy(&json!({ "rules": [{
            "destination": { "scheme": "http", "host": HOST, "port": port, "path_prefix": format!("/{bucket}/") },
            "allow_plain_http": true,
            "inject": { "aws_sigv4": {
                "region": "us-east-1", "service": "s3",
                "access_key_id": { "literal": RUSTFS_ACCESS_KEY },
                "payload": ["computed"],
            } },
        }] }));
        let secret = instance.setup.seal("secret_key", RUSTFS_SECRET_KEY.as_bytes(), &scoped).await;
        let sealed = [("secret_key", &secret)];
        let object = |key: &str| local(port, &format!("/{bucket}/{key}"));

        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("original"), &sealed, b"data".to_vec(), &[("x-amz-meta-owner", "tenant-a"), ("x-amz-storage-class", "STANDARD")])).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let response = instance.client.send(send_request(Method::HEAD, &object("original"), &sealed, Vec::new(), &[])).await.unwrap();
        assert_eq!(response.response.headers()["x-amz-meta-owner"], "tenant-a");
        read(response).await.unwrap();

        let source = format!("/{bucket}/original");
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("copy"), &sealed, Vec::new(), &[("x-amz-copy-source", &source)])).await;
        assert_eq!(status, StatusCode::OK, "copy: {text}");
        let (status, text) = status_and_text(&instance, get(&object("copy"), &sealed)).await;
        assert_eq!((status, text.as_str()), (StatusCode::OK, "data"));

        // The credential can read the other bucket, so a copy from it works: what a
        // credential may read is its own permissions' to say, not the rule's path.
        let outside = format!("/{bucket}-other/secret");
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object("elsewhere"), &sealed, Vec::new(), &[("x-amz-copy-source", &outside)])).await;
        assert_eq!(status, StatusCode::OK, "copy from another bucket: {text}");
        let (status, text) = status_and_text(&instance, get(&object("elsewhere"), &sealed)).await;
        assert_eq!((status, text.as_str()), (StatusCode::OK, "other"));
    };
}

container_matrix! {
    acceptance_a_presigned_s3_url_works_without_seal_and_only_as_signed => |mode: Mode| async move {
        let (_rustfs, port) = rustfs().await;
        let instance = start(mode, Options::default(), &[]).await;
        let mut allowing = serde_json::to_value(s3_policy(port, &["computed"], false)).unwrap();
        allowing["rules"][0]["methods"] = json!(["GET", "PUT"]);
        allowing["rules"][0]["inject"]["aws_sigv4"]["allow_presign"] = json!({ "max_expiry_s": 300 });
        let key = instance.setup.seal("secret_key", RUSTFS_SECRET_KEY.as_bytes(), &policy(&allowing)).await;
        let sealed = [("secret_key", &key)];
        let bucket = format!("bucket-{}", rand_suffix());
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &local(port, &format!("/{bucket}")), &sealed, Vec::new(), &[])).await;
        assert_eq!(status, StatusCode::OK, "create bucket: {text}");
        let object = local(port, &format!("/{bucket}/reports/q3%20final.csv"));
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &object, &sealed, b"through seal".to_vec(), &[])).await;
        assert_eq!(status, StatusCode::OK, "put: {text}");

        // A download, by whoever holds the URL.
        let url = instance.client.presign(presign_request(Method::GET, &object, &sealed, 60)).await.unwrap();
        let (status, body) = fetch_directly("GET", &url, &[], b"").await;
        assert_eq!(status, 200, "{body}");
        assert!(body.ends_with("through seal"), "{body}");

        // The URL is for that object, that method and that signature.
        let other = url.replace("q3%20final.csv", "q4%20final.csv");
        assert_eq!(fetch_directly("GET", &other, &[], b"").await.0, 403);
        assert_eq!(fetch_directly("PUT", &url, &[], b"overwritten").await.0, 403);
        let longer = url.replace("X-Amz-Expires=60", "X-Amz-Expires=600");
        assert_eq!(fetch_directly("GET", &longer, &[], b"").await.0, 403);

        // An upload, then read back through seal.
        let upload = local(port, &format!("/{bucket}/uploads/new.txt"));
        let url = instance.client.presign(presign_request(Method::PUT, &upload, &sealed, 60)).await.unwrap();
        let (status, body) = fetch_directly("PUT", &url, &[], b"uploaded directly").await;
        assert_eq!(status, 200, "{body}");
        let (status, text) = status_and_text(&instance, get(&upload, &sealed)).await;
        assert_eq!((status, text.as_str()), (StatusCode::OK, "uploaded directly"));

        // A response parameter is signed with the rest.
        let named = format!("{object}?response-content-disposition=attachment%3B%20filename%3D%22q3.csv%22");
        let url = instance.client.presign(presign_request(Method::GET, &named, &sealed, 60)).await.unwrap();
        assert_eq!(fetch_directly("GET", &url, &[], b"").await.0, 200);

        // Longer than the rule allows, or with a key whose rule does not allow it at all.
        let error = instance.client.presign(presign_request(Method::GET, &object, &sealed, 301)).await.err().unwrap();
        assert_eq!(error.code, seal_client::ErrorCode::PolicyDenied);
        let plain = instance.setup.seal("secret_key", RUSTFS_SECRET_KEY.as_bytes(), &s3_policy(port, &["computed"], false)).await;
        let error = instance.client.presign(presign_request(Method::GET, &object, &[("secret_key", &plain)], 60)).await.err().unwrap();
        assert_eq!(error.code, seal_client::ErrorCode::PolicyDenied);

        let record = instance.setup.audit_records().into_iter().rev().find(|record| record["op"] == "presign" && record["outcome"] == "ok").unwrap();
        assert_eq!(record["expires_s"], json!(60));
        assert!(!record.to_string().contains("X-Amz-Signature"));
    };

    acceptance_a_blob_shared_access_signature_works_without_seal_and_only_as_signed => |mode: Mode| async move {
        let azurite = containers::azurite().await.expect("Azurite starts");
        let port = azurite.port(10000).unwrap();
        let instance = start(mode, Options::default(), &[]).await;
        let allowing = policy(&json!({ "rules": [{
            "destination": destination(port),
            "allow_plain_http": true,
            "methods": ["GET", "PUT", "DELETE"],
            "inject": { "azure_shared_key": {
                "account": { "literal": AZURITE_ACCOUNT }, "service": "blob",
                "allow_presign": { "max_expiry_s": 300 }
            } },
        }] }));
        let key = instance.setup.seal("account_key", AZURITE_KEY.as_bytes(), &allowing).await;
        let sealed = [("account_key", &key)];
        let suffix: String = rand_suffix().chars().filter(char::is_ascii_alphanumeric).collect();
        let container = format!("c{suffix}");
        let at = |path: &str| local(port, &format!("/{AZURITE_ACCOUNT}/{container}{path}"));
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &at("?restype=container"), &sealed, Vec::new(), &[("content-length", "0")])).await;
        assert_eq!(status, StatusCode::CREATED, "create container: {text}");
        let blob = at("/reports/q3%20final.csv");
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &blob, &sealed, b"through seal".to_vec(), &[("x-ms-blob-type", "BlockBlob"), ("content-length", "12")])).await;
        assert_eq!(status, StatusCode::CREATED, "put blob: {text}");

        // A download, by whoever holds the URL.
        let url = instance.client.presign(presign_request(Method::GET, &blob, &sealed, 60)).await.unwrap();
        let (status, body) = fetch_directly("GET", &url, &[], b"").await;
        assert_eq!(status, 200, "{body}");
        assert!(body.ends_with("through seal"), "{body}");

        // It reads that blob, and nothing else: not another blob, and not a write.
        let other = url.replace("q3%20final.csv", "q4%20final.csv");
        assert_eq!(fetch_directly("GET", &other, &[], b"").await.0, 403);
        let (status, _) = fetch_directly("PUT", &url, &[("x-ms-blob-type", "BlockBlob")], b"overwritten").await;
        assert_eq!(status, 403);
        let wider = url.replace("sp=r", "sp=rw");
        assert_eq!(fetch_directly("GET", &wider, &[], b"").await.0, 403);

        // The response headers the caller asks for are signed with the rest.
        let typed = format!("{blob}?rsct=text/csv%3B%20charset%3Dutf-8&rscd=attachment%3B%20filename%3D%22q3.csv%22");
        let url = instance.client.presign(presign_request(Method::GET, &typed, &sealed, 60)).await.unwrap();
        let (status, response) = fetch_directly("GET", &url, &[], b"").await;
        assert_eq!(status, 200, "{response}");
        let head = response.to_ascii_lowercase();
        assert!(head.contains("content-type: text/csv; charset=utf-8"), "{response}");
        assert!(head.contains("content-disposition: attachment; filename=\"q3.csv\""), "{response}");
        let retyped = url.replace("rsct=text%2Fcsv", "rsct=text%2Fhtml");
        assert_ne!(retyped, *url);
        assert_eq!(fetch_directly("GET", &retyped, &[], b"").await.0, 403);

        // An upload and a delete, each with a signature of its own.
        let upload = at("/uploads/new.txt");
        let url = instance.client.presign(presign_request(Method::PUT, &upload, &sealed, 60)).await.unwrap();
        let (status, body) = fetch_directly("PUT", &url, &[("x-ms-blob-type", "BlockBlob")], b"uploaded directly").await;
        assert_eq!(status, 201, "{body}");
        let (status, text) = status_and_text(&instance, get(&upload, &sealed)).await;
        assert_eq!((status, text.as_str()), (StatusCode::OK, "uploaded directly"));
        let url = instance.client.presign(presign_request(Method::DELETE, &upload, &sealed, 60)).await.unwrap();
        assert_eq!(fetch_directly("DELETE", &url, &[], b"").await.0, 202);
        let (status, _) = status_and_text(&instance, get(&upload, &sealed)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let error = instance.client.presign(presign_request(Method::GET, &blob, &sealed, 301)).await.err().unwrap();
        assert_eq!(error.code, seal_client::ErrorCode::PolicyDenied);
    };
}

// Azure Storage, on Azurite.

fn azure_policy(azurite: &Container) -> Policy {
    let rule = |port: u16, service: &str| {
        json!({
            "destination": destination(port),
            "allow_plain_http": true,
            "inject": { "azure_shared_key": { "account": { "literal": AZURITE_ACCOUNT }, "service": service } },
        })
    };
    policy(&json!({
        "rules": [
            rule(azurite.port(10000).unwrap(), "blob"),
            rule(azurite.port(10001).unwrap(), "queue"),
            rule(azurite.port(10002).unwrap(), "table"),
        ]
    }))
}

container_matrix! {
    azure_blob_queue_and_table_work_with_shared_key => |mode: Mode| async move {
        let azurite = containers::azurite().await.expect("Azurite starts");
        let instance = start(mode, Options::default(), &[]).await;
        let key = instance.setup.seal("account_key", AZURITE_KEY.as_bytes(), &azure_policy(&azurite)).await;
        let sealed = [("account_key", &key)];
        let at = |port: u16, path: &str| local(azurite.port(port).unwrap(), &format!("/{AZURITE_ACCOUNT}{path}"));
        // Table names are letters and digits.
        let suffix: String = rand_suffix().chars().filter(char::is_ascii_alphanumeric).collect();

        // Blob.
        let container = format!("c{suffix}");
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &at(10000, &format!("/{container}?restype=container")), &sealed, Vec::new(), &[("content-length", "0")])).await;
        assert_eq!(status, StatusCode::CREATED, "create container: {text}");
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &at(10000, &format!("/{container}/hello%20world.txt")), &sealed, b"hello".to_vec(), &[("x-ms-blob-type", "BlockBlob"), ("content-type", "text/plain; charset=UTF-8"), ("content-length", "5"), ("x-ms-meta-owner", "seal")])).await;
        assert_eq!(status, StatusCode::CREATED, "put blob: {text}");
        let (status, text) = status_and_text(&instance, get(&at(10000, &format!("/{container}/hello%20world.txt")), &sealed)).await;
        assert_eq!((status, text.as_str()), (StatusCode::OK, "hello"));
        let (status, text) = status_and_text(&instance, get(&at(10000, &format!("/{container}?restype=container&comp=list&include=metadata")), &sealed)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("hello world.txt"), "{text}");

        // Queue.
        let queue = format!("q{suffix}");
        let (status, text) = status_and_text(&instance, send_request(Method::PUT, &at(10001, &format!("/{queue}")), &sealed, Vec::new(), &[("content-length", "0")])).await;
        assert_eq!(status, StatusCode::CREATED, "create queue: {text}");
        let message = b"<QueueMessage><MessageText>hi there</MessageText></QueueMessage>".to_vec();
        let length = message.len().to_string();
        let (status, text) = status_and_text(&instance, send_request(Method::POST, &at(10001, &format!("/{queue}/messages")), &sealed, message, &[("content-length", &length), ("content-type", "application/xml")])).await;
        assert_eq!(status, StatusCode::CREATED, "put message: {text}");
        let (status, text) = status_and_text(&instance, get(&at(10001, &format!("/{queue}/messages?numofmessages=1")), &sealed)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("hi there"), "{text}");

        // Table, with its own string to sign.
        let table = format!("t{suffix}");
        let json_headers: [(&'static str, &str); 3] = [
            ("content-type", "application/json"),
            ("accept", "application/json;odata=nometadata"),
            ("dataserviceversion", "3.0;NetFx"),
        ];
        let create = json!({ "TableName": table }).to_string().into_bytes();
        let (status, text) = status_and_text(&instance, send_request(Method::POST, &at(10002, "/Tables"), &sealed, create, &json_headers)).await;
        assert_eq!(status, StatusCode::CREATED, "create table: {text}");
        let entity = json!({ "PartitionKey": "p", "RowKey": "r", "Value": "from seal" }).to_string().into_bytes();
        let (status, text) = status_and_text(&instance, send_request(Method::POST, &at(10002, &format!("/{table}")), &sealed, entity, &json_headers)).await;
        assert_eq!(status, StatusCode::CREATED, "insert: {text}");
        let (status, text) = status_and_text(&instance, send_request(Method::GET, &at(10002, &format!("/{table}()?$filter=PartitionKey%20eq%20%27p%27")), &sealed, Vec::new(), &json_headers[1..])).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("from seal"), "{text}");
    };

    azure_with_the_wrong_key_is_the_providers_403 => |mode: Mode| async move {
        let azurite = containers::azurite().await.expect("Azurite starts");
        let instance = start(mode, Options::default(), &[]).await;
        let wrong = instance.setup.seal("account_key", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", &azure_policy(&azurite)).await;
        let url = local(azurite.port(10000).unwrap(), &format!("/{AZURITE_ACCOUNT}?comp=list"));
        let (status, _) = status_and_text(&instance, get(&url, &[("account_key", &wrong)])).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    };
}

/// A bucket in RustFS for seal's own keys, behind TLS, which the key source insists
/// on. It keeps versions.
struct KeyBucket {
    _container: Container,
    _proxy: seal_testkit::tls_proxy::TlsProxy,
    _directory: tempfile::TempDir,
    /// The key source, as `keys.source` is written.
    source: String,
}

/// One signed request to RustFS itself, for what seal never does: making the bucket.
async fn rustfs_admin(port: u16, method: &str, path: &str, query: &str, body: &[u8]) {
    use seal_keys::civil::Civil;
    use seal_keys::sigv4::{
        ALGORITHM, CanonicalParts, canonical_request, scope, sha256_hex, signature, signing_key,
        string_to_sign,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let civil = Civil::at(std::time::SystemTime::now());
    let (amz_date, date_stamp) = (civil.amz_date(), civil.date_stamp());
    let (host, payload_hash) = (format!("127.0.0.1:{port}"), sha256_hex(body));
    let headers = [
        ("host".to_owned(), host.clone()),
        ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
        ("x-amz-date".to_owned(), amz_date.clone()),
    ];
    let (canonical, signed) = canonical_request(&CanonicalParts {
        method,
        uri: path.to_owned(),
        query: query.to_owned(),
        headers: &headers,
        payload_hash: &payload_hash,
    });
    let scope = scope(&date_stamp, "us-east-1", "s3");
    let key = signing_key(RUSTFS_SECRET_KEY.as_bytes(), &date_stamp, "us-east-1", "s3");
    let signature = signature(&key, &string_to_sign(&amz_date, &scope, &canonical));
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nx-amz-content-sha256: {payload_hash}\r\n\
         x-amz-date: {amz_date}\r\nAuthorization: {ALGORITHM} Credential={RUSTFS_ACCESS_KEY}/{scope}, \
         SignedHeaders={signed}, Signature={signature}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut response),
    )
    .await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "{method} {target}: {response}"
    );
}

async fn key_bucket() -> KeyBucket {
    use std::os::unix::fs::PermissionsExt;

    let (container, port) = rustfs().await;
    rustfs_admin(port, "PUT", "/seal-keys", "", b"").await;
    rustfs_admin(
        port,
        "PUT",
        "/seal-keys",
        "versioning=",
        b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
          <Status>Enabled</Status></VersioningConfiguration>",
    )
    .await;
    let proxy = seal_testkit::tls_proxy::TlsProxy::start(port).await;
    let directory = tempfile::tempdir().unwrap();
    let (credentials, ca) = (
        directory.path().join("s3-credentials"),
        directory.path().join("s3-ca.crt"),
    );
    std::fs::write(
        &credentials,
        format!(
            "[default]\naws_access_key_id = {RUSTFS_ACCESS_KEY}\n\
             aws_secret_access_key = {RUSTFS_SECRET_KEY}\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&ca, proxy.ca_pem()).unwrap();
    let source = format!(
        "{{ s3 = {{ endpoint = \"https://localhost:{}\", region = \"us-east-1\", \
         bucket = \"seal-keys\", prefix = \"keys/\", credentials_file = {credentials:?}, \
         ca = {ca:?} }} }}",
        proxy.port()
    );
    KeyBucket {
        _container: container,
        _proxy: proxy,
        _directory: directory,
        source,
    }
}

/// Uses a sealed bearer token through a client, and checks what the provider was sent.
async fn uses(
    client: &dyn seal_client::SealClient,
    provider: &seal_testkit::mock_provider::MockProvider,
    token: &Envelope,
    expected: &str,
) {
    let response = client
        .send(get(&url(provider, "/quiet"), &[("token", token)]))
        .await
        .unwrap();
    assert_eq!(response.response.status(), 200);
    text(response).await;
    let received = provider.received();
    assert_eq!(
        received.last().unwrap().header("authorization"),
        Some(expected)
    );
}

container_matrix! {
    // seal itself, started as it is deployed, with its keys in a bucket: two instances
    // that share nothing else, the wrapping key replaced while they run, and a keyset
    // destroyed.
    seal_serves_with_its_keys_in_a_bucket => |mode: Mode| async move {
        use seal_testkit::mock_provider::MockProvider;

        let bucket = key_bucket().await;
        let provider = MockProvider::plain().await;
        let options = Options {
            source: Some(bucket.source.clone()),
            // So that an instance sees soon what another did.
            keys: "refresh_interval = \"1s\"\nmax_stale = \"5s\"\n".to_owned(),
            ..Options::default()
        };
        // The setup makes the keysets, which puts their keys in the bucket.
        let instance = start(mode, options.clone(), &[&provider]).await;
        let setup = &instance.setup;
        let keys_dir_is_unused = std::fs::read_dir(&setup.keys_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(keys_dir_is_unused, 0, "the keys are in the bucket, not on disk");
        let rule = policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }));
        // An instance uses a credential sealed to a key that is in the bucket.
        let token = setup.seal("token", b"SEALCANARY-bucket-1", &rule).await;
        uses(instance.client.as_ref(), &provider, &token, "Bearer SEALCANARY-bucket-1").await;

        // A second instance, with the same bucket and nothing else of the first, uses it
        // too.
        let (second, _second_process) = connect(mode, &options, setup).await;
        uses(second.as_ref(), &provider, &token, "Bearer SEALCANARY-bucket-1").await;

        // A key rotated through one instance is used by the other.
        let rotated = instance.client.rotate(&keyset()).await.unwrap();
        assert_eq!(setup.current_key().await.0.as_str(), rotated.kid);
        let newer = setup.seal("token", b"SEALCANARY-bucket-2", &rule).await;
        assert_eq!(newer.kid().as_str(), rotated.kid);
        uses(second.as_ref(), &provider, &newer, "Bearer SEALCANARY-bucket-2").await;

        // The wrapping key is replaced with the command, in the bucket, while instances
        // run.
        let run = |arguments: &[&std::ffi::OsStr]| {
            std::process::Command::new(env!("CARGO_BIN_EXE_seal"))
                .args(arguments)
                .output()
                .unwrap()
        };
        let new_kek = setup.dir.path().join("kek-2");
        assert!(
            run(&["keygen".as_ref(), "--wrapping-key".as_ref(), new_kek.as_ref()])
                .status
                .success()
        );
        let text_of = |options: &Options| {
            setup.config_text(Mode::Unix, options, "[listen]\nunix = \"/unused\"\n")
        };
        let old_wrap = format!("wrap = {{ file = {:?} }}", setup.kek.display().to_string());
        assert!(text_of(&options).contains(&old_wrap));
        // First, every instance learns the new wrapping key, as the guide says.
        let knowing = Options {
            keys: format!(
                "{}unwrap_also = [{{ file = {new_kek:?} }}]\n",
                options.keys
            ),
            ..options.clone()
        };
        let (third, _third_process) = connect(mode, &knowing, setup).await;
        uses(third.as_ref(), &provider, &newer, "Bearer SEALCANARY-bucket-2").await;
        // Then the new one is current, and the keys are wrapped again.
        let both = write_config(
            setup,
            &text_of(&options).replace(
                &old_wrap,
                &format!(
                    "wrap = {{ file = {new_kek:?} }}\nunwrap_also = [{{ file = {:?} }}]",
                    setup.kek.display().to_string()
                ),
            ),
        );
        let done = run(&["rewrap".as_ref(), "--config".as_ref(), both.as_ref()]);
        assert!(
            done.status.success(),
            "{}",
            String::from_utf8_lossy(&done.stderr)
        );
        let said = String::from_utf8_lossy(&done.stdout).into_owned();
        assert!(said.contains("re-wrapped 3 keys and left 0"), "{said}");
        // The instance that knows both wrapping keys reads the new forms once it has
        // refreshed, and still uses values sealed before and after the rotation.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        uses(third.as_ref(), &provider, &token, "Bearer SEALCANARY-bucket-1").await;
        uses(third.as_ref(), &provider, &newer, "Bearer SEALCANARY-bucket-2").await;
        // With the new wrapping key alone, seal reads every key in the bucket.
        let only_new = write_config(
            setup,
            &text_of(&options).replace(&old_wrap, &format!("wrap = {{ file = {new_kek:?} }}")),
        );
        let dry = run(&[
            "rewrap".as_ref(),
            "--config".as_ref(),
            only_new.as_ref(),
            "--dry-run".as_ref(),
        ]);
        assert!(
            dry.status.success(),
            "{}",
            String::from_utf8_lossy(&dry.stderr)
        );
        let said = String::from_utf8_lossy(&dry.stdout).into_owned();
        assert!(said.contains("would re-wrap 0 keys and leave 3"), "{said}");

        // A keyset is destroyed with the command, and nothing of it is left to read.
        let destroyed = run(&[
            "destroy-keyset".as_ref(),
            "--config".as_ref(),
            only_new.as_ref(),
            "--keyset".as_ref(),
            "acme".as_ref(),
            "--confirm".as_ref(),
            "acme".as_ref(),
        ]);
        assert!(
            destroyed.status.success(),
            "{}",
            String::from_utf8_lossy(&destroyed.stderr)
        );
        let config = seal::config::Config::parse(&std::fs::read_to_string(&only_new).unwrap()).unwrap();
        let (source, _) = seal::serve::key_parts(&config).unwrap();
        assert!(source.wrapped_keys(&keyset()).await.unwrap().is_empty());
        assert_eq!(source.keysets().await.unwrap(), [platform()]);
        // Within `max_stale`, the running instances stop using it.
        tokio::time::sleep(std::time::Duration::from_secs(7)).await;
        let error = third
            .send(get(&url(&provider, "/quiet"), &[("token", &newer)]))
            .await
            .err()
            .expect("a destroyed keyset opens nothing");
        assert!(
            matches!(
                error.code,
                seal_client::ErrorCode::KeysetUnknown | seal_client::ErrorCode::KeysUnavailable
            ),
            "{error}"
        );
    };
}
