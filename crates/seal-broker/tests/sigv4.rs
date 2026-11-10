//! SigV4 signing in the broker: each payload mode, header refusal, and every
//! signature the provider receives checked with the AWS SDK's own signer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use bytes::Bytes;
use http::{HeaderValue, Method, header};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use seal_broker::client::RequestBody;
use seal_broker::{BrokerError, ErrorCode, Limits};
use seal_format::policy::Policy;
use seal_testkit::mock_provider::Received;
use serde_json::{Value, json};
use support::{
    Harness, MockProvider, Options, field, plain_rule, read_body, request, rule_policy, url,
};

const KEY_ID: &str = "AKIDEXAMPLE";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

fn aws(provider: &MockProvider, payload: &[&str], allow_unsigned: bool) -> Value {
    let mut inject = json!({
        "aws_sigv4": {
            "region": "us-east-1",
            "service": "s3",
            "access_key_id": { "literal": KEY_ID },
            "payload": payload,
        }
    });
    if allow_unsigned {
        inject["aws_sigv4"]["allow_unsigned_payload"] = json!(true);
    }
    plain_rule(provider, &inject)
}

fn policy(rule: &Value) -> Policy {
    rule_policy(rule)
}

fn harness_with_cap(cap: u64) -> Harness {
    let mut options = Options::default();
    options.limits = Limits {
        buffer_cap: cap,
        ..options.limits
    };
    Harness::with(options)
}

fn put(
    harness: &Harness,
    provider: &MockProvider,
    policy: &Policy,
    body: RequestBody,
) -> seal_broker::SendRequest {
    let secret = harness.seal("secret_key", SECRET, policy);
    let mut send = request(
        &url(provider, "/bucket/my%20key"),
        &[("secret_key", &secret)],
    );
    send.method = Method::PUT;
    send.body = body;
    send
}

/// A body that arrives in these frames, without a declared length.
struct Frames(VecDeque<Bytes>);

impl Body for Frames {
    type Data = Bytes;
    type Error = BrokerError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BrokerError>>> {
        Poll::Ready(
            self.get_mut()
                .0
                .pop_front()
                .map(|bytes| Ok(Frame::data(bytes))),
        )
    }
}

fn frames(sizes: &[usize]) -> (RequestBody, Vec<u8>) {
    let mut all = Vec::new();
    let mut parts = VecDeque::new();
    for (index, size) in sizes.iter().enumerate() {
        let part: Vec<u8> = (0..*size).map(|n| (n * 31 + index) as u8).collect();
        all.extend_from_slice(&part);
        parts.push_back(Bytes::from(part));
    }
    (Frames(parts).boxed_unsync(), all)
}

fn set_length(send: &mut seal_broker::SendRequest, length: usize) {
    send.headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
}

/// Checks the received `Authorization` with the AWS SDK, signing the same headers.
fn assert_signed_as_the_sdk_would(received: &Received, port: u16) {
    let authorization = received.header("authorization").expect("signed");
    let signed_headers = authorization
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    let headers: Vec<(&str, &str)> = signed_headers
        .split(';')
        .map(|name| (name, received.header(name).unwrap()))
        .collect();
    let amz_date = received.header("x-amz-date").unwrap();
    let seconds = {
        // 20150830T123600Z
        let civil = |range: std::ops::Range<usize>| amz_date[range].parse::<i64>().unwrap();
        let (year, month, day) = (civil(0..4), civil(4..6), civil(6..8));
        let (hour, minute, second) = (civil(9..11), civil(11..13), civil(13..15));
        let days = {
            let y = if month <= 2 { year - 1 } else { year };
            let era = y.div_euclid(400);
            let yoe = y - era * 400;
            let mp = (month + 9) % 12;
            let doy = (153 * mp + 2) / 5 + day - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            era * 146_097 + doe - 719_468
        };
        u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).unwrap()
    };
    let identity = Credentials::new(
        KEY_ID,
        std::str::from_utf8(SECRET).unwrap(),
        received.header("x-amz-security-token").map(str::to_owned),
        None,
        "test",
    )
    .into();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(std::time::UNIX_EPOCH + Duration::from_secs(seconds))
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let hash = received.header("x-amz-content-sha256").unwrap().to_owned();
    let request = SignableRequest::new(
        &received.method,
        format!("http://{}:{port}{}", support::HOST, received.uri),
        headers
            .into_iter()
            // The SDK adds these itself.
            .filter(|(name, _)| {
                !matches!(
                    *name,
                    "x-amz-date" | "x-amz-content-sha256" | "x-amz-security-token"
                )
            }),
        SignableBody::Precomputed(hash),
    )
    .unwrap();
    let (instructions, _) = sign(request, &params).unwrap().into_parts();
    let (expected, _) = instructions.into_parts();
    let expected = expected
        .iter()
        .find(|header| header.name() == "authorization")
        .unwrap()
        .value();
    assert_eq!(authorization, expected);
}

fn sha256_hex(bytes: &[u8]) -> String {
    seal_broker::inject::sigv4::sha256_hex(bytes)
}

#[tokio::test]
async fn a_small_body_is_hashed_by_seal_and_signed() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let policy = policy(&aws(&provider, &["computed"], false));
    let mut send = put(
        &harness,
        &provider,
        &policy,
        support::request_body(b"hello"),
    );
    send.headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();

    let received = &provider.received()[0];
    assert_eq!(received.body, b"hello");
    assert_eq!(
        received.header("x-amz-content-sha256"),
        Some(sha256_hex(b"hello").as_str())
    );
    assert!(received.header("authorization").unwrap().contains(
        "SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date,"
    ));
    assert_signed_as_the_sdk_would(received, provider.port());
    let text = format!("{:?}", received.headers);
    assert!(!text.contains("wJalr"), "the secret key is never sent");
}

#[tokio::test]
async fn the_callers_hash_is_signed_and_the_body_streams() {
    let provider = MockProvider::plain().await;
    let harness = harness_with_cap(1024);
    let policy = policy(&aws(&provider, &["caller_hash"], false));
    let (body, all) = frames(&[3000, 5000, 1]);
    let mut send = put(&harness, &provider, &policy, body);
    let hash = sha256_hex(&all);
    send.headers.insert(
        "x-amz-content-sha256",
        HeaderValue::from_str(&hash).unwrap(),
    );
    set_length(&mut send, all.len());
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();

    let received = &provider.received()[0];
    assert_eq!(received.body, all, "over the cap, so it was not buffered");
    assert_eq!(received.header("x-amz-content-sha256"), Some(hash.as_str()));
    assert_signed_as_the_sdk_would(received, provider.port());
}

#[tokio::test]
async fn a_large_body_is_signed_in_chunks() {
    let provider = MockProvider::plain().await;
    let harness = harness_with_cap(1024);
    let policy = policy(&aws(&provider, &["computed", "streaming"], false));
    let (body, all) = frames(&[100, 70_000, 65_536, 3, 60_000]);
    let mut send = put(&harness, &provider, &policy, body);
    set_length(&mut send, all.len());
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();

    let received = &provider.received()[0];
    assert_eq!(
        received.header("x-amz-content-sha256"),
        Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
    );
    assert_eq!(received.header("content-encoding"), Some("aws-chunked"));
    assert_eq!(
        received.header("x-amz-decoded-content-length"),
        Some(all.len().to_string().as_str())
    );
    assert_eq!(
        received.header("content-length"),
        Some(
            seal_broker::inject::sigv4::framed_length(all.len() as u64)
                .unwrap()
                .to_string()
                .as_str()
        )
    );
    assert_signed_as_the_sdk_would(received, provider.port());

    // Unframe: every chunk but the last is 64 KiB, and the data is the caller's.
    let mut rest = received.body.as_slice();
    let mut decoded = Vec::new();
    let mut sizes = Vec::new();
    loop {
        let end = rest.windows(2).position(|pair| pair == b"\r\n").unwrap();
        let line = std::str::from_utf8(&rest[..end]).unwrap();
        let (size, signature) = line.split_once(";chunk-signature=").unwrap();
        assert_eq!(signature.len(), 64);
        let size = usize::from_str_radix(size, 16).unwrap();
        sizes.push(size);
        decoded.extend_from_slice(&rest[end + 2..end + 2 + size]);
        assert_eq!(&rest[end + 2 + size..end + 4 + size], b"\r\n");
        rest = &rest[end + 4 + size..];
        if size == 0 {
            break;
        }
    }
    assert!(rest.is_empty());
    assert_eq!(decoded, all);
    assert_eq!(sizes, [65_536, 65_536, 64_567, 0]);
}

#[tokio::test]
async fn a_body_shorter_or_longer_than_declared_fails_the_request() {
    for declared in [10_000_usize, 30_000] {
        let provider = MockProvider::plain().await;
        let harness = harness_with_cap(1024);
        let policy = policy(&aws(&provider, &["streaming"], false));
        let (body, _) = frames(&[20_000]);
        let mut send = put(&harness, &provider, &policy, body);
        set_length(&mut send, declared);
        let result = match harness.broker.send(send).await {
            Ok(response) => read_body(response).await.map(|_| ()),
            Err(error) => Err(error),
        };
        assert!(result.is_err(), "declared {declared}");
    }
}

#[tokio::test]
async fn an_unknown_length_is_sent_unsigned_where_the_rule_allows() {
    let provider = MockProvider::plain().await;
    let harness = harness_with_cap(1024);
    let policy = policy(&aws(&provider, &["streaming"], true));
    let (body, all) = frames(&[5000, 5000]);
    let send = put(&harness, &provider, &policy, body);
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[0];
    assert_eq!(received.body, all);
    assert_eq!(
        received.header("x-amz-content-sha256"),
        Some("UNSIGNED-PAYLOAD")
    );
    assert_signed_as_the_sdk_would(received, provider.port());
}

#[tokio::test]
async fn a_body_over_the_cap_with_only_a_computed_hash_is_refused_before_dns() {
    let provider = MockProvider::plain().await;
    let harness = harness_with_cap(1024);
    let policy = policy(&aws(&provider, &["computed"], false));
    let (body, all) = frames(&[5000]);
    let mut send = put(&harness, &provider, &policy, body);
    set_length(&mut send, all.len());
    let error = harness.broker.send(send).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BodyTooLarge);
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));

    // Without a declared length it is read, and refused at the cap.
    let (body, _) = frames(&[5000]);
    let send = put(&harness, &provider, &policy, body);
    let error = harness.broker.send(send).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BodyTooLarge);
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

#[tokio::test]
async fn caller_set_amz_headers_are_refused_before_dns() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let cases: [(&[&str], &str, &str, ErrorCode); 7] = [
        (
            &["computed"],
            "x-amz-acl",
            "public-read",
            ErrorCode::Conflict,
        ),
        (
            &["computed"],
            "x-amz-date",
            "20150830T123600Z",
            ErrorCode::Conflict,
        ),
        (
            &["computed"],
            "x-amz-security-token",
            "t",
            ErrorCode::Conflict,
        ),
        (
            &["computed"],
            "x-amz-content-sha256",
            sha256_hex(b"").leak(),
            ErrorCode::Conflict,
        ),
        (
            &["computed"],
            "authorization",
            "AWS4-HMAC-SHA256 x",
            ErrorCode::Conflict,
        ),
        (
            &["caller_hash"],
            "x-amz-content-sha256",
            "UNSIGNED-PAYLOAD",
            ErrorCode::BadRequest,
        ),
        (
            &["caller_hash"],
            "x-amz-content-sha256",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ErrorCode::BadRequest,
        ),
    ];
    for (payload, name, value, code) in cases {
        let policy = policy(&aws(&provider, payload, true));
        let mut send = put(&harness, &provider, &policy, support::request_body(b""));
        send.headers.insert(name, HeaderValue::from_static(value));
        let error = harness.broker.send(send).await.err().unwrap();
        assert_eq!(error.code(), code, "{name}: {value}");
    }
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

#[tokio::test]
async fn a_sealed_session_token_is_sent_and_signed() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let mut rule = aws(&provider, &["computed"], false);
    rule["inject"]["aws_sigv4"]["session_token"] = json!({ "field": "session_token" });
    let mut companion = plain_rule(&provider, &json!({ "companion": {} }));
    companion["destination"] = rule["destination"].clone();
    let secret = harness.seal("secret_key", SECRET, &policy(&rule));
    let token = harness.seal(
        "session_token",
        b"FwoGZXIvYXdzEXAMPLE+/=",
        &rule_policy(&companion),
    );
    let send = request(
        &url(&provider, "/bucket/key"),
        &[("secret_key", &secret), ("session_token", &token)],
    );
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[0];
    assert_eq!(
        received.header("x-amz-security-token"),
        Some("FwoGZXIvYXdzEXAMPLE+/=")
    );
    assert_signed_as_the_sdk_would(received, provider.port());
    let _ = field("secret_key");
}

const ASSUME_ROLE: &[u8] =
    br#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMPORARY</AccessKeyId>
      <SecretAccessKey>temporary-secret-key</SecretAccessKey>
      <SessionToken>temporary-session-token</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#;

/// STS: AssumeRole, signed with long-term keys, returns temporary ones that seal
/// seals from the XML; those then sign requests to S3 and nowhere else.
#[tokio::test]
async fn assume_role_credentials_are_sealed_and_then_sign_s3_requests() {
    let provider = MockProvider::plain().await;
    provider.respond("/sts", support::CannedResponse::ok("text/xml", ASSUME_ROLE));
    let harness = Harness::new();
    let credentials = "AssumeRoleResponse/AssumeRoleResult/Credentials";
    let mut sts = aws(&provider, &["computed"], false);
    sts["inject"]["aws_sigv4"]["service"] = json!("sts");
    sts["destination"]["path_prefix"] = json!("/sts");
    sts["seal_response"] = json!({
        "format": "xml",
        "fields": [
            { "at": format!("{credentials}/SecretAccessKey"), "as": "secret_key", "policy": "s3" },
            { "at": format!("{credentials}/SessionToken"), "as": "session_token", "policy": "s3_token" },
        ]
    });
    let mut s3 = aws(&provider, &["computed"], false);
    s3["destination"]["path_prefix"] = json!("/bucket");
    s3["inject"]["aws_sigv4"]["access_key_id"] = json!({ "field": "access_key_id" });
    s3["inject"]["aws_sigv4"]["session_token"] = json!({ "field": "session_token" });
    s3["plain"] = json!(["access_key_id"]);
    let mut companion = plain_rule(&provider, &json!({ "companion": {} }));
    companion["destination"]["path_prefix"] = json!("/bucket");
    let policy = Policy::from_json(
        json!({
            "rules": [sts],
            "definitions": {
                "s3": { "rules": [s3] },
                "s3_token": { "rules": [companion] },
            }
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();

    let long_term = harness.seal("secret_key", SECRET, &policy);
    let mut assume = request(&url(&provider, "/sts"), &[("secret_key", &long_term)]);
    assume.method = Method::POST;
    assume.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    assume.body = support::request_body(
        b"Action=AssumeRole&Version=2011-06-15&RoleArn=arn&RoleSessionName=s",
    );
    let response = harness.broker.send(assume).await.unwrap();
    let sealed = response.sealed_fields.clone();
    let body = String::from_utf8(read_body(response).await.unwrap().to_vec()).unwrap();
    assert!(!body.contains("temporary-secret-key") && !body.contains("temporary-session-token"));
    assert!(
        body.contains("<AccessKeyId>ASIATEMPORARY</AccessKeyId>"),
        "not secret, so readable"
    );
    assert!(
        provider.received()[0]
            .header("authorization")
            .unwrap()
            .contains("/us-east-1/sts/aws4_request")
    );

    let mut get = request(
        &url(&provider, "/bucket/key"),
        &[
            ("secret_key", &sealed[&field("secret_key")]),
            ("session_token", &sealed[&field("session_token")]),
        ],
    );
    get.plain
        .insert(field("access_key_id"), "ASIATEMPORARY".to_owned());
    read_body(harness.broker.send(get).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[1];
    assert_eq!(
        received.header("x-amz-security-token"),
        Some("temporary-session-token")
    );
    assert!(
        received
            .header("authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential=ASIATEMPORARY/")
    );

    // The temporary key cannot go back to STS.
    let mut again = request(
        &url(&provider, "/sts"),
        &[("secret_key", &sealed[&field("secret_key")])],
    );
    again.method = Method::POST;
    assert_eq!(
        harness.broker.send(again).await.err().unwrap().code(),
        ErrorCode::PolicyDenied
    );
}

#[tokio::test]
async fn ordinary_amz_headers_are_signed_and_sent() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let policy = policy(&aws(&provider, &["computed"], false));
    let mut send = put(&harness, &provider, &policy, support::request_body(b"data"));
    for (name, value) in [
        ("x-amz-meta-owner", "tenant-a"),
        ("x-amz-storage-class", "STANDARD_IA"),
        ("x-amz-server-side-encryption", "AES256"),
    ] {
        send.headers.insert(name, HeaderValue::from_static(value));
    }
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[0];
    assert_eq!(received.header("x-amz-meta-owner"), Some("tenant-a"));
    assert!(received.header("authorization").unwrap().contains(
        "SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date;x-amz-meta-owner;x-amz-server-side-encryption;x-amz-storage-class,"
    ));
    assert_signed_as_the_sdk_would(received, provider.port());
}

#[tokio::test]
async fn a_copy_within_the_prefix_is_signed_and_one_outside_is_refused_before_dns() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let mut rule = aws(&provider, &["computed"], false);
    rule["destination"]["path_prefix"] = json!("/bucket/");
    rule["inject"]["aws_sigv4"]["allow_headers"] = json!(["x-amz-copy-source"]);
    let policy = policy(&rule);
    let copy = |source: &'static str| {
        let mut send = put(&harness, &provider, &policy, support::request_body(b""));
        send.url = url(&provider, "/bucket/copy");
        send.headers
            .insert("x-amz-copy-source", HeaderValue::from_static(source));
        send.headers
            .insert("x-amz-metadata-directive", HeaderValue::from_static("COPY"));
        send
    };
    read_body(harness.broker.send(copy("/bucket/original")).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[0];
    assert_eq!(
        received.header("x-amz-copy-source"),
        Some("/bucket/original")
    );
    assert_signed_as_the_sdk_would(received, provider.port());

    let lookups = harness.lookups();
    let error = harness
        .broker
        .send(copy("/other/secret"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    let mut twice = copy("/bucket/original");
    twice.headers.append(
        "x-amz-copy-source",
        HeaderValue::from_static("/other/secret"),
    );
    let error = harness.broker.send(twice).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!(harness.lookups(), lookups);
    assert_eq!(provider.received().len(), 1);
}
