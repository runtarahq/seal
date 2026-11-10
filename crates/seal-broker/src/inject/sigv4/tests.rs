#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::Value;

use super::*;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigv4")
}

struct Case {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Reads a vector's `request.txt`: a request line, headers with folded continuation
/// lines, a blank line and the body.
fn parse_request(text: &str) -> Case {
    let mut lines = text.split('\n');
    let request_line = lines.next().unwrap();
    let (method, rest) = request_line.split_once(' ').unwrap();
    let target = rest.strip_suffix(" HTTP/1.1").unwrap();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = Vec::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            if !body.is_empty() {
                body.push(b'\n');
            }
            body.extend_from_slice(line.as_bytes());
        } else if line.is_empty() {
            in_body = true;
        } else if line.starts_with(' ') {
            let last = headers.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(line.trim());
        } else {
            let (name, value) = line.split_once(':').unwrap();
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    Case {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
    }
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap()
}

#[test]
fn the_aws_signing_test_suite_passes() {
    let mut checked = 0;
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let context: Value = serde_json::from_str(&read(&dir, "context.json")).unwrap();
        let mut case = parse_request(&read(&dir, "request.txt"));
        let now = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        assert_eq!(context["timestamp"], "2015-08-30T12:36:00Z");
        let civil = Civil::at(now);

        case.headers
            .push(("X-Amz-Date".to_owned(), civil.amz_date()));
        if let Some(token) = context["credentials"]["token"].as_str() {
            case.headers
                .push(("X-Amz-Security-Token".to_owned(), token.to_owned()));
        }
        let payload_hash = sha256_hex(&case.body);
        if context["sign_body"] == true {
            case.headers
                .push(("X-Amz-Content-SHA256".to_owned(), payload_hash.clone()));
        }

        let parts = CanonicalParts {
            method: &case.method,
            uri: canonical_uri(&case.path, false),
            query: canonical_query(&case.query),
            headers: &case.headers,
            payload_hash: &payload_hash,
        };
        let (request, _) = canonical_request(&parts);
        assert_eq!(
            request.as_str(),
            read(&dir, "header-canonical-request.txt"),
            "{name}"
        );

        let region = context["region"].as_str().unwrap();
        let service = context["service"].as_str().unwrap();
        let to_sign = string_to_sign(
            &civil.amz_date(),
            &scope(&civil.date_stamp(), region, service),
            &request,
        );
        assert_eq!(to_sign, read(&dir, "header-string-to-sign.txt"), "{name}");

        let secret = context["credentials"]["secret_access_key"]
            .as_str()
            .unwrap();
        let key = signing_key(secret.as_bytes(), &civil.date_stamp(), region, service);
        assert_eq!(
            signature(&key, &to_sign),
            read(&dir, "header-signature.txt").trim(),
            "{name}"
        );
        checked += 1;
    }
    assert_eq!(checked, 27);
}

const S3_KEY_ID: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
const S3_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// 2013-05-24T00:00:00Z, the date of the S3 examples.
fn may_24_2013() -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_369_353_600)
}

fn s3_signer(payload: Payload, session_token: Option<&[u8]>) -> Signer {
    Signer::new(SignerParts {
        secret: S3_SECRET,
        access_key_id: S3_KEY_ID,
        session_token: session_token.map(|token| Zeroizing::new(token.to_vec())),
        region: "us-east-1",
        service: "s3",
        now: may_24_2013(),
        payload,
    })
    .unwrap()
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, HeaderValue::from_str(value).unwrap());
    }
    map
}

fn signature_of(headers: &HeaderMap) -> String {
    let authorization = headers["authorization"].to_str().unwrap();
    authorization
        .rsplit_once("Signature=")
        .unwrap()
        .1
        .to_owned()
}

/// "Example: GET Object" in the Amazon S3 API reference.
#[test]
fn the_s3_get_object_example_signs_as_documented() {
    let signer = s3_signer(Payload::Computed, None);
    let mut map = headers(&[
        ("host", "examplebucket.s3.amazonaws.com"),
        ("range", "bytes=0-9"),
    ]);
    signer
        .sign("GET", "/test.txt", "", &mut map, Some(b""))
        .unwrap();
    assert_eq!(
        signature_of(&map),
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert_eq!(
        map["authorization"].to_str().unwrap(),
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
         SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
         Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert!(map["authorization"].is_sensitive());
    assert_eq!(map["x-amz-content-sha256"], EMPTY_SHA256);
    assert_eq!(map["x-amz-date"], "20130524T000000Z");
}

/// "Example: PUT Object" with chunked signing, in the Amazon S3 API reference.
#[test]
fn the_s3_chunked_upload_example_signs_as_documented() {
    assert_eq!(framed_length(66_560), 66_824);
    let signer = s3_signer(
        Payload::Streaming {
            decoded_length: 66_560,
        },
        None,
    );
    let mut map = headers(&[
        ("host", "s3.amazonaws.com"),
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("content-encoding", "aws-chunked"),
        ("content-length", "66824"),
    ]);
    let seed = signer
        .sign("PUT", "/examplebucket/chunkObject.txt", "", &mut map, None)
        .unwrap();
    assert_eq!(
        seed.as_str(),
        "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
    );
    assert_eq!(map["x-amz-content-sha256"], STREAMING_PAYLOAD);
    assert_eq!(map["x-amz-decoded-content-length"], "66560");

    let mut chunks = signer.chunks(seed);
    let first = chunks.frame(&[b'a'; 65_536]);
    let second = chunks.frame(&[b'a'; 1024]);
    let last = chunks.frame(&[]);
    let header = |framed: &[u8]| {
        let end = framed.windows(2).position(|pair| pair == b"\r\n").unwrap();
        String::from_utf8(framed[..end].to_vec()).unwrap()
    };
    assert_eq!(
        header(&first),
        "10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"
    );
    assert_eq!(
        header(&second),
        "400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"
    );
    assert_eq!(
        header(&last),
        "0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"
    );
    assert_eq!(
        (first.len() + second.len() + last.len()) as u64,
        framed_length(66_560)
    );
}

#[test]
fn framed_lengths_add_up_for_every_shape() {
    for decoded in [
        0_u64,
        1,
        65_535,
        65_536,
        65_537,
        131_072,
        5 * 1024 * 1024 * 1024,
    ] {
        let size = CHUNK_SIZE as u64;
        let mut expected = 0;
        let mut left = decoded;
        while left > 0 {
            let chunk = left.min(size);
            expected += format!("{chunk:x}").len() as u64 + 85 + chunk;
            left -= chunk;
        }
        expected += 1 + 85;
        assert_eq!(framed_length(decoded), expected, "{decoded}");
    }
}

#[test]
fn a_session_token_is_signed_and_marked_sensitive() {
    let signer = s3_signer(Payload::Unsigned, Some(b"token/with+chars=="));
    let mut map = headers(&[("host", "bucket.s3.amazonaws.com")]);
    signer.sign("GET", "/", "", &mut map, None).unwrap();
    assert!(map["x-amz-security-token"].is_sensitive());
    assert_eq!(map["x-amz-content-sha256"], UNSIGNED_PAYLOAD);
    assert!(
        map["authorization"]
            .to_str()
            .unwrap()
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,")
    );
}

#[test]
fn only_body_and_amz_headers_are_signed() {
    let signer = s3_signer(Payload::CallerHash(EMPTY_SHA256.to_owned()), None);
    let mut map = headers(&[
        ("host", "bucket.s3.amazonaws.com"),
        ("content-type", "text/plain"),
        ("user-agent", "app"),
        ("accept", "*/*"),
    ]);
    signer.sign("PUT", "/key", "", &mut map, None).unwrap();
    assert!(
        map["authorization"]
            .to_str()
            .unwrap()
            .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,")
    );
}

#[test]
fn s3_paths_are_encoded_once_and_others_twice() {
    assert_eq!(canonical_uri("/a%20b/c~d/%7E", true), "/a%20b/c~d/~");
    assert_eq!(canonical_uri("/a%20b/c~d", false), "/a%2520b/c~d");
    assert_eq!(canonical_uri("/caf%C3%A9+x", true), "/caf%C3%A9%2Bx");
    assert_eq!(canonical_uri("", true), "/");
    assert_eq!(canonical_uri("//a//", true), "//a//");
}

#[test]
fn queries_are_sorted_and_encoded_once() {
    assert_eq!(canonical_query("b=2&a=1&a=0"), "a=0&a=1&b=2");
    assert_eq!(canonical_query("uploads"), "uploads=");
    assert_eq!(
        canonical_query("partNumber=1&uploadId=a%2Fb~c"),
        "partNumber=1&uploadId=a%2Fb~c"
    );
    assert_eq!(canonical_query("x=a+b&y=%7e&z=%2B"), "x=a%20b&y=~&z=%2B");
    assert_eq!(canonical_query(""), "");
}

#[test]
fn caller_hashes_must_be_lowercase_hex() {
    assert!(is_sha256_hex(EMPTY_SHA256));
    assert!(!is_sha256_hex(&EMPTY_SHA256.to_uppercase()));
    assert!(!is_sha256_hex(UNSIGNED_PAYLOAD));
    assert!(!is_sha256_hex(STREAMING_PAYLOAD));
    assert!(!is_sha256_hex(&EMPTY_SHA256[1..]));
}

/// The example in the S3 documentation, "Authenticating Requests: Using Query
/// Parameters".
#[test]
fn a_presigned_url_matches_the_s3_example() {
    let query = s3_signer(Payload::Unsigned, None)
        .presign(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            "",
            86_400,
        )
        .unwrap();
    assert_eq!(
        &*query,
        "X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
         &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
         &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
}

/// Each expected URL is what botocore 1.42's `S3SigV4QueryAuth` makes at the same
/// time: temporary credentials, a caller's own parameter, and a port in the host.
#[test]
fn a_presigned_url_matches_botocores() {
    let signer = || {
        Signer::new(SignerParts {
            secret: S3_SECRET,
            access_key_id: S3_KEY_ID,
            session_token: Some(Zeroizing::new(b"SESSION/token+value=".to_vec())),
            region: "eu-west-1",
            service: "s3",
            // 2026-11-10T12:00:00Z.
            now: UNIX_EPOCH + Duration::from_secs(1_794_312_000),
            payload: Payload::Unsigned,
        })
        .unwrap()
    };
    let common = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261110%2Feu-west-1%2Fs3%2Faws4_request\
         &X-Amz-Date=20261110T120000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host\
         &X-Amz-Security-Token=SESSION%2Ftoken%2Bvalue%3D";
    let disposition = "response-content-disposition=attachment%3B%20filename%3D%22a.txt%22";
    let put = signer()
        .presign(
            "PUT",
            "s3.eu-west-1.amazonaws.com",
            "/bucket/dir/a%20b.txt",
            disposition,
            900,
        )
        .unwrap();
    assert_eq!(
        *put,
        format!(
            "{disposition}&{common}&X-Amz-Signature=\
             409a2767f79e27645952d479dcbf97781e646673479e5025088656b1a08e094d"
        )
    );
    let get = signer()
        .presign("GET", "provider.test:9000", "/bucket/key", "", 900)
        .unwrap();
    assert_eq!(
        *get,
        format!(
            "{common}&X-Amz-Signature=\
             68dd6dc4ac01753addf9e7c64a47c90a153ff665780928f659310467c407ff1d"
        )
    );
}

/// A caller chooses which version or part and how a download is described, and nothing
/// that asks for more than the object or that signing sets.
#[test]
fn a_presigned_url_carries_only_the_query_parameters_it_may() {
    let presign = |query: &str| {
        s3_signer(Payload::Unsigned, None).presign("GET", "b.s3.amazonaws.com", "/k", query, 60)
    };
    for allowed in ["versionId=3", "partNumber=1&uploadId=abc", "x-id=GetObject"] {
        let query = presign(allowed).unwrap();
        assert!(query.starts_with(&format!("{allowed}&X-Amz-Algorithm=")));
    }
    for refused in [
        "acl",
        "uploads",
        "tagging=",
        "X-Amz-Expires=604800",
        "x-amz-expires=1",
        "X-Amz-Signature=00",
        "X-Amz-Security-Token=mine",
        "versionId=1&versionId=2",
        "versionid=1",
        "a=b",
    ] {
        let error = presign(refused).unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest, "{refused}");
    }
}

#[test]
fn an_access_key_id_that_cannot_be_in_a_header_is_refused() {
    for id in [&b""[..], b"AKID/1", b"AKID 1", b"AK\xffID"] {
        let error = Signer::new(SignerParts {
            secret: S3_SECRET,
            access_key_id: id,
            session_token: None,
            region: "us-east-1",
            service: "s3",
            now: may_24_2013(),
            payload: Payload::Unsigned,
        })
        .err()
        .unwrap();
        assert_eq!(error.code(), ErrorCode::BadRequest);
    }
}

mod cross_check {
    //! For random requests, seal's signature is the AWS SDK's.

    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    };
    use aws_sigv4::sign::v4;
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
    use proptest::prelude::*;

    use super::*;

    const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');

    /// Path segments as an AWS SDK sends them: each encoded once, in AWS's form.
    fn segment() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9._~ !$&'()*+,;=:@é/-]{1,12}"
            .prop_filter("no dot segments", |raw| raw != "." && raw != "..")
            .prop_map(|raw| utf8_percent_encode(&raw, UNRESERVED).to_string())
    }

    fn query_part() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9._~ /=&+é-]{0,10}"
            .prop_map(|raw| utf8_percent_encode(&raw, UNRESERVED).to_string())
    }

    #[derive(Debug, Clone)]
    struct Generated {
        method: &'static str,
        path: String,
        query: Vec<(String, String)>,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        token: Option<String>,
        service: &'static str,
        region: &'static str,
        seconds: u64,
    }

    fn generated() -> impl Strategy<Value = Generated> {
        (
            prop::sample::select(vec!["GET", "PUT", "POST", "DELETE", "HEAD"]),
            prop::collection::vec(segment(), 0..4),
            prop::collection::vec(
                (
                    query_part().prop_filter("a name", |n| !n.is_empty()),
                    query_part(),
                ),
                0..4,
            ),
            prop::collection::vec(
                (
                    prop::sample::select(vec![
                        "content-type",
                        "range",
                        "content-md5",
                        "x-amz-meta-a",
                        "x-amz-acl",
                    ]),
                    "[ -~]{0,20}",
                ),
                0..4,
            ),
            prop::collection::vec(any::<u8>(), 0..64),
            prop::option::of("[A-Za-z0-9/+=]{16,40}"),
            prop::sample::select(vec!["s3", "sts", "execute-api", "dynamodb"]),
            prop::sample::select(vec!["us-east-1", "eu-west-2", "ap-southeast-1"]),
            1_000_000_000_u64..4_000_000_000,
        )
            .prop_map(
                |(method, segments, query, headers, body, token, service, region, seconds)| {
                    Generated {
                        method,
                        path: format!("/{}", segments.join("/")),
                        query,
                        headers: headers
                            .into_iter()
                            // Each name once, since the SDK and seal may order repeats differently.
                            .fold(
                                Vec::new(),
                                |mut unique: Vec<(&'static str, String)>, (name, value)| {
                                    if !unique.iter().any(|(seen, _)| *seen == name) {
                                        unique.push((name, value));
                                    }
                                    unique
                                },
                            ),
                        body,
                        token,
                        service,
                        region,
                        seconds,
                    }
                },
            )
    }

    fn sdk_signature(case: &Generated, host: &str, query: &str) -> String {
        let identity = Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            case.token.clone(),
            None,
            "test",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.percent_encoding_mode = if case.service == "s3" {
            PercentEncodingMode::Single
        } else {
            PercentEncodingMode::Double
        };
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(case.region)
            .name(case.service)
            .time(UNIX_EPOCH + Duration::from_secs(case.seconds))
            .settings(settings)
            .build()
            .unwrap()
            .into();
        let uri = if query.is_empty() {
            format!("https://{host}{}", case.path)
        } else {
            format!("https://{host}{}?{query}", case.path)
        };
        let headers: Vec<(&str, &str)> = case
            .headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let request = SignableRequest::new(
            case.method,
            uri,
            headers.into_iter(),
            SignableBody::Bytes(&case.body),
        )
        .unwrap();
        let (instructions, _) = sign(request, &params).unwrap().into_parts();
        let (headers, _) = instructions.into_parts();
        headers
            .iter()
            .find(|header| header.name() == "authorization")
            .unwrap()
            .value()
            .to_owned()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn seal_signs_as_the_aws_sdk_does(case in generated()) {
            let host = format!("example.{}.amazonaws.com", case.service);
            let query = case
                .query
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("&");
            let expected = sdk_signature(&case, &host, &query);

            let signer = Signer::new(SignerParts {
                secret: b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                access_key_id: b"AKIDEXAMPLE",
                session_token: case.token.as_ref().map(|token| Zeroizing::new(token.as_bytes().to_vec())),
                region: case.region,
                service: case.service,
                now: UNIX_EPOCH + Duration::from_secs(case.seconds),
                payload: Payload::Computed,
            })
            .unwrap();
            let mut map = HeaderMap::new();
            map.insert("host", HeaderValue::from_str(&host).unwrap());
            for (name, value) in &case.headers {
                map.insert(*name, HeaderValue::from_str(value).unwrap());
            }
            signer.sign(case.method, &case.path, &query, &mut map, Some(&case.body)).unwrap();
            prop_assert_eq!(map["authorization"].to_str().unwrap(), expected);
        }
    }
}

#[test]
fn the_payload_mode_is_the_first_that_suits_the_request() {
    use PayloadMode::{CallerHash, Computed, Streaming};
    let choose = |allowed: &[PayloadMode],
                  unsigned: bool,
                  pairs: &[(&'static str, &str)],
                  injected: bool| {
        choose_payload(&PayloadChoice {
            allowed,
            allow_unsigned: unsigned,
            headers: &headers(pairs),
            buffer_cap: 100,
            body_injected: injected,
        })
    };
    let all = [Computed, CallerHash, Streaming];
    assert_eq!(
        choose(&all, true, &[("x-amz-content-sha256", EMPTY_SHA256)], false).unwrap(),
        Payload::CallerHash(EMPTY_SHA256.to_owned())
    );
    assert_eq!(
        choose(&all, true, &[("content-length", "100")], false).unwrap(),
        Payload::Computed
    );
    assert_eq!(choose(&all, true, &[], false).unwrap(), Payload::Computed);
    assert_eq!(
        choose(&all, true, &[("content-length", "101")], false).unwrap(),
        Payload::Streaming {
            decoded_length: 101
        }
    );
    assert_eq!(
        choose(&[Streaming], true, &[], false).unwrap(),
        Payload::Unsigned
    );
    assert_eq!(
        choose(&[Computed], true, &[("content-length", "101")], false).unwrap(),
        Payload::Unsigned
    );

    // A body seal changes is hashed by seal, whatever its size.
    assert_eq!(
        choose(&all, false, &[("content-length", "500")], true).unwrap(),
        Payload::Computed
    );
    let code = |result: Result<Payload, BrokerError>| result.err().unwrap().code();
    assert_eq!(
        code(choose(&[Streaming], true, &[("content-length", "5")], true)),
        ErrorCode::BadRequest
    );
    assert_eq!(
        code(choose(
            &all,
            false,
            &[("x-amz-content-sha256", EMPTY_SHA256)],
            true
        )),
        ErrorCode::BadRequest
    );

    assert_eq!(
        code(choose(
            &[Computed],
            false,
            &[("x-amz-content-sha256", EMPTY_SHA256)],
            false
        )),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(choose(
            &[Computed],
            false,
            &[("content-length", "101")],
            false
        )),
        ErrorCode::BodyTooLarge
    );
    assert_eq!(
        code(choose(&[Streaming], false, &[], false)),
        ErrorCode::BadRequest
    );
    assert_eq!(
        code(choose(&all, false, &[("content-length", "x")], false)),
        ErrorCode::BadRequest
    );
}
