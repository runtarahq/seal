//! The parts of AWS Signature Version 4 that depend on nothing but the request: the
//! canonical request, the string to sign, the signing key and the signature.
//!
//! The broker signs callers' requests with these, and the S3 key source signs its own.
//! Signed with `ring`'s HMAC-SHA-256 and SHA-256.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, percent_encode};
use ring::{digest, hmac};
use zeroize::Zeroizing;

/// The algorithm, in the string to sign and in `Authorization`.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The payload hash of a chunked upload.
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

/// The payload hash when the body is not signed.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The hash of an empty body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Everything except RFC 3986's unreserved characters, as AWS's `UriEncode` has it.
pub const AWS_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// SHA-256, in lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

/// Whether a value is a SHA-256 hash in hex, as a caller's `X-Amz-Content-SHA256`
/// must be. Upper case is refused, since AWS compares the hash as lowercase hex.
#[must_use]
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The canonical URI from the path as sent. S3 encodes each segment once, so the
/// path is decoded and encoded again in AWS's form; other services encode the path
/// as sent a second time. Neither normalises, since seal refuses dot segments.
#[must_use]
pub fn canonical_uri(path: &str, s3: bool) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    path.split('/')
        .map(|segment| {
            if s3 {
                let decoded: Vec<u8> = percent_decode_str(segment).collect();
                percent_encode(&decoded, AWS_ENCODE).to_string()
            } else {
                percent_encode(segment.as_bytes(), AWS_ENCODE).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The canonical query: each name and value decoded as a form would be, with `+` as a
/// space, encoded in AWS's form, and sorted by name and then value. This is how the
/// AWS SDKs read a query.
#[must_use]
pub fn canonical_query(query: &str) -> String {
    let encode = |part: &str| percent_encode(part.as_bytes(), AWS_ENCODE).to_string();
    let mut pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| (encode(&name), encode(&value)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// A header value with its ends trimmed and each run of spaces made one space, as the
/// AWS SDKs do it. Other whitespace is not folded: `sign` refuses a value that has any.
fn trim_all(value: &str) -> String {
    value
        .split(' ')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The canonical headers and the signed header list, from `(name, value)` pairs in the
/// order sent. Names are lowercased and sorted; repeated names join with commas.
#[must_use]
pub fn canonical_headers(headers: &[(String, String)]) -> (Zeroizing<String>, String) {
    // A session token is among the values, so every copy is wiped, and the result is
    // sized up front so it never reallocates.
    let mut joined: std::collections::BTreeMap<String, Vec<Zeroizing<String>>> =
        std::collections::BTreeMap::new();
    for (name, value) in headers {
        joined
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(Zeroizing::new(trim_all(value)));
    }
    let room: usize = joined
        .iter()
        .map(|(name, values)| {
            name.len() + 2 + values.iter().map(|value| value.len() + 1).sum::<usize>()
        })
        .sum();
    let mut canonical = Zeroizing::new(String::with_capacity(room));
    for (name, values) in &joined {
        canonical.push_str(name);
        canonical.push(':');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str(value);
        }
        canonical.push('\n');
    }
    let signed = joined.keys().cloned().collect::<Vec<_>>().join(";");
    (canonical, signed)
}

/// The parts of a request that are signed.
pub struct CanonicalParts<'a> {
    /// The method.
    pub method: &'a str,
    /// The canonical URI.
    pub uri: String,
    /// The canonical query.
    pub query: String,
    /// The headers that are signed, as sent.
    pub headers: &'a [(String, String)],
    /// The payload's hash, or what stands for it.
    pub payload_hash: &'a str,
}

/// The canonical request, and the signed header list.
#[must_use]
pub fn canonical_request(parts: &CanonicalParts<'_>) -> (Zeroizing<String>, String) {
    let (headers, signed) = canonical_headers(parts.headers);
    let pieces = [
        parts.method,
        "\n",
        &parts.uri,
        "\n",
        &parts.query,
        "\n",
        &headers,
        "\n",
        &signed,
        "\n",
        parts.payload_hash,
    ];
    let mut request = Zeroizing::new(String::with_capacity(
        pieces.iter().map(|piece| piece.len()).sum(),
    ));
    for piece in pieces {
        request.push_str(piece);
    }
    (request, signed)
}

/// `20150830/us-east-1/service/aws4_request`.
#[must_use]
pub fn scope(date_stamp: &str, region: &str, service: &str) -> String {
    format!("{date_stamp}/{region}/{service}/aws4_request")
}

/// The string to sign for a canonical request.
#[must_use]
pub fn string_to_sign(amz_date: &str, scope: &str, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// HMAC-SHA-256, wiped when dropped.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Zeroizing::new(hmac::sign(&key, data).as_ref().to_vec())
}

/// The signing key for a day, region and service. It is a credential too, valid for
/// that scope, so it is wiped when dropped.
#[must_use]
pub fn signing_key(
    secret: &[u8],
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let mut first = Zeroizing::new(b"AWS4".to_vec());
    first.extend_from_slice(secret);
    let date = hmac_sha256(&first, date_stamp.as_bytes());
    let region = hmac_sha256(&date, region.as_bytes());
    let service = hmac_sha256(&region, service.as_bytes());
    hmac_sha256(&service, b"aws4_request")
}

/// A signature, in hex.
#[must_use]
pub fn signature(signing_key: &[u8], string_to_sign: &str) -> String {
    hex(&hmac_sha256(signing_key, string_to_sign.as_bytes()))
}
