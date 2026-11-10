//! AWS Signature Version 4, with the secret access key as the rule's own secret.
//!
//! seal signs the final request, after the caller's headers are fixed and the body is
//! known, and controls which headers are signed: `host`, the `content-*` headers that
//! describe the body, and every `x-amz-*` header, all of which are seal's own except
//! a well-formed `X-Amz-Content-SHA256` in caller-hash mode.
//!
//! A presigned URL is a credential the caller can copy, so query-string signing is
//! only for a rule that allows it, for S3, within the lifetime the rule gives.
//!
//! Signed with `ring`'s HMAC-SHA-256 and SHA-256, as JWTs are.

use http::header::{HeaderMap, HeaderName, HeaderValue};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, percent_encode};
use ring::{digest, hmac};
use zeroize::Zeroizing;

use seal_format::policy::PayloadMode;

use crate::error::{BrokerError, ErrorCode};
use crate::inject::civil::Civil;

/// The algorithm, in the string to sign and in `Authorization`.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The payload hash of a chunked upload.
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

/// The payload hash when the body is not signed.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The hash of an empty body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Everything except RFC 3986's unreserved characters, as AWS's `UriEncode` has it.
const AWS_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
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

/// A header value with its ends trimmed and each run of whitespace made one space.
fn trim_all(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
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
    pub method: &'a str,
    pub uri: String,
    pub query: String,
    pub headers: &'a [(String, String)],
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

fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
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

/// How the payload is hashed for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// seal hashes the buffered body.
    Computed,
    /// The caller's `X-Amz-Content-SHA256`, which the provider checks against the body.
    CallerHash(String),
    /// Chunked signing; the body's length before framing.
    Streaming { decoded_length: u64 },
    /// `UNSIGNED-PAYLOAD`.
    Unsigned,
}

/// Signs one request: everything but the payload is known when it is made.
pub struct Signer {
    key: Zeroizing<Vec<u8>>,
    access_key_id: Zeroizing<String>,
    session_token: Option<Zeroizing<Vec<u8>>>,
    scope: String,
    amz_date: String,
    s3: bool,
    /// How the payload is hashed.
    pub payload: Payload,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("scope", &self.scope)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

/// What a signer needs, apart from the payload.
pub struct SignerParts<'a> {
    pub secret: &'a [u8],
    pub access_key_id: &'a [u8],
    pub session_token: Option<Zeroizing<Vec<u8>>>,
    pub region: &'a str,
    pub service: &'a str,
    pub now: std::time::SystemTime,
    pub payload: Payload,
}

fn bad(detail: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::BadRequest, detail)
}

/// The query parameters a caller may put on a URL to be presigned: which version or
/// part, and how a download's response is described. Anything else could ask for more
/// than the object, such as its ACL.
pub const PRESIGN_QUERY: &[&str] = &[
    "partNumber",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "uploadId",
    "versionId",
    "x-id",
];

/// The headers SigV4 covers, apart from `x-amz-*`.
const SIGNED: &[&str] = &[
    "host",
    "content-encoding",
    "content-length",
    "content-md5",
    "content-type",
    "range",
];

impl Signer {
    /// A signer for a request made now.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] if the access key id is not printable ASCII.
    pub fn new(parts: SignerParts<'_>) -> Result<Self, BrokerError> {
        let access_key_id = std::str::from_utf8(parts.access_key_id)
            .ok()
            .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic() && b != b'/'))
            .ok_or_else(|| bad("the access key id is not valid"))?;
        let civil = Civil::at(parts.now);
        let date_stamp = civil.date_stamp();
        Ok(Self {
            key: signing_key(parts.secret, &date_stamp, parts.region, parts.service),
            access_key_id: Zeroizing::new(access_key_id.to_owned()),
            session_token: parts.session_token,
            scope: scope(&date_stamp, parts.region, parts.service),
            amz_date: civil.amz_date(),
            s3: parts.service == "s3",
            payload: parts.payload,
        })
    }

    /// The hash that goes in `X-Amz-Content-SHA256`, given the body if seal buffered it.
    fn payload_hash(&self, body: Option<&[u8]>) -> Result<String, BrokerError> {
        match (&self.payload, body) {
            (Payload::Computed, Some(body)) => Ok(sha256_hex(body)),
            (Payload::Computed, None) => Err(BrokerError::new(
                ErrorCode::Internal,
                "a computed payload hash needs the body",
            )),
            (Payload::CallerHash(hash), _) => Ok(hash.clone()),
            (Payload::Streaming { .. }, _) => Ok(STREAMING_PAYLOAD.to_owned()),
            (Payload::Unsigned, _) => Ok(UNSIGNED_PAYLOAD.to_owned()),
        }
    }

    /// Adds `X-Amz-Date`, `X-Amz-Content-SHA256`, any session token and
    /// `Authorization` to the final headers, and returns the signature, which seeds
    /// chunk signing.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] for a header value that cannot be signed.
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &mut HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<Zeroizing<String>, BrokerError> {
        let payload_hash = self.payload_hash(body)?;
        set(headers, "x-amz-date", self.amz_date.as_bytes(), false)?;
        set(
            headers,
            "x-amz-content-sha256",
            payload_hash.as_bytes(),
            false,
        )?;
        if let Some(token) = &self.session_token {
            set(headers, "x-amz-security-token", token, true)?;
        }
        if let Payload::Streaming { decoded_length } = self.payload {
            set(
                headers,
                "x-amz-decoded-content-length",
                decoded_length.to_string().as_bytes(),
                false,
            )?;
        }

        let mut signed_headers = Zeroizing::new(Vec::new());
        for (name, value) in headers.iter() {
            let name = name.as_str();
            if SIGNED.contains(&name) || name.starts_with("x-amz-") {
                let value = value
                    .to_str()
                    .map_err(|_| bad("a signed header is not printable ASCII"))?;
                signed_headers.push((name.to_owned(), value.to_owned()));
            }
        }
        let parts = CanonicalParts {
            method,
            uri: canonical_uri(path, self.s3),
            query: canonical_query(query),
            headers: &signed_headers,
            payload_hash: &payload_hash,
        };
        // The session token is in the canonical request, which wipes itself.
        let (request, signed) = canonical_request(&parts);
        drop(signed_headers);
        let to_sign = string_to_sign(&self.amz_date, &self.scope, &request);
        let signature = Zeroizing::new(signature(&self.key, &to_sign));
        let authorization = Zeroizing::new(format!(
            "{ALGORITHM} Credential={}/{}, SignedHeaders={signed}, Signature={}",
            self.access_key_id.as_str(),
            self.scope,
            signature.as_str()
        ));
        set(headers, "authorization", authorization.as_bytes(), true)?;
        Ok(signature)
    }

    /// The query of a presigned S3 URL for this request: the caller's own parameters
    /// as sent, then the signing parameters and the signature. Only `host` is signed,
    /// and the payload is not, as for every presigned URL.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] for a query parameter a presigned URL may not carry,
    /// or one that repeats.
    pub fn presign(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        query: &str,
        expires_s: u32,
    ) -> Result<Zeroizing<String>, BrokerError> {
        let mut seen = Vec::new();
        for (name, _) in form_urlencoded::parse(query.as_bytes()) {
            if !PRESIGN_QUERY.contains(&name.as_ref()) || seen.contains(&name) {
                return Err(bad("a presigned URL cannot carry this query parameter"));
            }
            seen.push(name);
        }
        let encode = |part: &[u8]| percent_encode(part, AWS_ENCODE).to_string();
        let credential = format!("{}/{}", self.access_key_id.as_str(), self.scope);
        let token = self.session_token.as_ref();
        // Sized up front: with temporary credentials it holds the session token.
        let room = query.len() + 256 + 3 * (credential.len() + token.map_or(0, |t| t.len()));
        let mut signed = Zeroizing::new(String::with_capacity(room));
        if !query.is_empty() {
            signed.push_str(query);
            signed.push('&');
        }
        signed.push_str("X-Amz-Algorithm=");
        signed.push_str(ALGORITHM);
        signed.push_str("&X-Amz-Credential=");
        signed.push_str(&encode(credential.as_bytes()));
        signed.push_str("&X-Amz-Date=");
        signed.push_str(&self.amz_date);
        signed.push_str("&X-Amz-Expires=");
        signed.push_str(&expires_s.to_string());
        signed.push_str("&X-Amz-SignedHeaders=host");
        if let Some(token) = token {
            signed.push_str("&X-Amz-Security-Token=");
            signed.extend(percent_encode(token, AWS_ENCODE));
        }
        let headers = [("host".to_owned(), authority.to_owned())];
        let (request, _) = canonical_request(&CanonicalParts {
            method,
            uri: canonical_uri(path, true),
            query: canonical_query(&signed),
            headers: &headers,
            payload_hash: UNSIGNED_PAYLOAD,
        });
        let to_sign = string_to_sign(&self.amz_date, &self.scope, &request);
        signed.push_str("&X-Amz-Signature=");
        signed.push_str(&signature(&self.key, &to_sign));
        Ok(signed)
    }

    /// Signs chunks, each with the signature before it, from the seed signature.
    #[must_use]
    pub fn chunks(&self, seed: Zeroizing<String>) -> ChunkSigner {
        ChunkSigner {
            key: self.key.clone(),
            scope: self.scope.clone(),
            amz_date: self.amz_date.clone(),
            previous: seed,
        }
    }
}

fn set(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &[u8],
    sensitive: bool,
) -> Result<(), BrokerError> {
    let mut value =
        HeaderValue::from_bytes(value).map_err(|_| bad("a signing value cannot be a header"))?;
    value.set_sensitive(sensitive);
    headers.insert(HeaderName::from_static(name), value);
    Ok(())
}

/// Signs the chunks of a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` upload.
pub struct ChunkSigner {
    key: Zeroizing<Vec<u8>>,
    scope: String,
    amz_date: String,
    previous: Zeroizing<String>,
}

/// The size of each chunk but the last.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// `;chunk-signature=` plus the signature, and the two line ends.
const CHUNK_OVERHEAD: u64 = 17 + 64 + 2 + 2;

/// The length of a body of `decoded` bytes once framed in chunks of [`CHUNK_SIZE`],
/// ending with an empty chunk.
#[must_use]
pub fn framed_length(decoded: u64) -> u64 {
    let size = CHUNK_SIZE as u64;
    let full = decoded / size;
    let rest = decoded % size;
    let frame = |length: u64| format!("{length:x}").len() as u64 + CHUNK_OVERHEAD + length;
    full * frame(size) + if rest > 0 { frame(rest) } else { 0 } + frame(0)
}

impl ChunkSigner {
    /// One chunk, framed with its signature. The last chunk is empty.
    pub fn frame(&mut self, data: &[u8]) -> Vec<u8> {
        let to_sign = format!(
            "{ALGORITHM}-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.amz_date,
            self.scope,
            self.previous.as_str(),
            sha256_hex(data)
        );
        let signature = Zeroizing::new(signature(&self.key, &to_sign));
        let mut framed = format!(
            "{:x};chunk-signature={}\r\n",
            data.len(),
            signature.as_str()
        )
        .into_bytes();
        framed.extend_from_slice(data);
        framed.extend_from_slice(b"\r\n");
        self.previous = signature;
        framed
    }
}

/// What the payload mode is chosen from.
pub struct PayloadChoice<'a> {
    /// The modes the rule allows.
    pub allowed: &'a [PayloadMode],
    /// Whether the rule also allows `UNSIGNED-PAYLOAD`.
    pub allow_unsigned: bool,
    /// The caller's headers.
    pub headers: &'a HeaderMap,
    /// The most seal buffers.
    pub buffer_cap: u64,
    /// Whether seal changes the body, which means hashing what it sends.
    pub body_injected: bool,
}

/// Chooses how to hash the payload, among the modes the rule allows: the caller's
/// hash if it sent one; otherwise seal's own hash if the body fits the buffer;
/// otherwise chunked signing, which needs the length; otherwise an unsigned payload.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] for a malformed `X-Amz-Content-SHA256`, such as
/// `UNSIGNED-PAYLOAD`, which cannot select a mode; [`ErrorCode::BodyTooLarge`] for a
/// body over the cap with no other mode; and [`ErrorCode::BadRequest`] when no allowed
/// mode suits the request.
pub fn choose_payload(choice: &PayloadChoice<'_>) -> Result<Payload, BrokerError> {
    let allows = |mode| choice.allowed.contains(&mode);
    if let Some(value) = choice.headers.get("x-amz-content-sha256") {
        let hash = value
            .to_str()
            .ok()
            .filter(|hash| is_sha256_hex(hash))
            .ok_or_else(|| bad("X-Amz-Content-SHA256 must be the body's SHA-256 hash in hex"))?;
        if !allows(PayloadMode::CallerHash) {
            return Err(BrokerError::new(
                ErrorCode::Conflict,
                "the rule does not allow the caller's payload hash",
            ));
        }
        if choice.body_injected {
            return Err(bad(
                "seal changes this body, so it cannot use the caller's hash",
            ));
        }
        return Ok(Payload::CallerHash(hash.to_owned()));
    }
    let length = content_length(choice.headers)?;
    let fits = length.is_none_or(|length| length <= choice.buffer_cap);
    if allows(PayloadMode::Computed) && (fits || choice.body_injected) {
        return Ok(Payload::Computed);
    }
    if choice.body_injected {
        return Err(bad(
            "seal changes this body, so it needs a computed payload hash",
        ));
    }
    if let (true, Some(decoded_length)) = (allows(PayloadMode::Streaming), length) {
        return Ok(Payload::Streaming { decoded_length });
    }
    if choice.allow_unsigned {
        return Ok(Payload::Unsigned);
    }
    if allows(PayloadMode::Computed) {
        return Err(BrokerError::new(
            ErrorCode::BodyTooLarge,
            "the body is over the cap for a computed payload hash",
        ));
    }
    Err(bad(
        "no payload mode the rule allows suits this request; chunked signing needs Content-Length",
    ))
}

fn content_length(headers: &HeaderMap) -> Result<Option<u64>, BrokerError> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or_else(|| bad("Content-Length is not valid"))
        })
        .transpose()
}

/// Sets the headers chunked signing needs before the request is signed: the framed
/// length, and `aws-chunked` ahead of any content coding the caller set.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] if the caller's content coding cannot be a header.
pub fn prepare_streaming(headers: &mut HeaderMap, decoded_length: u64) -> Result<(), BrokerError> {
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from(framed_length(decoded_length)),
    );
    let coding = match headers.get(http::header::CONTENT_ENCODING) {
        Some(existing) => {
            let existing = existing
                .to_str()
                .map_err(|_| bad("Content-Encoding is not valid"))?;
            HeaderValue::from_str(&format!("aws-chunked,{existing}"))
                .map_err(|_| bad("Content-Encoding is not valid"))?
        }
        None => HeaderValue::from_static("aws-chunked"),
    };
    headers.insert(http::header::CONTENT_ENCODING, coding);
    Ok(())
}

/// The caller's body, framed in signed chunks as it streams. It holds at most one
/// chunk, and fails if the body is not the length the caller declared.
pub struct ChunkedBody {
    inner: crate::client::RequestBody,
    signer: ChunkSigner,
    buffer: bytes::BytesMut,
    remaining: u64,
    state: ChunkState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Reading,
    /// The caller's body has ended; the final empty chunk is still to come.
    Final,
    Done,
}

impl ChunkedBody {
    /// Frames `inner`, which must be `decoded_length` bytes.
    #[must_use]
    pub fn new(
        inner: crate::client::RequestBody,
        signer: ChunkSigner,
        decoded_length: u64,
    ) -> Self {
        Self {
            inner,
            signer,
            buffer: bytes::BytesMut::new(),
            remaining: decoded_length,
            state: ChunkState::Reading,
        }
    }

    fn emit(&mut self, length: usize) -> http_body::Frame<bytes::Bytes> {
        let data = self.buffer.split_to(length);
        http_body::Frame::data(bytes::Bytes::from(self.signer.frame(&data)))
    }
}

fn wrong_length() -> BrokerError {
    bad("the body is not the length its Content-Length declares")
}

impl http_body::Body for ChunkedBody {
    type Data = bytes::Bytes;
    type Error = BrokerError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, BrokerError>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match this.state {
                ChunkState::Done => return Poll::Ready(None),
                ChunkState::Final => {
                    this.state = ChunkState::Done;
                    return Poll::Ready(Some(Ok(this.emit(0))));
                }
                ChunkState::Reading => {}
            }
            if this.buffer.len() >= CHUNK_SIZE {
                return Poll::Ready(Some(Ok(this.emit(CHUNK_SIZE))));
            }
            match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    this.state = ChunkState::Done;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        let length = data.len() as u64;
                        if length > this.remaining {
                            this.state = ChunkState::Done;
                            return Poll::Ready(Some(Err(wrong_length())));
                        }
                        this.remaining -= length;
                        this.buffer.extend_from_slice(&data);
                    }
                }
                Poll::Ready(None) => {
                    if this.remaining != 0 {
                        this.state = ChunkState::Done;
                        return Poll::Ready(Some(Err(wrong_length())));
                    }
                    this.state = ChunkState::Final;
                    if !this.buffer.is_empty() {
                        let length = this.buffer.len();
                        return Poll::Ready(Some(Ok(this.emit(length))));
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.state == ChunkState::Done
    }
}

#[cfg(test)]
mod tests;
