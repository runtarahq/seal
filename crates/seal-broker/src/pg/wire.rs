//! The parts of the Postgres wire protocol seal reads and writes itself: the
//! caller's first packets, and the messages of a login. Everything after a login is
//! relayed without being read.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{BrokerError, ErrorCode};

/// `SSLRequest`'s code.
pub const SSL_REQUEST: u32 = 80_877_103;
/// `GSSENCRequest`'s code.
pub const GSSENC_REQUEST: u32 = 80_877_104;
/// `CancelRequest`'s code.
pub const CANCEL_REQUEST: u32 = 80_877_102;
/// Protocol 3.0.
pub const PROTOCOL_3_0: u32 = 3 << 16;
/// Protocol 3.2, from Postgres 18, with longer cancel keys.
pub const PROTOCOL_3_2: u32 = (3 << 16) | 2;

/// The largest startup packet, as Postgres has it.
pub const MAX_STARTUP: usize = 10_000;
/// The largest cancel key, from protocol 3.2.
pub const MAX_CANCEL_KEY: usize = 256;

fn bad(detail: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::BadRequest, detail)
}

/// A caller's first packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Preamble {
    /// Asks for TLS, which seal declines: the leg to seal is already protected.
    SslRequest,
    /// Asks for GSSAPI encryption, which seal declines.
    GssEncRequest,
    /// Cancels a query: the whole packet, forwarded as it is.
    Cancel(Vec<u8>),
    /// Starts a session.
    Startup(Startup),
}

/// A `StartupMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Startup {
    /// The protocol version.
    pub version: u32,
    /// The parameters, in order. Names are unique.
    pub params: Vec<(String, String)>,
}

impl Startup {
    /// A parameter's value.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The packet, length first.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = self.version.to_be_bytes().to_vec();
        for (name, value) in &self.params {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        with_length(&body)
    }
}

fn with_length(body: &[u8]) -> Vec<u8> {
    let mut packet = u32::try_from(body.len() + 4)
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    packet.extend_from_slice(body);
    packet
}

/// Parses a first packet, without its length.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] for anything malformed or unsupported.
pub fn parse_preamble(body: &[u8]) -> Result<Preamble, BrokerError> {
    let code = body
        .get(..4)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or_else(|| bad("a Postgres packet is too short"))?;
    match code {
        SSL_REQUEST | GSSENC_REQUEST if body.len() != 4 => {
            Err(bad("an encryption request has a body"))
        }
        SSL_REQUEST => Ok(Preamble::SslRequest),
        GSSENC_REQUEST => Ok(Preamble::GssEncRequest),
        CANCEL_REQUEST => {
            // A process ID, then a key of 4 bytes (3.0) up to 256 (3.2).
            let key = body.len().saturating_sub(8);
            if body.len() < 12 || !(4..=MAX_CANCEL_KEY).contains(&key) {
                return Err(bad("a cancel request is malformed"));
            }
            Ok(Preamble::Cancel(with_length(body)))
        }
        PROTOCOL_3_0 | PROTOCOL_3_2 => parse_startup(code, &body[4..]).map(Preamble::Startup),
        _ => Err(bad("this Postgres protocol version is not supported")),
    }
}

fn parse_startup(version: u32, mut rest: &[u8]) -> Result<Startup, BrokerError> {
    let mut params: Vec<(String, String)> = Vec::new();
    let take = |rest: &mut &[u8]| -> Result<String, BrokerError> {
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| bad("a startup parameter is not terminated"))?;
        let text = std::str::from_utf8(&rest[..end])
            .map_err(|_| bad("a startup parameter is not UTF-8"))?
            .to_owned();
        *rest = &rest[end + 1..];
        Ok(text)
    };
    loop {
        let name = take(&mut rest)?;
        if name.is_empty() {
            break;
        }
        let value = take(&mut rest)?;
        if params.iter().any(|(existing, _)| *existing == name) {
            return Err(bad("a startup parameter repeats"));
        }
        params.push((name, value));
    }
    if !rest.is_empty() {
        return Err(bad("a startup packet has bytes after its end"));
    }
    Ok(Startup { version, params })
}

/// Reads one first packet.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] for a malformed or oversized packet, or if the caller
/// closes first.
pub async fn read_preamble<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Preamble, BrokerError> {
    let length = reader
        .read_u32()
        .await
        .map_err(|_| bad("the caller closed before starting"))?;
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if !(8..=MAX_STARTUP).contains(&length) {
        return Err(bad("a Postgres packet has a bad length"));
    }
    let mut body = vec![0; length - 4];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| bad("the caller closed mid-packet"))?;
    parse_preamble(&body)
}

/// A message: its type and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The type byte.
    pub tag: u8,
    /// The body, without type or length.
    pub body: Vec<u8>,
}

/// Reads one message of at most `max` bytes.
///
/// # Errors
///
/// `closed` if the stream ends, and [`ErrorCode::UpstreamReset`] for a bad length.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
    closed: BrokerError,
) -> Result<Message, BrokerError> {
    let mut head = [0; 5];
    if reader.read_exact(&mut head).await.is_err() {
        return Err(closed);
    }
    let length = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if !(4..=max).contains(&length) {
        return Err(BrokerError::new(
            ErrorCode::UpstreamReset,
            "a Postgres message has a bad length",
        ));
    }
    let mut body = vec![0; length - 4];
    if reader.read_exact(&mut body).await.is_err() {
        return Err(closed);
    }
    Ok(Message { tag: head[0], body })
}

/// A message, framed.
#[must_use]
pub fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut framed = vec![tag];
    framed.extend_from_slice(&with_length(body));
    framed
}

/// `AuthenticationOk`.
#[must_use]
pub fn authentication_ok() -> Vec<u8> {
    message(b'R', &0_u32.to_be_bytes())
}

/// An `ErrorResponse` with a SQLSTATE and a message of seal's own.
#[must_use]
pub fn error_response(sqlstate: &str, text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', text),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    message(b'E', &body)
}

/// The SQLSTATE of an `ErrorResponse`, if it has a well-formed one. Nothing else of
/// the server's message is kept.
#[must_use]
pub fn error_sqlstate(body: &[u8]) -> Option<String> {
    let mut rest = body;
    while let Some((&field, after)) = rest.split_first() {
        if field == 0 {
            break;
        }
        let end = after.iter().position(|byte| *byte == 0)?;
        if field == b'C' {
            let code = std::str::from_utf8(&after[..end]).ok()?;
            return (code.len() == 5 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
                .then(|| code.to_owned());
        }
        rest = &after[end + 1..];
    }
    None
}

/// A password message: a password, or the md5 response.
#[must_use]
pub fn password_message(password: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    // Built in one buffer of the right size, so no copy of the password is left behind.
    let mut framed = zeroize::Zeroizing::new(Vec::with_capacity(password.len() + 6));
    framed.push(b'p');
    framed.extend_from_slice(
        &u32::try_from(password.len() + 5)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    framed.extend_from_slice(password);
    framed.push(0);
    framed
}

/// `SASLInitialResponse`.
#[must_use]
pub fn sasl_initial_response(mechanism: &str, data: &[u8]) -> Vec<u8> {
    let mut body = mechanism.as_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    body.extend_from_slice(data);
    message(b'p', &body)
}

/// `SASLResponse`.
#[must_use]
pub fn sasl_response(data: &[u8]) -> Vec<u8> {
    message(b'p', data)
}

/// `SSLRequest`, as sent to the server.
#[must_use]
pub fn ssl_request() -> Vec<u8> {
    with_length(&SSL_REQUEST.to_be_bytes())
}

#[cfg(test)]
mod tests;
