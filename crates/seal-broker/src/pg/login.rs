//! Logs in to a Postgres server with the sealed credential.
//!
//! SCRAM-SHA-256-PLUS with `tls-server-end-point` channel binding when the server
//! offers it, otherwise SCRAM-SHA-256; MD5 and cleartext passwords only where the
//! rule allows them, and always over TLS. A client certificate may log in alone. Any
//! other method fails, and a server's error passes on only as its SQLSTATE.

use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
use ring::digest;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::{BrokerError, ErrorCode};
use crate::pg::wire::{self, Message};

/// How a session logged in, for the audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgAuth {
    /// SCRAM-SHA-256 with channel binding.
    ScramPlus,
    /// SCRAM-SHA-256.
    Scram,
    /// MD5.
    Md5,
    /// A cleartext password, over TLS.
    Cleartext,
    /// The client certificate alone.
    Cert,
    /// The server asked for nothing.
    Trust,
}

impl PgAuth {
    /// The name in the audit record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScramPlus => "scram-sha-256-plus",
            Self::Scram => "scram-sha-256",
            Self::Md5 => "md5",
            Self::Cleartext => "cleartext",
            Self::Cert => "cert",
            Self::Trust => "trust",
        }
    }
}

/// A login that failed, with the SQLSTATE to give the caller.
#[derive(Debug)]
pub struct LoginFailed {
    /// seal's error.
    pub error: BrokerError,
    /// The SQLSTATE: the server's, if it sent one.
    pub sqlstate: String,
}

/// What a login needs.
pub struct Credentials<'a> {
    /// The user, as sent in the startup message.
    pub user: &'a str,
    /// The password, if one was presented.
    pub password: Option<&'a [u8]>,
    /// Whether MD5 is allowed.
    pub allow_md5: bool,
    /// Whether a cleartext password is allowed.
    pub allow_cleartext: bool,
    /// Whether a client certificate was presented.
    pub client_cert: bool,
    /// The `tls-server-end-point` channel binding data, if the server's certificate
    /// allows it.
    pub end_point: Option<Vec<u8>>,
}

/// The largest message during a login.
const MAX_LOGIN_MESSAGE: usize = 64 * 1024;

fn failed(sqlstate: &str, detail: &'static str) -> LoginFailed {
    LoginFailed {
        error: BrokerError::new(ErrorCode::PgAuthFailed, detail),
        sqlstate: sqlstate.to_owned(),
    }
}

/// `invalid_authorization_specification`.
const AUTH_SPEC: &str = "28000";

fn protocol(detail: &'static str) -> LoginFailed {
    LoginFailed {
        error: BrokerError::new(ErrorCode::UpstreamReset, detail),
        sqlstate: "08P01".to_owned(),
    }
}

/// Runs a login, after the startup message has been sent. Returns how it logged in,
/// and the messages the caller should see before `AuthenticationOk`: a
/// `NegotiateProtocolVersion`, if the server sent one.
///
/// # Errors
///
/// [`LoginFailed`] with [`ErrorCode::PgAuthFailed`], or [`ErrorCode::UpstreamReset`]
/// if the server breaks the protocol or closes.
pub async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    server: &mut S,
    credentials: &Credentials<'_>,
) -> Result<(PgAuth, Vec<u8>), LoginFailed> {
    let mut before_ok = Vec::new();
    let mut method: Option<PgAuth> = None;
    loop {
        let message = read(server).await?;
        match message.tag {
            b'v' => before_ok.extend_from_slice(&wire::message(b'v', &message.body)),
            // A notice during a login says nothing the caller needs.
            b'N' => {}
            b'E' => {
                let sqlstate =
                    wire::error_sqlstate(&message.body).unwrap_or_else(|| AUTH_SPEC.to_owned());
                return Err(LoginFailed {
                    error: BrokerError::new(
                        ErrorCode::PgAuthFailed,
                        "the server refused the login",
                    ),
                    sqlstate,
                });
            }
            b'R' => {
                let (kind, rest) = authentication(&message)?;
                match kind {
                    0 => {
                        let method = match method {
                            Some(method) => method,
                            // A server that asks for nothing has proved nothing. With
                            // a password to present, that is not the login the policy
                            // describes, and the caller must not be told it is.
                            None if credentials.password.is_some() => {
                                return Err(failed(
                                    AUTH_SPEC,
                                    "the server accepted the login without asking for the password",
                                ));
                            }
                            None if credentials.client_cert => PgAuth::Cert,
                            None => PgAuth::Trust,
                        };
                        return Ok((method, before_ok));
                    }
                    3 => {
                        let password = credentials
                            .password
                            .filter(|_| credentials.allow_cleartext)
                            .ok_or_else(|| failed(AUTH_SPEC, "the server asks for a cleartext password, which the rule does not allow"))?;
                        send(server, &wire::password_message(password)).await?;
                        method = Some(PgAuth::Cleartext);
                    }
                    5 => {
                        let password = credentials
                            .password
                            .filter(|_| credentials.allow_md5)
                            .ok_or_else(|| {
                                failed(
                                    AUTH_SPEC,
                                    "the server asks for MD5, which the rule does not allow",
                                )
                            })?;
                        let salt: [u8; 4] = rest
                            .try_into()
                            .map_err(|_| protocol("an MD5 request is malformed"))?;
                        let hash =
                            Zeroizing::new(md5_hash(credentials.user.as_bytes(), password, salt));
                        send(
                            server,
                            &Zeroizing::new(wire::password_message(hash.as_bytes())),
                        )
                        .await?;
                        method = Some(PgAuth::Md5);
                    }
                    10 => {
                        let password = credentials.password.ok_or_else(|| {
                            failed(
                                AUTH_SPEC,
                                "the server asks for a password, and none was presented",
                            )
                        })?;
                        method = Some(
                            scram(server, password, rest, credentials.end_point.clone()).await?,
                        );
                    }
                    _ => {
                        return Err(failed(
                            AUTH_SPEC,
                            "the server asks for a method seal does not support",
                        ));
                    }
                }
            }
            _ => {
                return Err(protocol(
                    "the server sent something unexpected during the login",
                ));
            }
        }
    }
}

async fn read<S: AsyncRead + Unpin>(server: &mut S) -> Result<Message, LoginFailed> {
    let closed = BrokerError::new(
        ErrorCode::UpstreamReset,
        "the server closed during the login",
    );
    wire::read_message(server, MAX_LOGIN_MESSAGE, closed)
        .await
        .map_err(|error| LoginFailed {
            error,
            sqlstate: "08006".to_owned(),
        })
}

async fn send<S: AsyncWrite + Unpin>(server: &mut S, bytes: &[u8]) -> Result<(), LoginFailed> {
    server.write_all(bytes).await.map_err(|_| LoginFailed {
        error: BrokerError::new(
            ErrorCode::UpstreamReset,
            "the server closed during the login",
        ),
        sqlstate: "08006".to_owned(),
    })?;
    server.flush().await.map_err(|_| LoginFailed {
        error: BrokerError::new(
            ErrorCode::UpstreamReset,
            "the server closed during the login",
        ),
        sqlstate: "08006".to_owned(),
    })
}

/// An authentication request's kind and the rest of its body.
fn authentication(message: &Message) -> Result<(u32, &[u8]), LoginFailed> {
    let kind = message
        .body
        .get(..4)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or_else(|| protocol("an authentication request is malformed"))?;
    Ok((kind, &message.body[4..]))
}

const SCRAM: &str = "SCRAM-SHA-256";
const SCRAM_PLUS: &str = "SCRAM-SHA-256-PLUS";

async fn scram<S: AsyncRead + AsyncWrite + Unpin>(
    server: &mut S,
    password: &[u8],
    offered: &[u8],
    end_point: Option<Vec<u8>>,
) -> Result<PgAuth, LoginFailed> {
    let mechanisms: Vec<&[u8]> = offered
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .collect();
    let offers = |name: &str| mechanisms.contains(&name.as_bytes());
    // With PLUS offered, a client that cannot bind says so ("n"); one that could, but
    // was not offered it, says that ("y"), so the server can detect a downgrade.
    let (mechanism, binding, method) = match (offers(SCRAM_PLUS), end_point) {
        (true, Some(data)) => (
            SCRAM_PLUS,
            ChannelBinding::tls_server_end_point(data),
            PgAuth::ScramPlus,
        ),
        (true, None) if offers(SCRAM) => (SCRAM, ChannelBinding::unsupported(), PgAuth::Scram),
        (false, _) if offers(SCRAM) => (SCRAM, ChannelBinding::unrequested(), PgAuth::Scram),
        _ => {
            return Err(failed(
                AUTH_SPEC,
                "the server offers no SASL mechanism seal supports",
            ));
        }
    };
    let mut exchange = ScramSha256::new(password, binding);
    send(
        server,
        &wire::sasl_initial_response(mechanism, exchange.message()),
    )
    .await?;

    let message = expect_sasl(server, 11).await?;
    exchange
        .update(&message)
        .map_err(|_| failed(AUTH_SPEC, "the server's SCRAM challenge is not valid"))?;
    send(
        server,
        &Zeroizing::new(wire::sasl_response(exchange.message())),
    )
    .await?;

    let message = expect_sasl(server, 12).await?;
    // This checks the server's signature: it proves the server knows the password too.
    exchange
        .finish(&message)
        .map_err(|_| failed(AUTH_SPEC, "the server's SCRAM signature is not valid"))?;
    Ok(method)
}

/// The data of a SASL continue (11) or final (12) message.
async fn expect_sasl<S: AsyncRead + Unpin>(
    server: &mut S,
    expected: u32,
) -> Result<Vec<u8>, LoginFailed> {
    let message = read(server).await?;
    match message.tag {
        b'R' => {
            let (kind, rest) = authentication(&message)?;
            if kind == expected {
                Ok(rest.to_vec())
            } else {
                Err(protocol("the server's SCRAM exchange is out of order"))
            }
        }
        b'E' => Err(LoginFailed {
            error: BrokerError::new(ErrorCode::PgAuthFailed, "the server refused the login"),
            sqlstate: wire::error_sqlstate(&message.body).unwrap_or_else(|| AUTH_SPEC.to_owned()),
        }),
        _ => Err(protocol(
            "the server sent something unexpected during SCRAM",
        )),
    }
}

/// The `tls-server-end-point` data for a certificate: its hash under the hash of its
/// signature algorithm, with MD5 and SHA-1 raised to SHA-256 (RFC 5929). `None` for an
/// algorithm without one, such as Ed25519.
#[must_use]
pub fn tls_server_end_point(certificate: &[u8]) -> Option<Vec<u8>> {
    let algorithm = match signature_algorithm(certificate)? {
        // md5, sha1, sha256 with RSA; ecdsa with sha1 and sha256.
        [
            0x2a,
            0x86,
            0x48,
            0x86,
            0xf7,
            0x0d,
            0x01,
            0x01,
            0x04 | 0x05 | 0x0b,
        ]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] => &digest::SHA256,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] => &digest::SHA384,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] => &digest::SHA512,
        _ => return None,
    };
    Some(digest::digest(algorithm, certificate).as_ref().to_vec())
}

/// A DER element: its tag, its content, and what follows it.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// The OID of a certificate's `signatureAlgorithm`, as DER content bytes.
fn signature_algorithm(certificate: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    let (tag, inner, _) = der_element(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let (_, _, after_tbs) = der_element(inner)?;
    let (tag, algorithm, _) = der_element(after_tbs)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, oid, _) = der_element(algorithm)?;
    (tag == 0x06).then_some(oid)
}

#[cfg(test)]
mod tests;
