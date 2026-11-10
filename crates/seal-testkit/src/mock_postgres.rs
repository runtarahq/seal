//! A fake Postgres server, for testing the plumbing of a session without a database:
//! it answers an `SSLRequest`, completes TLS with a certificate for its host from a new
//! CA, records the first packet, accepts the login, and then echoes. The login is
//! accepted at once, or after SCRAM-SHA-256 with a password the server was given.

use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::{digest, hmac, pbkdf2};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::pki::TestPki;

/// The `SSLRequest` packet.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

/// A running fake server. Stops when dropped.
pub struct MockPostgres {
    port: u16,
    /// The CA its certificate is from, in PEM.
    pub ca_pem: String,
    packets: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl Drop for MockPostgres {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockPostgres {
    /// Starts a server with a certificate for `host`, which asks for no
    /// authentication, as `trust` does. Without `tls`, it declines TLS.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen or make certificates.
    pub async fn start(host: &str, tls: bool) -> Self {
        Self::start_inner(host, tls, None).await
    }

    /// Starts a server with a certificate for `host` that logs a client in with
    /// SCRAM-SHA-256, for this password.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen or make certificates.
    pub async fn start_scram(host: &str, password: &[u8]) -> Self {
        Self::start_inner(host, true, Some(password.to_vec())).await
    }

    async fn start_inner(host: &str, tls: bool, password: Option<Vec<u8>>) -> Self {
        let pki = TestPki::new("db CA");
        let issued = pki.server(&[host]);
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|_| unreachable!("protocol versions"))
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert_der.clone()], issued.key_der())
        .unwrap_or_else(|_| unreachable!("a test certificate"));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|_| unreachable!("binding a loopback port"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|_| unreachable!("a bound socket has an address"))
            .port();
        let packets = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&packets);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, recorded) = (acceptor.clone(), Arc::clone(&recorded));
                tokio::spawn(serve(stream, acceptor, recorded, tls, password.clone()));
            }
        });
        Self {
            port,
            ca_pem: pki.ca_pem,
            packets,
            task,
        }
    }

    /// The port it listens on, on 127.0.0.1.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The first packet of each session, without its length: a startup or a cancel.
    #[must_use]
    pub fn packets(&self) -> Vec<Vec<u8>> {
        self.packets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A startup parameter from the `index`th packet.
    #[must_use]
    pub fn startup_param(&self, index: usize, name: &str) -> Option<String> {
        let packets = self.packets();
        let body = packets.get(index)?;
        let mut parts = body.get(4..)?.split(|byte| *byte == 0);
        while let Some(key) = parts.next() {
            let value = parts.next()?;
            if key == name.as_bytes() {
                return String::from_utf8(value.to_vec()).ok();
            }
        }
        None
    }
}

async fn serve(
    mut stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    recorded: Arc<Mutex<Vec<Vec<u8>>>>,
    tls: bool,
    password: Option<Vec<u8>>,
) {
    let mut request = [0; 8];
    if stream.read_exact(&mut request).await.is_err() || request != SSL_REQUEST {
        return;
    }
    if !tls {
        let _ = stream.write_all(b"N").await;
        return;
    }
    if stream.write_all(b"S").await.is_err() {
        return;
    }
    let Ok(mut stream) = acceptor.accept(stream).await else {
        return;
    };
    let Ok(length) = stream.read_u32().await else {
        return;
    };
    let mut body = vec![0; usize::try_from(length).unwrap_or(0).saturating_sub(4)];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }
    let cancel = body.starts_with(&80_877_102_u32.to_be_bytes());
    recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(body);
    if cancel {
        return;
    }
    if let Some(password) = password
        && scram(&mut stream, &password).await.is_none()
    {
        return;
    }
    // AuthenticationOk, then ReadyForQuery.
    let hello = [b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'];
    if stream.write_all(&hello).await.is_err() {
        return;
    }
    let mut buffer = [0; 8192];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if stream.write_all(&buffer[..read]).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn authentication(kind: u32, data: &[u8]) -> Vec<u8> {
    let length = u32::try_from(8 + data.len()).unwrap_or(u32::MAX);
    let mut message = vec![b'R'];
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(data);
    message
}

/// The body of the client's next message, which must be a password message.
async fn password_message<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    if stream.read_u8().await.ok()? != b'p' {
        return None;
    }
    let length = usize::try_from(stream.read_u32().await.ok()?).ok()?;
    let mut body = vec![0; length.checked_sub(4).filter(|length| *length <= 1 << 16)?];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// The server's side of SCRAM-SHA-256 without channel binding (RFC 5802, RFC 7677).
/// `None` if the client broke the exchange or does not know the password.
async fn scram<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, password: &[u8]) -> Option<()> {
    let iterations = std::num::NonZeroU32::new(4096)?;
    stream
        .write_all(&authentication(10, b"SCRAM-SHA-256\0\0"))
        .await
        .ok()?;

    // The mechanism, a length, then the client's first message.
    let initial = password_message(stream).await?;
    let end = initial.iter().position(|byte| *byte == 0)?;
    let client_first = std::str::from_utf8(initial.get(end + 5..)?).ok()?;
    let gs2_end = client_first.match_indices(',').nth(1)?.0 + 1;
    let (_, bare) = client_first.split_at(gs2_end);
    let client_nonce = bare.split("r=").nth(1)?;
    let salt = b"salt-of-sixteen!";
    let server_first = format!(
        "r={client_nonce}server-nonce,s={},i={iterations}",
        STANDARD.encode(salt)
    );
    stream
        .write_all(&authentication(11, server_first.as_bytes()))
        .await
        .ok()?;

    let response = password_message(stream).await?;
    let client_final = std::str::from_utf8(&response).ok()?;
    let (without_proof, proof) = client_final.rsplit_once(",p=")?;
    let mut salted = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut salted,
    );
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = digest::digest(&digest::SHA256, &client_key);
    let auth_message = format!("{bare},{server_first},{without_proof}");
    let client_signature = hmac_sha256(stored_key.as_ref(), auth_message.as_bytes());
    let recovered: Vec<u8> = STANDARD
        .decode(proof)
        .ok()?
        .iter()
        .zip(&client_signature)
        .map(|(proof, signature)| proof ^ signature)
        .collect();
    if digest::digest(&digest::SHA256, &recovered).as_ref() != stored_key.as_ref() {
        return None;
    }
    let server_key = hmac_sha256(&salted, b"Server Key");
    let server_final = format!(
        "v={}",
        STANDARD.encode(hmac_sha256(&server_key, auth_message.as_bytes()))
    );
    stream
        .write_all(&authentication(12, server_final.as_bytes()))
        .await
        .ok()
}
