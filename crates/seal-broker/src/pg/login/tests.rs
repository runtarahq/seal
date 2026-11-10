#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::{hmac, pbkdf2};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;

const PASSWORD: &[u8] = b"pa ss\xc3\xa9word";

/// What the fake server does.
#[derive(Clone)]
struct Server {
    mechanisms: Vec<&'static str>,
    password: Vec<u8>,
    /// The channel binding data the server expects with PLUS.
    end_point: Vec<u8>,
    bad_signature: bool,
    negotiate: bool,
}

impl Server {
    fn new(mechanisms: &[&'static str]) -> Self {
        Self {
            mechanisms: mechanisms.to_vec(),
            password: PASSWORD.to_vec(),
            end_point: b"certificate hash".to_vec(),
            bad_signature: false,
            negotiate: false,
        }
    }
}

async fn read_client(stream: &mut DuplexStream) -> Message {
    let closed = BrokerError::new(ErrorCode::UpstreamReset, "closed");
    wire::read_message(stream, 1 << 16, closed).await.unwrap()
}

fn auth(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut body = kind.to_be_bytes().to_vec();
    body.extend_from_slice(data);
    wire::message(b'R', &body)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// A SCRAM-SHA-256 server, from RFC 5802 and RFC 7677. Returns the gs2 header the client
/// sent, or `None` if it refused the client.
async fn scram_server(stream: &mut DuplexStream, server: &Server) -> Option<String> {
    let mut offered = Vec::new();
    for mechanism in &server.mechanisms {
        offered.extend_from_slice(mechanism.as_bytes());
        offered.push(0);
    }
    offered.push(0);
    stream.write_all(&auth(10, &offered)).await.unwrap();

    let initial = read_client(stream).await;
    let end = initial.body.iter().position(|byte| *byte == 0).unwrap();
    let mechanism = std::str::from_utf8(&initial.body[..end])
        .unwrap()
        .to_owned();
    assert!(server.mechanisms.contains(&mechanism.as_str()));
    let client_first = std::str::from_utf8(&initial.body[end + 5..])
        .unwrap()
        .to_owned();
    let gs2_end = client_first.match_indices(',').nth(1).unwrap().0 + 1;
    let (gs2, bare) = client_first.split_at(gs2_end);
    let client_nonce = bare.split("r=").nth(1).unwrap().to_owned();
    let salt = b"salt-of-sixteen!";
    let nonce = format!("{client_nonce}server-nonce");
    let server_first = format!("r={nonce},s={},i=4096", STANDARD.encode(salt));
    stream
        .write_all(&auth(11, server_first.as_bytes()))
        .await
        .unwrap();

    let response = read_client(stream).await;
    let client_final = std::str::from_utf8(&response.body).unwrap().to_owned();
    let (without_proof, proof) = client_final.rsplit_once(",p=").unwrap();
    let binding = STANDARD
        .decode(
            without_proof
                .strip_prefix("c=")
                .unwrap()
                .split(',')
                .next()
                .unwrap(),
        )
        .unwrap();
    let mut expected_binding = gs2.as_bytes().to_vec();
    if mechanism.ends_with("-PLUS") {
        expected_binding.extend_from_slice(&server.end_point);
    }
    assert_eq!(
        binding, expected_binding,
        "the channel binding is what the server expects"
    );

    let mut salted = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(4096).unwrap(),
        salt,
        &server.password,
        &mut salted,
    );
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = digest::digest(&digest::SHA256, &client_key);
    let auth_message = format!("{bare},{server_first},{without_proof}");
    let client_signature = hmac_sha256(stored_key.as_ref(), auth_message.as_bytes());
    let recovered: Vec<u8> = STANDARD
        .decode(proof)
        .unwrap()
        .iter()
        .zip(&client_signature)
        .map(|(proof, signature)| proof ^ signature)
        .collect();
    if digest::digest(&digest::SHA256, &recovered).as_ref() != stored_key.as_ref() {
        stream
            .write_all(&wire::error_response(
                "28P01",
                "password authentication failed for user \"app\"",
            ))
            .await
            .unwrap();
        return None;
    }
    let server_key = hmac_sha256(&salted, b"Server Key");
    let mut signature = hmac_sha256(&server_key, auth_message.as_bytes());
    if server.bad_signature {
        signature[0] ^= 1;
    }
    let server_final = format!("v={}", STANDARD.encode(signature));
    stream
        .write_all(&auth(12, server_final.as_bytes()))
        .await
        .unwrap();
    if !server.bad_signature {
        stream.write_all(&auth(0, &[])).await.unwrap();
    }
    Some(gs2.to_owned())
}

fn credentials(end_point: Option<Vec<u8>>) -> Credentials<'static> {
    Credentials {
        user: "app",
        password: Some(PASSWORD),
        allow_md5: false,
        allow_cleartext: false,
        require_channel_binding: false,
        client_cert: false,
        end_point,
    }
}

async fn run_scram(
    server: Server,
    credentials: Credentials<'static>,
) -> (Result<(PgAuth, Vec<u8>), LoginFailed>, Option<String>) {
    let (mut client, mut server_side) = tokio::io::duplex(1 << 16);
    let task = tokio::spawn(async move {
        if server.negotiate {
            let mut body = 2_u32.to_be_bytes().to_vec();
            body.extend_from_slice(&0_u32.to_be_bytes());
            server_side
                .write_all(&wire::message(b'v', &body))
                .await
                .unwrap();
        }
        scram_server(&mut server_side, &server).await
    });
    let result = login(&mut client, &credentials).await;
    (result, task.await.unwrap())
}

#[tokio::test]
async fn scram_with_channel_binding_when_offered() {
    let (result, gs2) = run_scram(
        Server::new(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]),
        credentials(Some(b"certificate hash".to_vec())),
    )
    .await;
    assert_eq!(result.unwrap().0, PgAuth::ScramPlus);
    assert_eq!(gs2.unwrap(), "p=tls-server-end-point,,");
}

#[tokio::test]
async fn scram_without_binding_says_why() {
    // The server does not offer PLUS: the client could have bound, so it says "y".
    let (result, gs2) = run_scram(
        Server::new(&["SCRAM-SHA-256"]),
        credentials(Some(b"h".to_vec())),
    )
    .await;
    assert_eq!(result.unwrap().0, PgAuth::Scram);
    assert_eq!(gs2.unwrap(), "y,,");
    // The server offers PLUS, but the certificate gives no hash: the client says "n".
    let (result, gs2) = run_scram(
        Server::new(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]),
        credentials(None),
    )
    .await;
    assert_eq!(result.unwrap().0, PgAuth::Scram);
    assert_eq!(gs2.unwrap(), "n,,");
}

#[tokio::test]
async fn a_wrong_password_keeps_only_the_sqlstate() {
    let mut server = Server::new(&["SCRAM-SHA-256"]);
    server.password = b"another".to_vec();
    let (result, _) = run_scram(server, credentials(None)).await;
    let failure = result.unwrap_err();
    assert_eq!(failure.error.code(), ErrorCode::PgAuthFailed);
    assert_eq!(failure.sqlstate, "28P01");
    assert!(!failure.error.detail().contains("app"));
}

#[tokio::test]
async fn a_server_that_cannot_prove_it_knows_the_password_is_refused() {
    let mut server = Server::new(&["SCRAM-SHA-256"]);
    server.bad_signature = true;
    let (result, _) = run_scram(server, credentials(None)).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
}

#[tokio::test]
async fn a_protocol_negotiation_is_passed_to_the_caller() {
    let mut server = Server::new(&["SCRAM-SHA-256"]);
    server.negotiate = true;
    let (result, _) = run_scram(server, credentials(None)).await;
    let (_, before_ok) = result.unwrap();
    assert_eq!(before_ok[0], b'v');
}

/// Runs a login against a server that sends `requests` and records what comes back.
async fn scripted(
    requests: Vec<Vec<u8>>,
    credentials: Credentials<'static>,
) -> (Result<PgAuth, LoginFailed>, Vec<Message>) {
    let (mut client, mut server) = tokio::io::duplex(1 << 16);
    let replies = requests.len().saturating_sub(1);
    let task = tokio::spawn(async move {
        let mut received = Vec::new();
        for (index, request) in requests.iter().enumerate() {
            server.write_all(request).await.unwrap();
            if index < replies {
                received.push(read_client(&mut server).await);
            }
        }
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            server.read_to_end(&mut rest),
        )
        .await;
        received
    });
    let result = login(&mut client, &credentials)
        .await
        .map(|(method, _)| method);
    drop(client);
    (result, task.await.unwrap())
}

#[tokio::test]
async fn md5_and_cleartext_only_where_allowed() {
    let salt = [1, 2, 3, 4];
    let (result, _) = scripted(vec![auth(5, &salt)], credentials(None)).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
    let (result, _) = scripted(vec![auth(3, &[])], credentials(None)).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);

    let mut allowed = credentials(None);
    allowed.allow_md5 = true;
    allowed.allow_cleartext = true;
    let (result, received) = scripted(vec![auth(5, &salt), auth(0, &[])], allowed).await;
    assert_eq!(result.unwrap(), PgAuth::Md5);
    let mut expected = md5_hash(b"app", PASSWORD, salt).into_bytes();
    expected.push(0);
    assert_eq!(received[0].body, expected);

    let mut allowed = credentials(None);
    allowed.allow_cleartext = true;
    let (result, received) = scripted(vec![auth(3, &[]), auth(0, &[])], allowed).await;
    assert_eq!(result.unwrap(), PgAuth::Cleartext);
    assert_eq!(received[0].body, [PASSWORD, b"\0"].concat());
}

#[tokio::test]
async fn a_certificate_login_needs_no_password() {
    let mut certificate = credentials(None);
    certificate.password = None;
    certificate.client_cert = true;
    let (result, _) = scripted(vec![auth(0, &[])], certificate).await;
    assert_eq!(result.unwrap(), PgAuth::Cert);
    // Without a password, a request for one fails.
    let mut certificate = credentials(None);
    certificate.password = None;
    certificate.client_cert = true;
    let (result, _) = scripted(vec![auth(10, b"SCRAM-SHA-256\0\0")], certificate).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
}

#[tokio::test]
async fn a_server_that_never_asks_for_the_password_is_refused() {
    let (result, _) = scripted(vec![auth(0, &[])], credentials(None)).await;
    let failed = result.unwrap_err();
    assert_eq!(failed.error.code(), ErrorCode::PgAuthFailed);
    assert_eq!(failed.sqlstate, "28000");
    // Nor part way through SCRAM, before its signature has been checked.
    let (result, _) = scripted(
        vec![auth(10, b"SCRAM-SHA-256\0\0"), auth(0, &[])],
        credentials(None),
    )
    .await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::UpstreamReset);
    // Without a password or a certificate, that is a `trust` login.
    let mut nothing = credentials(None);
    nothing.password = None;
    let (result, _) = scripted(vec![auth(0, &[])], nothing).await;
    assert_eq!(result.unwrap(), PgAuth::Trust);
}

#[tokio::test]
async fn a_rule_can_require_channel_binding() {
    let required = |end_point: Option<Vec<u8>>| {
        let mut credentials = credentials(end_point);
        credentials.require_channel_binding = true;
        credentials
    };
    let server = Server::new(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]);
    let end_point = server.end_point.clone();
    let (result, _) = run_scram(server.clone(), required(Some(end_point.clone()))).await;
    assert_eq!(result.unwrap().0, PgAuth::ScramPlus);

    // A server that does not offer it, or a certificate that cannot be bound to: the
    // login stops before the password is used.
    for (mechanisms, end_point) in [
        (b"SCRAM-SHA-256\0\0".to_vec(), Some(end_point)),
        (b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0".to_vec(), None),
    ] {
        let (result, received) = scripted(vec![auth(10, &mechanisms)], required(end_point)).await;
        assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
        assert!(received.is_empty(), "nothing was sent");
    }
    // Nor any method without binding, even one another flag would allow.
    for request in [auth(5, &[1, 2, 3, 4]), auth(3, &[])] {
        let mut credentials = required(None);
        credentials.allow_md5 = true;
        credentials.allow_cleartext = true;
        let (result, _) = scripted(vec![request], credentials).await;
        assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
    }
}

#[tokio::test]
async fn other_methods_and_messages_are_refused() {
    for request in [auth(7, &[]), auth(2, &[]), auth(9, &[])] {
        let (result, _) = scripted(vec![request], credentials(None)).await;
        assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
    }
    let (result, _) = scripted(vec![auth(10, b"OTHER\0\0")], credentials(None)).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::PgAuthFailed);
    let (result, _) = scripted(vec![wire::message(b'Z', b"I")], credentials(None)).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::UpstreamReset);
    let (result, _) = scripted(vec![], credentials(None)).await;
    assert_eq!(result.unwrap_err().error.code(), ErrorCode::UpstreamReset);
}

#[test]
fn the_end_point_hash_follows_the_signature_algorithm() {
    let pki = seal_testkit::pki::TestPki::new("CA");
    // rcgen signs with ECDSA P-256 and SHA-256 by default.
    let ecdsa = pki.server(&["db.example.com"]).cert_der;
    assert_eq!(
        tls_server_end_point(ecdsa.as_ref()).unwrap(),
        digest::digest(&digest::SHA256, ecdsa.as_ref()).as_ref()
    );
    assert_eq!(tls_server_end_point(b"not a certificate"), None);
    assert_eq!(
        tls_server_end_point(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
        None
    );
}
