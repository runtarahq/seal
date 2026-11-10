#![allow(clippy::unwrap_used)]

use super::*;

fn startup(version: u32, params: &[(&str, &str)]) -> Vec<u8> {
    Startup {
        version,
        params: params
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
    .encode()
}

async fn read(packet: &[u8]) -> Result<Preamble, BrokerError> {
    let mut reader = packet;
    read_preamble(&mut reader).await
}

#[tokio::test]
async fn startup_messages_of_both_versions_parse() {
    for version in [PROTOCOL_3_0, PROTOCOL_3_2] {
        let packet = startup(
            version,
            &[
                ("user", "app"),
                ("database", "db"),
                ("application_name", "x"),
            ],
        );
        let Preamble::Startup(parsed) = read(&packet).await.unwrap() else {
            panic!("a startup");
        };
        assert_eq!(parsed.version, version);
        assert_eq!(parsed.param("database"), Some("db"));
        assert_eq!(parsed.encode(), packet, "it encodes back the same");
    }
}

#[tokio::test]
async fn encryption_and_cancel_requests_parse() {
    assert_eq!(
        read(&[0, 0, 0, 8, 4, 210, 22, 47]).await.unwrap(),
        Preamble::SslRequest
    );
    assert_eq!(
        read(&[0, 0, 0, 8, 4, 210, 22, 48]).await.unwrap(),
        Preamble::GssEncRequest
    );
    // Protocol 3.0's four-byte key, and 3.2's longer ones.
    for key in [4_usize, 32, 256] {
        let mut packet = u32::try_from(12 + key).unwrap().to_be_bytes().to_vec();
        packet.extend_from_slice(&CANCEL_REQUEST.to_be_bytes());
        packet.extend_from_slice(&1234_u32.to_be_bytes());
        packet.extend(std::iter::repeat_n(7, key));
        assert_eq!(
            read(&packet).await.unwrap(),
            Preamble::Cancel(packet.clone()),
            "{key}"
        );
    }
}

#[tokio::test]
async fn malformed_first_packets_are_refused() {
    let mut long_cancel = 269_u32.to_be_bytes().to_vec();
    long_cancel.extend_from_slice(&CANCEL_REQUEST.to_be_bytes());
    long_cancel.extend(std::iter::repeat_n(0, 261));
    let mut repeated = startup(PROTOCOL_3_0, &[("user", "a")]);
    repeated.truncate(repeated.len() - 1);
    repeated.extend_from_slice(b"user\0b\0\0");
    let length = u32::try_from(repeated.len()).unwrap().to_be_bytes();
    repeated[..4].copy_from_slice(&length);
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0, 0, 0, 4],
        vec![0, 0, 0, 12, 4, 210, 22, 47, 0, 0, 0, 0],
        startup(2 << 16, &[("user", "a")]),
        startup(PROTOCOL_3_0 | 1, &[("user", "a")]),
        vec![0, 0, 0, 12, 4, 210, 22, 46, 0, 0, 0, 1],
        long_cancel,
        repeated,
        vec![0, 0, 0, 13, 0, 3, 0, 0, b'u', b's', b'e', b'r', 0],
        vec![0, 0, 39, 17, 0, 3, 0, 0],
        vec![0, 0, 0, 14, 0, 3, 0, 0, b'u', 0, 0xff, 0, 0, 0],
    ];
    for packet in cases {
        assert_eq!(
            read(&packet).await.unwrap_err().code(),
            ErrorCode::BadRequest,
            "{packet:?}"
        );
    }
}

#[tokio::test]
async fn messages_are_framed_and_bounded() {
    let framed = message(b'R', &[0, 0, 0, 0]);
    assert_eq!(framed, authentication_ok());
    let closed = || BrokerError::new(ErrorCode::UpstreamReset, "closed");
    let mut reader = framed.as_slice();
    let read = read_message(&mut reader, 1024, closed()).await.unwrap();
    assert_eq!((read.tag, read.body.as_slice()), (b'R', &[0, 0, 0, 0][..]));
    let big = message(b'D', &[0; 2000]);
    let mut reader = big.as_slice();
    assert!(read_message(&mut reader, 1024, closed()).await.is_err());
    let mut reader: &[u8] = &[b'R', 0, 0];
    assert!(read_message(&mut reader, 1024, closed()).await.is_err());
}

#[test]
fn only_the_sqlstate_of_an_error_is_kept() {
    let error = error_response("28P01", "password authentication failed for user \"app\"");
    let body = &error[5..];
    assert_eq!(error_sqlstate(body).as_deref(), Some("28P01"));
    assert_eq!(error_sqlstate(b"Mno code\0\0"), None);
    assert_eq!(error_sqlstate(b"Cbad code here\0\0"), None);
    assert_eq!(error_sqlstate(b"C28P0"), None);
}

#[test]
fn login_messages_have_their_documented_form() {
    assert_eq!(
        password_message(b"pw").as_slice(),
        [b'p', 0, 0, 0, 7, b'p', b'w', 0]
    );
    let initial = sasl_initial_response("SCRAM-SHA-256", b"n,,n=,r=abc");
    assert_eq!(initial[0], b'p');
    assert!(initial.ends_with(b"SCRAM-SHA-256\0\0\0\0\x0bn,,n=,r=abc"));
    assert_eq!(ssl_request(), [0, 0, 0, 8, 4, 210, 22, 47]);
}
