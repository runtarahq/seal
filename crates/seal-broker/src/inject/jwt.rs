//! Signs the short-lived JWTs of `jwt_assertion`: client assertions for
//! `private_key_jwt`, and assertions for the JWT bearer grant.
//!
//! Signed with `ring`, which seal already uses for TLS. The JWT goes only into the
//! request, never back to the caller.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaKeyPair,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use seal_format::policy::{JwtAlg, JwtClaims, JwtHeader};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::error::{BrokerError, ErrorCode};

/// The `client_assertion_type` for `private_key_jwt`.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn bad_key() -> BrokerError {
    BrokerError::new(
        ErrorCode::BadRequest,
        "the signing key does not suit the rule's algorithm",
    )
}

enum SigningKey {
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair),
}

/// The DER prefix that turns a SEC1 P-256 key into PKCS#8: the version, and the
/// algorithm identifier `id-ecPublicKey` with `prime256v1`.
const P256_PKCS8_PREFIX: &[u8] = &[
    0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

/// DER length bytes.
fn der_length(length: usize) -> Vec<u8> {
    match length {
        0..=0x7f => vec![u8::try_from(length).unwrap_or(0)],
        0x80..=0xff => vec![0x81, u8::try_from(length).unwrap_or(0)],
        _ => {
            let [high, low] = u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes();
            vec![0x82, high, low]
        }
    }
}

/// Wraps a SEC1 P-256 private key as PKCS#8, which is what `ring` reads.
fn sec1_to_pkcs8(sec1: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut octets = vec![0x04];
    octets.extend(der_length(sec1.len()));
    let mut body = Zeroizing::new(P256_PKCS8_PREFIX.to_vec());
    body.extend_from_slice(&octets);
    body.extend_from_slice(sec1);
    let mut pkcs8 = Zeroizing::new(vec![0x30]);
    pkcs8.extend(der_length(body.len()));
    pkcs8.extend_from_slice(&body);
    pkcs8
}

fn parse_key(pem: &[u8], alg: JwtAlg, random: &SystemRandom) -> Result<SigningKey, BrokerError> {
    let der = PrivateKeyDer::from_pem_slice(pem).map_err(|_| bad_key())?;
    match (alg, der) {
        (JwtAlg::RS256 | JwtAlg::PS256, PrivateKeyDer::Pkcs8(der)) => {
            RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
                .map(SigningKey::Rsa)
                .map_err(|_| bad_key())
        }
        (JwtAlg::RS256 | JwtAlg::PS256, PrivateKeyDer::Pkcs1(der)) => {
            RsaKeyPair::from_der(der.secret_pkcs1_der())
                .map(SigningKey::Rsa)
                .map_err(|_| bad_key())
        }
        (JwtAlg::ES256, PrivateKeyDer::Pkcs8(der)) => EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            der.secret_pkcs8_der(),
            random,
        )
        .map(SigningKey::Ecdsa)
        .map_err(|_| bad_key()),
        (JwtAlg::ES256, PrivateKeyDer::Sec1(der)) => {
            let pkcs8 = sec1_to_pkcs8(der.secret_sec1_der());
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, random)
                .map(SigningKey::Ecdsa)
                .map_err(|_| bad_key())
        }
        _ => Err(bad_key()),
    }
}

fn alg_name(alg: JwtAlg) -> &'static str {
    match alg {
        JwtAlg::RS256 => "RS256",
        JwtAlg::PS256 => "PS256",
        JwtAlg::ES256 => "ES256",
    }
}

/// What a JWT is made from, besides the key.
pub struct JwtParts<'a> {
    /// The algorithm.
    pub alg: JwtAlg,
    /// The audience, as sent.
    pub aud: &'a str,
    /// The rule's claims.
    pub claims: &'a JwtClaims,
    /// The rule's header parameters.
    pub header: &'a JwtHeader,
    /// The lifetime in seconds.
    pub lifetime_s: u16,
    /// The time it is issued.
    pub now: SystemTime,
}

/// Signs a JWT with a PEM private key: PKCS#8 or PKCS#1 RSA of at least 2048 bits, or a
/// PKCS#8 or SEC1 P-256 key.
///
/// # Errors
///
/// Returns [`ErrorCode::BadRequest`] if the key is malformed or does not suit the
/// algorithm, and [`ErrorCode::Internal`] if signing fails.
pub fn sign(parts: &JwtParts<'_>, key_pem: &[u8]) -> Result<Zeroizing<String>, BrokerError> {
    let random = SystemRandom::new();
    let key = parse_key(key_pem, parts.alg, &random)?;
    let failed = || BrokerError::new(ErrorCode::Internal, "could not sign a JWT");

    let iat = parts
        .now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failed())?
        .as_secs();
    let mut jti = [0_u8; 16];
    random.fill(&mut jti).map_err(|_| failed())?;

    let mut header = Map::new();
    header.insert("alg".to_owned(), Value::from(alg_name(parts.alg)));
    header.insert(
        "typ".to_owned(),
        Value::from(parts.header.typ.as_deref().unwrap_or("JWT")),
    );
    if let Some(kid) = &parts.header.kid {
        header.insert("kid".to_owned(), Value::from(kid.as_str()));
    }
    if let Some(thumbprint) = &parts.header.x5t_s256 {
        header.insert("x5t#S256".to_owned(), Value::from(thumbprint.as_str()));
    }

    let mut claims = Map::new();
    for (name, value) in &parts.claims.extra {
        claims.insert(name.clone(), Value::from(value.as_str()));
    }
    claims.insert("iss".to_owned(), Value::from(parts.claims.iss.as_str()));
    if let Some(sub) = &parts.claims.sub {
        claims.insert("sub".to_owned(), Value::from(sub.as_str()));
    }
    if let Some(scope) = &parts.claims.scope {
        claims.insert("scope".to_owned(), Value::from(scope.as_str()));
    }
    // A single string, never an array, because servers compare it as one.
    claims.insert("aud".to_owned(), Value::from(parts.aud));
    claims.insert("iat".to_owned(), Value::from(iat));
    claims.insert("nbf".to_owned(), Value::from(iat));
    claims.insert(
        "exp".to_owned(),
        Value::from(iat + u64::from(parts.lifetime_s)),
    );
    claims.insert(
        "jti".to_owned(),
        Value::from(
            jti.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        ),
    );

    let encode = |value: &Map<String, Value>| {
        serde_json::to_vec(value)
            .map(|json| URL_SAFE_NO_PAD.encode(json))
            .map_err(|_| failed())
    };
    let mut jwt = Zeroizing::new(format!("{}.{}", encode(&header)?, encode(&claims)?));
    let signature = match key {
        SigningKey::Rsa(key) => {
            let mut signature = vec![0; key.public().modulus_len()];
            let padding: &dyn ring::signature::RsaEncoding = match parts.alg {
                JwtAlg::PS256 => &RSA_PSS_SHA256,
                _ => &RSA_PKCS1_SHA256,
            };
            key.sign(padding, &random, jwt.as_bytes(), &mut signature)
                .map_err(|_| failed())?;
            signature
        }
        SigningKey::Ecdsa(key) => key
            .sign(&random, jwt.as_bytes())
            .map_err(|_| failed())?
            .as_ref()
            .to_vec(),
    };
    jwt.push('.');
    jwt.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(jwt)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use ring::signature::{
        ECDSA_P256_SHA256_FIXED, KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
        UnparsedPublicKey,
    };

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/jwt/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn claims() -> JwtClaims {
        JwtClaims {
            iss: "client-id".to_owned(),
            sub: Some("client-id".to_owned()),
            scope: Some("read".to_owned()),
            extra: BTreeMap::from([("tenant".to_owned(), "acme".to_owned())]),
        }
    }

    fn parts<'a>(alg: JwtAlg, claims: &'a JwtClaims, header: &'a JwtHeader) -> JwtParts<'a> {
        JwtParts {
            alg,
            aud: "https://auth.example.com/oauth/token",
            claims,
            header,
            lifetime_s: 300,
            now: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        }
    }

    fn decode(jwt: &str) -> (Value, Value, Vec<u8>, String) {
        let pieces: Vec<&str> = jwt.split('.').collect();
        assert_eq!(pieces.len(), 3);
        let json = |piece: &str| {
            serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(piece).unwrap()).unwrap()
        };
        (
            json(pieces[0]),
            json(pieces[1]),
            URL_SAFE_NO_PAD.decode(pieces[2]).unwrap(),
            format!("{}.{}", pieces[0], pieces[1]),
        )
    }

    fn rsa_public(name: &str) -> Vec<u8> {
        let der = PrivateKeyDer::from_pem_slice(&fixture(name)).unwrap();
        let key = match der {
            PrivateKeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()).unwrap(),
            PrivateKeyDer::Pkcs1(der) => RsaKeyPair::from_der(der.secret_pkcs1_der()).unwrap(),
            _ => unreachable!(),
        };
        key.public_key().as_ref().to_vec()
    }

    #[test]
    fn rs256_signs_the_documented_claims_and_header() {
        let (claims, header) = (
            claims(),
            JwtHeader {
                typ: None,
                kid: Some("k1".to_owned()),
                x5t_s256: Some("thumb".to_owned()),
            },
        );
        let jwt = sign(
            &parts(JwtAlg::RS256, &claims, &header),
            &fixture("rsa-pkcs8.pem"),
        )
        .unwrap();
        let (header, claims, signature, input) = decode(&jwt);
        assert_eq!(
            header,
            serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "k1", "x5t#S256": "thumb" })
        );
        assert_eq!(claims["iss"], "client-id");
        assert_eq!(claims["sub"], "client-id");
        assert_eq!(claims["scope"], "read");
        assert_eq!(claims["tenant"], "acme");
        assert_eq!(claims["aud"], "https://auth.example.com/oauth/token");
        assert_eq!(claims["iat"], 1_800_000_000_u64);
        assert_eq!(claims["nbf"], 1_800_000_000_u64);
        assert_eq!(claims["exp"], 1_800_000_300_u64);
        assert_eq!(claims["jti"].as_str().unwrap().len(), 32);
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, rsa_public("rsa-pkcs8.pem"))
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn rs256_is_deterministic_apart_from_the_jti() {
        let (claims, header) = (claims(), JwtHeader::default());
        let first = sign(
            &parts(JwtAlg::RS256, &claims, &header),
            &fixture("rsa-pkcs8.pem"),
        )
        .unwrap();
        let second = sign(
            &parts(JwtAlg::RS256, &claims, &header),
            &fixture("rsa-pkcs8.pem"),
        )
        .unwrap();
        assert_ne!(*first, *second, "each JWT has its own jti");
        assert_ne!(decode(&first).1["jti"], decode(&second).1["jti"]);
    }

    #[test]
    fn ps256_signs_with_pss_and_a_pkcs1_key() {
        let (claims, header) = (claims(), JwtHeader::default());
        let jwt = sign(
            &parts(JwtAlg::PS256, &claims, &header),
            &fixture("rsa-pkcs1.pem"),
        )
        .unwrap();
        let (header, _, signature, input) = decode(&jwt);
        assert_eq!(header["alg"], "PS256");
        UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, rsa_public("rsa-pkcs1.pem"))
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn es256_signs_with_a_pkcs8_or_sec1_key_in_fixed_form() {
        let (claims, header) = (claims(), JwtHeader::default());
        let random = SystemRandom::new();
        for name in ["ec-pkcs8.pem", "ec-sec1.pem"] {
            let jwt = sign(&parts(JwtAlg::ES256, &claims, &header), &fixture(name)).unwrap();
            let (header, _, signature, input) = decode(&jwt);
            assert_eq!(header["alg"], "ES256");
            assert_eq!(signature.len(), 64, "JWS uses r || s, not DER");
            let SigningKey::Ecdsa(key) = parse_key(&fixture(name), JwtAlg::ES256, &random).unwrap()
            else {
                unreachable!()
            };
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
                .verify(input.as_bytes(), &signature)
                .unwrap();
        }
    }

    #[test]
    fn a_key_that_does_not_suit_the_algorithm_is_refused() {
        let (claims, header) = (claims(), JwtHeader::default());
        for (alg, name) in [
            (JwtAlg::RS256, "ec-pkcs8.pem"),
            (JwtAlg::ES256, "rsa-pkcs8.pem"),
            (JwtAlg::RS256, "rsa-1024.pem"),
            (JwtAlg::ES256, "ec-p384.pem"),
        ] {
            let error = sign(&parts(alg, &claims, &header), &fixture(name)).unwrap_err();
            assert_eq!(error.code(), ErrorCode::BadRequest, "{name}");
        }
        let error = sign(&parts(JwtAlg::RS256, &claims, &header), b"not a key").unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest);
        assert!(!error.to_string().contains("not a key"));
    }

    #[test]
    fn the_audience_and_typ_are_sent_as_given() {
        let claims = claims();
        let header = JwtHeader {
            typ: Some("client-authentication+jwt".to_owned()),
            ..JwtHeader::default()
        };
        let mut parts = parts(JwtAlg::RS256, &claims, &header);
        parts.aud = "https://tenant.example.com/";
        parts.lifetime_s = 60;
        let (header, claims, _, _) = decode(&sign(&parts, &fixture("rsa-pkcs8.pem")).unwrap());
        assert_eq!(header["typ"], "client-authentication+jwt");
        assert_eq!(claims["aud"], "https://tenant.example.com/");
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            60
        );
    }
}
