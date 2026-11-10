//! Client certificates toward providers: the TLS identity of one sealed private key.
//!
//! Connections that carry a client certificate are pooled per identity. An identity
//! is named by a fingerprint: HMAC-SHA-256, under a key generated when the client
//! starts, over the record and sealing key the private key came from, the
//! certificate, the key, the chain, and the rule's CA and server name. The `kid`
//! names the sealing key, not the certificate, so it cannot tell a replaced
//! certificate from the old one; the fingerprint does. The fingerprint stays in
//! memory and is never logged.

use std::sync::{Arc, Weak};

use ring::hmac;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use seal_format::FieldName;
use seal_keys::LiveKey;

use crate::error::{BrokerError, ErrorCode};

/// What a client certificate's TLS configuration is built from.
pub struct ClientCertMaterial {
    /// The certificate, then any intermediates.
    pub chain: Vec<CertificateDer<'static>>,
    /// The private key.
    pub key: PrivateKeyDer<'static>,
    /// The rule's CA for this destination, if it names one.
    pub ca: Vec<CertificateDer<'static>>,
    /// The rule's name to verify the provider's certificate against.
    pub server_name: Option<String>,
    /// The field holding the private key.
    pub field: FieldName,
}

/// `PrivateKeyDer` can be wiped but does not wipe itself when dropped.
impl Drop for ClientCertMaterial {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

impl std::fmt::Debug for ClientCertMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertMaterial")
            .field("field", &self.field)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

fn bad(detail: &'static str, field: &FieldName) -> BrokerError {
    BrokerError::for_field(ErrorCode::BadRequest, detail, field)
}

/// Certificates from PEM; at least one.
fn certificates(
    pem: &[u8],
    field: &FieldName,
) -> Result<Vec<CertificateDer<'static>>, BrokerError> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| bad("a certificate is not valid PEM", field))?;
    if certificates.is_empty() {
        return Err(bad("no certificate was found", field));
    }
    Ok(certificates)
}

impl ClientCertMaterial {
    /// Parses the parts: a PEM key in PKCS#8, PKCS#1 or SEC1, and PEM certificates.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] naming the field, for anything that does not parse.
    pub fn parse(
        field: &FieldName,
        key_pem: &[u8],
        cert_pem: &[u8],
        chain_pem: Option<&[u8]>,
        ca_pem: Option<&str>,
        server_name: Option<&str>,
    ) -> Result<Self, BrokerError> {
        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|_| bad("the private key is not a PEM key", field))?;
        let mut chain = certificates(cert_pem, field)?;
        if let Some(chain_pem) = chain_pem {
            chain.extend(certificates(chain_pem, field)?);
        }
        let ca = ca_pem
            .map(|pem| certificates(pem.as_bytes(), field))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            chain,
            key,
            ca,
            server_name: server_name.map(str::to_owned),
            field: field.clone(),
        })
    }
}

/// A client certificate for one request, with where its key came from.
pub struct ClientIdentity {
    /// The certificate, key and TLS settings.
    pub material: ClientCertMaterial,
    /// The record and sealing key the private key was opened with, length-prefixed.
    pub origin: Vec<u8>,
    /// The sealing key. Once the keyring lets it go, by eviction or removal, the
    /// identity's connections are closed.
    pub sealing_key: Weak<LiveKey>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("material", &self.material)
            .finish_non_exhaustive()
    }
}

/// Length-prefixed parts, so that no two different sets of parts run together.
pub(crate) fn length_prefixed<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The fingerprint of an identity, under the client's own key.
pub(crate) fn fingerprint(key: &hmac::Key, identity: &ClientIdentity) -> [u8; 32] {
    let material = &identity.material;
    let mut context = hmac::Context::with_key(key);
    let mut add = |bytes: &[u8]| {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    };
    add(&identity.origin);
    add(&(material.chain.len() as u64).to_be_bytes());
    for certificate in &material.chain {
        add(certificate.as_ref());
    }
    add(material.key.secret_der());
    add(&(material.ca.len() as u64).to_be_bytes());
    for certificate in &material.ca {
        add(certificate.as_ref());
    }
    add(material.server_name.as_deref().unwrap_or("").as_bytes());
    let tag = context.sign();
    let mut out = [0; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Whether two weak references are to the same live key.
pub(crate) fn same_live_key(first: &Weak<LiveKey>, second: &Weak<LiveKey>) -> bool {
    first.strong_count() > 0 && Weak::ptr_eq(first, second)
}

/// A strong reference, for checking that a key is still held by the keyring.
pub(crate) fn is_live(key: &Weak<LiveKey>) -> bool {
    key.upgrade().is_some_and(|key| Arc::strong_count(&key) > 1)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use seal_format::PrivateKey;

    use super::*;

    fn pem(label: &str, der: &[u8]) -> String {
        use base64::Engine;
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    }

    fn material(cert: &[u8], key: &[u8], server_name: Option<&str>) -> ClientCertMaterial {
        let field = FieldName::new("client_key").unwrap();
        ClientCertMaterial::parse(
            &field,
            pem("PRIVATE KEY", key).as_bytes(),
            pem("CERTIFICATE", cert).as_bytes(),
            None,
            None,
            server_name,
        )
        .unwrap()
    }

    fn identity(
        cert: &[u8],
        key: &[u8],
        server_name: Option<&str>,
        origin: &[u8],
    ) -> ClientIdentity {
        ClientIdentity {
            material: material(cert, key, server_name),
            origin: origin.to_vec(),
            sealing_key: Weak::new(),
        }
    }

    #[test]
    fn any_change_is_a_new_fingerprint() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]);
        let base = fingerprint(&key, &identity(b"cert", b"key", None, b"acme/c_1/k1"));
        assert_eq!(
            base,
            fingerprint(&key, &identity(b"cert", b"key", None, b"acme/c_1/k1"))
        );
        for other in [
            identity(b"cert2", b"key", None, b"acme/c_1/k1"),
            identity(b"cert", b"key2", None, b"acme/c_1/k1"),
            identity(b"cert", b"key", Some("api.example.com"), b"acme/c_1/k1"),
            identity(b"cert", b"key", None, b"acme/c_2/k1"),
        ] {
            assert_ne!(base, fingerprint(&key, &other));
        }
        // Under another process's key, the same identity is unrecognisable.
        let other_key = hmac::Key::new(hmac::HMAC_SHA256, &[8; 32]);
        assert_ne!(
            base,
            fingerprint(&other_key, &identity(b"cert", b"key", None, b"acme/c_1/k1"))
        );
    }

    #[test]
    fn a_chain_and_ca_are_part_of_the_identity() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]);
        let mut with_chain = identity(b"cert", b"key", None, b"o");
        with_chain
            .material
            .chain
            .push(CertificateDer::from(b"intermediate".to_vec()));
        let mut with_ca = identity(b"cert", b"key", None, b"o");
        with_ca
            .material
            .ca
            .push(CertificateDer::from(b"intermediate".to_vec()));
        assert_ne!(fingerprint(&key, &with_chain), fingerprint(&key, &with_ca));
    }

    #[test]
    fn unparseable_parts_are_refused_naming_the_field() {
        let field = FieldName::new("client_key").unwrap();
        let key = pem("PRIVATE KEY", b"k");
        let cert = pem("CERTIFICATE", b"c");
        for (key, cert, ca) in [
            ("not pem", cert.as_str(), None),
            (key.as_str(), "not pem", None),
            (key.as_str(), cert.as_str(), Some("not pem")),
        ] {
            let error =
                ClientCertMaterial::parse(&field, key.as_bytes(), cert.as_bytes(), None, ca, None)
                    .err()
                    .unwrap();
            assert_eq!(error.code(), ErrorCode::BadRequest);
            assert!(error.detail().contains("client_key"));
        }
    }

    #[test]
    fn a_key_is_live_while_someone_else_holds_it() {
        let (private, _) = PrivateKey::generate();
        let held = Arc::new(LiveKey::unlimited(private));
        let weak = Arc::downgrade(&held);
        assert!(is_live(&weak));
        assert!(same_live_key(&weak, &Arc::downgrade(&held)));
        drop(held);
        assert!(!is_live(&weak));
        assert!(!same_live_key(&weak, &weak));
        assert_eq!(length_prefixed([&b"a"[..], b"bc"]).len(), 8 + 1 + 8 + 2);
    }
}
