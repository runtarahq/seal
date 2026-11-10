//! A throwaway certificate authority for tests.

pub use rcgen::DnType;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A certificate and its key.
#[derive(Clone, Debug)]
pub struct Issued {
    /// The certificate, in PEM.
    pub cert_pem: String,
    /// The private key, in PEM.
    pub key_pem: String,
    /// The certificate, in DER.
    pub cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
}

impl Issued {
    /// The private key, for rustls.
    ///
    /// # Panics
    ///
    /// Never, since the key was generated here.
    #[must_use]
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der.clone())
            .unwrap_or_else(|_| unreachable!("a generated key"))
    }
}

/// A CA that issues server and client certificates.
pub struct TestPki {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    /// The CA's certificate, in PEM.
    pub ca_pem: String,
    /// The CA's certificate, in DER.
    pub ca_der: CertificateDer<'static>,
}

impl TestPki {
    /// A new CA.
    ///
    /// # Panics
    ///
    /// Panics if certificates cannot be made, which only a broken build causes.
    #[must_use]
    pub fn new(name: &str) -> Self {
        let ca_key = KeyPair::generate().unwrap_or_else(|_| unreachable!("key generation"));
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|_| unreachable!("parameters"));
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.distinguished_name.push(DnType::CommonName, name);
        let ca = ca_params
            .self_signed(&ca_key)
            .unwrap_or_else(|_| unreachable!("self-signing"));
        Self {
            ca_pem: ca.pem(),
            ca_der: ca.der().clone(),
            ca_params,
            ca_key,
        }
    }

    fn issue(&self, params: CertificateParams) -> Issued {
        let key = KeyPair::generate().unwrap_or_else(|_| unreachable!("key generation"));
        self.issue_for(params, &key)
    }

    fn issue_for(&self, params: CertificateParams, key: &KeyPair) -> Issued {
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let cert = params
            .signed_by(key, &issuer)
            .unwrap_or_else(|_| unreachable!("signing"));
        Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().clone(),
            key_der: key.serialize_der(),
        }
    }

    /// A server certificate for these names.
    #[must_use]
    pub fn server(&self, names: &[&str]) -> Issued {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let mut params =
            CertificateParams::new(names).unwrap_or_else(|_| unreachable!("parameters"));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        self.issue(params)
    }

    fn client_params(common_name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|_| unreachable!("parameters"));
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
    }

    /// A client certificate whose subject is `CN=<common_name>`.
    #[must_use]
    pub fn client(&self, common_name: &str) -> Issued {
        self.issue(Self::client_params(common_name))
    }

    /// A client certificate whose subject is these attributes, in this order.
    #[must_use]
    pub fn client_with_subject(&self, attributes: &[(DnType, &str)]) -> Issued {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|_| unreachable!("parameters"));
        params.distinguished_name = rcgen::DistinguishedName::new();
        for (kind, value) in attributes {
            params.distinguished_name.push(kind.clone(), *value);
        }
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        self.issue(params)
    }

    /// A client certificate whose subject is `CN=<common_name>`, with these DNS names
    /// and URIs as subject alternative names.
    ///
    /// # Panics
    ///
    /// Panics if a name cannot be in a certificate.
    #[must_use]
    pub fn client_with_names(&self, common_name: &str, dns: &[&str], uris: &[&str]) -> Issued {
        let mut params = Self::client_params(common_name);
        let name = |name: &str| {
            rcgen::string::Ia5String::try_from(name)
                .unwrap_or_else(|_| unreachable!("a name for a certificate"))
        };
        params.subject_alt_names = dns
            .iter()
            .map(|dns| rcgen::SanType::DnsName(name(dns)))
            .chain(uris.iter().map(|uri| rcgen::SanType::URI(name(uri))))
            .collect();
        self.issue(params)
    }

    /// A client certificate for an existing key, given as PKCS#8 PEM: RSA, ECDSA or
    /// Ed25519. `None` if the key cannot be read.
    #[must_use]
    pub fn client_for_key(&self, common_name: &str, pkcs8_pem: &str) -> Option<Issued> {
        let key = KeyPair::from_pem(pkcs8_pem).ok()?;
        let mut issued = self.issue_for(Self::client_params(common_name), &key);
        issued.key_pem = pkcs8_pem.to_owned();
        Some(issued)
    }
}
