//! Who may call, and which keysets each may use.

use std::collections::BTreeMap;

use seal_format::KeysetId;
use x509_parser::objects::{oid_registry, oid2abbrev};
use x509_parser::x509::X509Name;

use crate::config::CallerConfig;

/// How a connection's caller was identified.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Identity {
    /// A Unix socket peer's uid.
    Uid(u32),
    /// A TLS client certificate's subject, normalised.
    Subject(String),
}

/// A known caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The name in audit records.
    pub name: String,
    all_keysets: bool,
    keysets: Vec<KeysetId>,
    /// Whether it may make and rotate keys.
    pub admin: bool,
}

impl Caller {
    /// Whether it may use a keyset.
    #[must_use]
    pub fn may_use(&self, keyset: &KeysetId) -> bool {
        self.all_keysets || self.keysets.contains(keyset)
    }
}

/// Every known caller, by identity.
#[derive(Clone, Debug, Default)]
pub struct CallerMap {
    callers: BTreeMap<Identity, Caller>,
}

impl CallerMap {
    /// Builds the map. The configuration has been checked, so identifiers are valid.
    #[must_use]
    pub fn new(configs: &[CallerConfig]) -> Self {
        let callers = configs
            .iter()
            .filter_map(|config| {
                let identity = match (&config.unix_uid, &config.cert_subject) {
                    (Some(uid), None) => Identity::Uid(*uid),
                    (None, Some(subject)) => Identity::Subject(normalise_subject(subject)),
                    _ => return None,
                };
                let caller = Caller {
                    name: config.name.clone(),
                    all_keysets: config.keysets.iter().any(|keyset| keyset == "*"),
                    keysets: config
                        .keysets
                        .iter()
                        .filter_map(|keyset| KeysetId::new(keyset.clone()).ok())
                        .collect(),
                    admin: config.admin,
                };
                Some((identity, caller))
            })
            .collect();
        Self { callers }
    }

    /// The caller with this identity, if it is known.
    #[must_use]
    pub fn get(&self, identity: &Identity) -> Option<&Caller> {
        self.callers.get(identity)
    }
}

/// Puts a subject in one form: no spaces around separators, attribute names in upper
/// case. `CN=app, O=Example` and `cn=app,O=Example` become `CN=app,O=Example`.
#[must_use]
pub fn normalise_subject(subject: &str) -> String {
    subject
        .split(',')
        .map(|part| {
            let part = part.trim();
            match part.split_once('=') {
                Some((name, value)) => {
                    format!("{}={}", name.trim().to_ascii_uppercase(), value.trim())
                }
                None => part.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A certificate's subject in the form [`normalise_subject`] gives a configured one,
/// built from its attributes rather than from text, so that a value cannot pass for
/// an attribute boundary.
///
/// `None` for a subject that has no such form, which no caller can then be: one with
/// no attributes or a multi-valued one, or with a value that is not text, is empty,
/// holds a comma, or starts or ends with whitespace.
#[must_use]
pub fn certificate_subject(subject: &X509Name<'_>) -> Option<String> {
    let mut parts = Vec::new();
    for rdn in subject.iter() {
        let mut attributes = rdn.iter();
        let (Some(attribute), None) = (attributes.next(), attributes.next()) else {
            return None;
        };
        let name = oid2abbrev(attribute.attr_type(), oid_registry())
            .map_or_else(|_| attribute.attr_type().to_id_string(), str::to_owned);
        let value = attribute.as_str().ok()?;
        if value.is_empty() || value.contains(',') || value.trim() != value {
            return None;
        }
        parts.push(format!("{}={value}", name.to_ascii_uppercase()));
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

#[cfg(test)]
mod tests {
    use seal_testkit::pki::{DnType, TestPki};

    use super::*;

    fn subject_of(attributes: &[(DnType, &str)]) -> Option<String> {
        let issued = TestPki::new("client CA").client_with_subject(attributes);
        let (_, parsed) = x509_parser::parse_x509_certificate(issued.cert_der.as_ref()).unwrap();
        certificate_subject(parsed.subject())
    }

    #[test]
    fn a_certificate_subject_is_compared_by_attribute() {
        let honest = [
            (DnType::CommonName, "app"),
            (DnType::OrganizationName, "Example"),
        ];
        assert_eq!(subject_of(&honest).as_deref(), Some("CN=app,O=Example"));
        assert_eq!(
            subject_of(&honest),
            Some(normalise_subject("cn=app, O=Example"))
        );
        // One attribute whose value reads like two is no subject at all.
        assert_eq!(subject_of(&[(DnType::CommonName, "app,O=Example")]), None);
        assert_eq!(subject_of(&[(DnType::CommonName, "app, O=Example")]), None);
        // Nor is a value that trimming would turn into a configured one.
        assert_eq!(subject_of(&[(DnType::CommonName, " app")]), None);
        assert_eq!(subject_of(&[(DnType::CommonName, "")]), None);
        assert_eq!(subject_of(&[]), None);
        // A value may hold `=`, since a name never does.
        assert_eq!(
            subject_of(&[(DnType::CommonName, "a=b")]).as_deref(),
            Some("CN=a=b")
        );
    }

    fn config(
        name: &str,
        uid: Option<u32>,
        subject: Option<&str>,
        keysets: &[&str],
        admin: bool,
    ) -> CallerConfig {
        CallerConfig {
            name: name.to_owned(),
            unix_uid: uid,
            cert_subject: subject.map(str::to_owned),
            keysets: keysets.iter().map(|keyset| (*keyset).to_owned()).collect(),
            admin,
        }
    }

    #[test]
    fn callers_are_found_by_identity_and_limited_to_their_keysets() {
        let map = CallerMap::new(&[
            config("app", Some(990), None, &["acme", "beta"], false),
            config("ops", Some(0), None, &[], true),
            config("all", Some(5), None, &["*"], false),
        ]);
        let app = map.get(&Identity::Uid(990)).unwrap();
        assert_eq!(app.name, "app");
        assert!(app.may_use(&KeysetId::new("acme").unwrap()));
        assert!(!app.may_use(&KeysetId::new("other").unwrap()));
        assert!(!app.admin);

        let ops = map.get(&Identity::Uid(0)).unwrap();
        assert!(ops.admin);
        assert!(!ops.may_use(&KeysetId::new("acme").unwrap()));

        assert!(
            map.get(&Identity::Uid(5))
                .unwrap()
                .may_use(&KeysetId::new("anything").unwrap())
        );
        assert!(map.get(&Identity::Uid(1)).is_none());
    }

    #[test]
    fn subjects_compare_in_one_form() {
        let map = CallerMap::new(&[config(
            "app",
            None,
            Some("CN=app, O=Example"),
            &["*"],
            false,
        )]);
        for written in [
            "CN=app,O=Example",
            "cn=app, o=Example",
            " CN = app ,O=Example",
        ] {
            assert!(
                map.get(&Identity::Subject(normalise_subject(written)))
                    .is_some(),
                "{written}"
            );
        }
        assert!(
            map.get(&Identity::Subject(normalise_subject("CN=App,O=Example")))
                .is_none(),
            "values keep their case"
        );
        assert!(
            map.get(&Identity::Subject(normalise_subject("CN=app")))
                .is_none()
        );
    }
}
