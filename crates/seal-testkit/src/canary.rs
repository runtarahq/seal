//! Canary secrets and scanning for them.
//!
//! A canary is a fake secret with a recognisable prefix. Tests use canaries in
//! place of real secrets, register them, and scan everything seal emits for
//! them and their encodings. A hit means a secret leaked.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

/// The prefix of every generated canary.
pub const CANARY_PREFIX: &str = "SEALCANARY";

/// Characters that encode differently in each format, so that a generated
/// canary cannot look the same raw and encoded. All are valid in HTTP headers.
const SPECIAL_CHARACTERS: &str = "+/ \"&=\\";

/// Everything except RFC 3986's unreserved characters.
const STRICT_PERCENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A fake secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canary {
    value: String,
}

impl Canary {
    /// Generates a random canary.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system's random source fails.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)?;
        let random: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            value: format!("{CANARY_PREFIX}-{random}-{SPECIAL_CHARACTERS}"),
        })
    }

    /// Wraps a specific value, such as a token issued by a mock provider.
    #[must_use]
    pub fn from_value(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// The raw value, to use wherever a test needs the secret.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Every form of this canary that a scan looks for.
    #[must_use]
    pub fn encodings(&self) -> Vec<(Encoding, String)> {
        let bytes = self.value.as_bytes();
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let json = serde_json::Value::from(self.value.as_str()).to_string();
        let json = json
            .strip_prefix('"')
            .and_then(|escaped| escaped.strip_suffix('"'))
            .unwrap_or(&json)
            .to_owned();
        vec![
            (Encoding::Raw, self.value.clone()),
            (Encoding::Base64, STANDARD.encode(bytes)),
            (Encoding::Base64Url, URL_SAFE.encode(bytes)),
            (Encoding::Base64UrlNoPad, URL_SAFE_NO_PAD.encode(bytes)),
            (Encoding::HexLower, hex.clone()),
            (Encoding::HexUpper, hex.to_uppercase()),
            (
                Encoding::Percent,
                percent_encoding::utf8_percent_encode(&self.value, STRICT_PERCENT).to_string(),
            ),
            (
                Encoding::Form,
                form_urlencoded::byte_serialize(bytes).collect(),
            ),
            (Encoding::Json, json),
        ]
    }
}

/// A form in which a canary can appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// The value as is.
    Raw,
    /// Standard base64, with padding.
    Base64,
    /// URL-safe base64, with padding.
    Base64Url,
    /// URL-safe base64, without padding.
    Base64UrlNoPad,
    /// Lowercase hexadecimal.
    HexLower,
    /// Uppercase hexadecimal.
    HexUpper,
    /// Percent-encoded, as in a URL path.
    Percent,
    /// Form-encoded, where a space becomes `+`.
    Form,
    /// Escaped as the inside of a JSON string.
    Json,
    /// Base64 of `username:password`, as in basic auth.
    BasicAuth,
}

/// A canary found where it should not be.
///
/// Reports where the canary was found, never its value or the text around it,
/// so that a failing test does not add a secret to the test output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// What was being scanned, such as `"logs"` or `"audit"`.
    pub location: String,
    /// Which form of the canary was found.
    pub encoding: Encoding,
    /// The byte offset in the scanned text.
    pub offset: usize,
}

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "canary found in {} at byte {} ({:?})",
            self.location, self.offset, self.encoding
        )
    }
}

/// The canaries a test has registered.
#[derive(Clone, Debug, Default)]
pub struct CanaryRegistry {
    forms: Vec<(Encoding, String)>,
}

impl CanaryRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a canary and all of its encodings.
    pub fn register(&mut self, canary: &Canary) {
        self.add_forms(canary.encodings());
    }

    /// Registers the basic auth form of a username and password.
    ///
    /// This needs its own entry because base64 of `user:pass` does not contain
    /// the base64 of `pass`.
    pub fn register_basic_auth(&mut self, username: &str, password: &Canary) {
        let credentials = format!("{username}:{}", password.value());
        self.add_forms([(Encoding::BasicAuth, STANDARD.encode(credentials))]);
    }

    /// Finds every registered canary in `text`. `location` names what `text`
    /// is, for the report.
    #[must_use]
    pub fn scan(&self, location: &str, text: &str) -> Vec<Hit> {
        let mut hits: Vec<Hit> = self
            .forms
            .iter()
            .flat_map(|(encoding, form)| {
                text.match_indices(form.as_str()).map(|(offset, _)| Hit {
                    location: location.to_owned(),
                    encoding: *encoding,
                    offset,
                })
            })
            .collect();
        hits.sort_by_key(|hit| hit.offset);
        hits
    }

    fn add_forms(&mut self, forms: impl IntoIterator<Item = (Encoding, String)>) {
        for (encoding, form) in forms {
            // An empty form would match everywhere. A repeated one, such as a
            // value that encodes to itself, would report the same hit twice.
            if !form.is_empty() && !self.forms.iter().any(|(_, known)| *known == form) {
                self.forms.push((encoding, form));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered(canary: &Canary) -> CanaryRegistry {
        let mut registry = CanaryRegistry::new();
        registry.register(canary);
        registry
    }

    #[test]
    fn generated_canaries_are_recognisable_and_unique() {
        let first = Canary::generate().unwrap();
        let second = Canary::generate().unwrap();
        assert!(first.value().starts_with(CANARY_PREFIX));
        assert_ne!(first, second);
    }

    #[test]
    fn special_characters_make_a_generated_canary_encode_differently() {
        let encodings = Canary::generate().unwrap().encodings();
        // The base64 variants are left out: they match unless the output
        // happens to contain `+`, `/` or padding.
        let forms: Vec<(Encoding, String)> = encodings
            .into_iter()
            .filter(|(encoding, _)| {
                !matches!(encoding, Encoding::Base64Url | Encoding::Base64UrlNoPad)
            })
            .collect();
        for (index, (encoding, form)) in forms.iter().enumerate() {
            for (other_encoding, other) in &forms[index + 1..] {
                assert_ne!(form, other, "{encoding:?} and {other_encoding:?}");
            }
        }
    }

    #[test]
    fn encodings_match_known_answers() {
        let forms = Canary::from_value("a b+/\"é").encodings();
        let form = |wanted| {
            forms
                .iter()
                .find(|(encoding, _)| *encoding == wanted)
                .map(|(_, form)| form.as_str())
                .unwrap()
        };
        assert_eq!(form(Encoding::Raw), "a b+/\"é");
        assert_eq!(form(Encoding::Base64), "YSBiKy8iw6k=");
        assert_eq!(form(Encoding::Base64Url), "YSBiKy8iw6k=");
        assert_eq!(form(Encoding::Base64UrlNoPad), "YSBiKy8iw6k");
        assert_eq!(form(Encoding::HexLower), "6120622b2f22c3a9");
        assert_eq!(form(Encoding::HexUpper), "6120622B2F22C3A9");
        assert_eq!(form(Encoding::Percent), "a%20b%2B%2F%22%C3%A9");
        assert_eq!(form(Encoding::Form), "a+b%2B%2F%22%C3%A9");
        assert_eq!(form(Encoding::Json), "a b+/\\\"é");
    }

    #[test]
    fn base64_alphabets_are_scanned_separately() {
        // Encodes to `Pz8+` in the standard alphabet and `Pz8-` in the URL-safe one.
        let registry = registered(&Canary::from_value("??>"));
        let standard = registry.scan("logs", "Pz8+");
        let url_safe = registry.scan("logs", "Pz8-");
        assert_eq!(standard[0].encoding, Encoding::Base64);
        assert_eq!(url_safe[0].encoding, Encoding::Base64Url);
    }

    #[test]
    fn scan_finds_every_encoding() {
        let canary = Canary::generate().unwrap();
        let registry = registered(&canary);
        for (encoding, form) in canary.encodings() {
            let text = format!("before {form} after");
            let hits = registry.scan("logs", &text);
            // A form identical to an earlier one is reported as that encoding.
            assert!(!hits.is_empty(), "{encoding:?} not found");
            assert_eq!(hits[0].offset, "before ".len());
            assert_eq!(hits[0].location, "logs");
        }
    }

    #[test]
    fn scan_finds_every_occurrence_in_offset_order() {
        let canary = Canary::from_value("secret");
        let hits = registered(&canary).scan("logs", "secret and secret");
        let offsets: Vec<usize> = hits.iter().map(|hit| hit.offset).collect();
        assert_eq!(offsets, [0, 11]);
    }

    #[test]
    fn scan_ignores_clean_text_and_other_canaries() {
        let registry = registered(&Canary::generate().unwrap());
        let other = Canary::generate().unwrap();
        assert!(registry.scan("logs", "nothing here").is_empty());
        assert!(registry.scan("logs", other.value()).is_empty());
    }

    #[test]
    fn scan_with_no_canaries_finds_nothing() {
        assert!(CanaryRegistry::new().scan("logs", "anything").is_empty());
    }

    #[test]
    fn empty_canary_does_not_match_everything() {
        let registry = registered(&Canary::from_value(""));
        assert!(registry.scan("logs", "anything").is_empty());
    }

    #[test]
    fn a_value_that_encodes_to_itself_is_reported_once() {
        let hits = registered(&Canary::from_value("plain")).scan("logs", "plain");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Encoding::Raw);
    }

    #[test]
    fn basic_auth_is_found_only_when_registered() {
        let password = Canary::from_value("hunter2");
        // base64 of "user:hunter2", which contains no base64 of "hunter2".
        let header = "Authorization: Basic dXNlcjpodW50ZXIy";

        let mut registry = registered(&password);
        assert!(registry.scan("logs", header).is_empty());

        registry.register_basic_auth("user", &password);
        let hits = registry.scan("logs", header);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Encoding::BasicAuth);
    }

    #[test]
    fn a_hit_reports_where_but_not_what() {
        let canary = Canary::from_value("topsecret");
        let hits = registered(&canary).scan("audit", "xx topsecret");
        let report = hits[0].to_string();
        assert_eq!(report, "canary found in audit at byte 3 (Raw)");
        assert!(!format!("{:?}", hits[0]).contains("topsecret"));
    }
}
