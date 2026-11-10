//! The sealed value's JSON form.
//!
//! ```json
//! { "v": 1, "keyset": "acme", "kid": "k3", "enc": "…", "ct": "…" }
//! ```
//!
//! Parsing refuses anything unexpected, including encodings that would decode
//! to the same bytes as the canonical one, so one value has one written form.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::error::FormatError;
use crate::id::{KeyId, KeysetId};

/// The only envelope version.
pub const VERSION: u8 = 1;
/// The length of an X25519 encapsulated key.
pub const ENC_BYTES: usize = 32;
/// The length of an AES-GCM tag, and so the shortest possible ciphertext.
pub const TAG_BYTES: usize = 16;
/// The longest ciphertext. Secrets are small, and certificate chains fit.
pub const MAX_CT_BYTES: usize = 64 * 1024;

/// One sealed secret and its policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawEnvelope", into = "RawEnvelope")]
pub struct Envelope {
    pub(crate) v: u8,
    pub(crate) keyset: KeysetId,
    pub(crate) kid: KeyId,
    pub(crate) enc: Vec<u8>,
    pub(crate) ct: Vec<u8>,
}

impl Envelope {
    /// Parses an envelope.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidEnvelope`] if the JSON is malformed or has
    /// unknown fields, or the version, identifiers or lengths are not valid. The
    /// error never includes any of the input.
    pub fn from_json(json: &[u8]) -> Result<Self, FormatError> {
        serde_json::from_slice(json)
            .map_err(|_| FormatError::InvalidEnvelope("does not match the format"))
    }

    /// The envelope's compact JSON form.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidEnvelope`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, FormatError> {
        serde_json::to_string(self)
            .map_err(|_| FormatError::InvalidEnvelope("cannot be serialised"))
    }

    /// The keyset this value is sealed to.
    #[must_use]
    pub fn keyset(&self) -> &KeysetId {
        &self.keyset
    }

    /// The key this value is sealed to.
    #[must_use]
    pub fn kid(&self) -> &KeyId {
        &self.kid
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    v: u8,
    keyset: KeysetId,
    kid: KeyId,
    enc: String,
    ct: String,
}

impl TryFrom<RawEnvelope> for Envelope {
    type Error = FormatError;

    fn try_from(raw: RawEnvelope) -> Result<Self, FormatError> {
        if raw.v != VERSION {
            return Err(FormatError::InvalidEnvelope("unknown version"));
        }
        // Checked before decoding, so an oversized value costs no allocation.
        if raw.ct.len() > URL_SAFE_NO_PAD_LEN_OF_MAX_CT {
            return Err(FormatError::InvalidEnvelope("ct is too long"));
        }
        let enc = URL_SAFE_NO_PAD
            .decode(raw.enc)
            .map_err(|_| FormatError::InvalidEnvelope("enc is not base64url"))?;
        if enc.len() != ENC_BYTES {
            return Err(FormatError::InvalidEnvelope("enc has the wrong length"));
        }
        let ct = URL_SAFE_NO_PAD
            .decode(raw.ct)
            .map_err(|_| FormatError::InvalidEnvelope("ct is not base64url"))?;
        if ct.len() < TAG_BYTES {
            return Err(FormatError::InvalidEnvelope("ct is shorter than a tag"));
        }
        if ct.len() > MAX_CT_BYTES {
            return Err(FormatError::InvalidEnvelope("ct is too long"));
        }
        Ok(Self {
            v: raw.v,
            keyset: raw.keyset,
            kid: raw.kid,
            enc,
            ct,
        })
    }
}

impl From<Envelope> for RawEnvelope {
    fn from(envelope: Envelope) -> Self {
        Self {
            v: envelope.v,
            keyset: envelope.keyset,
            kid: envelope.kid,
            enc: URL_SAFE_NO_PAD.encode(envelope.enc),
            ct: URL_SAFE_NO_PAD.encode(envelope.ct),
        }
    }
}

/// The base64url length of the longest ciphertext, rounded up.
const URL_SAFE_NO_PAD_LEN_OF_MAX_CT: usize = MAX_CT_BYTES.div_ceil(3) * 4;

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn valid() -> Value {
        json!({
            "v": 1,
            "keyset": "acme",
            "kid": "k3",
            "enc": b64(&[7; ENC_BYTES]),
            "ct": b64(&[9; 40]),
        })
    }

    fn parse(value: &Value) -> Result<Envelope, FormatError> {
        Envelope::from_json(value.to_string().as_bytes())
    }

    fn changed(field: &str, value: Value) -> Value {
        let mut envelope = valid();
        envelope[field] = value;
        envelope
    }

    #[test]
    fn parses_and_round_trips() {
        let envelope = parse(&valid()).unwrap();
        assert_eq!(envelope.keyset().as_str(), "acme");
        assert_eq!(envelope.kid().as_str(), "k3");
        let json = envelope.to_json().unwrap();
        assert_eq!(Envelope::from_json(json.as_bytes()).unwrap(), envelope);
    }

    #[test]
    fn writes_the_documented_form() {
        let envelope = parse(&valid()).unwrap();
        assert_eq!(
            envelope.to_json().unwrap(),
            format!(
                "{{\"v\":1,\"keyset\":\"acme\",\"kid\":\"k3\",\"enc\":\"{}\",\"ct\":\"{}\"}}",
                b64(&[7; ENC_BYTES]),
                b64(&[9; 40])
            )
        );
    }

    #[test]
    fn refuses_unknown_versions() {
        for version in [
            json!(0),
            json!(2),
            json!(255),
            json!(256),
            json!("1"),
            json!(1.5),
        ] {
            assert!(parse(&changed("v", version.clone())).is_err(), "{version}");
        }
    }

    #[test]
    fn refuses_unknown_and_missing_fields() {
        let mut extra = valid();
        extra["policy"] = json!("x");
        parse(&extra).unwrap_err();
        for field in ["v", "keyset", "kid", "enc", "ct"] {
            let mut missing = valid();
            missing.as_object_mut().unwrap().remove(field);
            assert!(parse(&missing).is_err(), "{field}");
        }
    }

    #[test]
    fn refuses_duplicate_fields() {
        let json = format!(
            "{{\"v\":1,\"v\":1,\"keyset\":\"a\",\"kid\":\"k\",\"enc\":\"{}\",\"ct\":\"{}\"}}",
            b64(&[7; ENC_BYTES]),
            b64(&[9; 40])
        );
        Envelope::from_json(json.as_bytes()).unwrap_err();
    }

    #[test]
    fn refuses_bad_identifiers() {
        parse(&changed("keyset", json!(".."))).unwrap_err();
        parse(&changed("kid", json!("a/b"))).unwrap_err();
    }

    #[test]
    fn refuses_wrong_lengths_at_the_boundaries() {
        for length in [0, ENC_BYTES - 1, ENC_BYTES + 1] {
            assert!(parse(&changed("enc", json!(b64(&vec![7; length])))).is_err());
        }
        parse(&changed("ct", json!(b64(&[9; TAG_BYTES])))).unwrap();
        parse(&changed("ct", json!(b64(&[9; TAG_BYTES - 1])))).unwrap_err();
        parse(&changed("ct", json!(b64(&vec![9; MAX_CT_BYTES])))).unwrap();
        parse(&changed("ct", json!(b64(&vec![9; MAX_CT_BYTES + 1])))).unwrap_err();
        parse(&changed("ct", json!(b64(&vec![9; MAX_CT_BYTES + 100_000])))).unwrap_err();
    }

    #[test]
    fn refuses_other_base64_forms() {
        // 32 bytes of 0xfb encode with `-` and `_` in base64url, and `+` and `/` in standard.
        let bytes = [0xfb_u8; ENC_BYTES];
        let canonical = b64(&bytes);
        assert!(canonical.contains('-') || canonical.contains('_'));
        parse(&changed("enc", json!(canonical.clone()))).unwrap();
        let standard = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        parse(&changed("enc", json!(standard))).unwrap_err();
        let padded = format!("{canonical}=");
        parse(&changed("enc", json!(padded))).unwrap_err();
        let spaced = format!(" {canonical}");
        parse(&changed("enc", json!(spaced))).unwrap_err();
    }

    #[test]
    fn refuses_nonzero_trailing_bits_so_a_value_has_one_written_form() {
        // 32 bytes take 43 characters, and the last carries two unused bits.
        let canonical = b64(&[0_u8; ENC_BYTES]);
        assert!(canonical.ends_with('A'));
        let mut other = canonical;
        other.pop();
        other.push('B');
        parse(&changed("enc", json!(other))).unwrap_err();
    }

    #[test]
    fn errors_do_not_echo_the_input() {
        let error = Envelope::from_json(b"{\"v\":1,\"keyset\":\"SECRETVALUE/\"}").unwrap_err();
        assert!(!error.to_string().contains("SECRETVALUE"));
        assert!(!format!("{error:?}").contains("SECRETVALUE"));
        Envelope::from_json(b"not json").unwrap_err();
        Envelope::from_json(b"").unwrap_err();
        Envelope::from_json(b"[]").unwrap_err();
    }
}
