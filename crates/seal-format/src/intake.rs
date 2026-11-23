//! Sealing where a secret is entered, for seal to admit.
//!
//! An application that should never hold a secret derives the policies of a record's
//! secret fields first, and hands whoever enters them an [`Offer`]: a public key, a
//! binding and an intake policy naming those policies by their digests. The secrets are
//! sealed under the offer as one JSON object, written by [`object`], and only seal can
//! turn that envelope into the values the application stores. `docs/format.md`
//! describes the object.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::envelope::Envelope;
use crate::error::FormatError;
use crate::id::{FieldName, ItemId, KeyId, KeysetId};
use crate::policy::Policy;
use crate::seal::{Binding, PublicKey, seal};

/// The field every intake envelope is bound to. The policy names the fields its secrets
/// become, so this says nothing; the item is what holds an envelope to its record.
pub const INTAKE_FIELD: &str = "intake";

/// [`INTAKE_FIELD`] as a field name.
#[must_use]
pub fn intake_field() -> FieldName {
    FieldName::known(INTAKE_FIELD)
}

/// Everything a sealer needs: where to seal to, and under which policy.
///
/// It holds nothing secret, and a sealer need not understand it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    /// The keyset's public key, in base64url.
    pub public_key: PublicKey,
    /// That key's id.
    pub kid: KeyId,
    /// The keyset.
    pub keyset: KeysetId,
    /// The record.
    pub item: ItemId,
    /// The field: [`INTAKE_FIELD`] for an intake.
    pub field: FieldName,
    /// The policy to seal under.
    pub policy: Policy,
}

impl Offer {
    /// The offer for a record's secret fields, each to be sealed by seal under the
    /// policy given here and no other, until `not_after` in seconds since the Unix
    /// epoch.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] as [`Policy::for_intake`] does.
    pub fn for_intake(
        public_key: PublicKey,
        kid: KeyId,
        keyset: KeysetId,
        item: ItemId,
        outputs: &BTreeMap<FieldName, Policy>,
        not_after: u64,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            public_key,
            kid,
            keyset,
            item,
            field: intake_field(),
            policy: Policy::for_intake(outputs, not_after)?,
        })
    }

    /// Parses and validates an offer.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] if the JSON is not an offer or its policy
    /// is not valid. The error never includes any of the input.
    pub fn from_json(json: &[u8]) -> Result<Self, FormatError> {
        let offer: Self = serde_json::from_slice(json)
            .map_err(|_| FormatError::InvalidPolicy("the offer does not match the schema"))?;
        offer.policy.validate()?;
        Ok(offer)
    }

    /// The offer as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, FormatError> {
        serde_json::to_string(self).map_err(|_| FormatError::InvalidPolicy("cannot be serialised"))
    }

    /// Seals a secret under the offer. For an intake, the secret is what [`object`]
    /// writes.
    ///
    /// # Errors
    ///
    /// As for [`seal`].
    pub fn seal(&self, secret: &[u8]) -> Result<Envelope, FormatError> {
        let binding = Binding {
            keyset: &self.keyset,
            item: &self.item,
            field: &self.field,
        };
        seal(&self.public_key, &self.kid, binding, secret, &self.policy)
    }
}

/// One secret of an intake envelope.
#[derive(Clone, Copy)]
pub enum Value<'a> {
    /// Text, sealed as its UTF-8 bytes.
    Text(&'a str),
    /// Bytes that are not text, such as a key in DER.
    Bytes(&'a [u8]),
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// How many bytes `text` takes as a JSON string's contents.
fn escaped_len(text: &str) -> usize {
    text.bytes()
        .map(|byte| match byte {
            b'"' | b'\\' => 2,
            0..=0x1f => 6,
            _ => 1,
        })
        .sum()
}

/// How many characters `bytes` bytes take in base64 with no padding.
fn unpadded_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

/// Writes an intake envelope's secret: one JSON object of field name to value, a string
/// for text and `{"b64":"…"}` for bytes.
///
/// The buffer is sized up front, so it never reallocates and leaves a copy of a secret
/// behind, and it is wiped when dropped.
#[must_use]
pub fn object(members: &BTreeMap<FieldName, Value<'_>>) -> Zeroizing<Vec<u8>> {
    const BEFORE_BYTES: &[u8] = b"{\"b64\":\"";
    const AFTER_BYTES: &[u8] = b"\"}";

    // The braces, and a comma between members.
    let capacity = 2
        + members.len().saturating_sub(1)
        + members
            .iter()
            .map(|(name, value)| {
                // The name in quotes and a colon.
                name.as_str().len()
                    + 3
                    + match value {
                        Value::Text(text) => 2 + escaped_len(text),
                        Value::Bytes(bytes) => {
                            BEFORE_BYTES.len() + unpadded_len(bytes.len()) + AFTER_BYTES.len()
                        }
                    }
            })
            .sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    out.push(b'{');
    for (index, (name, value)) in members.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        // A field name needs no escapes.
        out.push(b'"');
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b"\":");
        match value {
            Value::Text(text) => {
                out.push(b'"');
                for byte in text.bytes() {
                    match byte {
                        b'"' | b'\\' => out.extend_from_slice(&[b'\\', byte]),
                        0..=0x1f => out.extend_from_slice(&[
                            b'\\',
                            b'u',
                            b'0',
                            b'0',
                            HEX[usize::from(byte >> 4)],
                            HEX[usize::from(byte & 0xf)],
                        ]),
                        _ => out.push(byte),
                    }
                }
                out.push(b'"');
            }
            Value::Bytes(bytes) => {
                out.extend_from_slice(BEFORE_BYTES);
                let start = out.len();
                let length = unpadded_len(bytes.len());
                out.resize(start + length, 0);
                // The slice is as long as unpadded base64 can be, so this cannot fail.
                let written = URL_SAFE_NO_PAD
                    .encode_slice(bytes, &mut out[start..])
                    .unwrap_or(0);
                out.truncate(start + written);
                out.extend_from_slice(AFTER_BYTES);
            }
        }
    }
    out.push(b'}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::builder;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn outputs() -> BTreeMap<FieldName, Policy> {
        BTreeMap::from([
            (
                field("api_key"),
                builder::bearer("https://api.example.com").unwrap(),
            ),
            (
                field("signing"),
                builder::webhook_hmac(crate::policy::HmacHash::Sha256).unwrap(),
            ),
        ])
    }

    fn offer() -> Offer {
        Offer::for_intake(
            PublicKey::from_bytes(&[7; 32]).unwrap(),
            KeyId::new("k3").unwrap(),
            KeysetId::new("acme").unwrap(),
            ItemId::new("c_123").unwrap(),
            &outputs(),
            1_800_000_000,
        )
        .unwrap()
    }

    #[test]
    fn the_intake_field_is_the_constant() {
        assert_eq!(intake_field(), FieldName::new(INTAKE_FIELD).unwrap());
    }

    #[test]
    fn an_offer_names_each_output_by_its_policys_digest() {
        let offer = offer();
        assert_eq!(offer.field.as_str(), "intake");
        let intake = offer.policy.intake.as_ref().unwrap();
        assert_eq!(intake.not_after, 1_800_000_000);
        for (name, policy) in outputs() {
            assert_eq!(intake.outputs[&name], policy.digest().unwrap());
        }
    }

    #[test]
    fn an_offer_reads_back_from_its_json() {
        let offer = offer();
        let json = offer.to_json().unwrap();
        assert_eq!(Offer::from_json(json.as_bytes()).unwrap(), offer);
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["extra"] = serde_json::json!(1);
        Offer::from_json(value.to_string().as_bytes()).unwrap_err();
    }

    #[test]
    fn an_offer_with_a_policy_that_is_not_valid_is_refused() {
        let mut value: serde_json::Value =
            serde_json::from_str(&offer().to_json().unwrap()).unwrap();
        value["policy"] = serde_json::json!({});
        Offer::from_json(value.to_string().as_bytes()).unwrap_err();
    }

    #[test]
    fn the_object_is_json_with_text_as_strings_and_bytes_as_base64url() {
        let members = BTreeMap::from([
            (field("b"), Value::Bytes(&[0xfb, 0xff, 0x00, 0x01])),
            (field("a"), Value::Text("li\"ne\\one\ntwo\u{1}é😀")),
            (field("c"), Value::Text("")),
        ]);
        let written = object(&members);
        assert_eq!(written.len(), written.capacity(), "sized exactly");
        let read: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(
            read,
            serde_json::json!({
                "a": "li\"ne\\one\ntwo\u{1}é😀",
                "b": {"b64": "-_8AAQ"},
                "c": "",
            })
        );
    }

    #[test]
    fn an_empty_object_is_written() {
        assert_eq!(object(&BTreeMap::new()).as_slice(), b"{}");
    }
}
