//! Reads the secret of an intake envelope: one JSON object of field name to value.
//!
//! A value is a string, taken as its UTF-8 bytes, or `{"b64":"…"}` for bytes that are
//! not text. Whoever sealed the object is not trusted, so anything else refuses all of
//! it: a name that repeats or is not a field name, a nested value, a number.
//!
//! `serde_json` decides where each value starts and ends, and hands it over as it was
//! written. A string with escapes then has to be copied to be read: into a buffer sized
//! up front and wiped, since what it holds is a secret.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seal_format::{FieldName, Secret};
use serde::Deserialize;
use serde::de::{Deserializer, Error as _, MapAccess, Visitor};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// The object is not what an intake envelope holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

/// The members as they were written, each name once.
struct Members<'a>(BTreeMap<FieldName, &'a RawValue>);

impl<'de: 'a, 'a> Deserialize<'de> for Members<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Members<'de>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut members = BTreeMap::new();
                // A name is read with its escapes undone, so one written two ways is
                // still the same name.
                while let Some(name) = map.next_key::<String>()? {
                    let name =
                        FieldName::new(name).map_err(|_| A::Error::custom("not a field name"))?;
                    let value = map.next_value::<&'de RawValue>()?;
                    if members.insert(name, value).is_some() {
                        return Err(A::Error::custom("a name repeats"));
                    }
                }
                Ok(Members(members))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

/// `{"b64":"…"}`. Borrowed, so that parsing makes no copy; base64url needs no escapes,
/// so a value that has them is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoded<'a> {
    #[serde(borrow)]
    b64: &'a str,
}

/// Reads an intake envelope's secret into one secret per field.
///
/// # Errors
///
/// Returns [`Invalid`] if it is not such an object. Nothing says which part was wrong.
pub fn parse(object: &[u8]) -> Result<BTreeMap<FieldName, Secret>, Invalid> {
    let members: Members<'_> = serde_json::from_slice(object).map_err(|_| Invalid)?;
    members
        .0
        .into_iter()
        .map(|(name, raw)| Ok((name, value(raw.get())?)))
        .collect()
}

fn value(written: &str) -> Result<Secret, Invalid> {
    match written.as_bytes() {
        [b'"', inside @ .., b'"'] => text(inside),
        [b'{', ..] => {
            let encoded: Encoded<'_> = serde_json::from_str(written).map_err(|_| Invalid)?;
            let mut bytes = Zeroizing::new(vec![0_u8; encoded.b64.len() / 4 * 3 + 3]);
            let length = URL_SAFE_NO_PAD
                .decode_slice(encoded.b64, &mut bytes)
                .map_err(|_| Invalid)?;
            Ok(Secret::new(&bytes[..length]))
        }
        _ => Err(Invalid),
    }
}

/// Undoes a JSON string's escapes. What comes out is never longer than what went in, so
/// the buffer is sized once.
fn text(inside: &[u8]) -> Result<Secret, Invalid> {
    let mut out = Zeroizing::new(Vec::with_capacity(inside.len()));
    let mut rest = inside;
    while let Some((&byte, after)) = rest.split_first() {
        rest = after;
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        let (&escape, after) = rest.split_first().ok_or(Invalid)?;
        rest = after;
        let plain = match escape {
            b'"' | b'\\' | b'/' => escape,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => {
                let first = hex4(&mut rest)?;
                let scalar = match first {
                    0xd800..=0xdbff => {
                        // A high surrogate is half a character, and the other half
                        // must follow.
                        let [b'\\', b'u', after @ ..] = rest else {
                            return Err(Invalid);
                        };
                        rest = after;
                        let second = hex4(&mut rest)?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(Invalid);
                        }
                        0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                    }
                    0xdc00..=0xdfff => return Err(Invalid),
                    other => other,
                };
                let character = char::from_u32(scalar).ok_or(Invalid)?;
                let mut encoded = Zeroizing::new([0_u8; 4]);
                out.extend_from_slice(character.encode_utf8(&mut *encoded).as_bytes());
                continue;
            }
            _ => return Err(Invalid),
        };
        out.push(plain);
    }
    Ok(Secret::new(&out))
}

fn hex4(rest: &mut &[u8]) -> Result<u32, Invalid> {
    let (digits, after) = rest.split_first_chunk::<4>().ok_or(Invalid)?;
    *rest = after;
    digits.iter().try_fold(0_u32, |value, digit| {
        let digit = char::from(*digit).to_digit(16).ok_or(Invalid)?;
        Ok(value << 4 | digit)
    })
}

#[cfg(test)]
mod tests {
    use seal_format::intake::{Value, object};

    use super::*;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn read(json: &str) -> Result<BTreeMap<String, Vec<u8>>, Invalid> {
        Ok(parse(json.as_bytes())?
            .into_iter()
            .map(|(name, secret)| (name.to_string(), secret.expose(<[u8]>::to_vec)))
            .collect())
    }

    #[test]
    fn strings_and_bytes_are_read_by_field() {
        let members =
            read(r#" { "api_key" : "sk-123" , "cert":{"b64":"-_8AAQ"}, "empty": "" } "#).unwrap();
        assert_eq!(members["api_key"], b"sk-123");
        assert_eq!(members["cert"], [0xfb, 0xff, 0x00, 0x01]);
        assert_eq!(members["empty"], b"");
        assert_eq!(members.len(), 3);
        assert!(read("{}").unwrap().is_empty());
    }

    #[test]
    fn escapes_are_undone() {
        let members = read(
            r#"{"a":"q\"b\\s\/n\nr\rt\tb\bf\f","b":"\u00e9\u20AC\ud83d\ude00é😀","c":"\u0000"}"#,
        )
        .unwrap();
        assert_eq!(members["a"], b"q\"b\\s/n\nr\rt\tb\x08f\x0c");
        assert_eq!(members["b"], "é€😀é😀".as_bytes());
        assert_eq!(members["c"], [0]);
    }

    #[test]
    fn what_the_sealer_writes_is_what_is_read() {
        let pem = "-----BEGIN KEY-----\nabc\"\\\u{1}\u{7f}é😀\n-----END KEY-----\n";
        let der: Vec<u8> = (0..=255).collect();
        let written = object(&BTreeMap::from([
            (field("pem"), Value::Text(pem)),
            (field("der"), Value::Bytes(&der)),
        ]));
        let members = parse(&written).unwrap();
        assert_eq!(
            members[&field("pem")].expose(<[u8]>::to_vec),
            pem.as_bytes()
        );
        assert_eq!(members[&field("der")].expose(<[u8]>::to_vec), der);
    }

    #[test]
    fn a_name_that_repeats_is_refused_however_it_is_written() {
        assert_eq!(read(r#"{"a":"1","a":"2"}"#), Err(Invalid));
        assert_eq!(read(r#"{"a":"1","\u0061":"2"}"#), Err(Invalid));
    }

    #[test]
    fn anything_but_a_flat_object_of_strings_and_bytes_is_refused() {
        for bad in [
            "",
            "null",
            "[]",
            r#""a""#,
            r#"{"a":1}"#,
            r#"{"a":null}"#,
            r#"{"a":true}"#,
            r#"{"a":["x"]}"#,
            r#"{"a":{"b":"x"}}"#,
            r#"{"a":{}}"#,
            r#"{"a":{"b64":"AA","b64":"AA"}}"#,
            r#"{"a":{"b64":"AA","x":"y"}}"#,
            r#"{"a":{"b64":1}}"#,
            r#"{"a":{"b64":"AA=="}}"#,
            r#"{"a":{"b64":"A+/A"}}"#,
            r#"{"a":{"b64":"AB"}}"#,
            r#"{"a":{"b64":"A\u0041"}}"#,
            r#"{"a":"x"} x"#,
            r#"{"a":"x"}{"b":"y"}"#,
            r#"{"a":"x",}"#,
            r#"{"a b":"x"}"#,
            r#"{"":"x"}"#,
            r#"{".a":"x"}"#,
            r#"{"a":"\ud83d"}"#,
            r#"{"a":"\ud83dx"}"#,
            r#"{"a":"\ud83d\u0041"}"#,
            r#"{"a":"\ude00"}"#,
            r#"{"a":"\x41"}"#,
            "{\"a\":\"line\nbreak\"}",
        ] {
            assert_eq!(read(bad), Err(Invalid), "{bad}");
        }
    }
}
