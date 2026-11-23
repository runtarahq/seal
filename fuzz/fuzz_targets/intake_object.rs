//! Whatever was sealed as an intake envelope's secret, what seal reads from it is what
//! any JSON reader sees: an object of field names, each a string or bytes, and no name
//! twice. Anything else is refused whole.

#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use seal_broker::intake::parse;
use seal_format::intake::{Value, object};
use serde_json::value::RawValue;

/// The members as written, to count the names: a map of values would keep only the last
/// of a name that repeats.
struct Names(Vec<String>);

impl<'de> serde::Deserialize<'de> for Names {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Names;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Names, A::Error> {
                let mut names = Vec::new();
                while let Some((name, _)) = map.next_entry::<String, &'de RawValue>()? {
                    names.push(name);
                }
                Ok(Names(names))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(members) = parse(data) else {
        return;
    };
    let names: Names = serde_json::from_slice(data).expect("what was read is a JSON object");
    assert_eq!(names.0.len(), members.len(), "no name is read twice, and none is dropped");
    let read: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(data).expect("what was read is a JSON object");
    for (name, secret) in &members {
        let bytes = secret.expose(<[u8]>::to_vec);
        match &read[name.as_str()] {
            serde_json::Value::String(text) => assert_eq!(bytes, text.as_bytes()),
            serde_json::Value::Object(encoded) => {
                assert_eq!(encoded.len(), 1);
                assert!(encoded["b64"].is_string());
            }
            other => panic!("read a secret from {other}"),
        }
    }

    // Written again as a sealer writes it, it reads as the same secrets.
    let held: Vec<(Vec<u8>, bool)> = members
        .values()
        .map(|secret| {
            let bytes = secret.expose(<[u8]>::to_vec);
            let is_text = std::str::from_utf8(&bytes).is_ok();
            (bytes, is_text)
        })
        .collect();
    let values = members
        .keys()
        .zip(&held)
        .map(|(name, (bytes, is_text))| {
            let value = if *is_text {
                Value::Text(std::str::from_utf8(bytes).expect("checked"))
            } else {
                Value::Bytes(bytes)
            };
            (name.clone(), value)
        })
        .collect();
    let again = parse(&object(&values)).expect("what a sealer writes is read");
    assert_eq!(again.len(), members.len());
    for ((name, secret), (bytes, _)) in again.iter().zip(&held) {
        assert!(members.contains_key(name));
        assert_eq!(&secret.expose(<[u8]>::to_vec), bytes);
    }
});
