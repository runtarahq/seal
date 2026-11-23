//! The application's and seal's halves of taking in a secret sealed in WebAssembly,
//! with the key from `vectors/envelope.json`. `scripts/wasm-roundtrip.sh` runs it twice.
//!
//! `offer` prints an offer for one field, `api_key`, as an application would make it.
//! `admit SECRET` reads the intake envelope sealed under that offer from standard
//! input, derives the field's policy again, has the broker admit it, and exits nonzero
//! unless the value that comes back holds `SECRET` under that policy.

#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use seal_broker::audit::{AuditFailed, AuditRecord, AuditSink};
use seal_broker::{AdmitOutput, AdmitRequest, Broker, BrokerConfig, Environment};
use seal_format::policy::builder;
use seal_format::{
    Binding, Envelope, FieldName, ItemId, KeyId, KeysetId, Offer, Policy, PrivateKey, open,
};
use seal_keys::StaticKeys;
use serde_json::Value;

/// Keeps nothing: the tests of the broker hold it to its audit records.
struct NoAudit;

impl AuditSink for NoAudit {
    fn record(&self, _: &AuditRecord) -> Result<(), AuditFailed> {
        Ok(())
    }
}

fn private_key() -> PrivateKey {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{manifest}/../../vectors/envelope.json")).unwrap(),
    )
    .unwrap();
    let key = vectors["private_key_hex"].as_str().unwrap();
    let key: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&key[index..index + 2], 16).unwrap())
        .collect();
    PrivateKey::from_bytes(&key).unwrap()
}

/// What the application derives from a record's fields that are not secret, the same
/// each time.
fn api_key_policy() -> Policy {
    builder::bearer("https://api.example.com").unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (keyset, kid, item, api_key) = (
        KeysetId::new("acme").unwrap(),
        KeyId::new("k3").unwrap(),
        ItemId::new("c_123").unwrap(),
        FieldName::new("api_key").unwrap(),
    );
    let private = private_key();
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("offer") => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let offer = Offer::for_intake(
                private.public_key().unwrap(),
                kid,
                keyset,
                item,
                &BTreeMap::from([(api_key, api_key_policy())]),
                now + 60,
            )
            .unwrap();
            println!("{}", offer.to_json().unwrap());
        }
        Some("admit") => {
            let expected = arguments.next().unwrap();
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            let envelope =
                Envelope::from_json(input.strip_suffix(b"\n").unwrap_or(&input)).unwrap();

            let mut keys = StaticKeys::new();
            keys.add(keyset.clone(), kid, private_key()).unwrap();
            let broker = Broker::new(
                BrokerConfig::default(),
                Arc::new(keys),
                Environment::production(Arc::new(NoAudit)).unwrap(),
            )
            .unwrap();
            let sealed = broker
                .admit(AdmitRequest {
                    caller: "wasm-roundtrip".to_owned(),
                    keyset: keyset.clone(),
                    item: item.clone(),
                    envelope,
                    outputs: BTreeMap::from([(
                        api_key.clone(),
                        AdmitOutput {
                            policy: api_key_policy(),
                            optional: false,
                        },
                    )]),
                })
                .await
                .unwrap();

            let opened = open(
                &private,
                &sealed[&api_key],
                Binding {
                    keyset: &keyset,
                    item: &item,
                    field: &api_key,
                },
            )
            .unwrap();
            assert_eq!(opened.secret.expose(<[u8]>::to_vec), expected.as_bytes());
            assert_eq!(opened.policy, api_key_policy());
            println!("admitted natively");
        }
        _ => panic!("usage: admit_wasm_envelope offer | admit SECRET"),
    }
}
