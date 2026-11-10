//! Properties of sealing and policies, over random inputs.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use seal_format::id::KeyId;
use seal_format::policy::builder::{self, PartSource};
use seal_format::policy::{AzureService, PayloadMode};
use seal_format::{
    Binding, Envelope, FieldName, FormatError, ItemId, KeysetId, Policy, PolicyName, PrivateKey,
    Sealed, open, seal,
};
use serde_json::{Value, json};

#[derive(Clone, Debug)]
struct Fixture {
    keyset: KeysetId,
    kid: KeyId,
    item: ItemId,
    field: FieldName,
    secret: Vec<u8>,
    policy: Policy,
}

impl Fixture {
    fn binding(&self) -> Binding<'_> {
        Binding {
            keyset: &self.keyset,
            item: &self.item,
            field: &self.field,
        }
    }

    fn seal_new(&self) -> (PrivateKey, Envelope) {
        let (private, public) = PrivateKey::generate();
        let envelope = seal(
            &public,
            &self.kid,
            self.binding(),
            &self.secret,
            &self.policy,
        )
        .unwrap();
        (private, envelope)
    }

    fn open_json(&self, private: &PrivateKey, json: &[u8]) -> Result<Sealed, FormatError> {
        open(private, &Envelope::from_json(json)?, self.binding())
    }
}

fn long_identifier() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_:-][A-Za-z0-9._:-]{0,127}"
}

fn short_identifier() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}"
}

fn host() -> impl Strategy<Value = String> {
    // Starts with a fixed letter, so that it is never an `xn--` label, which would
    // have to be valid punycode.
    "h[a-z0-9-]{0,20}[a-z0-9]\\.example\\.com"
}

fn path() -> impl Strategy<Value = String> {
    prop_oneof![Just(String::new()), "(/[a-z0-9_-]{1,10}){1,4}/?",]
}

fn api_base() -> impl Strategy<Value = String> {
    (host(), path()).prop_map(|(host, path)| format!("https://{host}{path}"))
}

fn policy() -> impl Strategy<Value = Policy> {
    prop_oneof![
        api_base().prop_map(|base| builder::bearer(&base).unwrap()),
        (api_base(), "X-[A-Za-z]{1,20}")
            .prop_map(|(base, name)| builder::api_key_header(&base, &name).unwrap()),
        api_base().prop_map(|base| {
            builder::basic(&base, PartSource::Literal("user".to_owned()))
                .unwrap()
                .secret
        }),
        (api_base(), "[a-z]{2,8}-[a-z]{2,8}-[0-9]").prop_map(|(base, region)| {
            builder::aws(
                &region,
                "s3",
                &base,
                PartSource::Plain(FieldName::new("access_key_id").unwrap()),
                None,
                vec![PayloadMode::Computed],
            )
            .unwrap()
            .secret
        }),
        api_base().prop_map(|base| {
            builder::azure(
                PartSource::Literal("account".to_owned()),
                AzureService::Blob,
                &base,
            )
            .unwrap()
            .secret
        }),
        (host(), 1_u16..=65535, "[a-z_]{1,16}").prop_map(|(host, port, database)| {
            builder::postgres(&host, port, vec![database], "app_user").unwrap()
        }),
    ]
}

fn fixture() -> impl Strategy<Value = Fixture> {
    (
        long_identifier(),
        long_identifier(),
        long_identifier(),
        short_identifier(),
        proptest::collection::vec(any::<u8>(), 0..512),
        policy(),
    )
        .prop_map(|(keyset, kid, item, field, secret, policy)| Fixture {
            keyset: KeysetId::new(keyset).unwrap(),
            kid: KeyId::new(kid).unwrap(),
            item: ItemId::new(item).unwrap(),
            field: FieldName::new(field).unwrap(),
            secret,
            policy,
        })
}

/// Changes one byte to a different value that is still valid in its context,
/// so that the change reaches the check it is meant to test.
fn changed_identifier(value: &str, index: usize) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let index = index % bytes.len();
    bytes[index] = if bytes[index] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn opening_returns_what_was_sealed(fixture in fixture()) {
        let (private, envelope) = fixture.seal_new();
        let opened = open(&private, &envelope, fixture.binding()).unwrap();
        prop_assert_eq!(opened.secret.expose(<[u8]>::to_vec), fixture.secret.clone());
        prop_assert_eq!(&opened.policy, &fixture.policy);
    }

    #[test]
    fn a_value_survives_its_json_form(fixture in fixture()) {
        let (private, envelope) = fixture.seal_new();
        let json = envelope.to_json().unwrap();
        let parsed = Envelope::from_json(json.as_bytes()).unwrap();
        prop_assert_eq!(&parsed, &envelope);
        prop_assert_eq!(parsed.to_json().unwrap(), json);
        prop_assert!(open(&private, &parsed, fixture.binding()).is_ok());
    }

    /// The milestone's condition: no change to any byte of the written form
    /// leaves a value that opens.
    #[test]
    fn changing_any_byte_of_the_envelope_means_it_does_not_open(
        fixture in fixture(),
        position in any::<proptest::sample::Index>(),
        delta in 1_u8..=255,
    ) {
        let (private, envelope) = fixture.seal_new();
        let mut json = envelope.to_json().unwrap().into_bytes();
        let index = position.index(json.len());
        json[index] = json[index].wrapping_add(delta);
        prop_assert!(fixture.open_json(&private, &json).is_err(), "byte {} of {:?}", index, String::from_utf8_lossy(&json));
    }

    #[test]
    fn changing_any_byte_of_enc_or_ct_means_it_does_not_open(
        fixture in fixture(),
        which in prop_oneof![Just("enc"), Just("ct")],
        position in any::<proptest::sample::Index>(),
        delta in 1_u8..=255,
    ) {
        let (private, envelope) = fixture.seal_new();
        let mut value: Value = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(value[which].as_str().unwrap()).unwrap();
        let index = position.index(bytes.len());
        bytes[index] = bytes[index].wrapping_add(delta);
        value[which] = json!(URL_SAFE_NO_PAD.encode(bytes));
        let result = fixture.open_json(&private, value.to_string().as_bytes());
        prop_assert_eq!(result.unwrap_err(), FormatError::OpenFailed);
    }

    /// The same for the associated data's inputs, with each change still a
    /// valid identifier, so that the refusal comes from the decryption.
    #[test]
    fn changing_any_byte_of_the_binding_means_it_does_not_open(
        fixture in fixture(),
        index in any::<usize>(),
    ) {
        let (private, envelope) = fixture.seal_new();

        let item = ItemId::new(changed_identifier(fixture.item.as_str(), index)).unwrap();
        let result = open(&private, &envelope, Binding { item: &item, ..fixture.binding() });
        prop_assert_eq!(result.unwrap_err(), FormatError::OpenFailed);

        let field = FieldName::new(changed_identifier(fixture.field.as_str(), index)).unwrap();
        let result = open(&private, &envelope, Binding { field: &field, ..fixture.binding() });
        prop_assert_eq!(result.unwrap_err(), FormatError::OpenFailed);

        let keyset = KeysetId::new(changed_identifier(fixture.keyset.as_str(), index)).unwrap();
        let result = open(&private, &envelope, Binding { keyset: &keyset, ..fixture.binding() });
        prop_assert_eq!(result.unwrap_err(), FormatError::KeysetMismatch);

        // A rewritten keyset that also matches the binding reaches decryption.
        let mut value: Value = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
        value["keyset"] = json!(keyset.as_str());
        let rewritten = Envelope::from_json(value.to_string().as_bytes()).unwrap();
        let result = open(&private, &rewritten, Binding { keyset: &keyset, ..fixture.binding() });
        prop_assert_eq!(result.unwrap_err(), FormatError::OpenFailed);

        let mut value: Value = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
        value["kid"] = json!(changed_identifier(fixture.kid.as_str(), index));
        let result = fixture.open_json(&private, value.to_string().as_bytes());
        prop_assert_eq!(result.unwrap_err(), FormatError::OpenFailed);
    }

    #[test]
    fn swapping_item_and_field_means_it_does_not_open(fixture in fixture()) {
        let (private, envelope) = fixture.seal_new();
        // A field name is always a valid item, but not always the reverse.
        let item = ItemId::new(fixture.field.as_str()).unwrap();
        if let Ok(field) = FieldName::new(fixture.item.as_str()) {
            prop_assume!(item != fixture.item || field != fixture.field);
            let result = open(&private, &envelope, Binding { item: &item, field: &field, ..fixture.binding() });
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn another_key_never_opens(fixture in fixture()) {
        let (_, envelope) = fixture.seal_new();
        let (other, _) = PrivateKey::generate();
        prop_assert!(open(&other, &envelope, fixture.binding()).is_err());
    }

    #[test]
    fn the_plaintext_never_appears_in_the_envelope(
        fixture in fixture(),
        secret in "[A-Za-z0-9]{16,64}",
    ) {
        let fixture = Fixture { secret: secret.clone().into_bytes(), ..fixture };
        let (_, envelope) = fixture.seal_new();
        let json = envelope.to_json().unwrap();
        prop_assert!(!json.contains(&secret));
        prop_assert!(!json.contains(&URL_SAFE_NO_PAD.encode(&secret)));
    }

    #[test]
    fn a_policy_round_trips_through_its_canonical_form(policy in policy()) {
        let canonical = policy.canonical_json().unwrap();
        let parsed = Policy::from_json(&canonical).unwrap();
        prop_assert_eq!(&parsed, &policy);
        prop_assert_eq!(parsed.canonical_json().unwrap(), canonical);
    }

    #[test]
    fn identifiers_match_a_simple_reference(value in "[ -~]{0,70}") {
        let reference = |max: usize, colon: bool| {
            !value.is_empty()
                && value.len() <= max
                && !value.starts_with('.')
                && value.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') || (colon && c == ':')
                })
        };
        prop_assert_eq!(KeysetId::new(value.clone()).is_ok(), reference(128, true));
        prop_assert_eq!(FieldName::new(value.clone()).is_ok(), reference(64, false));
        prop_assert_eq!(PolicyName::new(value.clone()).is_ok(), reference(64, false));
    }

    #[test]
    fn parsers_refuse_arbitrary_bytes_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = Envelope::from_json(&bytes);
        let _ = Policy::from_json(&bytes);
    }

    #[test]
    fn errors_never_echo_a_marker_in_the_input(marker in "MARKER[A-Z]{8}") {
        let inputs = [
            format!("{{\"v\":1,\"keyset\":\"{marker}/\",\"kid\":\"k\",\"enc\":\"\",\"ct\":\"\"}}"),
            format!("{{\"{marker}\":1}}"),
            marker.clone(),
        ];
        for input in inputs {
            let results = [
                Envelope::from_json(input.as_bytes()).map(|_| ()).unwrap_err(),
                Policy::from_json(input.as_bytes()).map(|_| ()).unwrap_err(),
            ];
            for error in results {
                let (display, debug) = (error.to_string(), format!("{error:?}"));
                prop_assert!(!display.contains(&marker));
                prop_assert!(!debug.contains(&marker));
            }
        }
    }
}
