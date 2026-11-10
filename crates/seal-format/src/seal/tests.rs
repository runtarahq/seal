use hpke::{OpModeR, OpModeS};

use super::*;
use crate::policy::builder;
use crate::secret::tests::take_dropped;

fn keyset() -> KeysetId {
    KeysetId::new("acme").unwrap()
}

fn kid() -> KeyId {
    KeyId::new("k3").unwrap()
}

fn item() -> ItemId {
    ItemId::new("c_123").unwrap()
}

fn field() -> FieldName {
    FieldName::new("api_key").unwrap()
}

fn policy() -> Policy {
    builder::bearer("https://api.example.com/v2/").unwrap()
}

/// Seals `secret` under a new key, bound to the fixtures above.
fn sealed(secret: &[u8]) -> (PrivateKey, Envelope) {
    let (private, public) = PrivateKey::generate();
    let (keyset, item, field) = (keyset(), item(), field());
    let binding = Binding {
        keyset: &keyset,
        item: &item,
        field: &field,
    };
    (
        private,
        seal(&public, &kid(), binding, secret, &policy()).unwrap(),
    )
}

fn open_fixture(private: &PrivateKey, envelope: &Envelope) -> Result<Sealed, FormatError> {
    let (keyset, item, field) = (keyset(), item(), field());
    open(
        private,
        envelope,
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
    )
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_sealed_value_opens() {
    let (private, envelope) = sealed(b"hunter2");
    let opened = open_fixture(&private, &envelope).unwrap();
    assert_eq!(opened.secret.expose(<[u8]>::to_vec), b"hunter2");
    assert_eq!(opened.policy, policy());
}

#[test]
fn secrets_of_any_length_and_content_open() {
    for secret in [
        Vec::new(),
        vec![0],
        vec![1, 2],
        vec![1, 2, 3],
        vec![0xff; 4],
        (0..=255).collect::<Vec<u8>>(),
        b"\"\\{}\n".to_vec(),
    ] {
        let (private, envelope) = sealed(&secret);
        let opened = open_fixture(&private, &envelope).unwrap();
        assert_eq!(opened.secret.expose(<[u8]>::to_vec), secret);
    }
}

#[test]
fn sealing_twice_gives_different_ciphertext() {
    let (private, public) = PrivateKey::generate();
    drop(private);
    let (keyset, item, field) = (keyset(), item(), field());
    let binding = Binding {
        keyset: &keyset,
        item: &item,
        field: &field,
    };
    let first = seal(&public, &kid(), binding, b"same", &policy()).unwrap();
    let second = seal(&public, &kid(), binding, b"same", &policy()).unwrap();
    assert_ne!(first.enc, second.enc);
    assert_ne!(first.ct, second.ct);
}

#[test]
fn the_envelope_records_the_keyset_and_kid_and_survives_json() {
    let (private, envelope) = sealed(b"hunter2");
    assert_eq!(*envelope.keyset(), keyset());
    assert_eq!(*envelope.kid(), kid());
    let parsed = Envelope::from_json(envelope.to_json().unwrap().as_bytes()).unwrap();
    assert!(open_fixture(&private, &parsed).is_ok());
}

#[test]
fn the_plaintext_is_not_in_the_envelope() {
    let (_, envelope) = sealed(b"hunter2-unique-marker");
    let json = envelope.to_json().unwrap();
    assert!(!json.contains("hunter2"));
    assert!(!json.contains("api.example.com"));
}

// Moving a value.

#[test]
fn a_value_moved_to_another_item_field_or_keyset_does_not_open() {
    let (private, envelope) = sealed(b"hunter2");
    let (keyset_id, item_id, field_name) = (keyset(), item(), field());
    let other_item = ItemId::new("c_999").unwrap();
    let other_field = FieldName::new("other").unwrap();
    let other_keyset = KeysetId::new("other").unwrap();

    let moved = open(
        &private,
        &envelope,
        Binding {
            keyset: &keyset_id,
            item: &other_item,
            field: &field_name,
        },
    );
    assert_eq!(moved.unwrap_err(), FormatError::OpenFailed);

    let moved = open(
        &private,
        &envelope,
        Binding {
            keyset: &keyset_id,
            item: &item_id,
            field: &other_field,
        },
    );
    assert_eq!(moved.unwrap_err(), FormatError::OpenFailed);

    let moved = open(
        &private,
        &envelope,
        Binding {
            keyset: &other_keyset,
            item: &item_id,
            field: &field_name,
        },
    );
    assert_eq!(moved.unwrap_err(), FormatError::KeysetMismatch);
}

#[test]
fn a_rewritten_keyset_or_kid_does_not_open() {
    let (private, mut envelope) = sealed(b"hunter2");
    envelope.kid = KeyId::new("k4").unwrap();
    assert_eq!(
        open_fixture(&private, &envelope).unwrap_err(),
        FormatError::OpenFailed
    );

    let (private, mut envelope) = sealed(b"hunter2");
    envelope.keyset = KeysetId::new("other").unwrap();
    let other = KeysetId::new("other").unwrap();
    let (item, field) = (item(), field());
    let moved = open(
        &private,
        &envelope,
        Binding {
            keyset: &other,
            item: &item,
            field: &field,
        },
    );
    assert_eq!(moved.unwrap_err(), FormatError::OpenFailed);
}

#[test]
fn another_key_does_not_open() {
    let (_, envelope) = sealed(b"hunter2");
    let (other, _) = PrivateKey::generate();
    assert_eq!(
        open_fixture(&other, &envelope).unwrap_err(),
        FormatError::OpenFailed
    );
}

// Tampering.

#[test]
fn every_single_byte_change_to_the_ciphertext_does_not_open() {
    let (private, envelope) = sealed(b"x");
    for index in 0..envelope.ct.len() {
        let mut changed = envelope.clone();
        changed.ct[index] ^= 0x01;
        assert_eq!(
            open_fixture(&private, &changed).unwrap_err(),
            FormatError::OpenFailed,
            "byte {index}"
        );
    }
}

#[test]
fn every_single_bit_change_to_enc_does_not_open() {
    let (private, envelope) = sealed(b"x");
    for index in 0..envelope.enc.len() {
        for bit in 0..8 {
            let mut changed = envelope.clone();
            changed.enc[index] ^= 1 << bit;
            assert_eq!(
                open_fixture(&private, &changed).unwrap_err(),
                FormatError::OpenFailed,
                "byte {index} bit {bit}"
            );
        }
    }
}

#[test]
fn a_truncated_or_extended_ciphertext_does_not_open() {
    let (private, envelope) = sealed(b"hunter2");
    let mut shorter = envelope.clone();
    shorter.ct.pop();
    open_fixture(&private, &shorter).unwrap_err();
    let mut longer = envelope;
    longer.ct.push(0);
    open_fixture(&private, &longer).unwrap_err();
}

// What is inside.

/// Encrypts arbitrary plaintext, to test what opening does with bad contents.
fn seal_raw(public: &PublicKey, plaintext: &[u8]) -> Envelope {
    let (keyset, item, field) = (keyset(), item(), field());
    let aad = associated_data(
        VERSION,
        &kid(),
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
    )
    .unwrap();
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &public.to_hpke().unwrap(),
        INFO,
        plaintext,
        &aad,
    )
    .unwrap();
    Envelope {
        v: VERSION,
        keyset,
        kid: kid(),
        enc: enc.to_bytes().to_vec(),
        ct,
    }
}

#[test]
fn the_plaintext_has_the_documented_form() {
    let plaintext = encode_plaintext(b"\xfb\xff", &policy()).unwrap();
    let text = std::str::from_utf8(&plaintext).unwrap();
    let canonical = String::from_utf8(policy().canonical_json().unwrap()).unwrap();
    assert_eq!(
        text,
        format!("{{\"policy\":{canonical},\"secret\":{{\"b64\":\"-_8\"}}}}")
    );
}

#[test]
fn a_well_formed_plaintext_with_other_key_order_opens() {
    let (private, public) = PrivateKey::generate();
    let canonical = String::from_utf8(policy().canonical_json().unwrap()).unwrap();
    let plaintext = format!("{{ \"secret\": {{\"b64\": \"aGk\"}}, \"policy\": {canonical} }}");
    let envelope = seal_raw(&public, plaintext.as_bytes());
    let opened = open_fixture(&private, &envelope).unwrap();
    assert_eq!(opened.secret.expose(<[u8]>::to_vec), b"hi");
}

#[test]
fn a_value_with_bad_contents_does_not_open() {
    let (private, public) = PrivateKey::generate();
    let good = String::from_utf8(policy().canonical_json().unwrap()).unwrap();
    let invalid_policy = r#"{"rules":[]}"#;
    let wildcard_host = good.replace("api.example.com", "*.example.com");
    assert_ne!(good, wildcard_host);
    let cases = [
        format!("{{\"policy\":{invalid_policy},\"secret\":{{\"b64\":\"aGk\"}}}}"),
        format!("{{\"policy\":{wildcard_host},\"secret\":{{\"b64\":\"aGk\"}}}}"),
        format!("{{\"policy\":{good}}}"),
        "{\"secret\":{\"b64\":\"aGk\"}}".to_owned(),
        format!("{{\"policy\":{good},\"secret\":{{\"b64\":\"not base64!\"}}}}"),
        format!("{{\"policy\":{good},\"secret\":{{\"b64\":\"aGk=\"}}}}"),
        format!("{{\"policy\":{good},\"secret\":{{\"b64\":\"a\\u0047k\"}}}}"),
        format!("{{\"policy\":{good},\"secret\":{{\"b64\":\"aGk\",\"extra\":1}}}}"),
        format!("{{\"policy\":{good},\"secret\":{{\"b64\":\"aGk\"}},\"extra\":1}}"),
        format!("{{\"policy\":{good},\"secret\":\"aGk\"}}"),
        "not json".to_owned(),
        String::new(),
    ];
    for case in cases {
        let envelope = seal_raw(&public, case.as_bytes());
        assert_eq!(
            open_fixture(&private, &envelope).unwrap_err(),
            FormatError::OpenFailed,
            "{case}"
        );
    }
}

#[test]
fn sealing_refuses_an_invalid_policy() {
    let (_, public) = PrivateKey::generate();
    let invalid = Policy {
        rules: Vec::new(),
        definitions: std::collections::BTreeMap::new(),
        shared: false,
        verify: None,
    };
    let (keyset, item, field) = (keyset(), item(), field());
    let result = seal(
        &public,
        &kid(),
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
        b"x",
        &invalid,
    );
    assert!(matches!(result, Err(FormatError::InvalidPolicy(_))));
}

#[test]
fn sealing_refuses_what_would_not_fit_in_an_envelope() {
    let (private, public) = PrivateKey::generate();
    let (keyset, item, field) = (keyset(), item(), field());
    let binding = Binding {
        keyset: &keyset,
        item: &item,
        field: &field,
    };
    let result = seal(&public, &kid(), binding, &vec![7; MAX_CT_BYTES], &policy());
    assert_eq!(result.unwrap_err(), FormatError::PlaintextTooLarge);

    // The largest secret that fits still survives a round trip through JSON.
    let mut largest = 0;
    for length in (40_000..MAX_CT_BYTES).rev() {
        if seal(&public, &kid(), binding, &vec![7; length], &policy()).is_ok() {
            largest = length;
            break;
        }
    }
    assert!(largest > 40_000);
    let envelope = seal(&public, &kid(), binding, &vec![7; largest], &policy()).unwrap();
    let parsed = Envelope::from_json(envelope.to_json().unwrap().as_bytes()).unwrap();
    assert!(open_fixture(&private, &parsed).is_ok());
}

// The associated data.

#[test]
fn associated_data_has_the_documented_encoding() {
    let (keyset, item, field) = (keyset(), item(), field());
    let aad = associated_data(
        1,
        &kid(),
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
    )
    .unwrap();
    let mut expected = b"seal/v1/aad\x01".to_vec();
    expected.extend_from_slice(b"\x00\x04acme");
    expected.extend_from_slice(b"\x00\x02k3");
    expected.extend_from_slice(b"\x00\x05c_123");
    expected.extend_from_slice(b"\x00\x07api_key");
    assert_eq!(aad, expected);
}

#[test]
fn associated_data_is_unambiguous_when_identifiers_shift() {
    let aad = |item: &str, field: &str| {
        let (keyset, item, field) = (
            keyset(),
            ItemId::new(item).unwrap(),
            FieldName::new(field).unwrap(),
        );
        associated_data(
            1,
            &kid(),
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
        )
        .unwrap()
    };
    assert_ne!(aad("ab", "c"), aad("a", "bc"));
}

// Keys and redaction.

#[test]
fn private_keys_are_redacted_and_wiped() {
    let (private, _) = PrivateKey::generate();
    assert_eq!(format!("{private:?}"), "PrivateKey([REDACTED])");
    take_dropped();
    drop(private);
    assert_eq!(take_dropped(), [vec![0_u8; KEY_BYTES]]);
}

#[test]
fn an_opened_secret_is_redacted_and_wiped() {
    let (private, envelope) = sealed(b"hunter2");
    let opened = open_fixture(&private, &envelope).unwrap();
    assert!(!format!("{opened:?}").contains("hunter2"));
    take_dropped();
    drop(opened);
    assert!(take_dropped().contains(&vec![0_u8; 7]));
}

#[test]
fn errors_from_a_failed_open_say_nothing_of_the_contents() {
    let (private, public) = PrivateKey::generate();
    let envelope = seal_raw(&public, b"SECRETVALUE not json");
    let error = open_fixture(&private, &envelope).unwrap_err();
    assert!(!error.to_string().contains("SECRETVALUE"));
    assert!(!format!("{error:?}").contains("SECRETVALUE"));
}

#[test]
fn keys_have_a_fixed_length_and_round_trip() {
    let (private, public) = PrivateKey::generate();
    assert_eq!(private.public_key().unwrap(), public);
    let copy = private.expose(PrivateKey::from_bytes).unwrap();
    assert_eq!(copy.public_key().unwrap(), public);
    assert_eq!(
        PublicKey::from_base64url(&public.to_base64url()).unwrap(),
        public
    );
    PublicKey::from_bytes(&[0; 31]).unwrap_err();
    PublicKey::from_bytes(&[0; 33]).unwrap_err();
    PublicKey::from_base64url("not base64!").unwrap_err();
    PrivateKey::from_bytes(&[0; 31]).unwrap_err();
    PrivateKey::from_bytes(&[0; 33]).unwrap_err();
}

#[test]
fn a_low_order_public_key_is_refused() {
    let low_order = PublicKey::from_bytes(&[0; KEY_BYTES]).unwrap();
    let (keyset, item, field) = (keyset(), item(), field());
    let result = seal(
        &low_order,
        &kid(),
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
        b"x",
        &policy(),
    );
    assert_eq!(result.unwrap_err(), FormatError::SealFailed);
}

// RFC 9180 known answers.

/// The base mode vector for this exact suite (KEM 0x0020, KDF 0x0001, AEAD
/// 0x0002) from the CFRG HPKE test vectors, sequence number 0.
mod rfc9180 {
    pub const IKM_E: &str = "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9";
    pub const IKM_R: &str = "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee";
    pub const SK_R: &str = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d";
    pub const PK_R: &str = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c";
    pub const ENC: &str = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256";
    pub const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    pub const AAD: &str = "436f756e742d30";
    pub const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    pub const CT: &str = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a";
}

#[test]
fn the_suite_derives_the_rfc_9180_keys() {
    let (private, public) = X25519HkdfSha256::derive_keypair(&hex(rfc9180::IKM_R));
    assert_eq!(public.to_bytes().as_slice(), hex(rfc9180::PK_R));
    // The vector's private key is written unclamped, and `hpke` clamps on
    // serialising, as RFC 9180 says it must. The two are the same X25519 key.
    let mut clamped = hex(rfc9180::SK_R);
    clamped[0] &= 0b1111_1000;
    clamped[31] &= 0b0111_1111;
    clamped[31] |= 0b0100_0000;
    assert_eq!(private.to_bytes().as_slice(), clamped);
}

#[test]
fn the_suite_opens_the_rfc_9180_ciphertext() {
    let private = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&hex(rfc9180::SK_R)).unwrap();
    let enc = EncappedKey::from_bytes(&hex(rfc9180::ENC)).unwrap();
    let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private,
        &enc,
        &hex(rfc9180::INFO),
        &hex(rfc9180::CT),
        &hex(rfc9180::AAD),
    )
    .unwrap();
    assert_eq!(plaintext, hex(rfc9180::PT));
}

/// The fixed-randomness path that vectors use has to produce exactly what the
/// RFC's vector says, or the vectors would prove nothing.
#[test]
fn fixed_randomness_reproduces_the_rfc_9180_ciphertext() {
    use hpke::rand_core::{TryCryptoRng, TryRng};

    struct Fixed(Vec<u8>);
    impl TryRng for Fixed {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unreachable!()
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unreachable!()
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            destination.copy_from_slice(&self.0);
            Ok(())
        }
    }
    impl TryCryptoRng for Fixed {}

    let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&hex(rfc9180::PK_R)).unwrap();
    let (enc, ct) = hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &public,
        &hex(rfc9180::INFO),
        &hex(rfc9180::PT),
        &hex(rfc9180::AAD),
        &mut Fixed(hex(rfc9180::IKM_E)),
    )
    .unwrap();
    assert_eq!(enc.to_bytes().as_slice(), hex(rfc9180::ENC));
    assert_eq!(ct, hex(rfc9180::CT));
}

#[test]
fn sealing_with_a_fixed_ephemeral_key_is_deterministic_and_opens() {
    let (private, public) = PrivateKey::generate();
    let (keyset, item, field) = (keyset(), item(), field());
    let binding = Binding {
        keyset: &keyset,
        item: &item,
        field: &field,
    };
    let ikm = [42; KEY_BYTES];
    let first = seal_with_ephemeral_ikm(&public, &kid(), binding, b"x", &policy(), &ikm).unwrap();
    let second = seal_with_ephemeral_ikm(&public, &kid(), binding, b"x", &policy(), &ikm).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        open(&private, &first, binding)
            .unwrap()
            .secret
            .expose(<[u8]>::to_vec),
        b"x"
    );
}
