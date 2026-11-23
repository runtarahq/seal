//! `seal-sealer` run as a program: what it seals opens with the private key, as what
//! it was given.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use seal_format::policy::{HmacHash, builder};
use seal_format::{
    Binding, Envelope, FieldName, ItemId, KeyId, KeysetId, Offer, Policy, PrivateKey,
};
use serde_json::json;

const SECRET: &str = "SEALCANARY-typed-in-a-terminal";

struct Setup {
    dir: tempfile::TempDir,
    private: PrivateKey,
    offer: Offer,
}

fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

/// An offer to seal one value under an ordinary policy, as an operator would write.
fn plain_setup() -> Setup {
    let (private, public) = PrivateKey::generate();
    let offer = Offer {
        public_key: public,
        kid: KeyId::new("k1").unwrap(),
        keyset: KeysetId::new("platform").unwrap(),
        item: ItemId::new("oauth-app").unwrap(),
        field: field("client_secret"),
        policy: builder::bearer("https://api.example.com").unwrap(),
    };
    Setup {
        dir: tempfile::tempdir().unwrap(),
        private,
        offer,
    }
}

/// An offer an application makes for a record's secret fields.
fn intake_setup(outputs: &[(&str, Policy)]) -> Setup {
    let (private, public) = PrivateKey::generate();
    let outputs: BTreeMap<FieldName, Policy> = outputs
        .iter()
        .map(|(name, policy)| (field(name), policy.clone()))
        .collect();
    let offer = Offer::for_intake(
        public,
        KeyId::new("k1").unwrap(),
        KeysetId::new("acme").unwrap(),
        ItemId::new("c_123").unwrap(),
        &outputs,
        1_800_000_000,
    )
    .unwrap();
    Setup {
        dir: tempfile::tempdir().unwrap(),
        private,
        offer,
    }
}

impl Setup {
    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn offer_file(&self) -> PathBuf {
        self.write("offer.json", self.offer.to_json().unwrap().as_bytes())
    }

    /// What the envelope the program printed holds.
    fn open(&self, printed: &str) -> (Vec<u8>, Policy) {
        let envelope = Envelope::from_json(printed.trim_end().as_bytes()).unwrap();
        let opened = seal_format::open(
            &self.private,
            &envelope,
            Binding {
                keyset: &self.offer.keyset,
                item: &self.offer.item,
                field: &self.offer.field,
            },
        )
        .unwrap();
        (opened.secret.expose(<[u8]>::to_vec), opened.policy)
    }
}

/// Runs the program, and returns whether it succeeded, what it printed and what it said.
fn run(args: &[&std::ffi::OsStr], stdin: &[u8]) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seal-sealer"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The program may stop before it has read everything it was sent.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn os(text: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(text)
}

fn pair(name: &str, path: &Path) -> std::ffi::OsString {
    let mut argument = std::ffi::OsString::from(format!("{name}="));
    argument.push(path);
    argument
}

#[test]
fn a_secret_from_standard_input_is_sealed_under_the_offer_as_it_is() {
    let setup = plain_setup();
    let offer = setup.offer_file();

    let (ok, printed, said) = run(&[os("--offer"), offer.as_os_str()], SECRET.as_bytes());
    assert!(ok, "{said}");
    assert!(!printed.contains(SECRET));
    assert_eq!(
        setup.open(&printed),
        (SECRET.as_bytes().to_vec(), setup.offer.policy.clone())
    );

    // A line ending is part of what was given, unless it is asked to be left out.
    let with_newline = format!("{SECRET}\n");
    let (_, printed, _) = run(&[os("--offer"), offer.as_os_str()], with_newline.as_bytes());
    assert_eq!(setup.open(&printed).0, with_newline.as_bytes());
    let (_, printed, _) = run(
        &[os("--offer"), offer.as_os_str(), os("--trim-newline")],
        format!("{SECRET}\r\n").as_bytes(),
    );
    assert_eq!(setup.open(&printed).0, SECRET.as_bytes());
}

#[test]
fn the_offer_may_come_from_standard_input_and_the_secret_from_a_file() {
    let setup = plain_setup();
    let secret = setup.write("secret", SECRET.as_bytes());
    let (ok, printed, said) = run(
        &[os("--offer"), os("-"), os("--secret"), secret.as_os_str()],
        setup.offer.to_json().unwrap().as_bytes(),
    );
    assert!(ok, "{said}");
    assert_eq!(setup.open(&printed).0, SECRET.as_bytes());
}

#[test]
fn fields_are_sealed_as_one_object_under_an_intake_offer() {
    let setup = intake_setup(&[
        (
            "api_key",
            builder::bearer("https://api.example.com").unwrap(),
        ),
        ("signing", builder::webhook_hmac(HmacHash::Sha256).unwrap()),
        (
            "client_key",
            builder::webhook_hmac(HmacHash::Sha256).unwrap(),
        ),
    ]);
    let offer = setup.offer_file();
    let pem = "-----BEGIN KEY-----\n\"quoted\" \\ and\ttabbed\n-----END KEY-----\n";
    let pem_file = setup.write("signing.pem", pem.as_bytes());
    let der: Vec<u8> = (0..=255).collect();
    let der_file = setup.write("client.der", &der);

    let (ok, printed, said) = run(
        &[
            os("--offer"),
            offer.as_os_str(),
            os("--text"),
            os("api_key=-"),
            os("--text"),
            pair("signing", &pem_file).as_os_str(),
            os("--bytes"),
            pair("client_key", &der_file).as_os_str(),
        ],
        SECRET.as_bytes(),
    );
    assert!(ok, "{said}");

    let (object, policy) = setup.open(&printed);
    assert_eq!(policy, setup.offer.policy);
    assert_eq!(setup.offer.field.as_str(), "intake");
    let object: serde_json::Value = serde_json::from_slice(&object).unwrap();
    let encoded = {
        use std::fmt::Write as _;
        // base64url of 0..=255, worked out here so the test does not lean on the
        // encoder it checks.
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut text = String::new();
        for chunk in der.chunks(3) {
            let bits = chunk
                .iter()
                .fold(0_u32, |bits, byte| bits << 8 | u32::from(*byte))
                << (8 * (3 - chunk.len()));
            for index in 0..=chunk.len() {
                let six = (bits >> (18 - 6 * index)) & 0x3f;
                write!(text, "{}", char::from(ALPHABET[six as usize])).unwrap();
            }
        }
        text
    };
    assert_eq!(
        object,
        json!({ "api_key": SECRET, "signing": pem, "client_key": { "b64": encoded } })
    );
}

#[test]
fn what_cannot_be_sealed_is_refused_without_repeating_it() {
    let setup = intake_setup(&[(
        "api_key",
        builder::bearer("https://api.example.com").unwrap(),
    )]);
    let offer = setup.offer_file();
    let secret = setup.write("secret", SECRET.as_bytes());
    let not_text = setup.write("not-text", &[0xff, 0xfe, b'S', b'E', b'A', b'L']);
    let large = setup.write("large", &vec![b'x'; 70 * 1024]);
    let mut broken: serde_json::Value =
        serde_json::from_str(&setup.offer.to_json().unwrap()).unwrap();
    broken["policy"] = json!({ "rules": [] });
    let broken = setup.write("broken.json", broken.to_string().as_bytes());
    let api_key = pair("api_key", &secret);
    let api_key_stdin = os("api_key=-");

    let cases: Vec<(Vec<&std::ffi::OsStr>, &str)> = vec![
        (
            vec![os("--offer"), broken.as_os_str()],
            "the offer is not valid",
        ),
        (
            vec![os("--offer"), os("-")],
            "only one of the offer and the secrets can come from standard input",
        ),
        (
            vec![os("--offer"), os("-"), os("--text"), api_key_stdin],
            "only one of the offer and the secrets can come from standard input",
        ),
        (
            vec![
                os("--offer"),
                offer.as_os_str(),
                os("--text"),
                os("api_key"),
            ],
            "a field is written NAME=FILE",
        ),
        (
            vec![
                os("--offer"),
                offer.as_os_str(),
                os("--text"),
                os("api key=x"),
            ],
            "a field's name is not valid",
        ),
        (
            vec![
                os("--offer"),
                offer.as_os_str(),
                os("--text"),
                api_key.as_os_str(),
                os("--bytes"),
                api_key.as_os_str(),
            ],
            "the field api_key is named twice",
        ),
        (
            vec![
                os("--offer"),
                offer.as_os_str(),
                os("--text"),
                pair("api_key", &not_text).as_os_str().to_owned().leak(),
            ],
            "the field api_key is not text",
        ),
        (
            vec![
                os("--offer"),
                offer.as_os_str(),
                os("--text"),
                pair("api_key", &large).as_os_str().to_owned().leak(),
            ],
            "the field api_key is too large",
        ),
        (
            vec![
                os("--offer"),
                offer.as_os_str(),
                os("--text"),
                pair("api_key", Path::new("/nonexistent/secret"))
                    .as_os_str()
                    .to_owned()
                    .leak(),
            ],
            "the field api_key cannot be read",
        ),
        (
            vec![os("--offer"), os("/nonexistent/offer.json")],
            "the offer cannot be read",
        ),
    ];
    for (args, reason) in cases {
        let (ok, printed, said) = run(&args, SECRET.as_bytes());
        assert!(!ok, "{args:?}");
        assert!(said.contains(reason), "{args:?}: {said}");
        assert!(printed.is_empty());
        assert!(!said.contains(SECRET) && !said.contains("SEAL\n"), "{said}");
    }

    // A secret and fields are two ways of saying what to seal.
    let (ok, _, said) = run(
        &[
            os("--offer"),
            offer.as_os_str(),
            os("--secret"),
            secret.as_os_str(),
            os("--text"),
            api_key.as_os_str(),
        ],
        b"",
    );
    assert!(!ok);
    assert!(said.contains("cannot be used with"), "{said}");
}

#[test]
fn a_secret_too_large_for_an_envelope_is_refused() {
    let setup = plain_setup();
    let offer = setup.offer_file();
    let (ok, _, said) = run(&[os("--offer"), offer.as_os_str()], &vec![b'x'; 60 * 1024]);
    assert!(!ok);
    assert!(
        said.contains("cannot seal: secret and policy too large to seal"),
        "{said}"
    );
}
