//! Sealing outside a browser: the native counterpart of the WASM sealer, for scripts,
//! API clients and operators.
//!
//! It takes an offer, which says where to seal to and under which policy, and a secret,
//! and prints the envelope. It links `seal-format` without its `open` feature, so there
//! is no code in it that could open a value: whoever runs it needs no more trust than a
//! browser does.
//!
//! It knows nothing of intake as such. An intake envelope is an object of fields sealed
//! under the policy in the offer, and the application that made the offer decides what
//! that policy is. An operator can as well seal one secret under a policy of their own.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Parser;
use seal_format::envelope::MAX_CT_BYTES;
use seal_format::intake::{Value, object};
use seal_format::{FieldName, Offer};
use zeroize::Zeroizing;

/// The largest offer read. A policy is at most 16 KiB.
const MAX_OFFER_BYTES: usize = 64 * 1024;

/// A secret sealed to a seal keyset. This program cannot open one.
#[derive(Debug, Parser)]
#[command(name = "seal-sealer", version)]
pub struct Args {
    /// The offer's JSON: public_key, kid, keyset, item, field and policy. `-` reads it
    /// from standard input.
    #[arg(long, value_name = "FILE")]
    pub offer: PathBuf,

    /// The secret, sealed as it is. `-` or nothing reads it from standard input.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["text", "bytes"])]
    pub secret: Option<PathBuf>,

    /// A field of an object of secrets, as text: NAME=FILE. May be repeated. With
    /// these, the secret sealed is one JSON object of every field named.
    #[arg(long, value_name = "NAME=FILE")]
    pub text: Vec<String>,

    /// A field of an object of secrets that is not text, such as a key in DER:
    /// NAME=FILE. May be repeated.
    #[arg(long, value_name = "NAME=FILE")]
    pub bytes: Vec<String>,

    /// Leaves out one line ending at the end of the secret, or of each text field. A
    /// file an editor saved usually has one that is not part of the secret.
    #[arg(long)]
    pub trim_newline: bool,
}

/// Where something is read from.
enum Source<'a> {
    Stdin,
    File(&'a Path),
}

impl<'a> Source<'a> {
    fn of(path: &'a Path) -> Self {
        if path == Path::new("-") {
            Self::Stdin
        } else {
            Self::File(path)
        }
    }
}

/// Reads at most `limit` bytes into a buffer that is wiped when dropped. The buffer is
/// sized up front, so reading never leaves a copy behind as it grows.
fn read(
    source: &Source<'_>,
    stdin: &mut dyn Read,
    limit: usize,
    what: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(limit + 1));
    let wanted = u64::try_from(limit + 1).unwrap_or(u64::MAX);
    let outcome = match source {
        Source::Stdin => stdin.take(wanted).read_to_end(&mut buffer),
        Source::File(path) => {
            File::open(path).and_then(|file| file.take(wanted).read_to_end(&mut buffer))
        }
    };
    outcome.map_err(|_| format!("{what} cannot be read"))?;
    if buffer.len() > limit {
        return Err(format!("{what} is too large"));
    }
    Ok(buffer)
}

/// Without one line ending at its end, if it has one.
fn trimmed(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

/// One `NAME=FILE`.
fn member(argument: &str) -> Result<(FieldName, &Path), String> {
    let (name, path) = argument
        .split_once('=')
        .ok_or_else(|| "a field is written NAME=FILE".to_owned())?;
    let name = FieldName::new(name).map_err(|_| "a field's name is not valid".to_owned())?;
    Ok((name, Path::new(path)))
}

/// Seals what the arguments name, and returns the envelope's JSON.
///
/// # Errors
///
/// Returns a message saying what was wrong. It names fields and never holds a value.
pub fn run(args: &Args, stdin: &mut dyn Read) -> Result<String, String> {
    let offer_source = Source::of(&args.offer);
    let members: Vec<(FieldName, &Path, bool)> = args
        .text
        .iter()
        .map(|argument| member(argument).map(|(name, path)| (name, path, true)))
        .chain(
            args.bytes
                .iter()
                .map(|argument| member(argument).map(|(name, path)| (name, path, false))),
        )
        .collect::<Result<_, _>>()?;
    let secret_source = match &args.secret {
        Some(path) => Source::of(path),
        None => Source::Stdin,
    };

    // Standard input is read once, so only one thing can come from it.
    let from_stdin = usize::from(matches!(offer_source, Source::Stdin))
        + if members.is_empty() {
            usize::from(matches!(secret_source, Source::Stdin))
        } else {
            members
                .iter()
                .filter(|(_, path, _)| matches!(Source::of(path), Source::Stdin))
                .count()
        };
    if from_stdin > 1 {
        return Err(
            "only one of the offer and the secrets can come from standard input".to_owned(),
        );
    }

    let offer = read(&offer_source, stdin, MAX_OFFER_BYTES, "the offer")?;
    let offer =
        Offer::from_json(&offer).map_err(|error| format!("the offer is not valid: {error}"))?;

    let secret = if members.is_empty() {
        let secret = read(&secret_source, stdin, MAX_CT_BYTES, "the secret")?;
        if args.trim_newline {
            Zeroizing::new(trimmed(&secret).to_vec())
        } else {
            secret
        }
    } else {
        let mut contents = BTreeMap::new();
        for (name, path, is_text) in &members {
            let bytes = read(
                &Source::of(path),
                stdin,
                MAX_CT_BYTES,
                &format!("the field {name}"),
            )?;
            if contents.insert(name.clone(), (bytes, *is_text)).is_some() {
                return Err(format!("the field {name} is named twice"));
            }
        }
        let mut values = BTreeMap::new();
        for (name, (bytes, is_text)) in &contents {
            let value = if *is_text {
                let bytes = if args.trim_newline {
                    trimmed(bytes)
                } else {
                    bytes
                };
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| format!("the field {name} is not text; name it with --bytes"))?;
                Value::Text(text)
            } else {
                Value::Bytes(bytes)
            };
            values.insert(name.clone(), value);
        }
        object(&values)
    };

    let envelope = offer
        .seal(&secret)
        .map_err(|error| format!("cannot seal: {error}"))?;
    envelope
        .to_json()
        .map_err(|error| format!("cannot write the envelope: {error}"))
}
