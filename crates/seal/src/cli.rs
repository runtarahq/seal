//! The offline commands: `check-config`, `keygen` and `reseal`.

use std::io::{BufRead, Write};
use std::path::Path;

use seal_format::{Binding, Envelope, FieldName, ItemId, KeysetId, seal};
use seal_keys::{FileKeyWrap, Keyring, Keys};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::limits;
use crate::serve::key_parts;

/// Writes how the memory ceiling adds up. Returns whether it fits the budget.
///
/// # Errors
///
/// Returns a message if the output cannot be written.
pub fn check_config(config: &Config, out: &mut impl Write) -> Result<bool, String> {
    let (total, terms) = limits::ceiling(config);
    let write = |out: &mut dyn Write, line: String| {
        writeln!(out, "{line}").map_err(|_| "cannot write the output".to_owned())
    };
    write(
        out,
        "The configuration is valid. Memory ceiling:".to_owned(),
    )?;
    for term in &terms {
        write(
            out,
            format!("  {:<34} {:>8} MiB", term.name, term.bytes >> 20),
        )?;
    }
    write(
        out,
        format!("  {:<34} {:>8} MiB", "with allocator margin", total >> 20),
    )?;
    let budget = config.limits.memory_budget.0;
    write(
        out,
        format!("  {:<34} {:>8} MiB", "limits.memory_budget", budget >> 20),
    )?;
    let fits = total <= budget;
    if !fits {
        write(
            out,
            "The ceiling is over the budget: lower limits or raise the budget.".to_owned(),
        )?;
    }
    Ok(fits)
}

/// Writes a new wrapping key file.
///
/// # Errors
///
/// Returns a message if the file exists or cannot be written.
pub fn create_wrapping_key(path: &Path) -> Result<(), String> {
    FileKeyWrap::create_file(path).map_err(|error| error.to_string())
}

/// Makes a keyset's first key, stored in the configured key source.
///
/// # Errors
///
/// Returns a message if the keyset exists or the key cannot be stored.
pub async fn keygen(config: &Config, keyset: &KeysetId) -> Result<String, String> {
    let (source, wrap) = key_parts(config)?;
    let keyring =
        Keyring::new(source, wrap, config.keyring()).map_err(|error| error.to_string())?;
    let key = keyring
        .generate(keyset)
        .await
        .map_err(|error| error.to_string())?;
    Ok(key.kid.to_string())
}

/// One line of `reseal`'s input and output.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResealLine {
    /// The record.
    pub item: ItemId,
    /// The field.
    pub field: FieldName,
    /// The sealed value.
    pub envelope: Envelope,
}

/// Reseals every value under the keyset's current key, keeping its policy. A value
/// already under the current key is written out unchanged. Returns how many changed.
///
/// # Errors
///
/// Returns a message naming the line that failed, never its contents.
pub async fn reseal(
    config: &Config,
    keyset: &KeysetId,
    input: impl BufRead,
    output: &mut impl Write,
) -> Result<usize, String> {
    let (source, wrap) = key_parts(config)?;
    let keyring =
        Keyring::new(source, wrap, config.keyring()).map_err(|error| error.to_string())?;
    let (current_kid, current) = keyring
        .current_public_key(keyset)
        .await
        .map_err(|error| error.to_string())?;
    let mut changed = 0;
    for (index, line) in input.lines().enumerate() {
        let number = index + 1;
        let line = line.map_err(|_| format!("line {number} cannot be read"))?;
        if line.trim().is_empty() {
            continue;
        }
        let mut entry: ResealLine =
            serde_json::from_str(&line).map_err(|_| format!("line {number} is not valid"))?;
        if entry.envelope.keyset() != keyset {
            return Err(format!("line {number} is for another keyset"));
        }
        if *entry.envelope.kid() != current_kid {
            let binding = Binding {
                keyset,
                item: &entry.item,
                field: &entry.field,
            };
            let key = keyring
                .private_key(keyset, entry.envelope.kid())
                .await
                .map_err(|_| format!("line {number}: its key is not available"))?;
            let opened = seal_format::open(&key, &entry.envelope, binding)
                .map_err(|_| format!("line {number} did not open"))?;
            drop(key);
            entry.envelope = opened
                .secret
                .expose(|secret| seal(&current, &current_kid, binding, secret, &opened.policy))
                .map_err(|_| format!("line {number} could not be sealed"))?;
            changed += 1;
        }
        let json = serde_json::to_string(&entry)
            .map_err(|_| format!("line {number} could not be written"))?;
        writeln!(output, "{json}").map_err(|_| "cannot write the output".to_owned())?;
    }
    Ok(changed)
}
