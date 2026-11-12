//! The offline commands: `check-config`, `keygen`, `reseal` and `rewrap`.

use std::io::{BufRead, Write};
use std::path::Path;

use seal_format::{Binding, Envelope, FieldName, ItemId, KeysetId, Policy, seal};
use seal_keys::{DirKeySource, FileKeyWrap, Keyring, Keys};
use serde::{Deserialize, Serialize};

use crate::config::{Config, SourceConfig, WrapConfig};
use crate::limits;
use crate::serve::{key_parts, key_wrap};

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

/// Deletes every key of a keyset from the configured key source.
///
/// # Errors
///
/// Returns a message if the keyset has no keys or the key source cannot delete.
pub async fn destroy_keyset(config: &Config, keyset: &KeysetId) -> Result<(), String> {
    let (source, wrap) = key_parts(config)?;
    let keyring =
        Keyring::new(source, wrap, config.keyring()).map_err(|error| error.to_string())?;
    keyring
        .destroy(keyset)
        .await
        .map_err(|error| error.to_string())
}

/// Wraps every key in the configured key directory again, under a new wrapping key,
/// into a new directory. The new wrapping key may be of another kind: this is also how
/// keys move from a wrapping key file to a KMS, or back. The configured directory and
/// wrapping key are left as they are; seal uses the new ones once its configuration
/// names them and it is restarted. Returns how many keys were written.
///
/// # Errors
///
/// Returns a message if the key source is not a directory, the new directory exists,
/// or a key cannot be re-wrapped. Nothing is said of any key's contents.
pub async fn rewrap(config: &Config, new_wrap: &WrapConfig, out: &Path) -> Result<usize, String> {
    let SourceConfig::Dir(keys) = &config.keys.source else {
        return Err(
            "rewrap needs a directory key source; re-wrap the keys where the key service keeps them"
                .to_owned(),
        );
    };
    if out.exists() {
        return Err(format!("{} must not exist", out.display()));
    }
    let old = key_wrap(&config.keys.wrap)?;
    let new = key_wrap(new_wrap)?;
    seal_keys::rewrap(
        &DirKeySource::new(keys, usize::MAX),
        &DirKeySource::new(out, usize::MAX),
        old.as_ref(),
        new.as_ref(),
    )
    .await
    .map_err(|error| format!("cannot re-wrap the keys: {error}"))
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
    /// In the input only: the policy the value is to have from now on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

/// What `reseal` did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resealed {
    /// How many values were sealed again, for a new key or a new policy.
    pub values: usize,
    /// How many of those got a new policy.
    pub policies: usize,
}

/// Reseals every value under the keyset's current key. A value keeps its policy unless
/// its line names a new one and `rewrite_policies` is set: only whoever runs seal can
/// change where an existing secret may go. A value already under the current key, with
/// nothing to change, is written out as it is.
///
/// A new policy cannot change whether a value is shared: that would let it serve every
/// record, or stop it serving them, without anyone having sealed it so.
///
/// # Errors
///
/// Returns a message naming the line that failed, never its contents.
pub async fn reseal(
    config: &Config,
    keyset: &KeysetId,
    rewrite_policies: bool,
    input: impl BufRead,
    output: &mut impl Write,
) -> Result<Resealed, String> {
    let (source, wrap) = key_parts(config)?;
    let keyring =
        Keyring::new(source, wrap, config.keyring()).map_err(|error| error.to_string())?;
    let (current_kid, current) = keyring
        .current_public_key(keyset)
        .await
        .map_err(|error| error.to_string())?;
    let mut done = Resealed::default();
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
        let new_policy = entry.policy.take();
        if let Some(policy) = &new_policy {
            if !rewrite_policies {
                return Err(format!(
                    "line {number} names a new policy, which needs --rewrite-policies"
                ));
            }
            policy
                .validate()
                .map_err(|_| format!("line {number}: its new policy is not valid"))?;
        }
        if new_policy.is_some() || *entry.envelope.kid() != current_kid {
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
            let rewritten = new_policy.filter(|policy| *policy != opened.policy);
            if let Some(policy) = &rewritten
                && policy.shared != opened.policy.shared
            {
                return Err(format!(
                    "line {number}: a new policy cannot change whether a value is shared"
                ));
            }
            if rewritten.is_some() || *entry.envelope.kid() != current_kid {
                let policy = rewritten.as_ref().unwrap_or(&opened.policy);
                entry.envelope = opened
                    .secret
                    .expose(|secret| seal(&current, &current_kid, binding, secret, policy))
                    .map_err(|_| format!("line {number} could not be sealed"))?;
                done.values += 1;
                done.policies += usize::from(rewritten.is_some());
            }
        }
        let json = serde_json::to_string(&entry)
            .map_err(|_| format!("line {number} could not be written"))?;
        writeln!(output, "{json}").map_err(|_| "cannot write the output".to_owned())?;
    }
    Ok(done)
}
