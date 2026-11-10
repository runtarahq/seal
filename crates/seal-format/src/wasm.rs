//! The sealing half for browsers, so that a secret can be sealed before anything
//! reaches the application. This build has no opening code.

use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::FormatError;
use crate::id::{FieldName, ItemId, KeyId, KeysetId};
use crate::policy::Policy;
use crate::seal::{Binding, PublicKey, seal as seal_value};

/// Seals a secret and returns the envelope's JSON.
///
/// `public_key` is base64url, and `policy` is the policy's JSON. Pass the secret
/// as bytes rather than a JavaScript string where you can: bytes can be
/// overwritten afterwards, and a string cannot.
///
/// # Errors
///
/// Throws an error naming what is not valid, and never including a value.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)] // One plain argument each, for JavaScript callers.
pub fn seal(
    public_key: &str,
    kid: &str,
    keyset: &str,
    item: &str,
    field: &str,
    secret: &[u8],
    policy: &str,
) -> Result<String, String> {
    seal_json(public_key, kid, keyset, item, field, secret, policy).map_err(|e| e.to_string())
}

fn seal_json(
    public_key: &str,
    kid: &str,
    keyset: &str,
    item: &str,
    field: &str,
    secret: &[u8],
    policy: &str,
) -> Result<String, FormatError> {
    let public_key = PublicKey::from_base64url(public_key)?;
    let kid = KeyId::new(kid)?;
    let keyset = KeysetId::new(keyset)?;
    let item = ItemId::new(item)?;
    let field = FieldName::new(field)?;
    let policy = Policy::from_json(policy.as_bytes())?;
    let binding = Binding {
        keyset: &keyset,
        item: &item,
        field: &field,
    };
    seal_value(&public_key, &kid, binding, secret, &policy)?.to_json()
}
