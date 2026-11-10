//! Envelope, HPKE and policy types. Sealing needs only a public key; opening is
//! behind the `open` feature, and without it there is no code path to a plaintext.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod id;
pub mod policy;
pub mod seal;
pub mod secret;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use envelope::Envelope;
pub use error::FormatError;
pub use id::{FieldName, ItemId, KeyId, KeysetId, PolicyName};
pub use policy::Policy;
pub use seal::{Binding, PublicKey, seal};
#[cfg(feature = "open")]
pub use seal::{PrivateKey, Sealed, open};
pub use secret::Secret;
