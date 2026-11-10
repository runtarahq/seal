//! Sealing works without the `open` feature, so the failures in the other files
//! are about the feature and not about the crate failing to build.

use seal_format::{Binding, FieldName, ItemId, KeysetId, PublicKey, policy::builder, seal};
use seal_format::id::KeyId;

fn main() {
    let keyset = KeysetId::new("acme").unwrap();
    let item = ItemId::new("c_1").unwrap();
    let field = FieldName::new("api_key").unwrap();
    let binding = Binding { keyset: &keyset, item: &item, field: &field };
    let public = PublicKey::from_bytes(&[9; 32]).unwrap();
    let policy = builder::bearer("https://api.example.com/").unwrap();
    seal(&public, &KeyId::new("k1").unwrap(), binding, b"secret", &policy).unwrap();
}
