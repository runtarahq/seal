//! Writes the files in `vectors/`.
//!
//! Run with `cargo run --package seal-format --example generate_vectors`. The
//! format is stable, so a change to these files means a compatibility break.

#![allow(clippy::unwrap_used)]

#[path = "../tests/support/vectors.rs"]
mod vectors;

use std::fs;
use std::path::Path;

fn main() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    for (name, contents) in vectors::generate() {
        fs::write(directory.join(name), contents).unwrap();
    }
}
