#!/usr/bin/env bash
# Seals in WebAssembly under Node, and opens the result natively.
#
# Needs Node and a wasm-bindgen-cli whose version matches the wasm-bindgen crate
# in Cargo.lock.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cargo build --locked --release --lib --package seal-format --features wasm \
  --target wasm32-unknown-unknown
wasm-bindgen --target nodejs --out-dir "$work/pkg" \
  target/wasm32-unknown-unknown/release/seal_format.wasm

public_key="$(node -e '
  const vectors = JSON.parse(require("fs").readFileSync("vectors/envelope.json"));
  process.stdout.write(Buffer.from(vectors.public_key_hex, "hex").toString("base64url"));
')"

# The module exports sealing and nothing that could open a value.
node -e '
  const exports = Object.keys(require(process.argv[1])).filter((name) => !name.startsWith("__"));
  if (exports.join() !== "seal") {
    throw new Error("unexpected exports: " + exports);
  }
  console.log("exports only: seal");
' "$work/pkg/seal_format.js"

secret='sealed in WebAssembly: +/ "&=\'
envelope="$(node -e '
  const { seal } = require(process.argv[1]);
  const [, , publicKey, secret] = process.argv.slice(1);
  const policy = JSON.stringify({
    rules: [{
      destination: { scheme: "https", host: "api.example.com" },
      inject: { header: { name: "Authorization", format: "Bearer {}" } },
    }],
  });
  const bytes = new TextEncoder().encode(secret);
  process.stdout.write(seal(publicKey, "k3", "acme", "c_123", "api_key", bytes, policy));
' "$work/pkg/seal_format.js" "" "$public_key" "$secret")"

printf '%s' "$envelope" \
  | cargo run --quiet --locked --package seal-format --example open_wasm_envelope -- "$secret"
