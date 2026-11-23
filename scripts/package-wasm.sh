#!/usr/bin/env bash
# Builds the WebAssembly sealer as it is released: an archive with the module for a
# page to load (web/) and the one for a bundler (bundler/). Before it is packed, the
# module for a page is loaded under Node, checked to export sealing and nothing that
# could open a value, and what it seals is opened natively.
#
#   scripts/package-wasm.sh [OUTPUT]     # seal-wasm.tar.gz by default
#
# Needs Node and a wasm-bindgen-cli whose version matches the wasm-bindgen crate
# in Cargo.lock.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
out="${1:-seal-wasm.tar.gz}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cargo build --locked --release --lib --package seal-format --features wasm \
  --target wasm32-unknown-unknown
for target in web bundler; do
  wasm-bindgen --target "$target" --out-dir "$work/seal-wasm/$target" \
    target/wasm32-unknown-unknown/release/seal_format.wasm
done
cp LICENSE "$work/seal-wasm/LICENSE"

public_key="$(node -e '
  const vectors = JSON.parse(require("fs").readFileSync("vectors/envelope.json"));
  process.stdout.write(Buffer.from(vectors.public_key_hex, "hex").toString("base64url"));
')"

# A copy named as a module, so that Node reads it as one whatever its version.
cp "$work/seal-wasm/web/seal_format.js" "$work/check.mjs"
secret='sealed by the released module: +/ "&=\'
envelope="$(node --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { pathToFileURL } from "node:url";
  const [module, wasm, publicKey, secret] = process.argv.slice(1);
  const sealer = await import(pathToFileURL(module).href);
  const exports = Object.keys(sealer).sort();
  if (exports.join() !== "default,initSync,seal") {
    throw new Error("unexpected exports: " + exports);
  }
  await sealer.default({ module_or_path: readFileSync(wasm) });
  const policy = JSON.stringify({
    rules: [{
      destination: { scheme: "https", host: "api.example.com" },
      inject: { header: { name: "Authorization", format: "Bearer {}" } },
    }],
  });
  const bytes = new TextEncoder().encode(secret);
  process.stdout.write(sealer.seal(publicKey, "k3", "acme", "c_123", "api_key", bytes, policy));
' "$work/check.mjs" "$work/seal-wasm/web/seal_format_bg.wasm" "$public_key" "$secret")"
printf '%s' "$envelope" \
  | cargo run --quiet --locked --package seal-format --example open_wasm_envelope -- "$secret"

tar -C "$work" -czf "$out" seal-wasm
echo "packed $out"
tar -tzf "$out"
