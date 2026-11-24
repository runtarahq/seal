#!/usr/bin/env bash
# Builds the WebAssembly sealer as it is released: an archive that is also an npm
# package, `seal-wasm`, which an application installs by the URL of the release's file.
# `seal-wasm` is the module for a bundler that loads WebAssembly itself (bundler/), and
# `seal-wasm/web` the one for a page to load, given the URL of
# `seal-wasm/web/seal_format_bg.wasm` (web/).
#
# Before it is done, the archive is installed into an empty project as an application
# would install it, the module for a page is imported by its name under Node, checked
# to export sealing and nothing that could open a value, and what it seals is opened
# natively.
#
#   scripts/package-wasm.sh [OUTPUT]     # seal-wasm.tar.gz by default
#
# Needs Node with npm, and a wasm-bindgen-cli whose version matches the wasm-bindgen
# crate in Cargo.lock.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

version="$(cargo metadata --locked --no-deps --format-version 1 | node -e '
  const metadata = JSON.parse(require("fs").readFileSync(0));
  process.stdout.write(metadata.packages.find((p) => p.name === "seal-format").version);
')"
out="${1:-seal-wasm.tar.gz}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# npm takes an archive whose one folder holds a package.json, whatever its name.
package="$work/seal-wasm"

cargo build --locked --release --lib --package seal-format --features wasm \
  --target wasm32-unknown-unknown
wasm=target/wasm32-unknown-unknown/release/seal_format.wasm
for target in web bundler; do
  wasm-bindgen --target "$target" --out-dir "$package/$target" "$wasm"
done
cp LICENSE "$package/LICENSE"

node -e '
  const [version, directory] = process.argv.slice(1);
  const manifest = {
    name: "seal-wasm",
    version,
    description: "Seals a secret to a seal keyset in a browser. It cannot open one",
    license: "Apache-2.0",
    repository: { type: "git", url: "https://github.com/runtarahq/seal" },
    type: "module",
    sideEffects: ["./bundler/seal_format.js"],
    exports: {
      ".": { types: "./bundler/seal_format.d.ts", default: "./bundler/seal_format.js" },
      "./web": { types: "./web/seal_format.d.ts", default: "./web/seal_format.js" },
      "./web/seal_format_bg.wasm": "./web/seal_format_bg.wasm",
      "./package.json": "./package.json",
    },
    keywords: ["seal", "hpke", "wasm"],
  };
  require("fs").writeFileSync(directory + "/package.json", JSON.stringify(manifest, null, 2) + "\n");
' "$version" "$package"

tar -C "$work" -czf "$work/seal-wasm.tar.gz" seal-wasm

# Installed as an application installs it, with nothing from the network: the package
# has no dependencies.
project="$work/project"
mkdir "$project"
printf '{"name":"check","private":true,"type":"module"}\n' > "$project/package.json"
(cd "$project" && npm install --offline --no-audit --no-fund --ignore-scripts --silent "$work/seal-wasm.tar.gz")

public_key="$(node -e '
  const vectors = JSON.parse(require("fs").readFileSync("vectors/envelope.json"));
  process.stdout.write(Buffer.from(vectors.public_key_hex, "hex").toString("base64url"));
')"
secret='sealed by the released module: +/ "&=\'
cat > "$project/check.mjs" <<'CHECK'
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import init, * as sealer from "seal-wasm/web";

const [publicKey, secret] = process.argv.slice(2);
const exports = Object.keys(sealer).sort();
if (exports.join() !== "default,initSync,seal") {
  throw new Error("unexpected exports: " + exports);
}
// A page gives `init` the module's URL. Here it is read from where the package put it.
const require = createRequire(import.meta.url);
const wasm = require.resolve("seal-wasm/web/seal_format_bg.wasm");
// The module for a bundler is what the package's own name gives, with its version.
if (!require.resolve("seal-wasm").endsWith("/bundler/seal_format.js")) {
  throw new Error("seal-wasm is not the module for a bundler");
}
if (require("seal-wasm/package.json").version !== process.env.VERSION) {
  throw new Error("the package does not have the version it was built from");
}
await init({ module_or_path: readFileSync(wasm) });
const policy = JSON.stringify({
  rules: [{
    destination: { scheme: "https", host: "api.example.com" },
    inject: { header: { name: "Authorization", format: "Bearer {}" } },
  }],
});
const bytes = new TextEncoder().encode(secret);
process.stdout.write(sealer.seal(publicKey, "k3", "acme", "c_123", "api_key", bytes, policy));
CHECK
envelope="$(VERSION="$version" node "$project/check.mjs" "$public_key" "$secret")"
printf '%s' "$envelope" \
  | cargo run --quiet --locked --package seal-format --example open_wasm_envelope -- "$secret"

cp "$work/seal-wasm.tar.gz" "$out"
echo "packed $out"
tar -tzf "$out"
