# Contributing to seal

A reviewer rejects a change that breaks one of these rules, whatever else it
does well.

To report a vulnerability, follow [`SECURITY.md`](SECURITY.md) instead of
opening an issue.

## Secrets in code

- Plaintext secrets live only in `seal_format::Secret`, and private keys only in
  `PrivateKey`. Both zeroize on drop, redact `Debug`, and implement no `Display`,
  `Serialize`, `Clone` or `PartialEq`. Reading one takes an explicit `expose(…)`
  call, so every use is greppable.
- Plaintext lasts only as long as one `send` or one login. Do not cache opened
  values. The only long-lived secrets are unwrapped private keys in the keyring,
  and a client certificate's private key, held by its pool's TLS configuration
  while the pool exists.
- Where a dependency copies a secret, mark the value sensitive and record the copy
  in the threat model. Do not imply that zeroization covers it.

## Errors, logs and metrics

- Errors carry identifiers and static text only: never a value, a query string, a
  header value, a body fragment or an upstream error body.
- Logs use an allowlist of field names. Do not format request, response or
  envelope types with `?value` or `%value`.
- Every new code path that can fail gets a canary test.

## Deny by default

- Refuse as early as the information allows: everything decidable locally is decided
  before any DNS lookup or provider connection. What each kind of refusal may already
  have caused, which tests hold to:

  | Refusal | Key source or KMS | DNS | Provider |
  |---|---|---|---|
  | Caller, rate limit, malformed head or envelope | None | None | None |
  | Opening, policy match, conflicts, caller-set headers or fields, over-cap buffered request body, Postgres startup checks | Only if the keyset is not loaded | None | None |
  | Address check | As above | Yes, unless the host is an IP literal | None |
  | Streamed request over its size limit, over-cap or unparseable response, wrong content type, Postgres login failure, timeouts | As above | Yes | **Contacted; may hold the credential** |

- Options that weaken a guarantee are named for it and default to off.
- Parse policies and configuration with `deny_unknown_fields`. Refuse anything
  unrecognised.

## Code style

- `#![forbid(unsafe_code)]` in every crate, with no exceptions. Hardening system
  calls use only `nix`'s safe functions.
- No `unwrap`, `expect` or `panic!` on the serving path. Clippy denies them outside
  tests.
- Time comes from an injected `Clock`, and network access goes through the `Resolve`
  and `Connect` traits, so tests can prove what happened.
- Document public APIs, and give every policy option an example in `docs/policy.md`.

## Review

- These areas are **security-sensitive**: `seal-format`, the policy matcher, the
  address checker, injection, signing, response sealing and the Postgres login.
  Changes to them need a second reviewer and a test that fails without the change.
- A new dependency needs a line in the pull request saying why it is needed, its
  license (which must pass `cargo deny`) and its maintenance status.

## Before opening a pull request

The toolchain is pinned in `rust-toolchain.toml`. These are the checks CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo check --package seal-format --features wasm --target wasm32-unknown-unknown --locked
```

`cargo deny` is a separate install: `cargo install --locked cargo-deny`.

CI also runs these, which need more tools:

```sh
# wasm-bindgen-cli, at the wasm-bindgen version in Cargo.lock, and Node
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --package seal-format --features wasm --target wasm32-unknown-unknown --test wasm --locked
scripts/wasm-roundtrip.sh

# The musl target and a musl C compiler (musl-tools): the released binary is static
cargo test --workspace --locked --target x86_64-unknown-linux-musl

# Docker: the container image, started by the service tests in place of their binary
docker build -f deploy/container/Dockerfile -t seal .
SEAL_TEST_BIN="$PWD/scripts/seal-in-container.sh" \
  cargo test --package seal --test modes --test oauth --test service --locked

# Python, with `pip install cryptography`
python3 vectors/verify.py

# Linux only: 5 GB transfers under a memory limit, and the ceiling's cost constants
cargo test --release --package seal-broker --test memory --locked -- --ignored --test-threads=1
cargo test --release --package seal --test memory --locked -- --ignored --test-threads=1

# Docker: providers in containers, and seal with its keys in a bucket
cargo test --package seal --test containers --locked -- --ignored
cargo test --package seal --test postgres --locked -- --ignored
cargo test --package seal-keys --lib --locked s3::tests -- --ignored

# A nightly toolchain and cargo-fuzz
mkdir -p fuzz/corpus/policy_parse
cargo +nightly fuzz run policy_parse fuzz/corpus/policy_parse fuzz/seeds/policy_parse -- -max_total_time=60
```

Two tests run against real services, with credentials from the environment, and skip
without them. Run them before relying on a store or a KMS that seal has not been run
against, and after changing how seal talks to either:

```sh
# A bucket that exists, in an S3-compatible object store such as OVHcloud Object
# Storage. Everything is written under a prefix made for the run, and destroyed.
export SEAL_TEST_S3_ENDPOINT=https://s3.gra.io.cloud.ovh.net
export SEAL_TEST_S3_REGION=gra
export SEAL_TEST_S3_BUCKET=…
export SEAL_TEST_S3_CREDENTIALS_FILE=…   # readable only by you; optionally SEAL_TEST_S3_PROFILE

# A service key in OVHcloud KMS. With it, the bucket test also moves the keys from a
# wrapping key file to that service key.
export SEAL_TEST_OVH_KMS_ENDPOINT=https://eu-central-waw.okms.ovh.net
export SEAL_TEST_OVH_KMS_OKMS_ID=…
export SEAL_TEST_OVH_KMS_KEY_ID=…
export SEAL_TEST_OVH_KMS_TOKEN_FILE=…    # or SEAL_TEST_OVH_KMS_CERT and SEAL_TEST_OVH_KMS_KEY

cargo test --package seal-keys --lib --locked s3::tests::a_real_bucket -- --ignored --nocapture
cargo test --package seal-keys --test real_kms --locked -- --ignored --nocapture ovh
```

The bucket test checks what seal depends on a store for: a key is stored only where
there is none, also when several store it at once; a key is replaced only if it is still
the one that was read; the wrapping key is replaced in place; and a destroyed keyset
leaves no version behind. The nightly workflow runs both, with the repository's secrets.

Contributions are licensed under [Apache-2.0](LICENSE).
