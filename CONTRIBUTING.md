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

# Python, with `pip install cryptography`
python3 vectors/verify.py

# Linux only: 5 GB transfers under a memory limit, and the ceiling's cost constants
cargo test --release --package seal-broker --test memory --locked -- --ignored --test-threads=1
cargo test --release --package seal --test memory --locked -- --ignored --test-threads=1

# A nightly toolchain and cargo-fuzz
mkdir -p fuzz/corpus/policy_parse
cargo +nightly fuzz run policy_parse fuzz/corpus/policy_parse fuzz/seeds/policy_parse -- -max_total_time=60
```

Contributions are licensed under [Apache-2.0](LICENSE).
