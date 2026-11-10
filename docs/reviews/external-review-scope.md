# External security review: scope

A brief for a reviewer of seal before its first release. seal is a broker for
credentials: an application uses a credential through seal but cannot read it. Start with
the [README](../../README.md), [`integrating.md`](../integrating.md) and the
[threat model](../threat-model.md).

## In scope, by priority

1. **The sealed-value format** (`crates/seal-format/src/seal.rs`, `envelope.rs`,
   [`format.md`](../format.md)). HPKE base mode, with associated data binding a value to
   its keyset, key, item and field, and the policy inside the ciphertext. Questions: can
   a value be moved, altered, or made to open under another binding? Is the associated
   data encoding unambiguous? `vectors/` has the published test vectors.
2. **The matcher** (`crates/seal-broker/src/matcher.rs`, [`policy.md`](../policy.md)). A
   pure function that decides whether a request may use the values it presents, treating
   every policy as untrusted, since anyone with the public key can seal a value with any
   policy. Questions: can one value's rule weaken how another is used? Can a request
   reach a destination, method, path or Postgres database no presented value allows?
   Can shared values serve where they should not, or a copy source escape its prefix?
3. **Injection and signing** (`crates/seal-broker/src/inject.rs`, `inject/sigv4.rs`,
   `inject/azure.rs`, `inject/jwt.rs`, [`signing.md`](../signing.md)). Questions: can a
   caller set or influence what seal signs, choose a payload mode the rule forbids, or
   make a secret land somewhere other than where the rule says? Are secrets wiped, as
   [the review of secret handling](secret-handling.md) claims?
4. **The Postgres login** (`crates/seal-broker/src/pg/`, [`postgres.md`](../postgres.md)).
   Questions: is TLS established and verified before anything is sent? Is channel
   binding computed and used correctly, and is a downgrade from SCRAM-PLUS detectable? Can
   a malicious server learn the password where the rule does not allow MD5 or cleartext?
   Can a caller reach a database or role the policy does not allow?
5. **Response sealing** (`crates/seal-broker/src/response_seal.rs`). Questions: can a
   provider's response, crafted or not, pass a declared field to the caller unsealed?

## Also worth a look

- The address checks before connecting (`crates/seal-broker/src/address.rs`), and URL
  parsing that refuses rather than normalises (`target.rs`).
- Caller authentication in the service (`crates/seal/src/listen.rs`, `callers.rs`).
- Key wrapping and the keyring (`crates/seal-keys`).

## Out of scope

- Root on seal's host, and library mode, where the application holds the keys (threat
  model, "Accepted by design").
- The application's own handling of sealed values and OAuth callbacks.
- Denial of service, beyond the documented limits.

## What exists to help

- [`acceptance.md`](../acceptance.md) maps every acceptance criterion to its tests.
- Fuzz targets under `fuzz/`, run in CI and nightly, and a 24-hour-per-target campaign
  (`scripts/fuzz-campaign.sh`).
- Container tests against RustFS, Azurite and Postgres 14–18, in all three modes.
- A canary scan after every test for any sealed secret in logs, audit records, metrics,
  errors and response heads.
- [`dependencies.md`](../dependencies.md): every direct dependency and why.
