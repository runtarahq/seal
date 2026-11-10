# Changelog

All notable changes to seal are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Security fixes are also announced as
GitHub Security Advisories.

## [0.1.0]

The first release.

### Sealed values

- A secret is sealed to a keyset's public key with HPKE (RFC 9180: X25519, HKDF-SHA256,
  AES-256-GCM). The associated data binds it to its keyset, key, item and field, and the
  policy travels inside the ciphertext. See [`docs/format.md`](docs/format.md).
- Sealing needs only the public key: `seal-format` without its `open` feature, and a
  WASM build for sealing in a browser.
- Published test vectors in [`vectors/`](vectors).

### Using credentials over HTTP

- Policies name the destinations, methods and paths a value may be used for. The matcher
  treats every policy as untrusted, and checks every address it connects to. See
  [`docs/policy.md`](docs/policy.md).
- Injection into a header, basic auth, the query, the path, a form field or a JSON
  field; companion values; shared values, such as a platform-wide OAuth app's client secret.
- Response sealing: declared fields in JSON, form and XML responses come back sealed.
  A policy may name claims of a sealed JWT to return in plaintext, such as its expiry.
- OAuth: authorization code with PKCE, refresh, client credentials, resource owner
  password, the JWT bearer grant, and revocation. Callbacks land on the application.
  See [`docs/oauth.md`](docs/oauth.md).
- Signing: AWS Signature Version 4, Azure Storage Shared Key, JWT assertions (RS256,
  PS256, ES256), and client certificates toward providers. See
  [`docs/signing.md`](docs/signing.md).
- Presigned S3 URLs and Blob shared access signatures, for a rule that sets
  `allow_presign`: off by default, within the lifetime the rule gives, and audited. This
  is the one credential seal hands back to a caller.

### Checking webhooks

- `verify`: a signing secret sealed with a `verify` policy checks a message's HMAC
  (SHA-1, SHA-256 or SHA-512) and can be sent nowhere. seal answers yes or no and never
  returns a code. See [`docs/policy.md`](docs/policy.md#verification).

### Postgres

- Sessions through seal: seal logs in with a sealed password, using SCRAM-SHA-256-PLUS
  with channel binding over TLS, then relays the session, including `COPY` and
  replication. MD5 and cleartext only where the policy allows them. Tested against
  Postgres 14 to 18. See [`docs/postgres.md`](docs/postgres.md).

### The service and the client

- Three modes behind one client interface: in-process, a Unix socket on the same host,
  and mutual TLS from another machine. See [`docs/operations.md`](docs/operations.md).
- `seal-client` for applications, with `connect_pg` and `cancel_pg` behind its
  `postgres` feature.
- Key management: keysets, rotation, wrapped keys, key sources, and administrative
  calls for callers marked `admin`.
- `seal reseal` moves stored values to a keyset's current key, and with
  `--rewrite-policies` gives them new policies, so that a change of destination does not
  mean entering every secret again. Only whoever runs seal can do this.
- Audit records for every use, Prometheus metrics, and process hardening (no core dumps,
  not dumpable, memory locked as configured, never as root).
- A systemd unit, a container image and example configurations in [`deploy/`](deploy).
  The binary is static, linked against musl, and the image holds nothing else.

### Hardening

- Fuzz targets for every parser and rewriter, run on every push, nightly, and in a
  24-hour-per-target campaign. See [`docs/reviews/fuzzing.md`](docs/reviews/fuzzing.md).
- A scan after every test for any sealed secret in logs, audit records, metrics, errors
  and response heads.
- Buffers holding secrets are sized up front and wiped. See
  [`docs/reviews/secret-handling.md`](docs/reviews/secret-handling.md).
- `cargo deny` and `cargo audit` on every push. See
  [`docs/dependencies.md`](docs/dependencies.md).
- The [threat model](docs/threat-model.md) states what seal does and does not protect
  against.

[0.1.0]: https://github.com/runtarahq/seal/releases/tag/v0.1.0
