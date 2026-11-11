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
- A value may go with one injected into the path where its own rule allows that prefix
  with `allow_injected_path`, as Telegram's `setWebhook` needs for the bot token and the
  webhook's secret.
- Injection into a header, basic auth, the query, the path, a form field or a JSON
  field; companion values; shared values, such as a platform-wide OAuth app's client secret.
- A response that repeats a credential seal sent, in a header or in its body, does not
  reach the caller with it.
- Response sealing: declared fields in JSON, form and XML responses come back sealed.
  A policy may name claims of a sealed JWT to return in plaintext, such as its expiry.
- A JSON body or response keeps everything seal does not change as it was written, digit
  for digit. seal does not turn on `serde_json`'s `arbitrary_precision` to do so, which
  would change how an application that embeds seal reads and writes every number.
- OAuth: authorization code with PKCE, refresh, client credentials, resource owner
  password, the JWT bearer grant, and revocation. Callbacks land on the application.
  See [`docs/oauth.md`](docs/oauth.md).
- Signing: AWS Signature Version 4, Azure Storage Shared Key, JWT assertions (RS256,
  PS256, ES256), and client certificates toward providers. See
  [`docs/signing.md`](docs/signing.md).
- A SigV4 request may name its operation in `X-Amz-Target`, as SQS, DynamoDB and other
  services that take JSON need. A rule for a whole S3 endpoint addressed by path may set
  `allow_copy_from_any_bucket`, so that a copy can read any object on its host.
- Presigned S3 URLs and Blob shared access signatures, for a rule that sets
  `allow_presign`: off by default, within the lifetime the rule gives, and audited. This
  is the one credential seal hands back to a caller.

### Checking webhooks

- `verify`: a signing secret sealed with a `verify` policy checks a message's HMAC
  (SHA-1, SHA-256 or SHA-512) and can be sent nowhere. seal answers yes or no and never
  returns a code. See [`docs/policy.md`](docs/policy.md#verification).
- `"verify": "equals"`, for a provider that sends back a token with each webhook instead
  of signing it, such as Telegram's `secret_token`: seal says whether a presented token
  is the sealed one.

### Postgres

- Sessions through seal: seal logs in with a sealed password, using SCRAM-SHA-256-PLUS
  with channel binding over TLS, then relays the session, including `COPY` and
  replication. MD5 and cleartext only where the policy allows them, and a policy may
  require channel binding. A server that never asks for the password is not logged in
  to. Tested against Postgres 14 to 18. See [`docs/postgres.md`](docs/postgres.md).

### The service and the client

- Three modes behind one client interface: in-process, a Unix socket on the same host,
  and mutual TLS from another machine, where a caller is a certificate's subject or one
  of its subject alternative names. See [`docs/operations.md`](docs/operations.md).
- `seal-client` for applications, with `connect_pg` and `cancel_pg` behind its
  `postgres` feature.
- Key management: keysets, rotation, wrapped keys, key sources, and administrative
  calls for callers marked `admin`.
- Destroying a keyset when a tenant leaves: `seal destroy-keyset`, or the `DestroyKeyset`
  call for a caller marked `destroy_keysets` that may use the keyset. `admin` does not
  allow it. See [`docs/operations.md`](docs/operations.md#destroying-a-keyset).
- `seal reseal` moves stored values to a keyset's current key, and with
  `--rewrite-policies` gives them new policies, so that a change of destination does not
  mean entering every secret again. Only whoever runs seal can do this.
- `seal rewrap` rotates the wrapping key, by wrapping every key again into a new
  directory.
- Audit records for every use and for every caller refused, Prometheus metrics, and process hardening (no core dumps,
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
- A [security audit](docs/security-audit.md) of the source, with what became of each
  finding.

[0.1.0]: https://github.com/runtarahq/seal/releases/tag/v0.1.0
