# seal: dependencies

Every direct dependency, what it is for, and where it is used. The goal is a small tree
where each crate that touches a secret or a security decision is one we chose
deliberately. `cargo deny` and `cargo audit` check the whole tree on every push and
nightly; `deny.toml` sets the allowed licenses and sources.

The shipped binary's tree has about 256 crates (`cargo tree -e normal`). Development
dependencies are listed separately.

## Cryptography and secrets

| Crate | For | Used in | Notes |
|---|---|---|---|
| `hpke` (`=0.15.1`) | Sealing and opening (RFC 9180: X25519, HKDF-SHA256, AES-256-GCM) | `seal-format` | Pinned exactly: the format depends on its output. RustCrypto, audited. Wipes its X25519 keys |
| `ring` | Key wrapping (AES-256-GCM), HMAC and SHA-256 for SigV4 (toward providers) and Azure, JWT signatures, TLS's crypto provider | `seal-keys`, `seal-broker`, `seal` | One crypto library for everything but HPKE. Its keys are not wiped from outside |
| `rustls`, `tokio-rustls` | TLS toward providers, Postgres, key sources and a KMS, and mTLS from callers | `seal-keys`, `seal-broker`, `seal-client`, `seal` | `ring` provider only; no `aws-lc-rs`, so no C build |
| `webpki-roots` | The public roots providers and a KMS are verified against | `seal-broker`, `seal-keys` | Mozilla's set, compiled in; operators add more |
| `postgres-protocol` | SCRAM-SHA-256(-PLUS) and the MD5 hash for Postgres logins | `seal-broker` | From the `rust-postgres` project; its SCRAM state is not wiped (threat model) |
| `zeroize` | Wiping buffers that hold secrets | all but `seal-proto` | |
| `getrandom` | Randomness for sealing, in the WASM build too | `seal-format` | |
| `x509-parser` | Reading a caller certificate's subject, to name the caller | `seal` | Parses only certificates that rustls has already verified |

### Only with the `aws-kms` feature

Off by default in a build, and then none of these is linked. The published container
image is built with it. With it the binary's tree has about 50 more crates.

| Crate | For | Notes |
|---|---|---|
| `aws-sdk-kms` | `Encrypt` and `Decrypt` with the wrapping key in AWS KMS | Sees each private key it wraps or unwraps, in buffers it does not wipe |
| `aws-config` | Finding seal's AWS credentials: the environment, the shared files, a web identity token, the container endpoint, instance metadata. Brings `aws-sdk-sts` | Without its `sso` feature. Its logging is off by default, since it logs whole responses |
| `aws-credential-types` | Handing the SDK the credentials seal reads from its own file | |
| `aws-smithy-http-client` | The SDK's HTTP client, on the `hyper` and `rustls` seal already has | `ring` only, so still no `aws-lc-rs` and no C build |
| `webpki-root-certs` | The public roots as certificates, the form that client takes | The same Mozilla set as `webpki-roots`. The host's certificate store is not used |

## Formats and parsing

| Crate | For | Used in |
|---|---|---|
| `serde`, `serde_json` | Envelopes, policies, configuration and JSON bodies; `raw_value` in the broker keeps what seal does not change in a body as it was written. Not `arbitrary_precision`, which Cargo would turn on for every crate an application that embeds seal builds | all |
| `base64` | Envelope fields, keys, basic auth, Shared Key | `seal-format`, `seal-keys`, `seal-broker` |
| `url` | Parsing URLs, which seal refuses if parsing would rewrite them | `seal-format`, `seal-keys`, `seal-broker` |
| `percent-encoding`, `form_urlencoded` | Query, form and SigV4 encoding | `seal-keys`, `seal-broker` |
| `quick-xml` | Sealing XML response fields (STS) | `seal-broker` |
| `toml` | Configuration | `seal` |

## Networking and the runtime

| Crate | For | Used in |
|---|---|---|
| `tokio` | The runtime | all but `seal-format` and `seal-proto` |
| `hyper`, `hyper-util`, `http`, `http-body`, `http-body-util`, `bytes` | HTTP toward providers, the HTTP key source and a KMS, and the metrics endpoint | `seal-keys`, `seal-broker`, `seal-client`, `seal` |
| `hickory-resolver` | DNS, so seal sees every address it will connect to and checks each one | `seal-broker` |
| `tonic`, `tonic-prost`, `prost`, `tower` | The gRPC service and client | `seal-proto`, `seal-client`, `seal` |
| `futures-util` | Streams of request and response bodies | `seal-client`, `seal` |
| `async-trait` | Async methods on traits used as objects (`Keys`, `Resolve`, `Connect`, `SealClient`) | `seal-keys`, `seal-broker`, `seal-client` |

## The binary

| Crate | For |
|---|---|
| `clap` | The command line |
| `nix` | Peer credentials on Unix sockets, and hardening: `PR_SET_DUMPABLE`, `RLIMIT_CORE`, `mlockall`, refusing root |
| `tracing`, `tracing-subscriber` | Logs, which never include a secret (checked by the canary scan). `seal-keys` uses `tracing` too, to say why a KMS refused |
| `metrics`, `metrics-exporter-prometheus` | The metrics endpoint |

## Optional

| Crate | Behind | For |
|---|---|---|
| `wasm-bindgen` | `seal-format`'s `wasm` feature | Sealing in a browser |
| `tokio-postgres` | `seal-client`'s `postgres` feature | `cancel_pg`, which takes a `tokio-postgres` cancel token |

## Build and development only

| Crate | For |
|---|---|
| `protox`, `tonic-prost-build` | Compiling the protocol without `protoc` |
| `proptest` | Property tests |
| `rcgen` | Test certificates |
| `tempfile` | Test directories |
| `trybuild` | Compile-fail tests: opening code is absent from the sealing build |
| `aws-sigv4`, `aws-credential-types` | Cross-checking seal's SigV4 against the AWS SDK's |
| `tokio-postgres` | The client in Postgres tests |
| `futures-core` | Test bodies |
| `libfuzzer-sys` | Fuzz targets, in their own workspace |

## Left out on purpose

- **`jsonwebtoken`:** it needs `aws-lc-rs`, a C build, or RustCrypto's `rsa`, which has
  an unfixed timing advisory (RUSTSEC-2023-0071). `ring` signs all three algorithms.
- **`aws-sigv4` at run time, and an Azure SDK:** seal signs itself, so it controls
  exactly what is signed and refused.
- **The AWS and OVHcloud SDKs:** a KMS wrapper is two JSON requests, sent with the HTTP
  and TLS stacks seal already has.
- **`testcontainers`:** a helper runs the `docker` command instead.
- **`aes-gcm`:** `ring` already provides it.
- **OpenSSL:** none anywhere in the tree.
