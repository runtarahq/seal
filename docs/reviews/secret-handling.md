# Review: where secrets are read

The hardening pass's review of every place seal reads a secret (`expose(`) or marks a
header sensitive (`set_sensitive`). For each: what the secret becomes, whether every
copy seal makes is wiped, and what a dependency keeps that seal cannot wipe. Tests are
left out.

## Rules checked

1. A secret is read only inside `expose`, and what it becomes is wiped
   (`Zeroizing`) or handed to a type that wipes itself.
2. A buffer that holds a secret never grows. `Zeroizing` wipes a buffer's last
   allocation, not the ones it outgrew, so such buffers are sized up front.
3. A header carrying a secret is marked sensitive, so HTTP/2 never indexes it.
4. No `Debug` output includes a secret.

## Findings, fixed in this pass

| Finding | Fix |
|---|---|
| Basic auth credentials, a query with a secret, and form and JSON bodies with injected fields were built in buffers that grew | Sized up front (`form_room`, `json_room`, `reserve_exact`); a test checks worst-case inputs never make them grow |
| A Postgres password message was framed through two intermediate vectors | Built in one buffer of the right size |
| A sealed XML field's text grew as it was read | Sized to the rest of the body first |
| SigV4's canonical headers, which hold a session token, were built in plain strings | Built and kept in wiped strings |
| Azure's signature and `Authorization` value were plain strings | Wiped |
| `ClientCertMaterial`'s private key was not wiped when dropped, since `rustls-pki-types` wipes only on request | Wiped on drop |

## Every site

| Site | Secret | What it becomes | Verdict |
|---|---|---|---|
| `seal-format/src/secret.rs`, `Secret::expose` | Any opened secret | Read in a closure; `Secret` wipes on drop | The one way in |
| `seal-format/src/seal.rs:346, 350` | A keyset's private key | `hpke`'s X25519 key | `hpke` wipes it on drop |
| `seal-keys/src/wrap.rs:162` | A private key, being wrapped | A wiped buffer encrypted in place | Sound |
| `seal/src/cli.rs:175` (`reseal`) | An opened secret | Sealed again at once, with its policy or the one the operator gave | Sound |
| `seal-broker/src/inject.rs:157` (`Sources::part`) | A credential's other parts, a Postgres password or key | A wiped copy | Sound |
| `inject.rs:217` (`header`) | The secret, in its template | A wiped buffer of exact size, then a sensitive header | Sound; the `HeaderValue` is a dependency's copy |
| `inject.rs:230, 235` (`basic`) | The password | Wiped buffers of exact size, base64, a sensitive header | Fixed: sized up front |
| `inject.rs:244, 251` (`query`) | The secret | The query, then the path and query, reserved first | Fixed: reserved; the `Uri` is a dependency's copy |
| `inject.rs:255` (`path`) | The secret | Percent-encoded into a wiped buffer of the largest size it can need, then a path of exact size; the encoded form is kept until the response head, to drop a header that repeats it | Sound; the `Uri` is a dependency's copy |
| `inject.rs:289, 294` (`form_field`, `json_field`) | The secret | Wiped copies, then a body sized up front | Fixed: bodies sized up front |
| `inject.rs:327` (`jwt_assertion`) | A signing key | Parsed by `ring`; the JWT in a wiped string | `ring`'s key pair is a dependency's copy |
| `inject.rs:353` (`aws_sigv4`) | A secret access key | A wiped signing key for one day, region and service | Sound |
| `inject.rs:373` (`azure_shared_key`) | An account key | Decoded into a wiped buffer | Sound |
| `inject.rs:387` (`client_cert`) | A private key | `ClientCertMaterial`, then a TLS configuration | Fixed: wiped on drop; the TLS configuration's copy lasts with the identity |
| `inject.rs:473` (`insert_sensitive`) | Header values | Marked sensitive | Sound |
| `broker.rs:524` (`verify`) | A signing secret | `ring`'s HMAC key, for one comparison; the code is never returned | `ring`'s HMAC key is a dependency's copy |
| `inject/sigv4.rs:409` (`set`) | `Authorization`, `X-Amz-Security-Token` | Marked sensitive; the date and hash are not secrets | Sound |
| `inject/azure.rs:276` | `Authorization` | Marked sensitive | Sound |

Postgres sessions read their password and key through `Sources::part`, above, and hold
them until the login ends. `postgres-protocol`'s SCRAM keeps its own copies.

## Debug output

`Secret`, `PrivateKey`, `BodyInjection`, `sigv4::Signer`, `azure::Signer`,
`ClientCertMaterial`, `ClientIdentity` and `PgSession` print no secrets: names, scopes
and fields only. The suite-wide canary scan checks logs, audit records,
metrics, errors and response heads for every sealed secret on every run.

## What dependencies keep

Recorded in the [threat model](../threat-model.md#copies-seal-cannot-erase):

- `http`'s `HeaderValue` and `Uri`;
- `hyper`'s write buffers;
- `ring`'s key pairs and HMAC keys;
- `rustls`'s client-certificate keys in a TLS configuration;
- `serde_json`'s parse of a response being sealed, or of a JWT's payload whose claims are
  exposed;
- `postgres-protocol`'s SCRAM state.

None can be wiped from outside. Reading any of them needs access to seal's memory,
which the threat model puts out of scope.
