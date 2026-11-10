# Security audit

An audit of seal at commit `087de1c` ("Let a shared access signature carry response
headers"), 10 November 2026. It is a source review of the whole workspace, with the
findings that could be reproduced executed to confirm them. It is not an external
review, for which [`reviews/external-review-scope.md`](reviews/external-review-scope.md)
is the brief, and it says nothing about the code's correctness outside the security
properties it lists.

## Summary

The core design holds. No way was found for a compromised application to read a
secret, to reach a destination no policy allows, to set or shadow a header the broker
injects, to smuggle a second request through a header or the request line, or to hide
the destination of a request. The matcher, the address checks, the injection and
signing code and the response sealing were all traced end to end and behave as
`docs/threat-model.md` describes.

The defects are in what surrounds that core: how a caller is identified, the state a
Postgres login may end in, what happens to an injected credential on its way back, and
what the audit log records.

| # | Severity | Finding |
|---|---|---|
| 1 | High | A certificate from the trusted CA can impersonate any configured mTLS caller |
| 2 | High | A Postgres login may succeed without any authentication taking place |
| 3 | Medium | The provider's response is returned with the injected credential still in it |
| 4 | Medium | Refusals at the service layer leave no audit record |
| 5 | Medium | Cloud metadata addresses are reachable when private destinations are allowed |
| 6 | Medium | `sigv4::framed_length` overflows `u64` on a caller's `Content-Length` |

Severity here is the damage to the guarantee the threat model claims, not the effort
to reach it. Finding 1 needs a certificate from the CA seal already trusts; finding 2
needs a server that already satisfies TLS verification. Both fail silently.

## Resolution

What has changed since, by commit. The findings below are left as they were written,
against `087de1c`; every one of them has since been fixed.

| Finding | What was done | Commit |
|---|---|---|
| 1. mTLS subject | The subject is compared attribute by attribute, and one with a comma in a value or a multi-valued name is refused | `6d52265` |
| 1. Identity bound to the subject only | A caller can be configured by `cert_san`, a URI or DNS name among the certificate's subject alternative names | `b12a2b7` |
| 2. Postgres login without authentication | With a password to present, the server must ask for it | `dbe121c` |
| 3. Reflected credential | Response headers that repeat an injected secret of eight bytes or more are dropped, and a response whose body repeats one fails, with none of it passed on | `8b216cd`, `c1f576c` |
| 4. Unaudited refusals | A refused keyset, shared value or administrative call is audited. Rate-limit refusals are not, on purpose: they bound the others | `1d255f0` |
| 5. Metadata addresses | `100.100.100.200`, `fd00:ec2::254` and `fd20:ce::254` are metadata addresses, which no rule can allow | `c23a2d7` |
| 6. `framed_length` overflow | Checked arithmetic, and the request is refused | `6a7b539` |
| Presigned URL copied unwiped | The broker and `seal-client` return it in a string that wipes itself, and the message that carries it between them wipes it when dropped | `d25806d`, `c8bd9ea` |
| `;` in form bodies | Refused in requests seal reads and in responses it seals | `09470d5` |
| Control characters in a literal | Refused. A certificate literal is PEM and keeps its line ends, which is why whitespace was allowed | `259f064` |
| `path_prefix` and an injected path prefix | By design: the injected prefix goes in front of the path the rule constrains. The policy guide now says what that bounds | `1af19a9` |
| XML locations matched by qualified name | Matched by local name, so a prefix cannot take a token out of reach | `0e49c2c` |
| SigV4 whitespace | A tab in a signed header is refused, and folding matches the SDKs | `c5e9fad` |
| Azure `collapse`, and a caller's `x-ms-version` | Trimming is ASCII, as folding was. The version must be one date | `5a4a834` |
| Unix socket's directory | A directory its group or others can write is refused | `c1842ff` |
| Two callers with one identity | Refused | `46c40d1` |
| Postgres login deadline | The login has the connection's deadline | `398473d` |
| Wrapping key cannot be rotated | `seal rewrap` wraps every key again under a new wrapping key. The documents no longer say that revoking the file takes effect within `max_unwrap_age` | `835681a`, `2d6ae4e` |
| Channel binding cannot be required | `require_channel_binding` on a `pg_password` rule | `2583e0c` |
| Key source URL with a password | Refused | `e58807e` |
| Wrapped key file read whole | Read to a bound | `c7dc0b6` |
| `public_keys` unverified | The list comes from the loaded keyset, where each key was unwrapped and compared | `2bbfcaa` |
| Caller's `Content-Length` forwarded | A body that is longer or shorter than it declares fails the request. Testing this found that a longer one was cut short without an error | `8d74426` |
| Audit file permissions | A file its group can write or others can reach is refused | `b22ce28` |
| Metrics listener and `/readyz` | The key source is asked at most once in five seconds. `metrics.token_file` names a bearer token every request must present, and seal does not start with the listener on anything but a loopback address without one | `17fd940`, `5374307` |
| Claims of an unsigned token | A token with `alg` `none`, no `alg` or no signature exposes nothing | `c2b996d` |

The row about `NegotiateProtocolVersion` in the first draft of this audit was wrong
and has been removed: the protocol asks for no reply to it.

## Findings

### 1. A certificate from the trusted CA can impersonate any configured mTLS caller

**High.** `seal/src/callers.rs:81`, `seal/src/listen.rs:268`.

A caller's identity over mutual TLS is the subject of its certificate, flattened into
a string and normalised:

```rust
pub fn normalise_subject(subject: &str) -> String {
    subject
        .split(',')
        .map(|part| { /* trim, upper-case the name */ })
        .collect::<Vec<_>>()
        .join(",")
}
```

`listen.rs:271` feeds it `parsed.subject().to_string()`, the subject as written. The
comparison is therefore over a string in which an attribute boundary and a comma
inside an attribute value are the same character.

A certificate issued by the trusted client CA whose only attribute is
`CN="app,O=Example"` renders as `CN=app,O=Example`, normalises to exactly the
configured caller `CN=app,O=Example`, and inherits that caller's keysets and its
`admin` flag. `webpki` checks the chain, the key usage and the validity, not the
contents of the common name, so the only thing standing in the way is the client CA
permitting a comma in a CN.

Confirmed with the repository's own `TestPki` and `x509-parser`:

```
honest rendered : "CN=app"
spoof  rendered : "CN=app,O=Example"      <- one CN, whose value contains a comma
config  CN=app,O=Example -> "CN=app,O=Example"
spoof  normalised : "CN=app,O=Example"
```

Two further consequences of the same comparison. The configured subject is not
enforced as a set of attributes: it is a flat string, so a certificate with
`CN=app` alone does not match a caller configured as `CN=app,O=Example`, and one with
`CN=app,O=Example` does. And a multi-valued RDN renders as `CN=app + O=Example`, so
it never matches anything.

The subject is also the only thing checked: `subject_of` reads `parsed.subject()` and
never the subject alternative name, so a certificate minted by a general internal CA
for an unrelated service authenticates to seal if its common name happens to match.

**Fix.** Compare the parsed distinguished name structurally, as the set of attribute
identifiers and values, rather than as a re-serialised string. Refuse a subject whose
value contains a separator. Bind the caller's identity to the subject alternative
name, which is what a certificate is issued for.

### 2. A Postgres login may succeed without any authentication taking place

**High.** `seal-broker/src/pg/login.rs:129`.

The `AuthenticationOk` message ends the login, and the method used is whatever was
asked for, or `trust` if the server asked for nothing:

```rust
0 => {
    let method = method.unwrap_or(if credentials.client_cert {
        PgAuth::Cert
    } else {
        PgAuth::Trust
    });
    return Ok((method, before_ok));
}
```

`method` stays `None` until the server asks for something. A server that sends
`AuthenticationOk` as its first message completes the login, and `session.rs:209`
accepts the result without checking it. A server that starts a SCRAM exchange cannot
do the same part way through: `scram()` expects the continue and final messages in
order and refuses anything else.

The policy presented a password, the server never asked for it, and the application is
told it is logged in as the policy's user. The audit record says `pg_auth: "trust"`,
which is the only sign.

This contradicts a boundary the threat model states: a database server should not be
able to "pass as the real server", because "TLS verifies its name, and SCRAM its
knowledge of the password"
([`threat-model.md`](threat-model.md#actors)). The server-signature check only
protects against a server that takes part in the SCRAM exchange.

**Fix.** When the session presents a password, require that the server asked for an
allowed method and that the method completed. `trust` and `cert` should be reachable
only when the rule presents no password.

### 3. The provider's response is returned with the injected credential still in it

**Medium.** `seal-broker/src/broker.rs:936`.

```rust
if let Some(secret) = outgoing.path_secret.take() {
    remove_headers_repeating(&mut parts.headers, &secret);
}
```

seal knows which secret it injected and already has the machinery to take it back out
of a response header, but it applies it only to a secret injected into the **path**.
A secret injected into a **header** or a **query parameter** is not tracked, and every
response header is copied to the caller (`seal/src/service.rs:387`) along with the
response body, unsealed, unless the rule declares response sealing.

A provider that reflects the credential it was given — an echo or debug endpoint, or
one that echoes the request in an error body — therefore hands the plaintext
credential to the compromised application. That is the one path in the code that turns
"use, not copies" into "read", and the threat model lists it as an accepted residual
risk ([`threat-model.md`](threat-model.md#accepted-by-design)), but the fix is
already in the same file: keep every injected value, as `path_secret` already keeps
one, and apply `remove_headers_repeating` to all of them.

**Fix.** Track the injected header and query values as well as the path secret, and
scrub all of them from the response head.

### 4. Refusals at the service layer leave no audit record

**Medium.** `seal/src/service.rs:537`, and the same pattern at `:594`, `:651` and
`:701`.

Every request that reaches the broker is audited, including a refusal. Everything the
**service** refuses happens before that, and writes nothing:

```rust
if !caller.may_use(&keyset) {
    return Err(refusal(
        ErrorCode::CallerDenied,
        "the caller may not use this keyset",
    ));
}
```

The same holds for the shared-value check, the admin operations and the rate limits.
The listener's refusal of an unknown caller is a `tracing::warn!` to stderr
(`listen.rs:133`), which is a different stream from the audit sink.

So a compromised application can enumerate the keysets it is allowed, present values
from keysets it is not, try `GenerateKeyset`, `Rotate` and `PublicKeys`, and spend
the rate limit's budget, with nothing in the log an operator reads after a breach.
`seal/tests/service.rs:170` asserts that a refused caller leaves no `generate` or
`public_keys` record, so the behaviour is deliberate, but it weakens the threat
model's claim that a compromised caller cannot hide its use.

**Fix.** Audit the service-level refusals too, with the same identifiers and no
values.

### 5. Cloud metadata addresses are reachable when private destinations are allowed

**Medium, conditional.** `seal-broker/src/address.rs:49`.

```rust
pub fn rule_may_allow(self) -> bool {
    matches!(
        self,
        Self::Loopback | Self::Private | Self::SharedAddressSpace | Self::UniqueLocal
    )
}
```

The comment above it says this covers internal services, "not link-local or metadata
addresses, which have never been a sensible destination for a credential". Only two
metadata addresses are excluded: `169.254.169.254` is `LinkLocal` and `168.63.129.16`
is `Metadata`. The classifier (`address.rs:96`) puts `100.64.0.0/10` in
`SharedAddressSpace` and `fc00::/7` in `UniqueLocal`, both of which a rule may allow.
That range contains Alibaba Cloud's metadata service at `100.100.100.200` and the AWS
IPv6 instance metadata endpoint at `fd00:ec2::254`.

So with `network.honour_private_rules` on and a rule that sets
`allow_private_destination`, a caller can reach the instance metadata service
through the broker and take the instance role's credentials. The default is off, so
this is a trap for an operator who turns it on rather than a hole in the default
configuration.

**Fix.** Classify the well-known metadata addresses as `Metadata` and refuse them
whatever a rule allows, or exclude `SharedAddressSpace` and `UniqueLocal` from
`rule_may_allow`.

### 6. `sigv4::framed_length` overflows `u64` on a caller's `Content-Length`

**Medium.** `seal-broker/src/inject/sigv4.rs:509`.

```rust
pub fn framed_length(decoded: u64) -> u64 {
    let size = CHUNK_SIZE as u64;
    let full = decoded / size;
    let rest = decoded % size;
    let frame = |length: u64| format!("{length:x}").len() as u64 + CHUNK_OVERHEAD + length;
    full * frame(size) + if rest > 0 { frame(rest) } else { 0 } + frame(0)
}
```

`decoded` is the caller's `Content-Length`, parsed as a `u64` with no bound
(`sigv4.rs:613`) and checked only for being digits (`inject.rs:493`). The product
overflows for any length from 18,421,446,067,330,466,091 upwards.

Confirmed by execution:

```
thread 'sigv4_framed_length_overflow' panicked:
attempt to multiply with overflow
```

In a build with overflow checks on — the default for development and test — the
panic is inside `Broker::send`, so the caller's connection is unwound and the broker
process survives. In a release build the multiplication wraps, and the request goes
out declaring a `Content-Length` that is wrong: about 25 petabytes for a caller's
length of `u64::MAX`.

**Fix.** Clamp the caller's `Content-Length` to a sane bound in `content_length`, and
compute the framing in checked arithmetic.

## Lower-severity findings

| Finding | Where | Note |
|---|---|---|
| A presigned URL is copied into a plain `String` and never wiped, though it is a credential that outlives the breach | `seal-broker/src/broker.rs:550` | `presigned_url` returns a `Zeroizing<String>`; `.as_str().to_owned()` makes a copy that is not wiped. Return the `Zeroizing<String>` to the transport |
| Form bodies are split on `&` only, so a `;`-separated field is invisible to seal | `seal-broker/src/response_seal.rs:298`, `seal-broker/src/inject.rs:673` | `form_urlencoded::parse` does not split on `;`. A declared response field written that way would not be sealed, and a caller could set a field the broker injects, for a provider that accepts `;` as a separator. Parsing on both, or refusing `;`, closes it |
| `Part::Literal` permits control characters that are also whitespace, so CR and LF are allowed in a policy literal | `seal-format/src/policy/validate.rs:493` | The condition is `is_control() && !is_whitespace()`, and CR, LF, TAB and FF are whitespace. The two places a literal reaches a header re-check it (`sigv4.rs:311` requires printable ASCII, `azure.rs:231` requires lower-case digits), so nothing is injected today, but the validation says "has control characters" and does not mean it |
| A rule's `path_prefix` constrains the caller's path, not the path after a prefix injection | `seal-broker/src/target.rs:130`, `seal-broker/src/inject.rs:253` | The injected prefix is never cross-checked against the destination's prefix, so a policy can send a credential outside the prefix its own rule declares. A policy the sealer wrote, so a footgun rather than an attack |
| XML response locations are matched by qualified name only | `seal-broker/src/response_seal.rs:143` | An element at the declared location in a namespace is not sealed, so a token passes through in plaintext. A policy cannot express a namespace either, only a prefix |
| seal's header-value normalisation differs from the AWS SDK's, and from S3's documented rule, for whitespace that is not a space | `seal-broker/src/inject/sigv4.rs:109` | seal's `trim_all` uses `split_whitespace`, which folds every kind of Unicode whitespace; the SDK's trims spaces only. The cross-check property test's alphabet (`inject/sigv4/tests.rs:513`) starts at `0x20`, so it never generates a tab. A request whose caller put a tab in a signed header gets a different signature, and is refused |
| Azure's `collapse` trims with `value.trim()`, which is Unicode, but folds only ASCII whitespace | `seal-broker/src/inject/azure.rs:63` | The same family of difference, the other way round |
| The Unix socket's parent directory is never checked, the socket is unlinked and re-bound at startup, and `set_permissions` follows symlinks | `seal/src/listen.rs:100` | In a directory another user can write, that user can unlink the socket and substitute their own, and every caller then talks to the impostor. The systemd unit's `RuntimeDirectory` covers this today, but the code does not |
| Two callers with the same identity silently overwrite each other | `seal/src/config.rs:502`, `seal/src/callers.rs:46` | Duplicate names are refused; duplicate `unix_uid` or `cert_subject` are not, and the last one wins. An application can be given `keysets = ["*"]` without any warning |
| The Postgres login has no deadline | `seal-broker/src/pg/session.rs:206` | `connect_timeout` covers the connection, the one-byte answer and the TLS handshake (`session.rs:351`), but not the login, which is a bare `read_exact`. A server that goes quiet after the handshake holds a stream slot and an upstream permit for as long as it likes |
| The wrapping key cannot be revoked or rotated | `seal-keys/src/wrap.rs:77`, `seal/src/serve.rs:66` | The file is read once at start-up and the key lives in `ring`'s key type for the life of the process, so replacing it has no effect until a restart. The threat model says "a revoked wrapping key takes effect within `max_unwrap_age`", which does not hold here. Worse, `wrap_id` is derived from the key bytes, so a restart with a new key fails every record's `wrap_id` check (`seal-keys/src/keyring.rs:493`) and no keyset can be read at all. No command re-wraps keys |
| Channel binding is chosen by the server and can never be required | `seal-broker/src/pg/login.rs:251` | A server that offers only `SCRAM-SHA-256` gets an unbound login even though seal could bind, and the audit record does not distinguish the two cases. The threat model's boundary table lists channel binding as an enforced control |
| The HTTP key source accepts a URL with a password and silently discards it | `seal-keys/src/http_source.rs:68` | The check covers the scheme, the query and the username, but not the password, so `https://:secret@host/` passes and the credential is dropped |
| A wrapped key file's size is checked with `stat` and then read whole | `seal-keys/src/source.rs:123` | A file that grows between the two is read without limit. The directory is seal's own, so this needs local access to it |
| `public_keys` returns the key source's claimed public key without deriving it from the private key | `seal-keys/src/keyring.rs:258` | The sealing path uses the derived key, and `unwrap` refuses a record whose stored public key does not match (`keyring.rs:512`), but this endpoint does not unwrap, so it publishes an unverified key |
| The caller's `Content-Length` is forwarded to the provider | `seal-broker/src/inject.rs:482` | Only its shape is checked. It cannot smuggle a request, but the caller chooses the framing of the request seal sends |
| The audit file's `0600` applies only when it is created | `seal/src/sinks.rs:40` | A file that already exists with wider permissions keeps them. The wrapping key and the configuration are both checked on open |
| The metrics and health listener has no authentication, and `/readyz` calls the key source | `seal/src/health.rs:36` | Each probe is an outbound request to the key service. The metrics carry no keyset names |
| Exposed claims are taken from any three-part token | `seal-broker/src/claims.rs:22` | The header is decoded and never read, and the signature is never checked, so an `alg: none` token's claims are returned verbatim. The threat model accepts unverified claims, but states it in terms of an unchecked signature rather than an unsigned token |
| A caller may set `x-ms-version` on an Azure request | `seal-broker/src/inject/azure.rs:260` | seal sets it only if the caller did not. `x-amz-*` headers are protected by `refuse_amz_headers`; the `x-ms-*` family is not |

## Checked and found sound

These were tested rather than assumed. Each is a property the threat model claims.

| Property | How it was checked |
|---|---|
| A caller cannot inject CR or LF into a header | `http`'s `HeaderValue` rejects them; injected values go through `HeaderValue::from_bytes` (`inject.rs:468`) |
| A caller cannot inject CR or LF into the request line | `Target::parse` refuses any URL a parser would rewrite; the path and query secrets are percent-encoded so `/`, `?`, `#` and `%` cannot appear |
| A caller cannot set, append to or shadow an injected header | `matcher.rs:376` refuses name collisions, case-insensitively and decoded for query names; `headers.insert` replaces every value |
| A caller cannot influence what is signed | `refuse_amz_headers` (`matcher.rs:431`) refuses every `x-amz-*` header that is not on the allow-list, including the signing headers |
| A path injection cannot be combined with another value | `matcher.rs:320`, because it moves the path every other value's rule matched |
| Two rules cannot inject into the same place | `matcher.rs:414`, and `json_pointers_do_not_overlap` for nested pointers |
| Rules must agree on response sealing | `matcher.rs:537`, including that they all agree there is none |
| A value from another record is refused unless it is shared | `broker.rs:1051` |
| A caller is refused a keyset it is not allowed, on every operation | `service.rs:537`, `:594`, `:651`, `:701`, against the authenticated identity, with the `Caller` copied before the check |
| A private address is refused after DNS | The check is on the resolved address (`client.rs:349`) and the connection is made to the checked `SocketAddr` (`client.rs:625`), so there is no rebinding window |
| IPv4 in IPv6 is classified as IPv4 | `address.rs:69`, for mapped, compatible, NAT64 and 6to4 addresses |
| Redirects are never followed | The client is hyper's connection API; no 3xx handling exists |
| A caller cannot choose the destination | `Host` is replaced from the parsed URL, `Proxy-*` is refused, and the request URI is always built from the checked target |
| A mutual TLS client certificate is required | `WebPkiClientVerifier` without `allow_unauthenticated`; there is no non-TLS listener |
| A Unix peer is refused unless its uid is known | `listen.rs:126`, before the connection reaches tonic |
| No secret is written to a log, an error, a metric or an audit record | The audit record's schema holds identifiers only; the errors hold static text and a field name; the suite's canary scan checks every run |
| A wrapped key cannot be moved between keysets or kids | The AAD is length-prefixed with the keyset and kid (`seal-keys/src/wrap.rs:41`) |
| A wrapped key that does not match its public key is refused | `seal-keys/src/keyring.rs:512` |
| A Postgres login reads exactly one byte of the `SSLRequest` answer | `pg/session.rs:376`, on the same socket, before the TLS handshake |
| SCRAM checks the server's signature | `pg/login.rs:283`, in constant time |
| A Postgres caller cannot set the user or the database | `pg/session.rs:273`, and duplicate startup parameters are refused outright |
| A URL that a parser would rewrite is refused | `Target::parse`, with a table of known bypass attempts in `target.rs:267` |
| A duplicate JSON key cannot smuggle a token past sealing | The document is re-serialised whole, so the earlier key is removed from the output |
| XML cannot hide a token in CDATA, a comment or an entity | The whole content range is replaced and verified; a document type declaration is refused |
| A JSON body cannot carry a key `serde_json` would read as a number | `mentions_number_token` (`inject.rs:547`), on both the request and the response |

## Not covered

- The build and deployment configuration, the CI workflows, the dependency tree and
  the fuzz targets were not part of this pass.
- The external review of the sealed-value format, the matcher, injection and signing,
  and the Postgres login that
  [`reviews/external-review-scope.md`](reviews/external-review-scope.md) asks for has
  still not happened.
- Only the `aarch64-apple-darwin` build was examined. The behaviour of the platform
  hardening in `seal/src/hardening.rs` on Linux was not tested.
