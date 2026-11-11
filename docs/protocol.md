# seal: the protocol

seal's service speaks gRPC, package `seal.v1`, defined in
[`crates/seal-proto/proto/seal/v1/seal.proto`](../crates/seal-proto/proto/seal/v1/seal.proto).
Applications in Rust use [`seal-client`](../crates/seal-client), which hides all of this
behind one interface for every mode. This document is for other languages, and for
reviewing what crosses the boundary.

`seal.v1` is stable from the first release. A breaking change goes to `seal.v2`, served
alongside `seal.v1` for one release.

## Transports

| Mode | Transport | Who the caller is |
|---|---|---|
| Process on the same host | HTTP/2 over a Unix socket | The peer's uid, from the socket's credentials |
| Separate machine | HTTP/2 over TLS 1.3 with a client certificate | The certificate's subject, such as `CN=app,O=Example` |

A caller seal does not know is refused when it connects, before any request is read:
the connection is closed. A known caller is then held to the keysets the configuration
gives it.

## `Send`

`rpc Send(stream SendIn) returns (stream SendOut)` sends one HTTP request using sealed
values.

The caller sends:

1. One `SendHead`: the keyset and item, the sealed values as envelope JSON by field name,
   any plain parts of a credential, the method, an absolute URL, and the headers.
2. Any number of `body` chunks, each at most 64 KiB.
3. One `end`. A stream that stops without `end` is a body that was cut off, and the
   request fails rather than send an incomplete body.

seal replies with:

1. One `ResponseHead`: the status, headers, any values sealed from the response, as
   envelope JSON by field name, and any claims their policy exposes, as a JSON object by
   field name.
2. Any number of `body` chunks, each at most 64 KiB.
3. A `Trailer`, only if the body failed after the head was sent.

HTTP/2 flow control carries backpressure both ways: seal reads from the provider only as
fast as the caller reads from seal, and the other way round.

## Errors

A refusal or failure before the response head is a gRPC status. The `seal-error-code`
metadata holds the code, and the message holds identifiers and static text only: never a
value, a header, a body or a query string. After the head, a failure is a `Trailer` with
the same code.

| Code | Meaning | Retry? |
|---|---|---|
| `CALLER_DENIED` | The caller may not use this keyset, make an admin call, or destroy this keyset | No |
| `BAD_REQUEST` | The request is malformed | No |
| `OPEN_FAILED` | A sealed value did not open: wrong item, field or key | No |
| `KEYSET_UNKNOWN` | The keyset has no keys | No |
| `KEYS_UNAVAILABLE` | The keys could not be loaded | Yes |
| `POLICY_DENIED` | No rule allows this request, or the value may not verify: a bug or an attack | No |
| `DESTINATION_REFUSED` | The destination's address is refused | No |
| `CONFLICT` | Rules conflict, or the caller set something an injection sets. For a keyset call: it already exists, has as many keys as it may, or the key source cannot delete | No |
| `BODY_TOO_LARGE` | A body that has to be buffered, or a message to verify, is over the cap | No |
| `RESPONSE_TOO_LARGE` | A response that has to be sealed is over the cap; nothing of it is returned | No |
| `RESPONSE_UNPARSEABLE` | A response that has to be sealed could not be parsed, or a response repeats a credential seal sent | No |
| `UPSTREAM_CONNECT`, `UPSTREAM_TLS`, `UPSTREAM_RESET` | The provider could not be reached, or failed | Yes |
| `UPSTREAM_TIMEOUT` | No progress within a timeout | Yes |
| `PG_AUTH_FAILED` | A Postgres login failed | No |
| `LIMIT_EXCEEDED` | A rate or concurrency limit was reached | Yes |
| `INTERNAL` | seal failed, or could not write an audit record | No |

A request with a body is never retried by seal, and must not be retried blindly by the
caller either: the provider may have acted on it.

## `Verify`

`rpc Verify(stream VerifyIn) returns (VerifyReply)` says whether a message's
authentication code was made with a sealed secret: a webhook's signature, checked without
the application holding the signing secret. The value's policy must have
[`verify`](policy.md#verification).

The caller sends one `VerifyHead` (the keyset and item, the field and its envelope JSON,
`value_item` for a shared value, and the code as bytes), then the message in `message`
chunks of at most 64 KiB, then one `end`. seal reads the message whole, up to the buffer
cap, and replies `valid`. A code that does not match is `valid = false`, not an error:
`POLICY_DENIED` means the value may not verify at all. seal never returns a code, and
only one of the hash's full length can match.

For a value whose policy has `"verify": "equals"`, `mac` is the token that came with the
webhook and there is no message: the caller sends the head, then `end`. A call that
sends a message is refused with `BAD_REQUEST`.

## `Presign`

`rpc Presign(PresignRequest) returns (PresignReply)` returns a presigned S3 URL, or a Blob
URL with a shared access signature, for one object ([`signing.md`](signing.md#presigned-urls)).
The request has the keyset, item, sealed and plain fields and `items` as in `SendHead`,
the method, the object's URL and `expires_s`. Nothing is sent anywhere.

The reply's `url` is a credential, unlike anything else seal returns: it works without
seal until it expires. `POLICY_DENIED` means the rule does not set `allow_presign`, or not
for this request or this long.

## Administrative calls

`GenerateKeyset`, `Rotate` and `PublicKeys` need a caller with `admin = true`, and every
call is audited. `GenerateKeyset` and `Rotate` return the wrapped key, which the
application stores if seal's key source is read-only. No private key leaves seal
unwrapped.

`DestroyKeyset` deletes every key of a keyset from the key source, and cannot be undone.
It needs a caller with `destroy_keysets = true` that may use the keyset; `admin` is
neither needed nor enough. It is audited as `destroy_keyset`. `KEYSET_UNKNOWN` means
there was nothing to delete, and `CONFLICT` that the key source cannot delete.

## `Info`

Any known caller may ask for the mode, version and buffer cap. Applications should show
the mode, since it decides what a compromised application gets.

## `Connect`

A Postgres session ([`postgres.md`](postgres.md)). The first message is a `ConnectHead`:
the keyset, item, sealed and plain fields as in `SendHead`, `items` for shared values,
and the server's host and port. Every check that needs no network runs before seal
answers: the caller's keysets, opening the values, and the policy. A refusal is a status,
with no messages.

After that, the caller's `data` messages are the Postgres session's bytes, as a client
would send them to a server, and seal's are the server side. seal logs in, then relays.
A failure during the login reaches the caller as a Postgres `ErrorResponse` in the data;
seal then ends the stream with a `Trailer` naming the code. A cancel is a session of its
own whose only bytes are a `CancelRequest`.
