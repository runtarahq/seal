# seal: sealed value format

The format is defined by this document and checked by the vectors in
[`vectors/`](../vectors). Implementations in other languages should pass the
vectors; [`vectors/verify.py`](../vectors/verify.py) is a short independent
implementation to compare against.

## Envelope

One envelope holds one secret and its policy, as JSON:

```json
{ "v": 1, "keyset": "acme", "kid": "k3", "enc": "…", "ct": "…" }
```

| Field | Meaning |
|---|---|
| `v` | The format version: `1` |
| `keyset` | The keyset the value is sealed to |
| `kid` | The key in that keyset |
| `enc` | HPKE's encapsulated key: 32 bytes, base64url |
| `ct` | HPKE's ciphertext, including the tag: 16 bytes to 64 KiB, base64url |

Binary fields use base64url with no padding and no unused trailing bits. Parsers
refuse unknown or repeated fields, other versions, other base64 forms and wrong
lengths, so a value has one written form.

## Identifiers

| Identifier | Pattern |
|---|---|
| Keyset, kid, item | `[A-Za-z0-9._:-]{1,128}` |
| Field name, policy definition name | `[A-Za-z0-9._-]{1,64}` |

None may start with `.`, so `.` and `..` are refused and an identifier is always
safe as a path segment. Anything else is refused when sealing and opening.

## Encryption

HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)), base mode:

| Parameter | Value |
|---|---|
| KEM | `DHKEM(X25519, HKDF-SHA256)` (`0x0020`) |
| KDF | `HKDF-SHA256` (`0x0001`) |
| AEAD | `AES-256-GCM` (`0x0002`) |
| `info` | The ASCII string `seal/v1` |

Keys are 32 bytes. Sealing is single-shot: a new ephemeral key for each value.

## Associated data

The associated data binds a value to where it is stored, so a value copied to
another record or field does not open. It is a canonical encoding, not JSON:

```
"seal/v1/aad" || u8(v) || lp(keyset) || lp(kid) || lp(item) || lp(field)
lp(x) = u16_be(len(x)) || x
```

`item` is the application's identifier for the record, and `field` is the field's
name. Neither is in the envelope: the caller supplies them each time. An
application therefore has to know a record's id before sealing.

## Plaintext

```json
{"policy":{"rules":[…]},"secret":{"b64":"…"}}
```

`secret.b64` is the secret's bytes in base64url, with no JSON escapes. A string
secret is its UTF-8 bytes. `policy` is described in [`policy.md`](policy.md).

Sealers write the policy in canonical form, with no whitespace and the fields
above in that order. Openers accept any valid JSON object with exactly these fields.
A value opens only if its policy passes validation, so a policy is checked both
when sealing and after opening.

The whole plaintext plus the 16-byte tag must fit in the 64 KiB limit on `ct`.

## Security properties

- **Sealing needs only the public key**, and a build without the `open` feature
  has no opening code.
- **A value cannot be moved or altered.** A change to any byte of `enc` or `ct`,
  or to the keyset, kid, item or field, means it does not open.
- **Anyone with the public key can seal a new value**, with any policy. HPKE's base
  mode does not authenticate the sender. That does not expose an existing secret:
  the new value holds only what its sealer already knew. It does mean an
  application should treat a stored envelope's policy as chosen by whoever could
  write to that store, and seal's guarantee covers secrets sealed by a trusted
  sealer, such as a browser, before an attacker has access.

## Versioning

From `0.1.0`, envelope `v: 1` and this encoding are stable: values sealed by `0.1.0`
open in every later version. A change to the format is a new version number, and
the committed vectors fail if the format changes by accident.

## Test vectors

| File | Contents |
|---|---|
| [`vectors/envelope.json`](../vectors/envelope.json) | Sealed values with fixed ephemeral keys: inputs, associated data, plaintext, envelope, and changed bindings that must not open |
| [`vectors/policy.json`](../vectors/policy.json) | Policies to accept, in canonical form, and to refuse |

The ephemeral key comes from `DeriveKeyPair(ephemeral_ikm_hex)`, as in RFC 9180, and
fixing it is what makes the vectors deterministic. Real sealing must use a new
random key each time. In `seal-format`, fixed randomness exists only behind the
`test-vectors` feature, which only tests enable.

To regenerate the files, which should only be needed for a new vector:

```sh
cargo run --package seal-format --example generate_vectors
```

To check them independently of the Rust code:

```sh
pip install cryptography
python3 vectors/verify.py
```
