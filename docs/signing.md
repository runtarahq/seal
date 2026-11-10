# seal: signing and client certificates

How seal signs requests with AWS Signature Version 4 and Azure Storage Shared Key, and
presents client certificates toward providers. The policies are in
[`policy.md`](policy.md); this explains what happens to a request.

In every case seal works on the final request. The caller's headers are fixed, any
injection has been applied, and then seal signs. A caller cannot set anything that seal
signs or sets, and seal refuses the request before any DNS lookup if it tries.

## AWS Signature Version 4

The secret is the secret access key. The access key ID and any session token are other
parts of the credential: the key ID is usually plain, and a session token is a sealed
companion.

seal sets `X-Amz-Date`, `X-Amz-Content-SHA256`, `X-Amz-Security-Token` if there is a
session token, and `Authorization`. It signs `host`, the `content-*` headers that describe
the body, `range`, and every `x-amz-*` header.

### Headers a caller may set

| Headers | Allowed |
|---|---|
| `x-amz-meta-*`, `x-amz-storage-class`, `x-amz-tagging`, `x-amz-server-side-encryption*`, `x-amz-checksum-*`, `x-amz-expected-bucket-owner`, `x-amz-request-payer` | Always: they change what the request does at its destination, not where it goes or how it is signed |
| `x-amz-acl`, `x-amz-grant-*` | Where the rule lists them in `allow_headers`, since they can widen who reads the data |
| `x-amz-copy-source` and the rest of the copy headers | Where the rule lists `x-amz-copy-source`, and only from within the rule's path prefix |
| `X-Amz-Content-SHA256` | A well-formed hash, where the rule allows the caller's hash |
| Every other `X-Amz-*` header, including `X-Amz-Date`, `X-Amz-Security-Token`, `X-Amz-Decoded-Content-Length` and `X-Amz-Trailer` | Never: they control signing, or are not on the list yet |

A copy reads the object its source names, not the one in the URL. Without a check, a
secret limited to one bucket could copy another bucket's object into it and read it. So
seal reads the copy source, `bucket/key` or `/bucket/key` with an optional
`?versionId=`, as a path on the request's own host, and refuses it unless it is within
the rule's path prefix. The same rules apply as to a request's URL. A rule that allows
copies must have a path prefix naming the bucket: with virtual-hosted URLs the bucket is
in the host name, so seal could not check a source against it.

### Payload modes

The rule lists the modes it allows. seal chooses one for each request, in this order:

| Mode | Chosen when | What seal does |
|---|---|---|
| `caller_hash` | The caller sends `X-Amz-Content-SHA256` | Checks it is 64 lowercase hex digits and signs with it. The body streams, and the provider checks the hash |
| `computed` | The body fits the buffer cap, or its length is unknown | Buffers the body and hashes it |
| `streaming` | The body is over the cap, with a declared `Content-Length` | Signs in 64 KiB chunks as the body streams (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) |
| `UNSIGNED-PAYLOAD` | Nothing else fits, and the rule sets `allow_unsigned_payload` | Signs the headers only |

The caller's `X-Amz-Content-SHA256` cannot select a mode the rule forbids. `UNSIGNED-PAYLOAD`
or a malformed value in it is refused. A body that seal changes, such as a form with an
injected field, is always hashed by seal.

For chunked signing, seal sets `Content-Encoding: aws-chunked`, ahead of any coding the
caller set. It also sets `X-Amz-Decoded-Content-Length` and the framed `Content-Length`. It
holds one chunk at a time. If the body is not the length its `Content-Length` declared, the
request fails.

### Canonical form

S3 paths are encoded once, so seal decodes each segment and encodes it in AWS's form.
Other services encode the path as sent a second time. Neither normalises, since seal
refuses dot segments. The query is read as a form, with `+` as a space, as the AWS SDKs
read it.

Presigned URLs are not implemented: a presigned URL is a usable credential.

### Temporary credentials

STS `AssumeRole` returns XML. A rule to STS with `seal_response` in `xml` format seals
`SecretAccessKey` and `SessionToken` under definitions that allow only the destinations
the temporary credentials are for. The access key ID is not secret and stays readable.
[`policy.md`](policy.md#response-sealing) has an example.

### Checked against

- The AWS signing test suite, from `aws-c-auth`
  (`crates/seal-broker/tests/fixtures/sigv4`).
- The S3 examples for a GET and for a chunked upload.
- The AWS SDK's own signer, on random requests (a property test).
- RustFS, in all three modes: each payload mode, ranges, listings and multipart uploads.
- 5 GB uploads and downloads against RustFS, within the memory limit (nightly).

## Azure Storage Shared Key

The secret is the account key, in base64, and the account name is another part. `service`
picks the string to sign: Blob, Queue and File share one, and Table has its own.

seal sets `x-ms-date`, `Date` as well for Table, `x-ms-version` (`2021-12-02`) if the
caller sent none, and `Authorization`. A caller cannot set `Authorization`, `x-ms-date` or
`Date`. Shared Key refuses a repeated header, so seal refuses one too.

seal sets `Content-Length` before signing whenever the body's length is known, because
the service signs it whenever the request carries it.

SAS generation is not implemented: a SAS is a usable credential.

Checked against the examples in Microsoft's Shared Key documentation, and against Azurite
in all three modes: Blob, Queue and Table.

## Client certificates

The secret is the private key, in PEM: PKCS#8, PKCS#1 (RSA) or SEC1 (EC), for an RSA,
ECDSA or Ed25519 key. The certificate and any chain may be plain. A rule can name a CA to
verify the provider with, added to the usual roots for that destination only, and a
server name to verify instead of the URL's host.

A key that does not match its certificate is refused before seal connects.

### Pools

Connections that carry a client certificate are pooled per identity. An identity is named
by a fingerprint: HMAC-SHA-256 over the following, under a key generated when seal starts:

- the keyset, item and kid the private key was opened with;
- the certificate, key and chain;
- the rule's CA and server name.

The fingerprint stays in memory and is never logged.

- A certificate replaced under the same kid is a new identity, with new connections. So
  is a changed CA or server name.
- Every request still opens its values and passes the policy before an identity is
  chosen. A pooled connection is never a substitute for authorisation.
- When the keyring lets the sealing key go, by eviction or removal, seal forgets the
  identity and closes its idle connections. A reloaded key makes a new identity.
- At most `pools.max_client_cert_identities` identities exist (default 256). At the limit,
  seal forgets the least recently used one. An identity keeps its TLS configuration, and
  counts against the limit, until its last connection ends. If none can be released in the
  connect timeout, the request fails with `LIMIT_EXCEEDED`.

The TLS configuration holds a copy of the private key for as long as the identity exists.
The [threat model](threat-model.md) lists this among the copies seal cannot erase.
