# seal: operations

How to run seal: modes, configuration, sizing, keys and rotation. The examples in
[`deploy/`](../deploy) are complete configurations for each service mode.

## Modes

| Mode | Where the private keys are | What a compromised application gets | Use |
|---|---|---|---|
| Library | In the application's memory | Every credential | Development, tests, migration |
| Process on the same host | In seal's process, under its own user | Use, not copies, unless the attacker also gets root | Single-node installs; the recommended default |
| Separate machine | On the seal host | Use, not copies, even with root on the application's host | Multi-tenant and high-value deployments |

An application moves between modes by configuration, through `seal-client`. In library
mode it logs at startup that credentials are readable by the process, and `Info` reports
the mode, so the application can show it.

### Same host

Install the binary, the [systemd unit](../deploy/systemd/seal.service) and the
[configuration](../deploy/config/same-host.toml):

```sh
useradd --system --no-create-home seal
install -d -o seal -g seal -m 0700 /var/lib/seal/keys
seal keygen --wrapping-key /etc/seal/kek && chown seal: /etc/seal/kek
systemctl enable --now seal
```

Callers are identified by the uid of the process on the other end of the socket. The
socket is group-readable, so add the application's user to seal's group.

### Separate machine

Use the [container image](../deploy/container/Dockerfile) or the binary, with the
[configuration](../deploy/config/separate-machine.toml). The image is published as
`ghcr.io/runtarahq/seal` for amd64 and arm64: a release is tagged with its version, such
as `0.1.0`, and `latest`; `main` follows the main branch. Callers present a client
certificate from the CA in `listen.tls.client_ca`, and are identified by its subject.
Certificates are short-lived: seal checks its certificate files every
`listen.reload_interval` and swaps them in. A change that does not load is logged and
the old certificates kept, so a half-written renewal cannot take seal down. Connections
already open keep the certificate they started with.

A caller's certificate is checked when it connects, and seal never resumes a TLS session,
so every connection is a full handshake with a certificate that is valid then. A
connection ends at `listen.max_connection_age`, once the requests on it have finished, and
the caller connects again. An expired or replaced certificate therefore stops working
within that time, plus the longest request still running.

## Configuration reference

Unknown settings are errors. Durations are written like `100ms`, `60s`, `15m` or `8h`,
sizes like `65536`, `256KiB` or `1GiB`, and rates like `1000/s` or `60/m`. seal refuses a
configuration file that its group or others can write.

### `[listen]`

| Setting | Default | |
|---|---|---|
| `unix` | | A socket path, in a directory only seal's user can write: seal refuses one its group or others can write, where the socket could be replaced. Callers then need `unix_uid` |
| `tcp`, `tls` | | An address, with `{ cert, key, client_ca }` in PEM. Callers then need `cert_subject` or `cert_san`. seal refuses a `key` that everyone on the host can read, and warns of one its group can read |
| `reload_interval` | `10s` | How often certificate files are checked |
| `max_connection_age` | `1h` | How long a TLS connection lasts before the caller must connect, and show its certificate, again |

### `[[callers]]`

| Setting | |
|---|---|
| `name` | The name in audit records |
| `unix_uid`, `cert_subject` or `cert_san` | Exactly one, matching the listener |
| `keysets` | The keysets it may use, or `["*"]` for all |
| `admin` | Whether it may generate keysets, rotate and list public keys. Default `false`. It holds for every keyset, whatever `keysets` lists: `keysets` says which a caller may use, and a platform that makes a keyset for each new tenant could not list one that does not exist yet. So an admin caller can add keys to any keyset, within its rate, though it reads no private key and can destroy nothing |
| `admin_keysets` | The keysets an admin caller may generate, rotate and list the keys of, where that should not be every one: the names, or `*`. Absent means every keyset. Only for a caller with `admin` |
| `destroy_keysets` | Whether it may [destroy](#destroying-a-keyset) the keysets it may use, which cannot be undone. Separate from `admin`. Default `false` |

A `cert_subject` is the certificate's whole subject, attribute by attribute and in the
certificate's order, such as `CN=app,O=Example`. Attribute names and the spaces around
separators do not matter; values are compared exactly. A certificate whose subject has
a comma in a value, or more than one attribute in a relative distinguished name, is
refused, because it could not be told from another subject once written down.

A `cert_san` is one of the certificate's subject alternative names instead: a URI,
compared as written, such as `spiffe://example.org/app`, or a DNS name. That is the
name a certificate is issued for, and the better choice where the client CA also
issues certificates for other services, since a subject is only what the requester
asked for. A certificate that matches two configured callers is refused.

### `[keys]`

| Setting | Default | |
|---|---|---|
| `source` | | `{ dir = "…" }`: the directory that holds the wrapped keys, as `<dir>/<keyset>/<kid>.json`. Or `{ s3 = { … } }`, a bucket that several instances share: see [keys in a bucket](#keys-in-a-bucket) |
| `wrap` | | The wrapping key that new keys are wrapped with. `{ file = "…" }`: 32 bytes readable only by seal's user. Or `{ ovh_kms = { … } }` or `{ aws_kms = { … } }`, a key that stays in a KMS: see [wrapping with a KMS](#wrapping-with-a-kms) |
| `unwrap_also` | `[]` | Older wrapping keys, each written as `wrap` is. They wrap nothing new, and unwrap any stored key that names them, while the wrapping key is replaced. Take one out as soon as `seal rewrap` is done, and at once if it may have leaked: while it is listed, whoever has it and can write to the key source can add a key of their own: see [rotating the wrapping key](#rotating-the-wrapping-key) |
| `idle_evict` | `15m` | A keyset unused this long is dropped from memory |
| `refresh_interval` | `60s` | How often a loaded keyset is fetched again |
| `max_stale` | `5m` | A keyset not fetched successfully this long is dropped |
| `max_unwrap_age` | `1h` | A key not unwrapped this long is dropped |
| `max_loaded_keysets` | `1024` | The least recently used goes first |
| `max_keys_per_keyset` | `16` | `rotate` refuses past this. A keyset is read with up to twice as many, so one left over the limit by rotations on separate instances at once still loads; more than that is refused |
| `max_live_keys` | `4096` | Every private key in memory, including ones a request still holds |
| `max_tracked_keysets` | `4096` | Unknown keysets remembered, and rate buckets |
| `lock_memory` | `best_effort` | `off`, `best_effort` or `required` |

seal checks `refresh_interval < max_stale < max_unwrap_age`, and that `max_live_keys` is at
least twice `max_keys_per_keyset`.

### `[network]`

| Setting | Default | |
|---|---|---|
| `deny_cidrs` | `[]` | Always refused |
| `allow_private_cidrs` | `[]` | Allowed whatever their class |
| `honour_private_rules` | `false` | Whether a rule's `allow_private_destination` has any effect |
| `honour_plaintext_postgres_rules` | `false` | Whether a Postgres rule whose `tls` is `"plaintext"` may connect with no TLS. Otherwise such a session is refused |
| `extra_ca_files` | `[]` | CAs to trust toward providers, besides the public roots |

### `[pools]`, `[limits]`, `[audit]`, `[metrics]`

| Setting | Default | |
|---|---|---|
| `pools.max_upstream_connections` | `1024` | At the limit, an idle connection is closed to make room |
| `pools.max_idle_per_host` | `8` | |
| `pools.idle_timeout` | `90s` | |
| `limits.max_concurrent_streams` | `512` | Past this, `LIMIT_EXCEEDED` |
| `limits.per_stream_buffer` | `256KiB` | Also sets HTTP/2 windows |
| `limits.max_concurrent_buffered` | `64` | Requests holding a capped buffer |
| `limits.buffer_cap` | `1MiB` | The largest buffered body or sealed response |
| `limits.max_head` | `256KiB` | The largest request head, including envelopes |
| `limits.max_caller_connections` | `256` | |
| `limits.idle_timeout` | `60s` | No bytes in either direction |
| `limits.connect_timeout` | `10s` | Including DNS and TLS |
| `limits.first_byte_timeout` | `60s` | Once the request is sent |
| `limits.buffered_total_timeout` | `60s` | For a request holding a capped buffer |
| `limits.max_stream_duration` | none | An optional total deadline for streams |
| `limits.rate_per_caller` | `1000/s` | |
| `limits.rate_per_keyset` | `200/s` | Counted against the request's keyset and against the keyset each presented value was sealed to |
| `limits.memory_budget` | `2GiB` | seal refuses to start if the ceiling is over it |
| `audit.sink` | `"stdout"` | Or `{ file = "…" }`, created readable only by seal's user. A file already there is refused if its group can write it or others can reach it |
| `audit.on_failure` | `fail_closed` | `best_effort` is for development only |
| `metrics.listen` | none | Serves `/metrics`, `/healthz` and `/readyz`, to at most 64 connections at once, each for at most 30 seconds |
| `metrics.token_file` | none | A file only seal's user can read, holding a token of at least 16 printable characters. Every request must then send `Authorization: Bearer <token>`. Required unless `metrics.listen` is a loopback address |

A rule in a sealed policy can only tighten a limit, never relax one.

## Sizing and the memory ceiling

Every resource that holds memory has a bound, and the ceiling is the sum of each bound
times its cost, plus fixed overhead and a 25% allocator margin. `seal check-config` prints
the terms:

```sh
seal check-config --config /etc/seal/seal.toml
```

Set the process's memory limit (`MemoryMax`, or the container's) to `memory_budget`.

The costs are in [`crates/seal/src/limits.rs`](../crates/seal/src/limits.rs). A nightly
test on Linux measures each one it can, and fails if a committed constant is too low:

| Cost | Measured | Committed |
|---|---|---|
| Idle process | 11 MiB | 64 MiB |
| Live key | 2 KiB | 4 KiB |
| Stalled stream | 29 KiB | 64 KiB, plus its provider connection |
| Caller connection (Unix socket) | 23 KiB | 128 KiB |
| Idle provider connection (plain HTTP) | 28 KiB | 128 KiB |
| Full capped buffer | about twice the cap | the cap × 4, plus 768 KiB |
| Remembered unknown keyset | 73 bytes | 512 bytes |
| Client-certificate identity, with its idle connection | 44 KiB | 32 KiB, plus 128 KiB for the connection |

A client-certificate identity, with its TLS configuration and an idle connection, is
measured against the identity and connection constants together. Not yet measured: TLS
on plain connections, and parsing a buffer. Another nightly test fills every bound at
once and checks that resident memory stays under the ceiling; with the test's limits,
including 256 client-certificate identities, it uses 30 MiB of a 386 MiB ceiling, so the constants are generous rather than tight.

Lock memory where you can: without it, key pages can reach swap. With `lock_memory =
"best_effort"` seal logs if locking fails; on Linux it needs `LimitMEMLOCK` at least the
budget. If memory cannot be locked, disable or encrypt swap.

## Keys

Each keyset is an X25519 key pair, plus retired ones. Private keys are held only in
memory, and wrapped everywhere else.

```sh
seal keygen --wrapping-key /etc/seal/kek               # once per deployment
seal keygen --config /etc/seal/seal.toml --keyset acme # a keyset's first key
```

Or call `GenerateKeyset` as an admin caller, which stores the wrapped private key in the
key source and returns it with the public key.

Instances do not coordinate. Each re-reads the key source for the keysets it has loaded
every `refresh_interval`, and at once, at most every 30 seconds, when a value names a key
it has not seen. So:

- A key added to the source reaches every instance within `max_stale`, normally within
  `refresh_interval`.
- A key deleted from the source stops opening on every instance within `max_stale`.
- An unwrapped key is dropped after `max_unwrap_age` and unwrapped again when needed.
- The wrapping key file is read once, at start-up. Deleting or replacing it takes
  effect at the next restart, and a restart with a different wrapping key cannot read
  any key wrapped with the old one, unless the old one is in `keys.unwrap_also`. To
  change it, see [rotating the wrapping key](#rotating-the-wrapping-key).
- A wrapping key in a KMS is asked for each time a key is unwrapped. Taking away
  seal's access to it stops every instance opening anything within `max_unwrap_age`.
- None of these interrupts a request already running.

If the key source is unreachable, loaded keysets keep working for `max_stale`, then return
`KEYS_UNAVAILABLE`.

### Keys in a bucket

Instances on separate machines need the same wrapped keys. Keep them in a bucket of an
S3-compatible object store, and every instance reads and writes the same ones:

```toml
[keys]
source = { s3 = { endpoint = "https://s3.gra.io.cloud.ovh.net", region = "gra", bucket = "example-seal-keys", prefix = "keys/", credentials_file = "/etc/seal/s3-credentials" } }
```

| Setting | |
|---|---|
| `endpoint` | The store's endpoint, `https` only. Objects are addressed as `<endpoint>/<bucket>/<name>` |
| `region` | The region requests are signed for |
| `bucket` | The bucket. seal does not create it |
| `prefix` | What every object's name starts with: a path that ends in `/`. Empty if not given |
| `credentials_file` | An access key id and a secret access key, in the AWS shared credentials format, in a file readable only by seal's user |
| `profile` | The profile in that file. `default` if not given |
| `ca` | The CA of the endpoint's certificate, if it is not a public one |

```ini
[default]
aws_access_key_id = …
aws_secret_access_key = …
```

- The objects are the files of a key directory, `<prefix><keyset>/<kid>.json`, so a
  directory and a bucket are copied into each other with any S3 tool. To move from a
  directory, copy it to the bucket and change `keys.source`.
- The bucket holds only wrapped keys. Whoever can write to it can delete keys, or put
  deleted ones back, and opens nothing without the wrapping key. Give seal's access key
  this bucket and nothing else: listing it, and reading, writing and deleting its
  objects and their versions.
- The store must support conditional writes, `If-None-Match` and `If-Match` on an
  upload. seal stores a key only where there is none, and replaces one, when it is
  wrapped again, only if it is still the one it read. A store without them refuses
  every new key.
- Turn on versioning for the bucket: a key deleted or overwritten by mistake is then
  still there. [Destroying a keyset](#destroying-a-keyset) deletes every version of
  its keys, so versioning does not keep what was destroyed.
- The credentials file is read for every request, so a new access key needs no restart.
- Each instance asks the store at most once per loaded keyset every `refresh_interval`,
  and downloads a key only when it is new or was wrapped again. Each request is a new
  connection, and may take ten seconds.
- With several instances, keep the wrapping key in a KMS: a wrapping key file would have
  to be copied to every machine.

### Wrapping with a KMS

With a wrapping key file, whoever reads seal's disk has the wrapping key and the wrapped
keys together. With a KMS the wrapping key never leaves the KMS: seal sends it each
private key to wrap when the key is made, and to unwrap when a keyset is loaded and
again every `max_unwrap_age`. Requests that use an already unwrapped key do not touch
the KMS.

The KMS sees every private key it wraps or unwraps, and whoever can use the wrapping key
there, with a copy of the wrapped keys, can open what seal can. Its access log shows
each unwrap.

**OVHcloud KMS.** Create a service key of type AES, 256 bits, for encryption and
decryption (not for wrapping), and give seal's identity an IAM policy that allows
encrypting and decrypting with it, and nothing else.

```toml
[keys]
source = { dir = "/var/lib/seal/keys" }
wrap = { ovh_kms = { endpoint = "https://eu-central-waw.okms.ovh.net", okms_id = "…", key_id = "…", cert = "/etc/seal/kms.crt", key = "/etc/seal/kms.key" } }
```

| Setting | |
|---|---|
| `endpoint` | The KMS's regional endpoint, `https://<region>.okms.ovh.net` |
| `okms_id`, `key_id` | The KMS and the service key, both UUIDs |
| `cert`, `key` | An access certificate and its key, in PEM. The key file must be readable only by seal's user |
| `token_file` | Instead of `cert` and `key`: a personal access token, in a file readable only by seal's user. It is sent as a bearer token |
| `ca` | The CA of the endpoint's certificate, if it is not a public one |

Prefer the access certificate: a token is a secret sent with every request, and it
expires. Credentials are read once, at start-up, so a renewed certificate or token
takes effect at a restart. An OVHcloud service account is not supported.

seal sends the keyset and kid as the KMS's `context`, so a wrapped key copied to
another keyset or kid does not unwrap.

**AWS KMS.** Only in a seal built with the `aws-kms` feature, which links the AWS SDK.
The published container image has it; a build of your own needs
`cargo build --features aws-kms`. A seal built without it refuses this configuration at
start-up and in `check-config`.

Create a symmetric key for encryption and decryption, and give seal's identity
`kms:Encrypt` and `kms:Decrypt` on it, and nothing else.

```toml
[keys]
source = { dir = "/var/lib/seal/keys" }
# With the role of the EC2 instance, ECS task or EKS pod that seal runs in:
wrap = { aws_kms = { key_arn = "arn:aws:kms:eu-central-1:123456789012:key/…" } }
# Anywhere else, with an access key in a file:
wrap = { aws_kms = { key_arn = "arn:aws:kms:eu-central-1:123456789012:key/…", credentials_file = "/etc/seal/aws-credentials" } }
```

| Setting | |
|---|---|
| `key_arn` | The key's ARN, which names its region. Not an alias or a bare key id: an alias can be pointed at another key |
| `credentials_file` | A file in the AWS shared credentials format, readable only by seal's user: `[default]`, then `aws_access_key_id`, `aws_secret_access_key` and, for temporary credentials, `aws_session_token`. Without it, seal uses what the AWS SDK finds |
| `profile` | The profile, in that file or in the shared files the SDK finds. `default` if not given |
| `endpoint` | The endpoint, if it is not the region's public one: a VPC or FIPS endpoint |
| `ca` | The CA of the endpoint's certificate, if it is not a public one |

With `credentials_file`, seal reads that file for every request to the KMS, so a rotated
access key, or temporary credentials that something else keeps fresh, need no restart.
Nothing else is looked for.

Without it, the AWS SDK looks for credentials in its usual order, and keeps and renews
what it finds:

1. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the environment. A file is the
   better place: the environment shows in the unit or the pod's description, and a new
   key needs a restart.
2. The shared files, `~/.aws/credentials` and `~/.aws/config` or where
   `AWS_SHARED_CREDENTIALS_FILE` and `AWS_CONFIG_FILE` say, including a profile that
   assumes a role, runs a `credential_process` as IAM Roles Anywhere does, or signs in
   with IAM Identity Center (SSO), which needs `aws sso login` to have been run and so
   suits a developer's machine, not a server. seal does not check who can read these
   files.
3. A web identity token: IAM roles for service accounts on EKS.
4. The container credentials endpoint: a task role on ECS and Fargate, and EKS Pod
   Identity.
5. The instance metadata service, version 2: an instance profile on EC2. In a container
   on an instance, it answers only if the instance's hop limit is 2 or more.

Only credentials are looked for this way. The region is the key's, and the endpoint and
CA are the configured ones, whatever `AWS_REGION`, `AWS_ENDPOINT_URL` or a profile say.
The KMS, and STS when a role is assumed, are verified against the public roots compiled
into seal, not the host's certificate store, which a minimal image does not have.

A role's credentials come from the host with no way for it to tell seal from anything
else in the same instance, task or pod: whatever else runs there can take the same
role. Give the role this key and nothing more.

Requests are signed with Signature Version 4, so seal's clock must be within five
minutes of the KMS's. A request that fails in passing is tried up to three times within
its ten seconds.

seal sends the keyset and kid as the encryption context, `seal:keyset` and `seal:kid`.
A wrapped key copied to another keyset or kid does not unwrap, CloudTrail shows which
keyset each `Decrypt` was for, and a key policy can limit an identity to some keysets
with a condition on `kms:EncryptionContext:seal:keyset`.

**Either KMS.** A wrapped key records the KMS key that wrapped it, and seal refuses one
wrapped by any other.

If the KMS cannot be reached or refuses, keys already unwrapped keep working until
`max_unwrap_age`, and then that keyset returns `KEYS_UNAVAILABLE` until the KMS answers.
`/readyz` does not ask the KMS. Each refusal is logged with the HTTP status and the
KMS's own name or code for the error, a failure to find AWS credentials is logged with
what the SDK says of it, and each request is counted in `seal_kms_requests_total` by `kms`
(`ovh` or `aws`), `operation` (`encrypt` or `decrypt`) and `outcome` (`ok`, `refused`, `unreachable` or
`timeout`). A request to the KMS may take ten seconds. The AWS SDK's own logging is off
unless `RUST_LOG` turns it on: when a credential source fails, it logs the whole
response, which may hold a token.

To move existing keys to the KMS, see
[rotating the wrapping key](#rotating-the-wrapping-key). To rotate an OVHcloud
service key, create a new one and do the same. AWS KMS's automatic rotation keeps the
key's ARN and needs nothing from seal.

### Rotation

1. `Rotate` as an admin caller. The new key becomes current at once on that instance.
2. Wait `max_stale`. Until then another instance may still seal responses to the old key.
3. Stop sealing to the old public key in the application.
4. Reseal stored values under the new key:

   ```sh
   seal reseal --config /etc/seal/seal.toml --keyset acme --in values.jsonl --out resealed.jsonl
   ```

   Each line is `{"item": …, "field": …, "envelope": …}`. Values already under the current
   key pass through unchanged, so running it again is safe, and it never overwrites its
   output. Store the results.
5. Delete the old wrapped key from the key source.

### Rotating the wrapping key

seal reads a stored key with whichever configured wrapping key wrapped it, so the
wrapping key is replaced while seal runs, without a moment when keys cannot be made.
The same steps move the keys from a wrapping key file to a KMS, from one KMS key to
another, or back.

1. Make the new wrapping key: a file, or a key in a KMS.

   ```sh
   seal keygen --wrapping-key /etc/seal/kek-2 && chown seal: /etc/seal/kek-2
   ```

2. With several instances on one key source, first add the new wrapping key to
   `keys.unwrap_also` on every instance, and restart each. An instance cannot load a
   keyset that has a key under a wrapping key it does not know, so every instance must
   know the new one before any instance wraps with it. With one instance, skip this.

3. Make the new one current, and keep the old one for unwrapping, on every instance,
   and restart each:

   ```toml
   [keys]
   wrap = { file = "/etc/seal/kek-2" }
   unwrap_also = [{ file = "/etc/seal/kek" }]
   ```

   From now on new keys are wrapped with the new wrapping key, and the old one only
   unwraps.

4. Wrap the existing keys again, in place. seal may be running:

   ```sh
   seal rewrap --config /etc/seal/seal.toml --dry-run   # how many keys each wrapping key has
   seal rewrap --config /etc/seal/seal.toml
   ```

   Before anything is changed, every key's wrapping key must be configured. Each key
   is then unwrapped and checked against its public key, wrapped with `keys.wrap`,
   and unwrapped again from its new form and checked once more, before it replaces
   the old form. A run that stops part way has changed some keys and not others, all
   of them readable: run it again. Running instances read the new forms at their next
   refresh.

5. When `--dry-run` shows no key under the old wrapping key, take it out of
   `keys.unwrap_also`, at any later restart, and destroy it: delete the file, or the
   service key in the KMS. Until then it still opens older copies of the keys: backups
   of a key directory, and the earlier versions a bucket with versioning keeps. In
   OVHcloud KMS, deactivate the old service key for a while before deleting it, so
   that a key that was missed can still be recovered.

During step 4, seal's identity at a KMS needs to decrypt with the old key and to
encrypt and decrypt with the new one.

AWS KMS's automatic rotation keeps the key's ARN, and needs none of this. Keys wrapped
before it stay under what was behind the ARN then, which AWS keeps. To move them to
what is behind it now, run `seal rewrap --include-current`.

### Changing policies

A policy is sealed with its secret, so an application cannot change where an existing
secret may go. Whoever runs seal can: `reseal` opens each value anyway. When a provider
moves to another host, or an integration changes how it authenticates, this saves every
user entering the secret again.

The application writes the input, one line per value to change, with the policy that
value is to have:

```json
{"item": "connection-1", "field": "token", "envelope": {…}, "policy": {"rules": […]}}
```

```sh
seal reseal --config /etc/seal/seal.toml --keyset acme --rewrite-policies \
  --in values.jsonl --out resealed.jsonl
```

- Read the input before running it. It decides where secrets may go from now on, and it
  comes from the application, which this step exists not to trust. Without
  `--rewrite-policies`, a line that names a policy fails the run.
- A new policy is checked like any other, and it cannot change whether a value is
  `shared`. Seal a value anew to share it.
- A line with no `policy`, or with the policy its value already has, is resealed only if
  its key is not the current one. The output has no policies, so it can be run again.
- For OAuth, give the refresh token the builder's `refresh` definition as its policy,
  and the access token the `api` one, or wait for the next refresh to replace it.

### Destroying a keyset

Delete every wrapped key of the keyset from the key source, including any copies in
backups, or destroy the wrapping key. Once that has taken effect, within `max_stale` or
`max_unwrap_age`, every value sealed to those keys, in every backup, is unreadable.

seal deletes the keyset's wrapped keys itself, and in a bucket every version of them:

```sh
seal destroy-keyset --config /etc/seal/seal.toml --keyset acme --confirm acme
```

Or call `DestroyKeyset` as a caller with `destroy_keysets = true` that may use the
keyset. `admin` does not allow it: give the permission to the one service that offboards
tenants, and list its keysets if they can be listed, since `["*"]` lets it end them all.
The instance that takes the call stops using the keyset at once, the others within
`max_stale`. This cannot be undone, and it does not reach backups of the key source: a
copy of the wrapped keys still opens the keyset's values while the wrapping key exists.

## Audit

One JSON line per request and per administrative call: time, caller, keyset, item, field
names, matched rule indexes, method, host, path without the query string, status, bytes
each way, duration, outcome (`ok`, `refused`, `failed` or `cancelled`) and error code. A
`verify` record has `verified`, whether the code matched: a run of `false` for one value
is someone guessing. A `presign` record has `expires_s`, how long the URL lasts: what is
done with a URL afterwards never reaches seal. Never headers, bodies, query strings or values. With `on_failure = "fail_closed"`, a record
that cannot be written fails the request rather than leave it unaudited.

A record is written when its request ends, with what happened, so the request that finds
the sink broken has already used its credential: a streamed response has been delivered
before it fails, and a Postgres session has run. seal keeps that record, up to 1024 of
them, and refuses every request after it with `INTERNAL`, before opening a value, until
the missed records are written. What goes unrecorded while the sink is broken is
therefore the requests under way when it broke, and their records follow once it works
again. `seal_audit_failures_total` counts each failed write: alert on it.

A caller refused a keyset, a value's keyset or an administrative call leaves a record
too, with the operation, the keyset and `CALLER_DENIED`: a run of them is an
application trying what it was not given. Two refusals leave none: a request over a
rate or concurrency limit, which bounds how many records a caller can cause, and a
request too malformed to name a keyset.

## Health and metrics

`/healthz` answers when the process is up, and `/readyz` when the key source answers;
the key source is asked at most once in five seconds, however often `/readyz` is.
On a loopback address the listener answers anyone on the host. On any other address
seal does not start without `metrics.token_file`, and every request must then present
the token: give it to the scraper as a bearer token, and to probes as a header.
`/metrics` is in Prometheus format, with no keyset or item labels.

## Hardening

At startup seal refuses to run as root, turns off core dumps, marks itself undumpable on
Linux, and locks memory as configured. The systemd unit adds a read-only file system, no
capabilities, a system call filter and no access to home directories. Logs go to standard
error, with only identifiers in them; audit records go to their own sink.
