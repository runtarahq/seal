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
[configuration](../deploy/config/separate-machine.toml). Callers present a client
certificate from the CA in `listen.tls.client_ca`, and are identified by its subject.
Certificates are short-lived: seal checks its certificate files every
`listen.reload_interval` and swaps them in. A change that does not load is logged and
the old certificates kept, so a half-written renewal cannot take seal down. Connections
already open keep the certificate they started with.

## Configuration reference

Unknown settings are errors. Durations are written like `100ms`, `60s`, `15m` or `8h`,
sizes like `65536`, `256KiB` or `1GiB`, and rates like `1000/s` or `60/m`. seal refuses a
configuration file that its group or others can write.

### `[listen]`

| Setting | Default | |
|---|---|---|
| `unix` | | A socket path, in a directory only seal's user can write: seal refuses one its group or others can write, where the socket could be replaced. Callers then need `unix_uid` |
| `tcp`, `tls` | | An address, with `{ cert, key, client_ca }` in PEM. Callers then need `cert_subject` |
| `reload_interval` | `10s` | How often certificate files are checked |

### `[[callers]]`

| Setting | |
|---|---|
| `name` | The name in audit records |
| `unix_uid` or `cert_subject` | Exactly one, matching the listener |
| `keysets` | The keysets it may use, or `["*"]` for all |
| `admin` | Whether it may generate keysets, rotate and list public keys. Default `false` |

A `cert_subject` is the certificate's whole subject, attribute by attribute and in the
certificate's order, such as `CN=app,O=Example`. Attribute names and the spaces around
separators do not matter; values are compared exactly. A certificate whose subject has
a comma in a value, or more than one attribute in a relative distinguished name, is
refused, because it could not be told from another subject once written down. The
client CA should issue certificates for seal's callers only: seal checks the subject,
not the subject alternative names.

### `[keys]`

| Setting | Default | |
|---|---|---|
| `source` | | `{ dir = "…" }`, or `{ http = { url, ca, cert, key } }` for a key service with a client certificate |
| `wrap` | | `{ file = "…" }`: 32 bytes readable only by seal's user |
| `idle_evict` | `15m` | A keyset unused this long is dropped from memory |
| `refresh_interval` | `60s` | How often a loaded keyset is fetched again |
| `max_stale` | `5m` | A keyset not fetched successfully this long is dropped |
| `max_unwrap_age` | `1h` | A key not unwrapped this long is dropped |
| `max_loaded_keysets` | `1024` | The least recently used goes first |
| `max_keys_per_keyset` | `16` | `rotate` refuses past this |
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
| `limits.rate_per_keyset` | `200/s` | |
| `limits.memory_budget` | `2GiB` | seal refuses to start if the ceiling is over it |
| `audit.sink` | `"stdout"` | Or `{ file = "…" }`, created readable only by seal's user. A file already there is refused if its group can write it or others can reach it |
| `audit.on_failure` | `fail_closed` | `best_effort` is for development only |
| `metrics.listen` | none | Serves `/metrics`, `/healthz` and `/readyz` |

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

Or call `GenerateKeyset` as an admin caller, which returns the public key and the wrapped
private key. With a directory source, seal stores it; with a read-only source, the
application stores it.

Instances do not coordinate. Each re-reads the key source for the keysets it has loaded
every `refresh_interval`, and at once, at most every 30 seconds, when a value names a key
it has not seen. So:

- A key added to the source reaches every instance within `max_stale`, normally within
  `refresh_interval`.
- A key deleted from the source stops opening on every instance within `max_stale`.
- Revoking or destroying the wrapping key takes effect within `max_unwrap_age`.
- None of these interrupts a request already running.

If the key source is unreachable, loaded keysets keep working for `max_stale`, then return
`KEYS_UNAVAILABLE`. If the wrapping key is unavailable, they keep working until each key's
`max_unwrap_age`.

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

## Audit

One JSON line per request and per administrative call: time, caller, keyset, item, field
names, matched rule indexes, method, host, path without the query string, status, bytes
each way, duration, outcome (`ok`, `refused`, `failed` or `cancelled`) and error code. A
`verify` record has `verified`, whether the code matched: a run of `false` for one value
is someone guessing. A `presign` record has `expires_s`, how long the URL lasts: what is
done with a URL afterwards never reaches seal. Never headers, bodies, query strings or values. With `on_failure = "fail_closed"`, a record
that cannot be written fails the request rather than leave it unaudited.

A caller refused a keyset, a value's keyset or an administrative call leaves a record
too, with the operation, the keyset and `CALLER_DENIED`: a run of them is an
application trying what it was not given. Two refusals leave none: a request over a
rate or concurrency limit, which bounds how many records a caller can cause, and a
request too malformed to name a keyset.

## Health and metrics

`/healthz` answers when the process is up, and `/readyz` when the key source answers.
`/metrics` is in Prometheus format, with no keyset or item labels.

## Hardening

At startup seal refuses to run as root, turns off core dumps, marks itself undumpable on
Linux, and locks memory as configured. The systemd unit adds a read-only file system, no
capabilities, a system call filter and no access to home directories. Logs go to standard
error, with only identifiers in them; audit records go to their own sink.
