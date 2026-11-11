# seal 🦭

**The seal in tactical gear. It carries your credentials on the mission and never
hands them over.**

seal is a credential broker. Your application stores credentials it can **write but
not read**: each secret is sealed to a public key, and only seal holds the private key.

```
app ── sealed value + request without credentials ──▶ seal ── request + credential ──▶ provider
app ◀──────────────────── response ────────────────── seal ◀──────── response ──────── provider
```

seal opens the value, checks the request against the policy sealed inside it, attaches
the credential, sends the request itself, and streams the response back.

## Why

A compromised application can ask seal to *use* a credential, only toward the
destination it was sealed for, and seal logs every use. It cannot *copy* one. Use ends
when the breach is closed; a copied credential does not.

The one exception is opt-in: a rule may allow presigned storage URLs, which are copies
that expire. The limits of the guarantee are in the [threat model](docs/threat-model.md).

## What it handles

- **HTTP APIs**: static credentials, every OAuth flow, SigV4, Azure Shared Key, client
  certificates
- **Postgres** sessions
- **Webhooks**: checking a signature against a sealed signing secret
- **Sealing in the browser**, with a WASM build that needs only the public key

## Deployment modes

One implementation behind one client interface (`seal-client`), chosen by configuration:

| Mode | Where the private keys are | What a compromised application gets |
|---|---|---|
| Library (in-process) | In the application's memory | Everything |
| Process on the same host | In another process, under another OS user | Use, not copies, unless the attacker also gets root on the host |
| Separate machine | On the seal host | Use, not copies, even with root on the application's host |

## Get started

- **Run it**: [`docs/operations.md`](docs/operations.md) and [`deploy/`](deploy), with a
  systemd unit, example configurations and the container image `ghcr.io/runtarahq/seal`
- **Integrate an application**: [`docs/integrating.md`](docs/integrating.md), then
  [`policy`](docs/policy.md), [`oauth`](docs/oauth.md), [`signing`](docs/signing.md),
  [`postgres`](docs/postgres.md)
- **Check the claims**: [`threat model`](docs/threat-model.md),
  [`acceptance`](docs/acceptance.md), [`reviews`](docs/reviews)
- **Internals**: [`format`](docs/format.md), [`protocol`](docs/protocol.md),
  [`dependencies`](docs/dependencies.md)
- **Project**: [`CHANGELOG`](CHANGELOG.md), [`CONTRIBUTING`](CONTRIBUTING.md),
  [`SECURITY`](SECURITY.md)

## Compatibility

From 0.1.0: values sealed today open in every later version (envelope `v: 1`), the
policy schema changes only by addition and never weakens a guarantee by default, and
the wire protocol `seal.v1` is stable. Breaking changes go to `seal.v2`.

## License

[Apache-2.0](LICENSE).
