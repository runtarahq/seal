# seal

seal is a credential broker. An application stores credentials it can **write
but not read**: each secret is sealed to a public key, and only seal holds the
private key. To use a credential, the application hands seal the sealed value
and a request with no credentials. seal opens the value, checks the request
against a policy sealed inside it, attaches the credential, sends the request
itself, and streams the response back.

A compromised application can ask seal to *use* a credential, only toward the
destination it was sealed for, and seal logs every use. It cannot *copy* one.
Use ends when the breach is closed; a copied credential does not. The limits of
that guarantee are in the [threat model](docs/threat-model.md).

## Status

Sealed values, the HTTP broker, key management, the service (on a Unix socket or
over mutual TLS), `seal-client`, every OAuth flow, SigV4, Azure Shared Key and client
certificates toward providers are implemented, and pass the same tests in all three
modes, as do Postgres sessions and checking a webhook's signature against a sealed
signing secret.

## Deployment modes

One implementation behind one client interface, chosen by configuration:

| Mode | Where the private keys are | What a compromised application gets |
|---|---|---|
| Library (in-process) | In the application's memory | Everything |
| Process on the same host | In another process, under another OS user | Use, not copies, unless the attacker also gets root on the host |
| Separate machine | On the seal host | Use, not copies, even with root on the application's host |

## Documents

- [`CHANGELOG.md`](CHANGELOG.md): what each release changed
- [`docs/threat-model.md`](docs/threat-model.md): what seal does and does not
  protect against
- [`docs/format.md`](docs/format.md): the sealed value format
- [`docs/policy.md`](docs/policy.md): every policy option, with examples
- [`docs/oauth.md`](docs/oauth.md): running each OAuth flow with seal
- [`docs/signing.md`](docs/signing.md): SigV4, Azure Shared Key and client certificates
- [`docs/postgres.md`](docs/postgres.md): Postgres sessions through seal
- [`docs/dependencies.md`](docs/dependencies.md): every direct dependency, and why
- [`docs/protocol.md`](docs/protocol.md): the gRPC protocol and error codes
- [`docs/operations.md`](docs/operations.md): running seal, configuration, keys and
  rotation
- [`docs/integrating.md`](docs/integrating.md): how an application should store and use
  sealed values
- [`deploy/`](deploy): a systemd unit, a container image and example configurations
- [`docs/acceptance.md`](docs/acceptance.md): what seal guarantees, and the tests that
  show it
- [`docs/reviews/`](docs/reviews): the reviews of secret handling and fuzzing, and the
  scope for an external review
- [`CONTRIBUTING.md`](CONTRIBUTING.md): the rules for changes
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability

## Compatibility

From 0.1.0:

- Envelope `v: 1` and its associated data encoding are stable: values sealed by 0.1.0
  open in every later version.
- The policy schema changes only by addition within `v: 1`, and an option that weakens
  a guarantee is never added with a default other than off.
- The wire protocol `seal.v1` is stable; breaking changes go to `seal.v2`.

## License

[Apache-2.0](LICENSE).
