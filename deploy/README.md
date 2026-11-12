# Deploying seal

| File | For |
|---|---|
| [`systemd/seal.service`](systemd/seal.service) | A process on the same host as the application, on a Unix socket |
| [`container/Dockerfile`](container/Dockerfile) | A container, usually on a separate machine over mutual TLS |
| [`config/same-host.toml`](config/same-host.toml) | The configuration for the same host |
| [`config/separate-machine.toml`](config/separate-machine.toml) | The configuration for a separate machine |

The binary is static: build it for musl and it needs nothing from the host, whatever the
distribution.

```sh
rustup target add x86_64-unknown-linux-musl     # and a musl C compiler, such as musl-tools
cargo build --release --locked --package seal --target x86_64-unknown-linux-musl
```

Wrapping with a key in AWS KMS links the AWS SDK, and a build leaves it out unless
asked: add `--features aws-kms` to that command. The container image has it; build one
without with `--build-arg FEATURES=` to `docker build`.

The container image is that binary alone, `FROM scratch`: no libc, shell or package
manager. It runs as uid 65532.

[`docs/operations.md`](../docs/operations.md) explains the modes, every setting, sizing,
key management and rotation. Before starting, run `seal check-config --config <file>`: it
validates the configuration and prints how the memory ceiling adds up.
