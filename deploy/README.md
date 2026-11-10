# Deploying seal

| File | For |
|---|---|
| [`systemd/seal.service`](systemd/seal.service) | A process on the same host as the application, on a Unix socket |
| [`container/Dockerfile`](container/Dockerfile) | A container, usually on a separate machine over mutual TLS |
| [`config/same-host.toml`](config/same-host.toml) | The configuration for the same host |
| [`config/separate-machine.toml`](config/separate-machine.toml) | The configuration for a separate machine |

[`docs/operations.md`](../docs/operations.md) explains the modes, every setting, sizing,
key management and rotation. Before starting, run `seal check-config --config <file>`: it
validates the configuration and prints how the memory ceiling adds up.
