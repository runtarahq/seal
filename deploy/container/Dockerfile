# seal as a container, for a separate machine or a sidecar. See docs/operations.md.
#
#   docker build -f deploy/container/Dockerfile -t seal .
#   docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
#     --memory=2g --ulimit memlock=2147483648 \
#     -v /etc/seal:/etc/seal:ro -v seal-keys:/var/lib/seal/keys -p 7443:7443 seal

# Alpine's own target is musl, so the binary links statically with no cross-compiler.
# The C compiler is for `ring`, the one dependency that is not Rust.
FROM rust:1.99.1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
RUN cargo build --release --locked --package seal \
    && install -D -m 0755 target/release/seal /out/seal

# Nothing but the binary: no libc, no shell and no package manager. TLS roots are
# compiled in, and the runtime supplies /etc/resolv.conf.
FROM scratch
COPY --from=build /out/seal /usr/local/bin/seal
# Not root, which seal refuses to run as. The same id as distroless's `nonroot`.
USER 65532:65532
EXPOSE 7443
ENTRYPOINT ["/usr/local/bin/seal"]
CMD ["serve", "--config", "/etc/seal/seal.toml"]
