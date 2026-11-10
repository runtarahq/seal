# seal as a container, for a separate machine or a sidecar. See docs/operations.md.
#
#   docker build -f deploy/container/Dockerfile -t seal .
#   docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
#     --memory=2g --ulimit memlock=2147483648 \
#     -v /etc/seal:/etc/seal:ro -v seal-keys:/var/lib/seal/keys -p 7443:7443 seal

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --package seal \
    && install -D -m 0755 target/release/seal /out/seal

# No shell and no package manager: only the binary and what TLS needs.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/seal /usr/local/bin/seal
USER nonroot:nonroot
EXPOSE 7443
ENTRYPOINT ["/usr/local/bin/seal"]
CMD ["serve", "--config", "/etc/seal/seal.toml"]
