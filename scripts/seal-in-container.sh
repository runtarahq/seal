#!/bin/sh
# Runs seal from a container image, with the arguments it is given, so that the test
# suite can start the image in place of the binary it built:
#
#   docker build -f deploy/container/Dockerfile -t seal .
#   SEAL_TEST_BIN="$PWD/scripts/seal-in-container.sh" \
#     cargo test --package seal --test modes --test oauth --test service
#
# The container runs as the image is meant to: read-only, with no capabilities. It
# shares the host's network and temporary directory, where the tests put their
# configuration, keys and sockets, and runs as the caller, whom the tests' Unix-socket
# configuration names. SEAL_IMAGE names another image.
set -eu
tmp="${TMPDIR:-/tmp}"
exec docker run --rm --network host --user "$(id -u):$(id -g)" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --volume "$tmp:$tmp" --env RUST_LOG --label seal-test \
  "${SEAL_IMAGE:-seal}" "$@"
