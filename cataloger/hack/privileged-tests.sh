#!/usr/bin/env bash
# Run the capability-model tests (build tag "privileged") in containers set
# up like the worker: uid 0, every capability dropped except the ones under
# test, no-new-privileges, Docker's default seccomp profile (the closest
# local stand-in for RuntimeDefault).
#
#   model (i):  DAC_READ_SEARCH + SETUID + SETGID  -> ambient caps in the child
#   model (ii): SETUID + SETGID                    -> no DAC_READ_SEARCH
#
# Then the resolver tests that need real mounts and device nodes (mount
# crossing, a mount appearing mid-scan, /proc magic links, devices), in a
# --privileged container.
#
# Needs docker and Go. Creates and removes only its own containers.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
image=${KG_PRIV_TEST_IMAGE:-debian:12-slim}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

arch=$(docker version --format '{{.Server.Arch}}')
(cd "$here" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -tags privileged -o "$out/server.test" ./internal/server)
(cd "$here" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -tags privileged -o "$out/rootfs.test" ./internal/rootfs)
chmod 0755 "$out" "$out/server.test" "$out/rootfs.test"

run() { # model caps...
  local model=$1
  shift
  local args=(--rm --name "kgc-priv-$model-$$" --user 0 --cap-drop ALL --security-opt no-new-privileges
    -e KG_EXPECT_MODEL="$model" -v "$out:/t:ro")
  for c in "$@"; do args+=(--cap-add "$c"); done
  echo "== model ($model): caps $*"
  docker run "${args[@]}" "$image" /t/server.test -test.v -test.count=1 -test.run 'TestCapsModel|TestScanRoundTrip|TestTimeout|TestImmediate|TestBusy|TestClosing|TestOOM|TestTempSpace|TestFileBudget|TestComponentBudget|TestNoPackages|TestChildrenInherit'
}

run i DAC_READ_SEARCH SETUID SETGID
run ii SETUID SETGID

echo "== resolver with real mounts (--privileged)"
docker run --rm --name "kgc-priv-rootfs-$$" --privileged -e KG_PRIVILEGED_ROOTFS=1 -v "$out:/t:ro" \
  "$image" /t/rootfs.test -test.v -test.count=1
