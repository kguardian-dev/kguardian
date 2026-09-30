#!/usr/bin/env bash
# Run the capability-model tests (build tag "privileged") in containers set
# up like the worker: uid 0, every capability dropped except the ones under
# test, no-new-privileges, Docker's default seccomp profile (the closest
# local stand-in for RuntimeDefault).
#
#   model (i):  DAC_READ_SEARCH + SETUID + SETGID  -> ambient caps in the child
#   model (ii): SETUID + SETGID                    -> no DAC_READ_SEARCH
#
# Needs docker and Go. Creates and removes only its own containers.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
image=${KG_PRIV_TEST_IMAGE:-debian:12-slim}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

arch=$(docker version --format '{{.Server.Arch}}')
(cd "$here" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -tags privileged -o "$out/server.test" ./internal/server)
chmod 0755 "$out" "$out/server.test"

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
