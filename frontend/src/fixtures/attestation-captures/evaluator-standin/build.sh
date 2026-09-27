#!/usr/bin/env bash
# Build the evaluator stand-in (main.go) into $1, offline.
#
# main.go imports the evaluator's own packages. The module is made in a
# temporary directory at build time (a replace onto this checkout's
# evaluator/, the evaluator's go.sum), so no go.mod lives in frontend/ for
# dependency scanners and updaters to pick up. Offline: GOPROXY=off and
# GOTOOLCHAIN=local, so it only uses modules already in the Go module cache
# (the ones building the evaluator fetched) and the installed Go.
set -euo pipefail
out=${1:?usage: build.sh <output binary>}
here=$(cd "$(dirname "$0")" && pwd)
evaluator=$(cd "$here/../../../../../evaluator" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$here/main.go" "$tmp/"
cat > "$tmp/go.mod" <<MOD
module kguardian-fixtures/evaluator-standin

go 1.26.0

require github.com/kguardian-dev/kguardian/evaluator v0.0.0

replace github.com/kguardian-dev/kguardian/evaluator => $evaluator
MOD
cp "$evaluator/go.sum" "$tmp/go.sum"
cd "$tmp"
export GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod
go mod tidy
go vet .
go build -o "$out" .
echo "built $out"
