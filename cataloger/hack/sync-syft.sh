#!/usr/bin/env bash
# Set the cataloger's syft and stereoscope to the versions the supplychain
# matcher resolves through grype, then tidy and re-run the lock check.
#
# Syft usually releases ahead of Grype, so the cataloger never takes a
# Syft bump on its own (Renovate ignores syft/stereoscope in
# cataloger/go.mod). When a Grype bump moves the matcher's Syft, run this
# on that branch and commit the result; cataloger-difftest.yaml then
# re-proves the resolver against the new Syft.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)

version() { # go.mod module
  awk -v m="$2" '$1 == m { print $2 } $1 == "require" && $2 == m { print $3 }' "$1" | head -1
}

args=()
for mod in github.com/anchore/syft github.com/anchore/stereoscope; do
  v=$(version "$repo/supplychain-matcher/go.mod" "$mod")
  if [ -z "$v" ]; then
    echo "$mod not found in supplychain-matcher/go.mod" >&2
    exit 1
  fi
  args+=("$mod@$v")
done

cd "$repo/cataloger"
go get "${args[@]}"
go mod tidy
"$repo/cataloger/hack/check-syft-version.sh"
