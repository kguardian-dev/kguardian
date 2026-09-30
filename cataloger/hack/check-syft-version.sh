#!/usr/bin/env bash
# The cataloger produces the SBOMs the supplychain matcher feeds to Grype,
# so both must resolve the same Syft (package types, PURLs and metadata
# must be what Grype's matchers expect), and the same stereoscope (the
# cataloger's resolver reuses stereoscope's filetree search; the
# differential test proves it against that exact version). Fail if either
# module drifts from the other.
#
# Run from anywhere in the repository. Reads go.mod only (no Go needed):
# since Go 1.17 go.mod lists every module in the build, so the matcher's
# go.mod records the Syft version Grype resolves to.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
status=0

version() { # go.mod module
  awk -v m="$2" '$1 == m { print $2 } $1 == "require" && $2 == m { print $3 }' "$1" | head -1
}

for mod in github.com/anchore/syft github.com/anchore/stereoscope; do
  cat_v=$(version "$repo/cataloger/go.mod" "$mod")
  match_v=$(version "$repo/supplychain-matcher/go.mod" "$mod")
  if [ -z "$cat_v" ] || [ -z "$match_v" ]; then
    echo "::error::$mod missing from cataloger/go.mod ('$cat_v') or supplychain-matcher/go.mod ('$match_v')"
    status=1
  elif [ "$cat_v" != "$match_v" ]; then
    echo "::error::$mod differs: cataloger $cat_v, supplychain-matcher (via grype) $match_v. Bump both together (Renovate group 'syft-grype')."
    status=1
  else
    echo "$mod $cat_v in both modules"
  fi
done
for f in cataloger/go.mod supplychain-matcher/go.mod; do
  if grep -Eq '^\s*replace\s.*anchore/(syft|stereoscope)|^\s*github.com/anchore/(syft|stereoscope)\s.*=>' "$repo/$f"; then
    echo "::error::$f replaces syft or stereoscope; the lock-step check would be meaningless"
    status=1
  fi
done
exit $status
