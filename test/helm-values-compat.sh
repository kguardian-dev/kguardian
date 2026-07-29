#!/usr/bin/env bash
# G4 chart values-compatibility gate (SIMPLIFICATION-GOAL.md §3).
#
# Renders the CURRENT chart with the value sets real operators are running —
# especially the legacy per-component AI flags that predate the ai.enabled
# umbrella — and asserts each still renders and produces the expected
# workloads. This guards the charter's "upgrade for a year without a migration
# guide" promise: a `helm upgrade` onto the new chart with an old values file
# must never break. A fast template-render check (no cluster), complementing
# the ct install-on-kind job.
set -euo pipefail

CHART="$(cd "$(dirname "$0")/../charts/kguardian" && pwd)"
fail=0

# render <name> <helm-args...> — template the chart, capture output or fail.
render() {
  local name="$1"; shift
  if ! OUT="$(helm template compat "$CHART" "$@" 2>/dev/null)"; then
    echo "FAIL [$name]: chart did not render with: $*"
    fail=1
    return 1
  fi
  return 0
}

# assert_has <label> <needle> — OUT must contain needle.
assert_has() { grep -q "$2" <<<"$OUT" || { echo "FAIL [$1]: expected to find '$2'"; fail=1; }; }
# assert_absent <label> <needle> — OUT must NOT contain needle.
assert_absent() { grep -q "$2" <<<"$OUT" && { echo "FAIL [$1]: did not expect '$2'"; fail=1; } || true; }
# assert_deploys <label> <n> — exactly n Deployment workloads.
assert_deploys() {
  local got; got="$(grep -c '^kind: Deployment' <<<"$OUT" || true)"
  [ "$got" = "$2" ] || { echo "FAIL [$1]: expected $2 Deployments, got $got"; fail=1; }
}

echo "G4 chart values-compatibility check"

# 1. Defaults: core only, no AI workloads.
render "defaults" && {
  assert_deploys "defaults" 4
  assert_has     "defaults" "kguardian-broker"
  assert_absent  "defaults" "kguardian-llm-bridge"
  assert_absent  "defaults" "kguardian-mcp-server"
}

# 2. LEGACY per-component AI flags (pre-ai.enabled operators) must still work.
# The retired mcpServer.enabled / advisor.enabled keys are still passed here on
# purpose: an operator upgrading with an OLD values file that sets them must
# render without error (Helm ignores unknown values) and must NOT resurrect the
# retired workloads. The assistant is now a single workload (llm-bridge).
render "legacy-ai-flags" \
  --set llmBridge.enabled=true --set mcpServer.enabled=true --set advisor.enabled=true && {
  assert_deploys "legacy-ai-flags" 5
  assert_has     "legacy-ai-flags" "kguardian-llm-bridge"
  assert_absent  "legacy-ai-flags" "kguardian-mcp-server"
  assert_absent  "legacy-ai-flags" "kguardian-advisor"
}

# 3. New ai.enabled umbrella renders the single-workload assistant.
render "ai-umbrella" --set ai.enabled=true && {
  assert_deploys "ai-umbrella" 5
  assert_has     "ai-umbrella" "kguardian-llm-bridge"
  assert_absent  "ai-umbrella" "kguardian-mcp-server"
  assert_absent  "ai-umbrella" "kguardian-advisor"
}

# 3b. One-line provider path (ai.provider + ai.secret) wires the right env var.
render "ai-provider" --set ai.enabled=true --set ai.provider=anthropic --set ai.secret=my-llm-key && {
  assert_has "ai-provider" "ANTHROPIC_API_KEY"
  assert_has "ai-provider" "name: my-llm-key"
}

# 4. External database (database.enabled=false) must render with no bundled DB.
render "external-db" \
  --set database.enabled=false --set database.external.host=pg.example.com && {
  # External DB: core drops from 4 Deployments to 3 (no bundled postgres).
  # The kguardian-db-credentials Secret still renders (it holds the external
  # creds), so assert on the workload count, not the name string.
  assert_deploys "external-db" 3
  assert_has     "external-db" "kguardian-broker"
}

# 5. Broker bearer-token auth must render given the required existingSecret.
render "broker-auth" \
  --set broker.auth.enabled=true --set broker.auth.existingSecret=kg-broker-token && {
  assert_has "broker-auth" "kguardian-broker"
}

if [ "$fail" -ne 0 ]; then
  echo "G4 values-compatibility check FAILED"
  exit 1
fi
echo "G4 values-compatibility check passed"
