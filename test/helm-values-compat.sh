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
# assert_render_fails <label> <needle> <helm-args...> — the chart must REFUSE to
# render, and the error must mention needle. For guards that are supposed to
# stop a dangerous config at template time rather than ship it to the cluster.
assert_render_fails() {
  local name="$1" needle="$2"; shift 2
  local err
  if err="$(helm template compat "$CHART" "$@" 2>&1)"; then
    echo "FAIL [$name]: chart rendered, but should have refused with: $*"
    fail=1
    return
  fi
  grep -q "$needle" <<<"$err" || {
    echo "FAIL [$name]: render failed as expected but the error did not mention '$needle'"
    fail=1
  }
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

# ---------------------------------------------------------------------------
# Gateway support (ai.baseUrl / ai.model) and the external MCP endpoint.
# Both features are opt-in and default-off; these cases pin that down so a
# future change cannot start emitting them on a default install.
# ---------------------------------------------------------------------------

# 6. Defaults emit NONE of the new env vars. Deliberately a separate render
# from case 1 so the original default-install assertions stay untouched.
render "defaults-no-new-env" && {
  for v in MCP_ENABLED MCP_AUTH_TOKEN MCP_RATE_LIMIT_PER_MIN \
           OPENAI_BASE_URL ANTHROPIC_BASE_URL GEMINI_BASE_URL COPILOT_BASE_URL \
           OPENAI_MODEL ANTHROPIC_MODEL GEMINI_MODEL COPILOT_MODEL; do
    assert_absent "defaults-no-new-env" "$v"
  done
  # And the assistant itself is still off, so behaviour is wholly unchanged.
  assert_deploys "defaults-no-new-env" 4
}

# 6b. The assistant enabled WITHOUT the new keys must also emit none of them —
# this is the shape an existing operator upgrades into, and it must be a no-op.
render "ai-enabled-no-new-env" --set ai.enabled=true --set ai.provider=anthropic --set ai.secret=k && {
  assert_has    "ai-enabled-no-new-env" "ANTHROPIC_API_KEY"
  assert_absent "ai-enabled-no-new-env" "ANTHROPIC_BASE_URL"
  assert_absent "ai-enabled-no-new-env" "ANTHROPIC_MODEL"
  assert_absent "ai-enabled-no-new-env" "MCP_ENABLED"
}

# 7. ai.baseUrl / ai.model map onto the right env var for every provider.
# Note the gemini row: the API key is GOOGLE_API_KEY while the base and model
# are GEMINI_*. That asymmetry is intentional (the key is named for the vendor,
# the endpoint for the provider kguardian exposes) and the bridge reads exactly
# these names — assert it so nobody "fixes" it into a silent breakage.
while read -r provider key base model; do
  render "gateway-$provider" \
    --set ai.enabled=true --set ai.provider="$provider" --set ai.secret=k \
    --set ai.baseUrl=http://gw.example.com:4000/v1 --set ai.model=local-model-id && {
    assert_has "gateway-$provider" "$key"
    assert_has "gateway-$provider" "name: $base"
    assert_has "gateway-$provider" "name: $model"
    assert_has "gateway-$provider" "http://gw.example.com:4000/v1"
  }
done <<'PROVIDERS'
openai    OPENAI_API_KEY    OPENAI_BASE_URL    OPENAI_MODEL
anthropic ANTHROPIC_API_KEY ANTHROPIC_BASE_URL ANTHROPIC_MODEL
gemini    GOOGLE_API_KEY    GEMINI_BASE_URL    GEMINI_MODEL
copilot   GITHUB_TOKEN      COPILOT_BASE_URL   COPILOT_MODEL
PROVIDERS

# 7b. Whitespace-only counts as unset — no env var at all, rather than one
# carrying "   ". The bridge trims and would treat it as unset either way, but
# an emitted-but-blank var is a confusing thing to find in `kubectl describe`.
render "gateway-whitespace" \
  --set ai.enabled=true --set ai.provider=openai --set ai.secret=k \
  --set 'ai.baseUrl=   ' --set 'ai.model=  ' && {
  assert_has    "gateway-whitespace" "OPENAI_API_KEY"
  assert_absent "gateway-whitespace" "OPENAI_BASE_URL"
  assert_absent "gateway-whitespace" "OPENAI_MODEL"
}

# 7c. A base URL with no provider is a silent no-op waiting to happen — the
# chart cannot know which env var to write. Fail loudly instead.
assert_render_fails "gateway-no-provider" "require ai.provider" \
  --set ai.enabled=true --set ai.baseUrl=http://gw.example.com:4000/v1

# 8. MCP endpoint: enabled with a token emits MCP_ENABLED plus a secretKeyRef.
render "mcp-enabled" \
  --set ai.enabled=true --set ai.mcp.enabled=true \
  --set ai.mcp.auth.existingSecret=kguardian-mcp-token \
  --set ai.mcp.rateLimitPerMin=600 && {
  assert_has "mcp-enabled" "MCP_ENABLED"
  assert_has "mcp-enabled" "MCP_AUTH_TOKEN"
  assert_has "mcp-enabled" "name: kguardian-mcp-token"
  assert_has "mcp-enabled" "MCP_RATE_LIMIT_PER_MIN"
  # No new listener, Service or workload — /mcp rides the existing port 8080.
  assert_deploys "mcp-enabled" 5
}

# 8b. The token secretKeyRef must NOT be optional. An optional ref whose Secret
# is missing leaves MCP_AUTH_TOKEN unset, and the bridge reads unset as "no
# auth" — a typo'd Secret name would silently serve the endpoint wide open.
render "mcp-token-not-optional" \
  --set ai.enabled=true --set ai.mcp.enabled=true \
  --set ai.mcp.auth.existingSecret=kguardian-mcp-token && {
  # Extract just the MCP_AUTH_TOKEN env entry and assert it carries no
  # `optional:` line (the provider API keys above legitimately do).
  block="$(awk '/name: MCP_AUTH_TOKEN/{f=1} f&&/optional:/{print} f&&/^ *- name:/&&!/MCP_AUTH_TOKEN/{f=0}' <<<"$OUT")"
  [ -z "$block" ] || { echo "FAIL [mcp-token-not-optional]: MCP_AUTH_TOKEN must not be optional"; fail=1; }
}

# 8c. Enabling MCP with neither a token nor an explicit opt-out must REFUSE to
# render. The endpoint serves cluster telemetry to anything that can reach the
# ClusterIP Service, so insecure-by-accident is not an available outcome.
assert_render_fails "mcp-no-auth" "requires ai.mcp.auth.existingSecret" \
  --set ai.enabled=true --set ai.mcp.enabled=true

# 8d. ...but the operator can still say "yes, unauthenticated, I mean it".
# That opt-out is deliberately a value they have to write down, so it shows up
# in a values diff and in review the way a missing token never would.
render "mcp-unauthenticated-optout" \
  --set ai.enabled=true --set ai.mcp.enabled=true \
  --set ai.mcp.auth.allowUnauthenticated=true && {
  assert_has    "mcp-unauthenticated-optout" "MCP_ENABLED"
  assert_absent "mcp-unauthenticated-optout" "MCP_AUTH_TOKEN"
}

# 8e. MCP toggled on while the assistant is off renders cleanly (the value is
# inert — no llm-bridge to serve /mcp). It must not fail, and must not smuggle
# the env var into some other workload. NOTES.txt points this out to the user.
render "mcp-without-assistant" --set ai.mcp.enabled=true && {
  assert_deploys "mcp-without-assistant" 4
  assert_absent  "mcp-without-assistant" "MCP_ENABLED"
}

if [ "$fail" -ne 0 ]; then
  echo "G4 values-compatibility check FAILED"
  exit 1
fi
echo "G4 values-compatibility check passed"
