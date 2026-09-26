#!/usr/bin/env bash
# G4 chart values-compatibility gate.
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
# assert_cgroup_volume <label> — the cgroupfs hostPath volume is declared.
# Matched on the hostPath block rather than on `name: cgroupfs`, which the
# volumeMount also carries: the two halves are gated separately in the
# template and a check that cannot tell them apart passes when only one
# renders. See the compute-off case for what that costs.
assert_cgroup_volume() {
  grep -A2 '^      - name: cgroupfs' <<<"$OUT" | grep -q 'path: /sys/fs/cgroup' || \
    { echo "FAIL [$1]: expected a cgroupfs hostPath volume"; fail=1; }
}
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

# 5. Broker auth. Default (off): no token env anywhere, so a default install
# is byte-for-byte what it was.
render "broker-auth-off" && {
  assert_absent "broker-auth-off" "BROKER_AUTH_TOKEN"
  assert_absent "broker-auth-off" "BROKER_TOKEN_"
}

# workload <kind> <name> — the one rendered document of that kind and name.
workload() {
  awk -v k="kind: $1" -v n="  name: $2" 'BEGIN { RS = "\n---\n" }
    index($0, k "\n") && index($0, "\n" n "\n") { print }' <<<"$OUT"
}
# assert_client_key <label> <kind> <name> <key> — the workload's
# BROKER_AUTH_TOKEN comes from Secret key <key>.
assert_client_key() {
  local got
  got="$(workload "$2" "$3" | { grep -A4 'name: BROKER_AUTH_TOKEN' || true; } | sed -n 's/^ *key: //p')"
  [ "$got" = "$4" ] || { echo "FAIL [$1]: $2/$3 BROKER_AUTH_TOKEN key: want '$4', got '$got'"; fail=1; }
}

# 5a. Scoped auth (the default mode): each client mounts only its scope's key,
# the broker gets one env per scope, and the optional scopes stay optional.
render "broker-auth-scoped" \
  --set broker.auth.enabled=true --set broker.auth.existingSecret=kg-broker-token \
  --set llmBridge.enabled=true && {
  assert_client_key "broker-auth-scoped" DaemonSet  kguardian-controller ingest
  assert_client_key "broker-auth-scoped" Deployment kguardian-frontend   read
  assert_client_key "broker-auth-scoped" Deployment kguardian-llm-bridge read
  # Captured, not piped into grep -q: under pipefail an early-exiting grep
  # SIGPIPEs awk and fails the pipeline at random.
  broker_doc="$(workload Deployment kguardian-broker)"
  for v in READ INGEST SUPPLYCHAIN ADMIN; do
    grep -q "name: BROKER_TOKEN_$v" <<<"$broker_doc" || \
      { echo "FAIL [broker-auth-scoped]: broker lacks BROKER_TOKEN_$v"; fail=1; }
  done
  grep -q 'name: BROKER_AUTH_TOKEN' <<<"$broker_doc" && \
    { echo "FAIL [broker-auth-scoped]: broker must not get the legacy shared token"; fail=1; }
  # read/ingest are required keys; supplychain/admin optional while unused.
  [ "$(grep -c 'optional: true' <<<"$broker_doc")" = "2" ] || \
    { echo "FAIL [broker-auth-scoped]: expected exactly 2 optional token keys"; fail=1; }
}

# 5b. Legacy shared mode: the same values file an operator used before
# scopes (existingSecret + secretKey) still renders, with every component on
# the one key.
render "broker-auth-shared" \
  --set broker.auth.enabled=true --set broker.auth.existingSecret=kg-broker-token \
  --set broker.auth.mode=shared --set broker.auth.secretKey=token && {
  assert_client_key "broker-auth-shared" DaemonSet  kguardian-controller token
  assert_client_key "broker-auth-shared" Deployment kguardian-broker     token
  assert_absent     "broker-auth-shared" "BROKER_TOKEN_"
  # The shared token can write, so the frontend doesn't get it by default.
  assert_client_key "broker-auth-shared" Deployment kguardian-frontend   ""
}
render "broker-auth-shared-frontend-optin" \
  --set broker.auth.enabled=true --set broker.auth.existingSecret=kg-broker-token \
  --set broker.auth.mode=shared --set frontend.brokerAuth.allowSharedToken=true && {
  assert_client_key "broker-auth-shared-frontend-optin" Deployment kguardian-frontend token
}

# 5c. Custom key names are honoured.
render "broker-auth-custom-keys" \
  --set broker.auth.enabled=true --set broker.auth.existingSecret=kg \
  --set broker.auth.keys.read=ui-token --set broker.auth.keys.ingest=node-token && {
  assert_client_key "broker-auth-custom-keys" Deployment kguardian-frontend   ui-token
  assert_client_key "broker-auth-custom-keys" DaemonSet  kguardian-controller node-token
}

# 5d. Guards.
assert_render_fails "broker-auth-no-secret" "broker.auth.existingSecret is required" \
  --set broker.auth.enabled=true
assert_render_fails "broker-auth-bad-mode" "broker.auth.mode must be" \
  --set broker.auth.enabled=true --set broker.auth.existingSecret=kg --set broker.auth.mode=open
# Supply-chain data never ships from an open broker, nor with a shared token.
assert_render_fails "supplychain-needs-auth" "supplychain.enabled=true requires broker.auth.enabled=true" \
  --set supplychain.enabled=true
assert_render_fails "supplychain-needs-scoped" "requires broker.auth.mode=scoped" \
  --set supplychain.enabled=true --set broker.auth.enabled=true \
  --set broker.auth.existingSecret=kg --set broker.auth.mode=shared
render "supplychain-with-auth" \
  --set supplychain.enabled=true --set broker.auth.enabled=true --set broker.auth.existingSecret=kg && {
  # With a supply-chain component on, its key becomes required.
  [ "$(workload Deployment kguardian-broker | grep -c 'optional: true')" = "1" ] || \
    { echo "FAIL [supplychain-with-auth]: the supplychain key must be required"; fail=1; }
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

# ---------------------------------------------------------------------------
# Compute gauges (values.yaml `compute`). The master switch owns BOTH the
# read-only /sys/fs/cgroup hostPath and the controller's COMPUTE_* env; the
# broker's retention/threshold env renders regardless so a disabled cluster
# still prunes what it collected. Pinned here so a refactor cannot start
# mounting cgroupfs on an operator who turned the feature off.
# ---------------------------------------------------------------------------

# 9. Defaults: gauges on, scheduler probe off, cgroupfs mounted read-only.
render "compute-defaults" && {
  assert_has "compute-defaults" "name: COMPUTE_ENABLED"
  assert_has "compute-defaults" "name: COMPUTE_CONTENTION_ENABLED"
  assert_has "compute-defaults" "name: cgroupfs"
  assert_has "compute-defaults" "path: /sys/fs/cgroup"
  assert_has "compute-defaults" "name: COMPUTE_HISTORY_RETENTION_DAYS"
  assert_has "compute-defaults" "name: COMPUTE_THRESHOLD_BLAME_SHARE"
  grep -A1 'name: COMPUTE_THRESHOLD_REFAULT_PER_MIN' <<<"$OUT" | grep -q 'value: "1000"' || \
    { echo "FAIL [compute-defaults]: COMPUTE_THRESHOLD_REFAULT_PER_MIN must default to 1000"; fail=1; }
  grep -A1 'name: COMPUTE_THRESHOLD_MIN_RUNQ_EVENTS' <<<"$OUT" | grep -q 'value: "50"' || \
    { echo "FAIL [compute-defaults]: COMPUTE_THRESHOLD_MIN_RUNQ_EVENTS must default to 50"; fail=1; }
  grep -q 'name: COMPUTE_CONTENTION_ENABLED' <<<"$OUT" && \
    grep -A1 'name: COMPUTE_CONTENTION_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [compute-defaults]: COMPUTE_CONTENTION_ENABLED must default to false"; fail=1; }
  assert_deploys "compute-defaults" 4
}

# 9b. compute.enabled=false: COMPUTE_ENABLED=false is still rendered (the
# controller must not fall back to its own default), and no sampler env, no
# probe env.
#
# The cgroup mount is deliberately NOT asserted absent here any more. It used
# to be compute-specific, and this case pinned that. Denial attribution now
# resolves a cgroup id to a container through the same registry — that is how
# a `hostNetwork: true` pod's denials reach the right workload, since every
# such pod shares one network namespace inode — so the mount renders under
# `or compute.enabled seccomp.denials.enabled`. Asserting it absent on
# compute alone would pin the coupling that made the denial fix inert.
# 9b-ii below covers the case where it really must not render.
render "compute-off" --set compute.enabled=false && {
  assert_has    "compute-off" "name: COMPUTE_ENABLED"
  assert_absent "compute-off" "COMPUTE_SAMPLE_INTERVAL_SECS"
  assert_absent "compute-off" "COMPUTE_CONTENTION_ENABLED"
  assert_absent "compute-off" "COMPUTE_MIN_RUNQ_LATENCY_US"
  # Broker-side retention still renders: prune what was collected.
  assert_has    "compute-off" "name: COMPUTE_HISTORY_RETENTION_DAYS"
  # ... and with denial capture at its default (on), the mount IS present,
  # because the cgroup is what identifies the container the verdict came from.
  #
  # Both halves are asserted separately, and that is the point. `name:
  # cgroupfs` appears twice in a correct render — once on the volumeMount and
  # once on the volume — so a bare `assert_has` for it is satisfied by either
  # one alone. Re-couple only the volumeMount to compute and the volume still
  # renders, the substring is still found, and the check passes while the
  # controller gets a volume it never mounts: `/sys/fs/cgroup` inside the pod
  # is then its own cgroup directory rather than the host root, no container
  # resolves, and every hostNetwork workload reports no denials. `mountPath:`
  # is unique to the mount and `hostPath:` to the volume.
  assert_has    "compute-off" "mountPath: /sys/fs/cgroup"
  assert_cgroup_volume "compute-off"
}

# 9b-ii. Both consumers off: the mount and its volume disappear entirely.
# This is the assertion that keeps the mount honest — it must be tied to
# something wanting it, not rendered unconditionally.
render "cgroup-consumers-off" --set compute.enabled=false \
  --set seccomp.denials.enabled=false && {
  assert_absent "cgroup-consumers-off" "name: cgroupfs"
  assert_absent "cgroup-consumers-off" "path: /sys/fs/cgroup"
}

# 9c. Scheduler probe on: same mount, probe env flips, filter propagates.
render "compute-contention" --set compute.contention.enabled=true \
  --set compute.contention.minRunqLatencyUs=250 && {
  assert_has "compute-contention" "name: cgroupfs"
  grep -A1 'name: COMPUTE_CONTENTION_ENABLED' <<<"$OUT" | grep -q 'value: "true"' || \
    { echo "FAIL [compute-contention]: COMPUTE_CONTENTION_ENABLED must render true"; fail=1; }
  grep -A1 'name: COMPUTE_MIN_RUNQ_LATENCY_US' <<<"$OUT" | grep -q 'value: "250"' || \
    { echo "FAIL [compute-contention]: COMPUTE_MIN_RUNQ_LATENCY_US must carry the configured value"; fail=1; }
}

# 9d. retentionDays: 0 (disable history) must propagate — a `with` guard would
# swallow the zero, the same trap the audit retention block documents.
render "compute-history-off" --set compute.history.retentionDays=0 && {
  grep -A1 'name: COMPUTE_HISTORY_RETENTION_DAYS' <<<"$OUT" | grep -q 'value: "0"' || \
    { echo "FAIL [compute-history-off]: COMPUTE_HISTORY_RETENTION_DAYS=0 must propagate"; fail=1; }
}

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

# 9. GitOps inputs: values a kustomize/Argo CD consumer would otherwise have to
# patch into the rendered output. Each defaults to today's behaviour, so an
# existing values file keeps rendering identically.

# 9a. Defaults render no priorityClassName anywhere and keep the /api ingress
# path, so nothing changes for operators who never set these.
render "gitops-defaults" --set frontend.ingress.enabled=true && {
  assert_absent "gitops-defaults" "priorityClassName"
  assert_absent "gitops-defaults" "updateStrategy"
  assert_has    "gitops-defaults" "path: /api"
}

# 9b. global.priorityClassName reaches every workload, including the in-cluster
# database and the assistant, and a per-component value wins over it.
render "gitops-priorityclass" \
  --set global.priorityClassName=medium-priority \
  --set broker.priorityClassName=high-priority \
  --set ai.enabled=true --set ai.provider=openai --set ai.secret=k && {
  assert_has "gitops-priorityclass" "high-priority"
  # 5 of the 6 workloads take the global; the Broker takes its override.
  got="$(grep -c 'priorityClassName: "medium-priority"' <<<"$OUT" || true)"
  [ "$got" = "5" ] || { echo "FAIL [gitops-priorityclass]: expected 5 global, got $got"; fail=1; }
}

# 9c. The Controller DaemonSet accepts an updateStrategy. Without one, Kubernetes
# updates a single node at a time and a node that refuses the pod holds that slot
# indefinitely, stalling the rollout for every remaining node.
render "gitops-updatestrategy" \
  --set controller.updateStrategy.rollingUpdate.maxUnavailable=20% && {
  assert_has "gitops-updatestrategy" "maxUnavailable: 20%"
}

# 9d. apiPath=false drops the /api rule for ingress controllers that do not
# rewrite the prefix. The UI image proxies /api to the Broker itself, so the
# application still works end to end from the UI Service alone.
render "gitops-no-apipath" \
  --set frontend.ingress.enabled=true --set frontend.ingress.apiPath=false && {
  assert_absent "gitops-no-apipath" "path: /api"
  assert_has    "gitops-no-apipath" "path: /"
}

# 10. Controller ClusterRole. Pods spawned by a CronJob are keyed on the
# CronJob, which needs a get on the owning Job; without it the controller logs
# "jobs.batch is forbidden" and keys every run on its throwaway Job name. The
# grant is get only, and the role never gains secrets (charter D3), with or
# without seccomp distribution.
for dist in false true; do
  label="clusterrole-distribute-$dist"
  if ! OUT="$(helm template compat "$CHART" -s templates/clusterrole.yaml \
      --set seccomp.distribute=$dist 2>/dev/null)"; then
    echo "FAIL [$label]: ClusterRole did not render"; fail=1; continue
  fi
  # The batch rule: from its apiGroups line up to the next rule.
  jobs_rule="$(awk '/^- apiGroups:/{inrule=/"batch"/} inrule' <<<"$OUT")"
  grep -q 'resources: \["jobs"\]' <<<"$jobs_rule" || \
    { echo "FAIL [$label]: expected a batch/jobs rule"; fail=1; }
  verbs="$(grep -E '^ +- [a-z*]+$' <<<"$jobs_rule" | tr -d ' -' | tr '\n' ' ')"
  [ "$verbs" = "get " ] || \
    { echo "FAIL [$label]: batch/jobs must be get only, got: $verbs"; fail=1; }
  assert_absent "$label" "cronjobs"
  assert_absent "$label" "secrets"
done

# ---------------------------------------------------------------------------
# Supplychain (#1533). Off by default; when on, its RBAC is read-only on the
# two Trivy Operator report resources and never touches Secrets (decision
# D3: kguardian does not read imagePullSecrets).
# ---------------------------------------------------------------------------

# supplychain requires scoped broker auth (guarded in the chart), so every
# enabled render below carries it.
SC_ON=(--set supplychain.enabled=true --set broker.auth.enabled=true --set broker.auth.existingSecret=kg)

# 11a. Defaults render nothing of it.
render "supplychain-default-off" && {
  assert_absent  "supplychain-default-off" "kguardian-supplychain"
  assert_absent  "supplychain-default-off" "aquasecurity.github.io"
  assert_deploys "supplychain-default-off" 4
}

# 11b. Enabled: one more Deployment, hardened, broker ingest still off.
render "supplychain-enabled" "${SC_ON[@]}" && {
  assert_deploys "supplychain-enabled" 5
  assert_has     "supplychain-enabled" "name: kguardian-supplychain"
  assert_has     "supplychain-enabled" 'args: \["serve"\]'
  assert_has     "supplychain-enabled" "readOnlyRootFilesystem: true"
  # Its token is the supplychain-scoped key, never read/ingest/admin.
  workload Deployment kguardian-supplychain | grep -A4 'name: BROKER_AUTH_TOKEN' | grep -q 'key: supplychain' || \
    { echo "FAIL [supplychain-enabled]: supplychain must mount the supplychain-scoped broker token"; fail=1; }
  grep -A1 'name: BROKER_INGEST_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-enabled]: BROKER_INGEST_ENABLED must default to false"; fail=1; }
  grep -A1 'name: TRIVY_OPERATOR_ENABLED' <<<"$OUT" | grep -q 'value: "true"' || \
    { echo "FAIL [supplychain-enabled]: TRIVY_OPERATOR_ENABLED must default to true"; fail=1; }
  # Registry lookups are opt-in.
  grep -A1 'name: REGISTRY_LOOKUP_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-enabled]: REGISTRY_LOOKUP_ENABLED must default to false"; fail=1; }
  grep -A1 'name: REGISTRY_ALLOW_PRIVATE' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-enabled]: REGISTRY_ALLOW_PRIVATE must default to false"; fail=1; }
  grep -A1 'name: REGISTRY_SBOM_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-enabled]: REGISTRY_SBOM_ENABLED must default to false"; fail=1; }
}

# 11b-ii. Every registry egress path is opt-in: broker ingest alone turns
# on neither the digest-kind lookup nor the registry SBOM source.
render "supplychain-ingest-only-no-registry-egress" "${SC_ON[@]}" \
  --set supplychain.brokerIngest.enabled=true && {
  grep -A1 'name: REGISTRY_LOOKUP_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-ingest-only-no-registry-egress]: registry lookup must stay off with ingest"; fail=1; }
  grep -A1 'name: REGISTRY_SBOM_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-ingest-only-no-registry-egress]: registry SBOM source must stay off with ingest"; fail=1; }
}
render "supplychain-lookup-explicit-on" "${SC_ON[@]}" \
  --set supplychain.brokerIngest.enabled=true --set supplychain.registryLookup.enabled=true && {
  grep -A1 'name: REGISTRY_LOOKUP_ENABLED' <<<"$OUT" | grep -q 'value: "true"' || \
    { echo "FAIL [supplychain-lookup-explicit-on]: explicit true must turn the lookup on"; fail=1; }
}
render "supplychain-registry-sbom-explicit-on" "${SC_ON[@]}" \
  --set supplychain.brokerIngest.enabled=true --set supplychain.sources.registry.enabled=true && {
  grep -A1 'name: REGISTRY_SBOM_ENABLED' <<<"$OUT" | grep -q 'value: "true"' || \
    { echo "FAIL [supplychain-registry-sbom-explicit-on]: explicit true must turn the source on"; fail=1; }
}
render "supplychain-lookup-explicit-off" "${SC_ON[@]}" \
  --set supplychain.brokerIngest.enabled=true --set supplychain.registryLookup.enabled=false && {
  grep -A1 'name: REGISTRY_LOOKUP_ENABLED' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [supplychain-lookup-explicit-off]: explicit false must win"; fail=1; }
}
render "supplychain-lookup-private" "${SC_ON[@]}" \
  --set supplychain.registryLookup.allowPrivateRegistries=true && {
  grep -A1 'name: REGISTRY_ALLOW_PRIVATE' <<<"$OUT" | grep -q 'value: "true"' || \
    { echo "FAIL [supplychain-lookup-private]: allowPrivateRegistries must propagate"; fail=1; }
}

# 11c. The ClusterRole is exactly get/list/watch on the two report resources.
# Rendered alone so nothing else in the chart can satisfy or mask the checks.
if role="$(helm template compat "$CHART" "${SC_ON[@]}" \
    --show-only templates/supplychain/clusterrole.yaml 2>/dev/null)"; then
  rules="$(awk '/^kind: ClusterRole$/{f=1} /^---/{f=0} f' <<<"$role" | sed -n '/^rules:/,$p')"
  grep -q 'apiGroups: \["aquasecurity.github.io"\]' <<<"$rules" || \
    { echo "FAIL [supplychain-rbac]: missing aquasecurity.github.io rule"; fail=1; }
  grep -q 'resources: \[vulnerabilityreports, sbomreports\]' <<<"$rules" || \
    { echo "FAIL [supplychain-rbac]: rule must cover exactly vulnerabilityreports, sbomreports"; fail=1; }
  grep -q 'verbs: \[get, list, watch\]' <<<"$rules" || \
    { echo "FAIL [supplychain-rbac]: verbs must be exactly get, list, watch"; fail=1; }
  [ "$(grep -c 'apiGroups:' <<<"$rules")" = "1" ] || \
    { echo "FAIL [supplychain-rbac]: expected exactly one rule"; fail=1; }
  grep -qiE 'secrets|\*' <<<"$rules" && \
    { echo "FAIL [supplychain-rbac]: ClusterRole must never grant secrets or wildcards (D3)"; fail=1; } || true
else
  echo "FAIL [supplychain-rbac]: clusterrole did not render"; fail=1
fi

# 11d. Source off: no ClusterRole, and no API token mounted.
render "supplychain-no-trivy" "${SC_ON[@]}" \
  --set supplychain.sources.trivyOperator.enabled=false && {
  assert_absent  "supplychain-no-trivy" "aquasecurity.github.io"
  assert_has     "supplychain-no-trivy" "automountServiceAccountToken: false"
  assert_deploys "supplychain-no-trivy" 5
}

# 11e. With the broker NetworkPolicy on, supplychain is an admitted peer;
# without supplychain, it is not.
render "supplychain-broker-netpol" "${SC_ON[@]}" \
  --set broker.networkPolicy.enabled=true --set 'broker.networkPolicy.allowedNodeCIDRs={10.0.0.0/16}' && {
  grep -B1 -A2 'podSelector:' <<<"$OUT" | grep -q 'app.kubernetes.io/name: kguardian-supplychain' || \
    { echo "FAIL [supplychain-broker-netpol]: broker policy must admit supplychain"; fail=1; }
}
render "broker-netpol-no-supplychain" --set broker.networkPolicy.enabled=true \
  --set 'broker.networkPolicy.allowedNodeCIDRs={10.0.0.0/16}' && {
  assert_absent "broker-netpol-no-supplychain" "kguardian-supplychain"
}

# 11f. Its own NetworkPolicy: closed ingress unless scrapers are listed.
render "supplychain-netpol" "${SC_ON[@]}" \
  --set supplychain.networkPolicy.enabled=true && {
  assert_has "supplychain-netpol" "ingress: \[\]"
}

# 11g. Grype matcher sidecar (#1533 option B): off by default; when on, a
# second container that listens on loopback only, gets no API token (the
# pod never auto-mounts one; only the supplychain container gets a
# projected token) and owns the DB volume.
render "supplychain-grype-off" "${SC_ON[@]}" && {
  assert_absent "supplychain-grype-off" "grype-matcher"
  assert_absent "supplychain-grype-off" "GRYPE_MATCHER_URL"
  assert_absent "supplychain-grype-off" "kguardian-supplychain-grype-db"
}
if dep="$(helm template compat "$CHART" "${SC_ON[@]}" --set supplychain.grype.enabled=true \
    --show-only templates/supplychain/deployment.yaml 2>/dev/null)"; then
  grep -q 'automountServiceAccountToken: false' <<<"$dep" || \
    { echo "FAIL [supplychain-grype]: pod must not auto-mount a token"; fail=1; }
  # The matcher container block: from its name to the volumes list.
  matcher="$(awk '/- name: grype-matcher/{f=1} /^      volumes:/{f=0} f' <<<"$dep")"
  [ -n "$matcher" ] || { echo "FAIL [supplychain-grype]: no matcher container"; fail=1; }
  grep -q 'value: "127.0.0.1:8090"' <<<"$matcher" || \
    { echo "FAIL [supplychain-grype]: matcher must listen on loopback"; fail=1; }
  if grep -qE 'serviceaccount|BROKER_AUTH_TOKEN|secretKeyRef' <<<"$matcher"; then
    echo "FAIL [supplychain-grype]: matcher must get no Kubernetes or broker token"; fail=1
  fi
  grep -q 'mountPath: /var/lib/grype' <<<"$matcher" || \
    { echo "FAIL [supplychain-grype]: matcher must mount the DB volume"; fail=1; }
  grep -q 'value: "http://127.0.0.1:8090"' <<<"$dep" || \
    { echo "FAIL [supplychain-grype]: supplychain must point GRYPE_MATCHER_URL at the sidecar"; fail=1; }
  grep -A2 -- '- name: grype-db' <<<"$dep" | grep -q 'sizeLimit: 8Gi' || \
    { echo "FAIL [supplychain-grype]: default DB volume must be an 8Gi emptyDir"; fail=1; }
  grep -q 'ephemeral-storage: 7Gi' <<<"$matcher" && grep -q 'ephemeral-storage: 9Gi' <<<"$matcher" || \
    { echo "FAIL [supplychain-grype]: emptyDir mode must request 7Gi / limit 9Gi ephemeral storage"; fail=1; }
  grep -A1 'name: GRYPE_DB_UPDATE_INTERVAL' <<<"$matcher" | grep -q 'value: "12h"' || \
    { echo "FAIL [supplychain-grype]: DB update interval must default to 12h"; fail=1; }
  # The supplychain container still reaches the API (Trivy Operator on).
  sc="$(awk '/- name: supplychain$/{f=1} /- name: grype-matcher/{f=0} f' <<<"$dep")"
  grep -q 'mountPath: /var/run/secrets/kubernetes.io/serviceaccount' <<<"$sc" || \
    { echo "FAIL [supplychain-grype]: supplychain container lost its projected token"; fail=1; }
else
  echo "FAIL [supplychain-grype]: deployment did not render"; fail=1
fi
render "supplychain-grype-pvc" "${SC_ON[@]}" --set supplychain.grype.enabled=true \
  --set supplychain.grype.persistence.enabled=true && {
  assert_has "supplychain-grype-pvc" "name: kguardian-supplychain-grype-db"
  assert_has "supplychain-grype-pvc" "type: Recreate"
  assert_has "supplychain-grype-pvc" "claimName: kguardian-supplychain-grype-db"
  assert_absent "supplychain-grype-pvc" "ephemeral-storage"
}
render "supplychain-grype-existing-claim" "${SC_ON[@]}" --set supplychain.grype.enabled=true \
  --set supplychain.grype.persistence.enabled=true --set supplychain.grype.persistence.existingClaim=my-db && {
  assert_has    "supplychain-grype-existing-claim" "claimName: my-db"
  assert_absent "supplychain-grype-existing-claim" "name: kguardian-supplychain-grype-db"
}
# Trivy source off: no projected token anywhere in the pod.
render "supplychain-no-api" "${SC_ON[@]}" --set supplychain.sources.trivyOperator.enabled=false \
  --set supplychain.grype.enabled=true && {
  assert_absent "supplychain-no-api" "kube-api-access"
}

# 12. ApplicationSecurityProfile (#1533 P2-6): off by default — no CRD, no
# RBAC, no broker env on the evaluator.
render "asp-default-off" && {
  assert_absent "asp-default-off" "applicationsecurityprofiles"
  assert_absent "asp-default-off" "ASP_ENABLED"
}

# 12a. On: CRD kept on uninstall, env wired, READ-scope token (never ingest).
ASP_ON=(--set evaluator.applicationSecurityProfiles.enabled=true)
render "asp-on" "${ASP_ON[@]}" && {
  assert_has    "asp-on" "name: applicationsecurityprofiles.kguardian.dev"
  assert_has    "asp-on" "helm.sh/resource-policy: keep"
  assert_has    "asp-on" "name: ASP_ENABLED"
  assert_has    "asp-on" "name: ASP_RESYNC_INTERVAL"
  assert_deploys "asp-on" 4
}
if ev="$(helm template compat "$CHART" "${ASP_ON[@]}" --set broker.auth.enabled=true \
    --set broker.auth.existingSecret=kg-auth --show-only templates/evaluator/deployment.yaml 2>/dev/null)"; then
  grep -A4 'name: BROKER_AUTH_TOKEN' <<<"$ev" | grep -q 'key: read' || \
    { echo "FAIL [asp-auth]: evaluator must present the read-scope token"; fail=1; }
  grep -A4 'name: BROKER_AUTH_TOKEN' <<<"$ev" | grep -q 'key: ingest' && \
    { echo "FAIL [asp-auth]: evaluator must never hold the ingest token"; fail=1; } || true
else
  echo "FAIL [asp-auth]: evaluator deployment did not render"; fail=1
fi

# 12b. RBAC: list/watch on the resource, patch on status only. No create,
# delete, update or wildcard.
if role="$(helm template compat "$CHART" "${ASP_ON[@]}" \
    --show-only templates/evaluator/clusterrole.yaml 2>/dev/null)"; then
  grep -A1 'resources: \[applicationsecurityprofiles\]' <<<"$role" | grep -q 'verbs: \[list, watch\]' || \
    { echo "FAIL [asp-rbac]: applicationsecurityprofiles must be exactly list, watch"; fail=1; }
  grep -A1 'resources: \[applicationsecurityprofiles/status\]' <<<"$role" | grep -q 'verbs: \[patch\]' || \
    { echo "FAIL [asp-rbac]: applicationsecurityprofiles/status must be exactly patch"; fail=1; }
  grep -qE 'verbs: \[.*(create|delete|\*).*\]' <<<"$(grep -A1 applicationsecurityprofiles <<<"$role")" && \
    { echo "FAIL [asp-rbac]: no create/delete/wildcard on applicationsecurityprofiles"; fail=1; } || true
else
  echo "FAIL [asp-rbac]: evaluator clusterrole did not render"; fail=1
fi

# 12c. installCRD=false leaves the CRD to the operator.
render "asp-no-crd" "${ASP_ON[@]}" --set evaluator.applicationSecurityProfiles.installCRD=false && {
  assert_absent "asp-no-crd" "name: applicationsecurityprofiles.kguardian.dev"
  assert_has    "asp-no-crd" "name: ASP_ENABLED"
}

# 12d. Broker NetworkPolicy admits the evaluator only when the feature is on.
render "asp-broker-netpol" "${ASP_ON[@]}" --set broker.networkPolicy.enabled=true \
  --set 'broker.networkPolicy.allowedNodeCIDRs={10.0.0.0/16}' && {
  awk '/^kind: NetworkPolicy$/{f=1} /^---/{f=0} f' <<<"$OUT" | grep -q 'app.kubernetes.io/name: kguardian-evaluator' || \
    { echo "FAIL [asp-broker-netpol]: broker policy must admit the evaluator"; fail=1; }
}
render "broker-netpol-no-asp" --set broker.networkPolicy.enabled=true \
  --set 'broker.networkPolicy.allowedNodeCIDRs={10.0.0.0/16}' && {
  awk '/^kind: NetworkPolicy$/{f=1} /^---/{f=0} f' <<<"$OUT" | grep -q 'app.kubernetes.io/name: kguardian-evaluator' && \
    { echo "FAIL [broker-netpol-no-asp]: evaluator admitted without the feature"; fail=1; } || true
}

# 12e. Refuses to render without the evaluator that writes the status.
assert_render_fails "asp-without-evaluator" "requires evaluator.enabled=true" \
  "${ASP_ON[@]}" --set evaluator.enabled=false

if [ "$fail" -ne 0 ]; then
  echo "G4 values-compatibility check FAILED"
  exit 1
fi
echo "G4 values-compatibility check passed"
