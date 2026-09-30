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
  # Signature discovery (registry + Sigstore TUF egress) is off unless asked.
  if grep -A1 'name: ATTESTATION_ENABLED' <<<"$OUT" | grep -q 'value: "true"'; then
    echo "FAIL [supplychain-ingest-only-no-registry-egress]: signature discovery must stay off with ingest"; fail=1
  fi
}
render "supplychain-signature-discovery-on" "${SC_ON[@]}" \
  --set supplychain.brokerIngest.enabled=true --set supplychain.signatureDiscovery.enabled=true \
  --set-string 'supplychain.signatureDiscovery.publicKeys.release=-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----' && {
  grep -A1 'name: ATTESTATION_ENABLED' <<<"$OUT" | grep -q 'value: "true"' || \
    { echo "FAIL [supplychain-signature-discovery-on]: explicit true must turn discovery on"; fail=1; }
  grep -q 'checksum/signing-keys:' <<<"$OUT" || \
    { echo "FAIL [supplychain-signature-discovery-on]: a signing-keys checksum must roll the pod on key changes"; fail=1; }
  grep -q 'name: kguardian-supplychain-signing-keys' <<<"$OUT" || \
    { echo "FAIL [supplychain-signature-discovery-on]: the signing-keys ConfigMap must render"; fail=1; }
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
  # It holds up to 96 MiB of SBOMs: GOMEMLIMIT keeps the heap under its
  # 256Mi limit (80% = 214748364), on the supplychain container itself.
  grep -A1 'name: GOMEMLIMIT' <<<"$sc" | grep -q 'value: "214748364"' || \
    { echo "FAIL [supplychain-grype]: supplychain GOMEMLIMIT must default to 80% of 256Mi"; fail=1; }
else
  echo "FAIL [supplychain-grype]: deployment did not render"; fail=1
fi
# supplychain GOMEMLIMIT follows the memory limit, can be set outright, and
# is left out without a limit; a limit it cannot read refuses to render.
sc_gomemlimit() {
  helm template compat "$CHART" "${SC_ON[@]}" "$@" --show-only templates/supplychain/deployment.yaml 2>/dev/null |
    awk '/- name: supplychain$/{f=1} /- name: grype-matcher/{f=0} f' | grep -A1 'name: GOMEMLIMIT' | sed -n 's/.*value: //p' || true
}
for c in '1Gi="858993459"' '512M="409600000"' '1.5Gi="1288490188"' '268435456="214748364"'; do
  lim="${c%%=*}" want="${c#*=}"
  got="$(sc_gomemlimit --set supplychain.resources.limits.memory="$lim")"
  [ "$got" = "$want" ] || { echo "FAIL [supplychain-gomemlimit]: limit $lim gave '$got', want $want"; fail=1; }
done
got="$(sc_gomemlimit --set supplychain.goMemLimit=150MiB)"
[ "$got" = '"150MiB"' ] || { echo "FAIL [supplychain-gomemlimit]: explicit goMemLimit gave '$got'"; fail=1; }
got="$(sc_gomemlimit --set supplychain.resources.limits=null)"
[ -z "$got" ] || { echo "FAIL [supplychain-gomemlimit]: no memory limit must mean no GOMEMLIMIT, got '$got'"; fail=1; }
# A GOMEMLIMIT already set in supplychain.env is the only one: a duplicate
# env name breaks server-side apply on upgrade.
if dep="$(helm template compat "$CHART" "${SC_ON[@]}" --set 'supplychain.env[0].name=GOMEMLIMIT' \
    --set 'supplychain.env[0].value=100MiB' --show-only templates/supplychain/deployment.yaml 2>/dev/null)"; then
  sc="$(awk '/- name: supplychain$/{f=1} /- name: grype-matcher/{f=0} f' <<<"$dep")"
  n="$(grep -c 'name: GOMEMLIMIT' <<<"$sc" || true)"
  v="$(grep -A1 'name: GOMEMLIMIT' <<<"$sc" | sed -n 's/.*value: //p' || true)"
  [ "$n" = 1 ] && [ "$v" = 100MiB ] || \
    { echo "FAIL [supplychain-gomemlimit-user-env]: want one GOMEMLIMIT=100MiB, got $n: $v"; fail=1; }
else
  echo "FAIL [supplychain-gomemlimit-user-env]: did not render"; fail=1
fi
assert_render_fails "supplychain-gomemlimit-bad-limit" "cannot derive GOMEMLIMIT" \
  "${SC_ON[@]}" --set supplychain.resources.limits.memory=lots
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
# Trivy source off: no projected token anywhere in the pod. Scoped to the
# supplychain Deployment: the broker mounts its own for leader election.
render "supplychain-no-api" "${SC_ON[@]}" --set supplychain.sources.trivyOperator.enabled=false \
  --set supplychain.grype.enabled=true -s templates/supplychain/deployment.yaml && {
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

# 12f. staleAfter: unset leaves the default to the binary (3x resync);
# set, it is passed through; malformed, the render fails.
render "asp-stale-default" "${ASP_ON[@]}" && assert_absent "asp-stale-default" "ASP_STALE_AFTER"
render "asp-stale-set" "${ASP_ON[@]}" --set evaluator.applicationSecurityProfiles.staleAfter=20m && {
  assert_has "asp-stale-set" "name: ASP_STALE_AFTER"
  assert_has "asp-stale-set" 'value: "20m"'
}
assert_render_fails "asp-stale-bad" "is not a Go duration" \
  "${ASP_ON[@]}" --set evaluator.applicationSecurityProfiles.staleAfter=soon

# 12e. Refuses to render without the evaluator that writes the status.
assert_render_fails "asp-without-evaluator" "requires evaluator.enabled=true" \
  "${ASP_ON[@]}" --set evaluator.enabled=false

# 13. ImageTrustPolicy evaluation (#1533 P2-2) follows signature discovery.
IT_ON=("${SC_ON[@]}" --set supplychain.brokerIngest.enabled=true --set supplychain.signatureDiscovery.enabled=true)
render "image-trust-on" "${IT_ON[@]}" && {
  workload Deployment kguardian-evaluator | grep -A1 'name: IMAGE_TRUST_ENABLED' | grep -q 'value: "true"' || \
    { echo "FAIL [image-trust-on]: evaluator must evaluate ImageTrustPolicies when discovery is on"; fail=1; }
  assert_client_key "image-trust-on" Deployment kguardian-evaluator read
  assert_has "image-trust-on" "imagetrustpolicies/status, clusterimagetrustpolicies/status"
}
render "image-trust-default-off" "${SC_ON[@]}" && {
  assert_absent "image-trust-default-off" "name: IMAGE_TRUST_ENABLED"
  assert_absent "image-trust-default-off" "imagetrustpolicies/status"
}
# The broker NetworkPolicy must admit the evaluator when image trust alone
# needs the broker, or every pass fails.
render "image-trust-broker-netpol" "${IT_ON[@]}" --set broker.networkPolicy.enabled=true \
  --set 'broker.networkPolicy.allowedNodeCIDRs={10.0.0.0/16}' && {
  workload NetworkPolicy kguardian-broker | grep -q 'app.kubernetes.io/name: kguardian-evaluator' || \
    { echo "FAIL [image-trust-broker-netpol]: broker NetworkPolicy must admit the evaluator for image trust"; fail=1; }
}
render "image-trust-off-broker-netpol" "${SC_ON[@]}" --set broker.networkPolicy.enabled=true \
  --set 'broker.networkPolicy.allowedNodeCIDRs={10.0.0.0/16}' && {
  if workload NetworkPolicy kguardian-broker | grep -q 'app.kubernetes.io/name: kguardian-evaluator'; then
    echo "FAIL [image-trust-off-broker-netpol]: evaluator must not be admitted when nothing needs it"; fail=1
  fi
}

# Profile contract v1.8: the broker is told whether image signature
# discovery is configured. "true" only with supplychain AND
# signatureDiscovery on; every other combination is an explicit "false"
# (the broker reads unset as on, so the chart must never leave it out).
sig_env() {
  workload Deployment kguardian-broker | awk '/name: SIGNATURE_DISCOVERY_ENABLED/ { getline; print $2 }'
}
for case in "sig-env-default:false" "sig-env-supplychain-only:false" "sig-env-discovery-on:true" "sig-env-discovery-without-supplychain:false"; do
  name=${case%%:*} want=${case##*:}
  case "$name" in
    sig-env-default) args=() ;;
    sig-env-supplychain-only) args=("${SC_ON[@]}") ;;
    sig-env-discovery-on) args=("${SC_ON[@]}" --set supplychain.signatureDiscovery.enabled=true --set supplychain.brokerIngest.enabled=true) ;;
    sig-env-discovery-without-supplychain) args=(--set supplychain.signatureDiscovery.enabled=true) ;;
  esac
  render "$name" "${args[@]}" && {
    got="$(sig_env)"
    [ "$got" = "\"$want\"" ] || { echo "FAIL [$name]: SIGNATURE_DISCOVERY_ENABLED is ${got:-missing}, want \"$want\""; fail=1; }
  }
done

# 13a. The ImageTrustPolicy CRDs are release resources, rendered by
# default (whether or not evaluation or the evaluator is on) and kept on
# uninstall. They must not be in crds/: Helm (and Flux) never upgrade that
# directory, so an upgraded install would have no CRDs.
itp_crds_rendered() {
  local label="$1" crd doc
  for crd in imagetrustpolicies.kguardian.dev clusterimagetrustpolicies.kguardian.dev; do
    doc="$(workload CustomResourceDefinition "$crd")"
    [ -n "$doc" ] || { echo "FAIL [$label]: CRD $crd not rendered"; fail=1; continue; }
    grep -q 'helm.sh/resource-policy: keep' <<<"$doc" || \
      { echo "FAIL [$label]: CRD $crd must carry helm.sh/resource-policy: keep"; fail=1; }
  done
}
render "itp-crds-default" && itp_crds_rendered "itp-crds-default"
render "itp-crds-image-trust-on" "${IT_ON[@]}" && itp_crds_rendered "itp-crds-image-trust-on"
render "itp-crds-evaluator-off" --set evaluator.enabled=false && itp_crds_rendered "itp-crds-evaluator-off"
render "itp-crds-off" --set evaluator.imageTrust.installCRDs=false && {
  assert_absent "itp-crds-off" "imagetrustpolicies.kguardian.dev"
}
if grep -lqE 'kind: (Cluster)?ImageTrustPolicy$' "$CHART"/crds/*.yaml 2>/dev/null; then
  echo "FAIL [itp-crds-not-in-crds-dir]: ImageTrustPolicy CRDs must not ship in crds/ (never upgraded)"; fail=1
fi

# 14. Runtime inventory (#1533 P1-2) and capability counting (P2-7) are
# opt-in: by default the controller loads neither probe. Each switch flips
# only its own env var, and neither adds RBAC.
# env_value <env-name> — the value rendered for that controller env var.
env_value() { workload DaemonSet kguardian-controller | grep -A1 -- "- name: $1\$" | sed -n 's/^ *value: //p' | head -1; }
BASE_RBAC="$(helm template compat "$CHART" --show-only templates/clusterrole.yaml 2>/dev/null)"
render "runtime-inventory-default-off" && {
  [ "$(env_value RUNTIME_INVENTORY)" = '"off"' ] || \
    { echo "FAIL [runtime-inventory-default-off]: RUNTIME_INVENTORY must default to \"off\" (got $(env_value RUNTIME_INVENTORY))"; fail=1; }
  [ "$(env_value RUNTIME_INVENTORY_CAPABILITIES)" = '"false"' ] || \
    { echo "FAIL [runtime-inventory-default-off]: RUNTIME_INVENTORY_CAPABILITIES must default to \"false\""; fail=1; }
}
for mode in exec full; do
  render "runtime-inventory-$mode" --set controller.runtimeInventory.mode=$mode && {
    [ "$(env_value RUNTIME_INVENTORY)" = "\"$mode\"" ] || \
      { echo "FAIL [runtime-inventory-$mode]: mode=$mode must render RUNTIME_INVENTORY=\"$mode\""; fail=1; }
    [ "$(env_value RUNTIME_INVENTORY_CAPABILITIES)" = '"false"' ] || \
      { echo "FAIL [runtime-inventory-$mode]: setting the mode must not turn capabilities on"; fail=1; }
  }
done
render "runtime-inventory-capabilities" --set controller.runtimeInventory.mode=exec \
  --set controller.runtimeInventory.capabilities=true && {
  [ "$(env_value RUNTIME_INVENTORY_CAPABILITIES)" = '"true"' ] || \
    { echo "FAIL [runtime-inventory-capabilities]: capabilities=true must render \"true\""; fail=1; }
  [ "$(env_value RUNTIME_INVENTORY)" = '"exec"' ] || \
    { echo "FAIL [runtime-inventory-capabilities]: capabilities must not change the mode"; fail=1; }
}
if [ "$(helm template compat "$CHART" --set controller.runtimeInventory.mode=full \
    --set controller.runtimeInventory.capabilities=true \
    --show-only templates/clusterrole.yaml 2>/dev/null)" != "$BASE_RBAC" ]; then
  echo "FAIL [runtime-inventory-rbac]: runtime inventory and capabilities must not change the ClusterRole"; fail=1
fi
# Capabilities with the inventory off would be silently dropped by the
# controller, so the chart refuses it (default mode and explicit off).
CAPS_NEEDS_MODE="controller.runtimeInventory.capabilities requires controller.runtimeInventory.mode exec or full"
assert_render_fails "runtime-inventory-capabilities-mode-default" "$CAPS_NEEDS_MODE" \
  --set controller.runtimeInventory.capabilities=true
assert_render_fails "runtime-inventory-capabilities-mode-off" "$CAPS_NEEDS_MODE" \
  --set controller.runtimeInventory.mode=off --set controller.runtimeInventory.capabilities=true
assert_render_fails "runtime-inventory-capabilities-mode-off-mixed-case" "$CAPS_NEEDS_MODE" \
  --set controller.runtimeInventory.mode=Off --set controller.runtimeInventory.capabilities=true
# "On" is the controller's reading: case-insensitive and trimmed.
assert_render_fails "runtime-inventory-capabilities-upper-string" "$CAPS_NEEDS_MODE" \
  --set-string controller.runtimeInventory.capabilities=TRUE
assert_render_fails "runtime-inventory-capabilities-padded-on" "$CAPS_NEEDS_MODE" \
  --set-string "controller.runtimeInventory.capabilities= On "
# ...but an explicit "false" (string or bool) with mode off still renders.
render "runtime-inventory-capabilities-false-string" --set-string controller.runtimeInventory.capabilities=false && {
  [ "$(env_value RUNTIME_INVENTORY_CAPABILITIES)" = '"false"' ] || \
    { echo "FAIL [runtime-inventory-capabilities-false-string]: capabilities=\"false\" must render \"false\""; fail=1; }
}
assert_render_fails "runtime-inventory-bad-mode" "controller.runtimeInventory.mode must be one of off, exec, full" \
  --set controller.runtimeInventory.mode=on

# ---------------------------------------------------------------------------
# Seccomp distribution live-node window. A node posts its node-status once
# per distribution pass, so `broker.seccomp.nodeStatusStaleSeconds` under
# three passes reads a healthy fleet as stale and every SeccompProfile as
# Pending; the chart refuses that at template time, where both values are
# known. The interval falls back to the controller default (30) when unset,
# 0 disables the window and with it the check, and a fleet without
# distribution posts nothing, so nothing is checked either.
# ---------------------------------------------------------------------------
broker_env_value() { workload Deployment kguardian-broker | grep -A1 -- "- name: $1\$" | sed -n 's/^ *value: //p' | head -1; }
STALE_RULE="must be at least 3x seccomp.distributeIntervalSeconds"
render "seccomp-stale-window-default" --set seccomp.distribute=true && {
  [ "$(broker_env_value SECCOMP_NODE_STATUS_STALE_SECS)" = '"900"' ] || \
    { echo "FAIL [seccomp-stale-window-default]: expected the 900 default rendered as SECCOMP_NODE_STATUS_STALE_SECS"; fail=1; }
}
# The boundary: 900 is exactly three 300 s passes, the cadence large
# clusters run, and it renders.
render "seccomp-stale-window-three-passes" --set seccomp.distribute=true \
  --set seccomp.distributeIntervalSeconds=300
# A string interval (an old values file quoting it) is read as a number.
render "seccomp-stale-window-string-interval" --set seccomp.distribute=true \
  --set-string seccomp.distributeIntervalSeconds=300
assert_render_fails "seccomp-stale-window-under-three-passes" "$STALE_RULE" \
  --set seccomp.distribute=true --set seccomp.distributeIntervalSeconds=301
assert_render_fails "seccomp-stale-window-lowered" "$STALE_RULE" \
  --set seccomp.distribute=true --set seccomp.distributeIntervalSeconds=300 \
  --set broker.seccomp.nodeStatusStaleSeconds=600
# The message names both values and the rule, so the fix is in the error.
assert_render_fails "seccomp-stale-window-message" "nodeStatusStaleSeconds (600) must be at least 3x seccomp.distributeIntervalSeconds (300, so 900)" \
  --set seccomp.distribute=true --set seccomp.distributeIntervalSeconds=300 \
  --set broker.seccomp.nodeStatusStaleSeconds=600
# 0 is the documented "no window": nothing to be shorter than, and it still
# reaches the Broker (hasKey, not `with`).
render "seccomp-stale-window-disabled" --set seccomp.distribute=true \
  --set seccomp.distributeIntervalSeconds=3600 --set broker.seccomp.nodeStatusStaleSeconds=0 && {
  [ "$(broker_env_value SECCOMP_NODE_STATUS_STALE_SECS)" = '"0"' ] || \
    { echo "FAIL [seccomp-stale-window-disabled]: 0 must render as SECCOMP_NODE_STATUS_STALE_SECS"; fail=1; }
}
# Without distribution no node ever posts, so the interval is not checked.
render "seccomp-stale-window-no-distribution" --set seccomp.distributeIntervalSeconds=3600

# UI host allowlist (ALLOWED_HOSTS). Set only when the chart knows the names
# users open the UI on; with none, an existing install keeps answering every
# host (the server logs a warning), so an upgrade never locks anyone out.
SVC_HOSTS="kguardian-frontend,kguardian-frontend.kg,kguardian-frontend.kg.svc,kguardian-frontend.kg.svc.cluster.local"
render "allowed-hosts-default" -n kg && assert_absent "allowed-hosts-default" "ALLOWED_HOSTS"
render "allowed-hosts-ingress" -n kg --set frontend.ingress.enabled=true \
  --set 'frontend.ingress.tls[0].secretName=kg-tls' --set 'frontend.ingress.tls[0].hosts[0]=kguardian.example.com' \
  --set 'frontend.ingress.tls[0].hosts[1]=alt.example.com' && \
  assert_has "allowed-hosts-ingress" "value: \"kguardian.example.com,alt.example.com,$SVC_HOSTS\""
render "allowed-hosts-sso" -n kg --set frontend.sso.enabled=true --set frontend.sso.httpRouteName=kg \
  --set 'frontend.sso.hostnames[0]=kg.example.com' --set 'frontend.sso.parentRefs[0].name=gw' && \
  assert_has "allowed-hosts-sso" "value: \"kg.example.com,$SVC_HOSTS\""
render "allowed-hosts-extra" -n kg --set 'frontend.allowedHosts[0]=*.corp.example.com' && \
  assert_has "allowed-hosts-extra" "value: \"\*.corp.example.com,$SVC_HOSTS\""
# A catch-all ingress rule (empty host) answers every name, so its TLS hosts
# alone must not lock the UI down to them.
# (--set-json: `--set hosts[0].host=` drops the rule instead of emptying the host.)
CATCH_ALL=(--set frontend.ingress.enabled=true
  --set-json 'frontend.ingress.hosts=[{"host":"","paths":[{"path":"/","pathType":"Prefix"}]}]'
  --set 'frontend.ingress.tls[0].secretName=kg-tls' --set 'frontend.ingress.tls[0].hosts[0]=a.example.com')
render "allowed-hosts-catch-all-ingress" -n kg "${CATCH_ALL[@]}" && {
  assert_has    "allowed-hosts-catch-all-ingress" 'host: ""'
  assert_absent "allowed-hosts-catch-all-ingress" "ALLOWED_HOSTS"
}
# A rule with no host key at all is a catch-all too.
render "allowed-hosts-hostless-ingress" -n kg --set frontend.ingress.enabled=true \
  --set-json 'frontend.ingress.hosts=[{"paths":[{"path":"/","pathType":"Prefix"}]}]' && \
  assert_absent "allowed-hosts-hostless-ingress" "ALLOWED_HOSTS"
# ...unless the operator lists names explicitly.
render "allowed-hosts-catch-all-ingress-explicit" -n kg "${CATCH_ALL[@]}" --set 'frontend.allowedHosts[0]=b.example.com' && \
  assert_has "allowed-hosts-catch-all-ingress-explicit" "value: \"a.example.com,b.example.com,$SVC_HOSTS\""
# The same for an empty SSO hostname.
render "allowed-hosts-catch-all-sso" -n kg --set frontend.sso.enabled=true --set frontend.sso.httpRouteName=kg \
  --set-json 'frontend.sso.hostnames=["kg.example.com",""]' --set 'frontend.sso.parentRefs[0].name=gw' && \
  assert_absent "allowed-hosts-catch-all-sso" "ALLOWED_HOSTS"
# A comma-separated string works (--set frontend.allowedHosts=a,b needs escaping; a quoted string is the common form).
render "allowed-hosts-string" -n kg --set-string 'frontend.allowedHosts=foo.example.com\, bar.example.com' && \
  assert_has "allowed-hosts-string" "value: \"foo.example.com,bar.example.com,$SVC_HOSTS\""
render "allowed-hosts-single-string" -n kg --set 'frontend.allowedHosts=foo.example.com' && \
  assert_has "allowed-hosts-single-string" "value: \"foo.example.com,$SVC_HOSTS\""
assert_render_fails "allowed-hosts-map" "frontend.allowedHosts must be a list" -n kg --set 'frontend.allowedHosts.a=b'
# The full in-cluster name follows global.clusterDomain.
render "allowed-hosts-cluster-domain" -n kg --set 'frontend.allowedHosts[0]=x.example.com' --set global.clusterDomain=corp.internal && \
  assert_has "allowed-hosts-cluster-domain" "kguardian-frontend.kg.svc.corp.internal\""
# The UI container runs read-only, with writable /tmp and the .vite-temp
# directory older frontend images bundle their config into at startup.
if dep="$(helm template compat "$CHART" -n kg -s templates/frontend/deployment.yaml 2>/dev/null)"; then
  grep -q "readOnlyRootFilesystem: true" <<<"$dep" || \
    { echo "FAIL [frontend-read-only]: frontend root filesystem must be read-only"; fail=1; }
  for path in /tmp /app/node_modules/.vite-temp; do
    grep -q "mountPath: $path$" <<<"$dep" || \
      { echo "FAIL [frontend-read-only]: expected a writable mount at $path"; fail=1; }
  done
  [ "$(grep -c 'emptyDir:' <<<"$dep")" = 2 ] || \
    { echo "FAIL [frontend-read-only]: expected two emptyDir volumes"; fail=1; }
else
  echo "FAIL [frontend-read-only]: frontend Deployment did not render"; fail=1
fi
# NOTES prints the same list the Deployment gets (one helper feeds both), or
# says the check is off and how to turn it on.
if notes="$(helm install compat "$CHART" -n kg --dry-run=client --set 'frontend.allowedHosts[0]=x.example.com' 2>/dev/null)"; then
  grep -q "UI answers only these host names" <<<"$notes" && \
    grep -q "  x.example.com, kguardian-frontend, kguardian-frontend.kg," <<<"$notes" || \
    { echo "FAIL [allowed-hosts-notes]: NOTES must print the effective host list"; fail=1; }
else
  echo "FAIL [allowed-hosts-notes]: dry-run install failed"; fail=1
fi
if notes="$(helm install compat "$CHART" -n kg --dry-run=client 2>/dev/null)"; then
  grep -q "UI host check: OFF" <<<"$notes" && grep -q "frontend.allowedHosts={" <<<"$notes" || \
    { echo "FAIL [allowed-hosts-notes-off]: NOTES must say the UI answers any host and how to restrict it"; fail=1; }
else
  echo "FAIL [allowed-hosts-notes-off]: dry-run install failed"; fail=1
fi

# 15. Broker leader election. On by default at any replica count: a Role
# limited to the broker's own Lease in the release namespace, the downward
# API identity, and a token mounted only for it (the pod keeps
# automountServiceAccountToken: false).
for replicas in 1 3; do
  label="leader-election-replicas-$replicas"
  render "$label" -n kg --set broker.replicaCount=$replicas && {
    assert_has "$label" "kind: Role$"
    assert_has "$label" "name: compat-kguardian-broker-leader-election"
    assert_has "$label" 'resourceNames: \["compat-kguardian-broker-leader"\]'
    assert_has "$label" "value: \"compat-kguardian-broker-leader\""
    assert_has "$label" "fieldPath: metadata.name"
    assert_has "$label" "mountPath: /var/run/secrets/kubernetes.io/serviceaccount"
    assert_has "$label" "automountServiceAccountToken: false"
  }
done
if OUT="$(helm template compat "$CHART" -n kg -s templates/broker/role.yaml 2>/dev/null)"; then
  # Leases only, namespaced, never cluster-wide or list/watch/patch/delete.
  assert_absent "leader-election-rbac" "ClusterRole"
  assert_absent "leader-election-rbac" "list\|watch\|patch\|delete"
  assert_has    "leader-election-rbac" "namespace: kg"
  [ "$(grep -c 'resources: \[leases\]' <<<"$OUT")" = 2 ] || \
    { echo "FAIL [leader-election-rbac]: expected exactly two leases rules"; fail=1; }
  grep -A1 'resourceNames:' <<<"$OUT" | grep -q 'verbs: \[get, update\]' || \
    { echo "FAIL [leader-election-rbac]: get/update must be pinned to the Lease name"; fail=1; }
else
  echo "FAIL [leader-election-rbac]: Role did not render"; fail=1
fi
# Off: no Role, no token, and the broker is told election is off.
render "leader-election-off" -n kg --set broker.leaderElection.enabled=false && {
  assert_absent "leader-election-off" "broker-leader-election"
  assert_absent "leader-election-off" "kube-api-access"
  assert_absent "leader-election-off" "LEADER_ELECTION_LEASE_NAME"
  assert_has    "leader-election-off" "name: LEADER_ELECTION_ENABLED"
}
# A custom ServiceAccount name is the RoleBinding's subject.
render "leader-election-custom-sa" -n kg --set broker.serviceAccount.name=kg-broker && \
  assert_has "leader-election-custom-sa" "name: kg-broker"
# Timings reach the broker.
render "leader-election-timings" -n kg --set broker.leaderElection.leaseDurationSeconds=30 && \
  assert_has "leader-election-timings" 'value: "30"'
render "leader-election-timings-30-20-4" -n kg --set broker.leaderElection.leaseDurationSeconds=30 \
  --set broker.leaderElection.renewDeadlineSeconds=20 --set broker.leaderElection.retryPeriodSeconds=4
# Off is fine at one replica, and refused at more: every replica would run
# every background job.
render "leader-election-off-one-replica" -n kg --set broker.leaderElection.enabled=false --set broker.replicaCount=1
assert_render_fails "leader-election-off-replicas" "every broker replica would run every background job" \
  -n kg --set broker.leaderElection.enabled=false --set broker.replicaCount=2
# Timings the broker would silently replace with 15/10/2 (leader.rs
# Timings::from_secs: lease > renew > 1.2 x retry, retry > 0) are refused.
LE_ORDER="leaseDurationSeconds > renewDeadlineSeconds > 1.2 x retryPeriodSeconds"
assert_render_fails "leader-election-renew-equals-lease" "$LE_ORDER" \
  -n kg --set broker.leaderElection.renewDeadlineSeconds=15
assert_render_fails "leader-election-renew-above-lease" "$LE_ORDER" \
  -n kg --set broker.leaderElection.leaseDurationSeconds=10 --set broker.leaderElection.renewDeadlineSeconds=12
assert_render_fails "leader-election-retry-zero" "$LE_ORDER" \
  -n kg --set broker.leaderElection.retryPeriodSeconds=0
# 1.2 x 5 = 6: renew must be strictly above it.
assert_render_fails "leader-election-retry-jitter" "$LE_ORDER" \
  -n kg --set broker.leaderElection.renewDeadlineSeconds=6 --set broker.leaderElection.retryPeriodSeconds=5
render "leader-election-retry-jitter-edge" -n kg --set broker.leaderElection.renewDeadlineSeconds=7 \
  --set broker.leaderElection.retryPeriodSeconds=5
assert_render_fails "leader-election-not-a-number" "must be a whole number of seconds" \
  -n kg --set-string broker.leaderElection.leaseDurationSeconds=15s
# Timings are not checked when election is off (the broker never reads them).
render "leader-election-off-bad-timings" -n kg --set broker.leaderElection.enabled=false \
  --set broker.leaderElection.retryPeriodSeconds=0

# 16. Database connections vs broker pools. Every broker pod of a rolling
# update (replicaCount + 25% surge, rounded up) may hold a full pool, plus 13
# for other clients. The bundled database keeps the image default (100) while
# that fits, and is raised to it (rounded up to 10) once it does not.
render "db-conns-default" && assert_absent "db-conns-default" "max_connections"
render "db-conns-replicas-3" --set broker.replicaCount=3 && \
  assert_has "db-conns-replicas-3" 'max_connections=150'
# The pool the broker really uses: dbPoolMaxSize raised to inflightPermits + 8.
render "db-conns-permit-floor" --set broker.replicaCount=10 --set broker.dbPoolMaxSize=16 && \
  assert_has "db-conns-permit-floor" 'max_connections=330'
render "db-conns-explicit" --set database.maxConnections=300 && \
  assert_has "db-conns-explicit" 'max_connections=300'
assert_render_fails "db-conns-explicit-too-low" "database.maxConnections=50 is below" \
  --set broker.replicaCount=3 --set database.maxConnections=50
# Raised: NOTES says the database pod restarts once to apply it; not at 1.
if notes="$(helm install compat "$CHART" --dry-run=client --set broker.replicaCount=3 2>/dev/null)"; then
  grep -q "database pod" <<<"$notes" || \
    { echo "FAIL [db-conns-restart-notes]: NOTES must warn of the one database restart"; fail=1; }
else
  echo "FAIL [db-conns-restart-notes]: dry-run install failed"; fail=1
fi
if notes="$(helm install compat "$CHART" --dry-run=client 2>/dev/null)"; then
  grep -q "^max_connections" <<<"$notes" && \
    { echo "FAIL [db-conns-default-notes]: no max_connections note at replicaCount 1"; fail=1; }
fi
# External database: nothing to size, but NOTES states the requirement.
render "db-conns-external" --set database.enabled=false --set database.external.host=db.example.com \
  --set database.existingSecret=kg-db --set broker.replicaCount=3 && \
  assert_absent "db-conns-external" "max_connections="
if notes="$(helm install compat "$CHART" --dry-run=client --set database.enabled=false \
    --set database.external.host=db.example.com --set database.existingSecret=kg-db \
    --set broker.replicaCount=3 2>/dev/null)"; then
  grep -q "max_connections must be at least 141" <<<"$notes" || \
    { echo "FAIL [db-conns-external-notes]: NOTES must state the required max_connections"; fail=1; }
else
  echo "FAIL [db-conns-external-notes]: dry-run install failed"; fail=1
fi

# 17. Node catalog (nodeCatalog). Off by default, and off must be byte-for-
# byte what the chart rendered before the block existed: no knob under
# nodeCatalog, and not broker.auth.keys.catalog, may reach the output while
# it is off. A values file without the block (nodeCatalog=null) is the
# pre-feature values. The DB password is fixed so the renders can be
# compared (it is random otherwise).
nc_cmp() { # nc_cmp <label> <helm-args...>: every variant renders the same bytes
  local label="$1"; shift
  local base variant
  base="$(helm template compat "$CHART" --set database.password=cmp "$@" 2>&1)" || \
    { echo "FAIL [$label]: base did not render"; fail=1; return; }
  grep -qE 'NODE_CATALOG|NODE_SBOM|GRYPE_NODE_GROUP|BROKER_TOKEN_CATALOG|cataloger|catalog-(socket|tmp|no-token)|node-catalog' <<<"$base" && \
    { echo "FAIL [$label]: node catalog output while nodeCatalog is off"; fail=1; }
  for v in "--set nodeCatalog=null" \
           "--set nodeCatalog.enabled=false --set nodeCatalog.epoch=5 --set nodeCatalog.maxEpoch=9 --set nodeCatalog.grants=false --set nodeCatalog.retentionDays=0 --set nodeCatalog.worker.image.tag=v9.9.9 --set nodeCatalog.worker.tmpLimit=64Mi --set nodeCatalog.readOnlyClone=true" \
           "--set broker.auth.keys.catalog=node-sbom" \
           "--set supplychain.sources.node=null --set supplychain.grype.nodeGroupMaxWait=null" \
           "--set supplychain.sources.node.interval=1m --set supplychain.grype.nodeGroupMaxWait=5m"; do
    # shellcheck disable=SC2086 # $v is a list of flags
    variant="$(helm template compat "$CHART" --set database.password=cmp "$@" $v 2>&1)" || \
      { echo "FAIL [$label]: did not render with $v"; fail=1; continue; }
    [ "$variant" = "$base" ] || { echo "FAIL [$label]: output changed with $v while nodeCatalog is off"; fail=1; }
  done
}
nc_cmp "node-catalog-off-defaults"
nc_cmp "node-catalog-off-auth" --set broker.auth.enabled=true --set broker.auth.existingSecret=kg \
  --set broker.metrics.prometheusRule.enabled=true --set supplychain.enabled=true \
  --set supplychain.grype.enabled=true

NC_ON=(--set broker.auth.enabled=true --set broker.auth.existingSecret=kg --set nodeCatalog.enabled=true)
# container <name> — the named container's spec from the Controller DaemonSet.
container() {
  workload DaemonSet kguardian-controller | awk -v c="        - name: $1" '
    $0 == c { on = 1; print; next }
    on && (/^        - name: / || /^      [a-z]/) { exit }
    on { print }'
}
render "node-catalog-on" "${NC_ON[@]}" && {
  ctl="$(container controller)"
  cat_c="$(container cataloger)"
  broker_doc="$(workload Deployment kguardian-broker)"
  [ -n "$cat_c" ] || { echo "FAIL [node-catalog-on]: no cataloger container"; fail=1; }
  grep -A1 'name: NODE_CATALOG$' <<<"$ctl" | grep -q 'value: "on"' || \
    { echo "FAIL [node-catalog-on]: controller lacks NODE_CATALOG=on"; fail=1; }
  grep -A5 'name: BROKER_TOKEN_CATALOG' <<<"$ctl" | tr -d ' ' | tr '\n' ' ' | \
    grep -q 'name:kg key:catalog optional:true' || \
    { echo "FAIL [node-catalog-on]: controller BROKER_TOKEN_CATALOG must be optional key catalog"; fail=1; }
  grep -A1 'name: NODE_CATALOG_EPOCH' <<<"$ctl" | grep -q 'value: "1"' || \
    { echo "FAIL [node-catalog-on]: controller NODE_CATALOG_EPOCH must default to 1"; fail=1; }
  grep -A3 'name: POD_UID' <<<"$ctl" | grep -q 'fieldPath: metadata.uid' || \
    { echo "FAIL [node-catalog-on]: controller POD_UID must come from metadata.uid"; fail=1; }
  grep -q 'name: catalog-socket' <<<"$ctl" || \
    { echo "FAIL [node-catalog-on]: controller must mount the socket emptyDir"; fail=1; }
  # The token shadow is the worker's alone: the Controller needs its token.
  grep -q 'catalog-no-token' <<<"$ctl" && \
    { echo "FAIL [node-catalog-on]: the controller must keep its service-account token"; fail=1; }
  for want in 'runAsUser: 0' 'runAsNonRoot: false' 'allowPrivilegeEscalation: false' \
              'readOnlyRootFilesystem: true' '- DAC_READ_SEARCH' '- SETUID' '- SETGID' \
              'type: RuntimeDefault' 'type: container_t' 'level: s0-s0:c0.c1023' \
              'image: "ghcr.io/kguardian-dev/kguardian/cataloger:v' 'name: CATALOG_MEMORY_LIMIT' \
              'mountPath: /var/run/secrets/kubernetes.io/serviceaccount' 'mountPath: /tmp' \
              'mountPath: /run/kguardian/catalog' 'memory: 1Gi' 'kguardian-cataloger", "ping"'; do
    grep -qF -- "$want" <<<"$cat_c" || { echo "FAIL [node-catalog-on]: cataloger lacks '$want'"; fail=1; }
  done
  [ "$(grep -A3 'add:' <<<"$cat_c" | grep -c '^ *- ')" = "3" ] || \
    { echo "FAIL [node-catalog-on]: cataloger must add exactly three capabilities"; fail=1; }
  grep -qE 'BROKER_|privileged|hostPath|name: hostproc' <<<"$cat_c" && \
    { echo "FAIL [node-catalog-on]: cataloger must get no token, privilege or host mount"; fail=1; }
  grep -A3 '^      - name: catalog-tmp' <<<"$OUT" | tr -d ' ' | tr '\n' ' ' | \
    grep -q 'medium:Memory sizeLimit:"201326592"' || \
    { echo "FAIL [node-catalog-on]: /tmp must be a memory emptyDir sized to tmpLimit (192Mi)"; fail=1; }
  grep -q 'readinessProbe' <<<"$cat_c" && \
    { echo "FAIL [node-catalog-on]: the cataloger must have no readiness probe"; fail=1; }
  grep -A2 'requests:' <<<"$cat_c" | grep -q 'memory: 512Mi' || \
    { echo "FAIL [node-catalog-on]: the cataloger must request 512Mi"; fail=1; }
  for a in 'eks.amazonaws.com/skip-containers: cataloger' 'azure.workload.identity/skip-containers: cataloger'; do
    grep -qF "$a" <<<"$OUT" || { echo "FAIL [node-catalog-on]: pod lacks annotation $a"; fail=1; }
  done
  grep -A5 'name: BROKER_TOKEN_CATALOG' <<<"$broker_doc" | grep -q 'optional: true' || \
    { echo "FAIL [node-catalog-on]: broker BROKER_TOKEN_CATALOG must be optional"; fail=1; }
  for v in 'NODE_CATALOG_GRANTS' 'NODE_CATALOG_RETENTION_DAYS' 'NODE_CATALOG_MAX_EPOCH' 'NODE_CATALOG_MAX_HOLD_SECS'; do
    grep -q "name: $v" <<<"$broker_doc" || { echo "FAIL [node-catalog-on]: broker lacks $v"; fail=1; }
  done
  assert_absent "node-catalog-on" "kguardian-broker-node-catalog"
}
render "node-catalog-custom" "${NC_ON[@]}" --set broker.auth.keys.catalog=node-sbom \
  --set nodeCatalog.epoch=7 --set nodeCatalog.maxEpoch=7 --set nodeCatalog.grants=false \
  --set broker.metrics.prometheusRule.enabled=true && {
  [ "$(grep -A4 'name: BROKER_TOKEN_CATALOG' <<<"$OUT" | grep -c 'key: node-sbom')" = "2" ] || \
    { echo "FAIL [node-catalog-custom]: broker and controller must both read key node-sbom"; fail=1; }
  grep -A1 'name: NODE_CATALOG_GRANTS' <<<"$OUT" | grep -q 'value: "false"' || \
    { echo "FAIL [node-catalog-custom]: grants=false must reach the broker"; fail=1; }
  assert_has "node-catalog-custom" "kguardian-broker-node-catalog"
}
# `helm upgrade --reuse-values` from a release before nodeCatalog existed
# renders the new templates over the OLD chart's values: no nodeCatalog
# block and no broker.auth.keys.catalog, then `--set nodeCatalog.enabled=true`.
# Simulated with a copy of the chart whose values.yaml has both removed.
# Every key must fall back to the value values.yaml ships, so the workloads
# match a normal install byte for byte, the cataloger image included (Renovate
# bumps its tag in values.yaml and _helpers.tpl in one PR; checked below).
PRE="$(mktemp -d)"
trap 'rm -rf "$PRE"' EXIT
cp -R "$CHART" "$PRE/kguardian"
awk '/^nodeCatalog:/ { skip = 1; next }
     skip && /^[a-zA-Z]/ { skip = 0 }
     /^    node:$/ { sub_skip = 1; next }
     sub_skip && /^ {0,4}[a-zA-Z]/ { sub_skip = 0 }
     !skip && !sub_skip && !/^      catalog: catalog$/ && !/^    nodeGroupMaxWait:/' \
  "$CHART/values.yaml" > "$PRE/kguardian/values.yaml"
if grep -qE '^nodeCatalog:|catalog: catalog|^    node:$|nodeGroupMaxWait' "$PRE/kguardian/values.yaml"; then
  echo "FAIL [node-catalog-reuse-values]: could not strip the nodeCatalog defaults"; fail=1
fi
nc_workloads() { # nc_workloads <chart>: the Controller and Broker docs, enabled
  local out
  out="$(helm template compat "$1" "${NC_ON[@]}" --set database.password=cmp \
    --set supplychain.enabled=true --set supplychain.grype.enabled=true 2>&1)" || { echo "RENDER FAILED: $out"; return; }
  OUT="$out"
  workload DaemonSet kguardian-controller
  workload Deployment kguardian-broker
  workload Deployment kguardian-supplychain
}
helper_tag="$(sed -nE 's|.*"repository" "ghcr.io/kguardian-dev/kguardian/cataloger" "pullPolicy" "[^"]*" "tag" "([^"]+)".*|\1|p' \
  "$CHART/templates/_helpers.tpl")"
values_tag="$(awk '/^nodeCatalog:/ { nc = 1 } nc && /^[a-zA-Z]/ && !/^nodeCatalog:/ { nc = 0 }
  nc && /repository: ghcr.io\/kguardian-dev\/kguardian\/cataloger/ { img = 1 }
  nc && img && /^ *tag:/ { gsub(/[" ]|tag:/, ""); print; exit }' "$CHART/values.yaml")"
if [ -z "$helper_tag" ] || [ "$helper_tag" != "$values_tag" ]; then
  echo "FAIL [node-catalog-tag]: _helpers.tpl cataloger tag '$helper_tag' != values.yaml '$values_tag'"; fail=1
fi
want="$(nc_workloads "$CHART")"
got="$(nc_workloads "$PRE/kguardian")"
grep -q 'RENDER FAILED' <<<"$got" && { echo "FAIL [node-catalog-reuse-values]: ${got:0:300}"; fail=1; }
[ "$got" = "$want" ] || {
  echo "FAIL [node-catalog-reuse-values]: output differs from a full install:"
  diff <(echo "$want") <(echo "$got") | head -20; fail=1; }
if notes="$(helm install compat "$PRE/kguardian" --dry-run=client "${NC_ON[@]}" 2>&1)"; then
  grep -q 'need the "catalog"' <<<"$notes" || \
    { echo "FAIL [node-catalog-reuse-values]: NOTES must name the catalog key"; fail=1; }
else
  echo "FAIL [node-catalog-reuse-values]: dry-run install failed"; fail=1
fi
# Sizes as numbers (YAML reads 671088640 as a float) and in Ti reach the
# worker as bytes.
render "node-catalog-numeric-sizes" "${NC_ON[@]}" --set nodeCatalog.worker.memoryLimit=671088640 \
  --set nodeCatalog.worker.tmpLimit=201326592 && {
  grep -A1 'name: CATALOG_MEMORY_LIMIT' <<<"$OUT" | grep -q 'value: "671088640"' || \
    { echo "FAIL [node-catalog-numeric-sizes]: numeric memoryLimit must render as bytes"; fail=1; }
}
render "node-catalog-ti" "${NC_ON[@]}" --set nodeCatalog.worker.memoryLimit=1Ti \
  --set nodeCatalog.worker.resources.limits.memory=2Ti && {
  grep -A1 'name: CATALOG_MEMORY_LIMIT' <<<"$OUT" | grep -q 'value: "1099511627776"' || \
    { echo "FAIL [node-catalog-ti]: 1Ti must render as bytes"; fail=1; }
}
assert_render_fails "node-catalog-limit-milli" "the milli suffix m is not a byte count" \
  "${NC_ON[@]}" --set nodeCatalog.worker.resources.limits.memory=1000000000000m

# Supplychain node SBOM source: follows nodeCatalog.enabled unless set, and
# GRYPE_NODE_GROUP_MAX_WAIT only comes with the matcher.
SC_ON=(--set broker.auth.enabled=true --set broker.auth.existingSecret=kg --set supplychain.enabled=true)
render "node-source-follows" "${SC_ON[@]}" --set nodeCatalog.enabled=true --set supplychain.grype.enabled=true && {
  sc="$(workload Deployment kguardian-supplychain)"
  grep -A1 'name: NODE_SBOM_ENABLED' <<<"$sc" | grep -q 'value: "true"' || \
    { echo "FAIL [node-source-follows]: NODE_SBOM_ENABLED must follow nodeCatalog.enabled"; fail=1; }
  grep -A1 'name: NODE_SBOM_INTERVAL' <<<"$sc" | grep -q 'value: "5m"' || \
    { echo "FAIL [node-source-follows]: NODE_SBOM_INTERVAL must default to 5m"; fail=1; }
  grep -A1 'name: GRYPE_NODE_GROUP_MAX_WAIT' <<<"$sc" | grep -q 'value: "30m"' || \
    { echo "FAIL [node-source-follows]: GRYPE_NODE_GROUP_MAX_WAIT must default to 30m"; fail=1; }
}
render "node-source-off-override" "${SC_ON[@]}" --set nodeCatalog.enabled=true \
  --set supplychain.grype.enabled=true --set supplychain.sources.node.enabled=false && \
  assert_absent "node-source-off-override" "NODE_SBOM_ENABLED"
render "node-source-on-no-matcher" "${SC_ON[@]}" --set supplychain.sources.node.enabled=true && {
  assert_has    "node-source-on-no-matcher" "name: NODE_SBOM_ENABLED"
  assert_absent "node-source-on-no-matcher" "GRYPE_NODE_GROUP_MAX_WAIT"
}
if notes="$(helm install compat "$CHART" --dry-run=client "${SC_ON[@]}" --set supplychain.sources.node.enabled=true 2>&1)"; then
  grep -q 'Node SBOM source: ON but idle' <<<"$notes" || \
    { echo "FAIL [node-source-notes]: NOTES must say the node source needs the matcher"; fail=1; }
else
  echo "FAIL [node-source-notes]: dry-run install failed"; fail=1
fi
assert_render_fails "node-source-schema-interval" "supplychain/sources/node/interval" \
  "${SC_ON[@]}" --set-string supplychain.sources.node.interval=5
# Durations the component refuses at startup (a crash loop would also stop
# Trivy ingest) are refused at template time instead.
assert_render_fails "node-source-interval-zero" "supplychain.sources.node.interval must be a positive duration" \
  "${SC_ON[@]}" --set supplychain.sources.node.enabled=true --set supplychain.sources.node.interval=0s
assert_render_fails "node-source-max-wait-short" "supplychain.grype.nodeGroupMaxWait must be at least 1m" \
  "${SC_ON[@]}" --set supplychain.sources.node.enabled=true --set supplychain.grype.enabled=true \
  --set supplychain.grype.nodeGroupMaxWait=59s
render "node-source-durations-ok" "${SC_ON[@]}" --set supplychain.sources.node.enabled=true \
  --set supplychain.grype.enabled=true --set supplychain.sources.node.interval=1h30m \
  --set supplychain.grype.nodeGroupMaxWait=90000ms && {
  grep -A1 'name: GRYPE_NODE_GROUP_MAX_WAIT' <<<"$OUT" | grep -q 'value: "90000ms"' || \
    { echo "FAIL [node-source-durations-ok]: 90000ms is 1m30s and must render"; fail=1; }
}
# A name already in supplychain.env wins: the chart does not add its own
# (a duplicate env name is rejected by server-side apply).
render "node-source-env-override" "${SC_ON[@]}" --set supplychain.sources.node.enabled=true \
  --set supplychain.grype.enabled=true \
  --set 'supplychain.env[0].name=NODE_SBOM_INTERVAL' --set 'supplychain.env[0].value=10m' \
  --set 'supplychain.env[1].name=GRYPE_NODE_GROUP_MAX_WAIT' --set 'supplychain.env[1].value=45m' \
  --set 'supplychain.env[2].name=NODE_SBOM_ENABLED' --set-string 'supplychain.env[2].value=true' && {
  sc="$(workload Deployment kguardian-supplychain)"
  for v in NODE_SBOM_ENABLED NODE_SBOM_INTERVAL GRYPE_NODE_GROUP_MAX_WAIT; do
    [ "$(grep -c "name: $v\$" <<<"$sc")" = "1" ] || \
      { echo "FAIL [node-source-env-override]: $v must appear once (from supplychain.env)"; fail=1; }
  done
  grep -A1 'name: NODE_SBOM_INTERVAL' <<<"$sc" | grep -q 'value: 10m' || \
    { echo "FAIL [node-source-env-override]: supplychain.env's NODE_SBOM_INTERVAL must win"; fail=1; }
}

# Guards, at template time and in values.schema.json.
assert_render_fails "node-catalog-needs-auth" "nodeCatalog.enabled=true requires broker.auth.enabled=true" \
  --set nodeCatalog.enabled=true
assert_render_fails "node-catalog-needs-scoped" "requires broker.auth.mode=scoped" \
  "${NC_ON[@]}" --set broker.auth.mode=shared
assert_render_fails "node-catalog-epoch-above-max" "nodeCatalog.epoch must be between 1 and" \
  "${NC_ON[@]}" --set nodeCatalog.epoch=11 --set nodeCatalog.maxEpoch=10
assert_render_fails "node-catalog-hold-below-timeout" "nodeCatalog.maxHoldSeconds must be" \
  "${NC_ON[@]}" --set nodeCatalog.scanTimeoutSeconds=1800 --set nodeCatalog.maxHoldSeconds=1200
assert_render_fails "node-catalog-memory" "must hold memoryLimit" \
  "${NC_ON[@]}" --set nodeCatalog.worker.resources.limits.memory=768Mi
assert_render_fails "node-catalog-schema-epoch" "nodeCatalog/epoch" \
  "${NC_ON[@]}" --set nodeCatalog.epoch=0
assert_render_fails "node-catalog-schema-quantity" "nodeCatalog/worker/memoryLimit" \
  "${NC_ON[@]}" --set nodeCatalog.worker.memoryLimit=1G
assert_render_fails "node-catalog-schema-selinux" "nodeCatalog/worker/seLinuxOptions/type" \
  "${NC_ON[@]}" --set nodeCatalog.worker.seLinuxOptions.type=spc_t
assert_render_fails "node-catalog-schema-unknown-key" "nodeCatalog" \
  --set nodeCatalog.enable=true

if [ "$fail" -ne 0 ]; then
  echo "G4 values-compatibility check FAILED"
  exit 1
fi
echo "G4 values-compatibility check passed"
