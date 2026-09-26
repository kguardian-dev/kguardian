{{/*
Expand the name of the chart.
*/}}
{{- define "kguardian.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kguardian.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
This gets around an problem within helm discussed here
https://github.com/helm/helm/issues/5358
*/}}
{{- define "kguardian.namespace" -}}
    {{ .Values.namespace.name | default .Release.Namespace }}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kguardian.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kguardian.labels" -}}
{{ include "kguardian.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.global.labels}}
{{ toYaml .Values.global.labels }}
{{- end }}
{{- end }}

{{/*
Common Annotations
*/}}
{{- define "kguardian.annotations" -}}
{{- if .Values.global.annotations -}}
  {{- toYaml .Values.global.annotations | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kguardian.selectorLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve an image tag, prepending "v" for bare semver versions.
release-please writes bare versions (e.g. "1.8.0"); GHCR tags use "v" prefix.
Passes through non-semver values like "latest" or "sha-abc123" unchanged.
Usage: include "kguardian.imageTag" .Values.<component>.image.tag
*/}}
{{- define "kguardian.imageTag" -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+" . -}}v{{ . }}{{- else -}}{{ . }}{{- end -}}
{{- end -}}

{{/*
Resolve a pod's priorityClassName: the component's own value first, falling
back to global.priorityClassName. Both default to "" so nothing renders
unless an operator asks for one.
Usage: {{- with include "kguardian.priorityClassName" (dict "component" .Values.broker "global" .Values.global) }}
*/}}
{{- define "kguardian.priorityClassName" -}}
{{- .component.priorityClassName | default .global.priorityClassName -}}
{{- end -}}

{{/*
Name of the Secret holding the database password.
Returns `database.existingSecret` if set, otherwise the chart-managed default.
Usage: include "kguardian.dbSecretName" .
*/}}
{{- define "kguardian.dbSecretName" -}}
{{- .Values.database.existingSecret | default "kguardian-db-credentials" -}}
{{- end -}}

{{/*
Hostname for the broker's DATABASE_URL.
- database.enabled=true  -> in-cluster service FQDN
- database.enabled=false -> database.external.host (required)
Usage: include "kguardian.dbHost" .
*/}}
{{- define "kguardian.dbHost" -}}
{{- if .Values.database.enabled -}}
{{- printf "%s.%s.svc.cluster.local" .Values.database.service.name (include "kguardian.namespace" . | trim) -}}
{{- else -}}
{{- required "database.external.host is required when database.enabled=false" .Values.database.external.host -}}
{{- end -}}
{{- end -}}

{{/*
Port for the broker's DATABASE_URL.
*/}}
{{- define "kguardian.dbPort" -}}
{{- if .Values.database.enabled -}}
{{- .Values.database.container.port -}}
{{- else -}}
{{- .Values.database.external.port -}}
{{- end -}}
{{- end -}}

{{/*
Full broker DATABASE_URL value, with $(DB_PASSWORD) interpolated by the
container at runtime via secretKeyRef. sslmode is appended only for the
external case so the in-cluster URL stays identical to prior releases.
*/}}
{{- define "kguardian.dbUrl" -}}
{{- $base := printf "postgres://%s:$(DB_PASSWORD)@%s:%v/%s" .Values.database.user (include "kguardian.dbHost" .) (include "kguardian.dbPort" .) .Values.database.databaseName -}}
{{- if and (not .Values.database.enabled) .Values.database.external.sslMode -}}
{{- printf "%s?sslmode=%s" $base .Values.database.external.sslMode -}}
{{- else -}}
{{- $base -}}
{{- end -}}
{{- end -}}

{{/*
Broker auth mode, validated. "scoped" (default): one Secret with a key per
scope (broker.auth.keys.*), each client mounts only the key it needs.
"shared": the pre-scopes single token (broker.auth.secretKey) that every
component presents and that grants read + ingest.
*/}}
{{- define "kguardian.brokerAuthMode" -}}
{{- $mode := .Values.broker.auth.mode | default "scoped" -}}
{{- if not (has $mode (list "scoped" "shared")) -}}
{{- fail (printf "broker.auth.mode must be \"scoped\" or \"shared\", got %q" $mode) -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

{{- define "kguardian.brokerAuthSecret" -}}
{{- required "broker.auth.existingSecret is required when broker.auth.enabled=true. Create one with a key per scope:\n  kubectl -n <ns> create secret generic kguardian-broker-auth --from-literal=read=\"$(openssl rand -hex 32)\" --from-literal=ingest=\"$(openssl rand -hex 32)\"\nand set broker.auth.existingSecret=kguardian-broker-auth." .Values.broker.auth.existingSecret -}}
{{- end -}}

{{/*
True when some component that WRITES supply-chain data (vulnerability
reports, attestations) is enabled. Keyed on .Values.supplychain.enabled,
which may not exist yet; a missing block reads as false.
*/}}
{{- define "kguardian.supplychainEnabled" -}}
{{- $sc := .Values.supplychain | default dict -}}
{{- if and (kindIs "map" $sc) $sc.enabled -}}true{{- end -}}
{{- end -}}

{{/*
Guard: supply-chain components must never run against an open broker. A
vulnerability inventory is a target list, and an unauthenticated broker
would let any pod post a forged "clean" scan result. Fails at template time.
*/}}
{{- define "kguardian.supplychainAuthGuard" -}}
{{- if and (include "kguardian.supplychainEnabled" .) (not .Values.broker.auth.enabled) -}}
{{- fail "supplychain.enabled=true requires broker.auth.enabled=true: the supply-chain endpoints expose every known vulnerability in the cluster and accept scan results, so they are never served without authentication. Create the token Secret (keys read, ingest, supplychain) and set broker.auth.enabled=true and broker.auth.existingSecret. See docs: Broker authentication." -}}
{{- end -}}
{{- if and (include "kguardian.supplychainEnabled" .) (eq (include "kguardian.brokerAuthMode" .) "shared") -}}
{{- fail "supplychain.enabled=true requires broker.auth.mode=scoped: in shared mode every component holds the same token, so any of them could post supply-chain results. Add a supplychain key to the auth Secret and use scoped mode." -}}
{{- end -}}
{{- end -}}

{{/*
Broker-side token env. Emits nothing unless broker.auth.enabled.
scoped: BROKER_TOKEN_<SCOPE> per key. read and ingest are required keys
(the pod will not start without them, which is the point: a typo must not
silently leave a scope open). supplychain is required only when a
supply-chain component is enabled; admin is always optional.
shared: BROKER_AUTH_TOKEN from broker.auth.secretKey.
Usage: {{- include "kguardian.brokerAuthServerEnv" . | nindent 12 }}
*/}}
{{- define "kguardian.brokerAuthServerEnv" -}}
{{- if .Values.broker.auth.enabled -}}
{{- $secret := include "kguardian.brokerAuthSecret" . -}}
{{- if eq (include "kguardian.brokerAuthMode" .) "shared" -}}
- name: BROKER_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ .Values.broker.auth.secretKey }}
{{- else -}}
{{- $keys := .Values.broker.auth.keys -}}
{{- $scEnabled := include "kguardian.supplychainEnabled" . -}}
- name: BROKER_TOKEN_READ
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.read }}
- name: BROKER_TOKEN_INGEST
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.ingest }}
- name: BROKER_TOKEN_SUPPLYCHAIN
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.supplychain }}
      {{- if not $scEnabled }}
      optional: true
      {{- end }}
- name: BROKER_TOKEN_ADMIN
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.admin }}
      optional: true
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Client-side token env: BROKER_AUTH_TOKEN holding the one token this
component presents. Emits nothing unless broker.auth.enabled.
scope is one of read | ingest | supplychain.
  controller  → ingest (also grants read: /pod/list, seccomp profiles)
  frontend    → read   (injected server-side by the /api proxy)
  llm-bridge  → read
  supplychain → supplychain
Usage: {{- include "kguardian.brokerAuthClientEnv" (dict "root" $ "scope" "read") | nindent 12 }}
*/}}
{{- define "kguardian.brokerAuthClientEnv" -}}
{{- $root := .root -}}
{{- if $root.Values.broker.auth.enabled -}}
{{- if not (has .scope (list "read" "ingest" "supplychain")) -}}
{{- fail (printf "kguardian.brokerAuthClientEnv: unknown scope %q" .scope) -}}
{{- end -}}
{{- $key := $root.Values.broker.auth.secretKey -}}
{{- if eq (include "kguardian.brokerAuthMode" $root) "scoped" -}}
{{- $key = index $root.Values.broker.auth.keys .scope -}}
{{- end -}}
- name: BROKER_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "kguardian.brokerAuthSecret" $root }}
      key: {{ $key }}
{{- end -}}
{{- end -}}

{{/*
Deprecated alias kept so an out-of-tree template that still includes it
renders; it now emits the least-privilege (read) client token.
*/}}
{{- define "kguardian.brokerAuthEnv" -}}
{{- include "kguardian.brokerAuthClientEnv" (dict "root" . "scope" "read") -}}
{{- end -}}

{{/*
AI-path component gate. ai.enabled=true turns
on the assistant with one value. The assistant is a single
workload — llm-bridge runs the tools and policy/seccomp generation in-process,
so the retired mcp-server and advisor-serve components no longer render. The
per-component `llmBridge.enabled` flag still works and remains the way to
switch the component on; this helper ORs the two so existing values files
render identically. Truthy = non-empty string.
Usage: {{- if include "kguardian.llmBridgeEnabled" . }}
*/}}
{{- define "kguardian.llmBridgeEnabled" -}}
{{- if or .Values.ai.enabled .Values.llmBridge.enabled }}true{{- end -}}
{{- end -}}

{{/*
AI provider env. The one-line provider path:
ai.provider + ai.secret inject the correct env var for the chosen LLM provider
from a single operator-supplied Secret. Emits nothing unless ai.provider is set.
The per-provider llmBridge.secrets.* blocks remain and are additive, so an
existing values file keeps working unchanged.
Usage: {{- include "kguardian.aiProviderEnv" . | nindent 12 }}
*/}}
{{- define "kguardian.aiProviderEnv" -}}
{{- $provider := .Values.ai.provider | default "" -}}
{{- if $provider -}}
{{- $envByProvider := dict "openai" "OPENAI_API_KEY" "anthropic" "ANTHROPIC_API_KEY" "gemini" "GOOGLE_API_KEY" "copilot" "GITHUB_TOKEN" -}}
{{- $envName := index $envByProvider $provider -}}
{{- if not $envName -}}
{{- fail (printf "ai.provider must be one of openai|anthropic|gemini|copilot, got %q" $provider) -}}
{{- end -}}
- name: {{ $envName }}
  valueFrom:
    secretKeyRef:
      name: {{ required "ai.secret is required when ai.provider is set" .Values.ai.secret }}
      key: {{ .Values.llmBridge.secrets.keyName }}
      optional: true
{{- end -}}
{{- end -}}

{{/*
AI endpoint env: base URL and default model for the provider named by
ai.provider. Keyed identically to `kguardian.aiProviderEnv` above so one
`ai.provider` value drives the key, the endpoint, and the model together.

These are plain values, not secrets — which is why they live on ai.* and NOT
under llmBridge.secrets.*. Each is emitted only when non-empty (whitespace
counts as empty), so a default install renders exactly the env block it
rendered before these keys existed.

The bridge appends its request path to the base URL verbatim and never
adjusts a /v1 segment; see llm-bridge/src/providers/baseUrl.ts for why.
Usage: {{- include "kguardian.aiEndpointEnv" . | nindent 12 }}
*/}}
{{- define "kguardian.aiEndpointEnv" -}}
{{- $provider := .Values.ai.provider | default "" -}}
{{- $baseUrl := .Values.ai.baseUrl | default "" | toString | trim -}}
{{- $model := .Values.ai.model | default "" | toString | trim -}}
{{- if and (not $provider) (or $baseUrl $model) -}}
{{- fail "ai.baseUrl and ai.model require ai.provider to be set — without it the chart cannot know which provider's env var to write, and the value would be silently ignored. Set ai.provider (openai|anthropic|gemini|copilot), or use llmBridge.env to set the provider env var directly." -}}
{{- end -}}
{{- if $provider -}}
{{- /* Note the deliberate asymmetry for gemini: the API key env var is
       GOOGLE_API_KEY (see aiProviderEnv) while the base and model are
       GEMINI_*. The bridge reads exactly these names — do not "fix" it. */ -}}
{{- $baseUrlByProvider := dict "openai" "OPENAI_BASE_URL" "anthropic" "ANTHROPIC_BASE_URL" "gemini" "GEMINI_BASE_URL" "copilot" "COPILOT_BASE_URL" -}}
{{- $modelByProvider := dict "openai" "OPENAI_MODEL" "anthropic" "ANTHROPIC_MODEL" "gemini" "GEMINI_MODEL" "copilot" "COPILOT_MODEL" -}}
{{- if $baseUrl }}
- name: {{ index $baseUrlByProvider $provider }}
  value: {{ $baseUrl | quote }}
{{- end }}
{{- if $model }}
- name: {{ index $modelByProvider $provider }}
  value: {{ $model | quote }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
MCP endpoint env. Emits nothing unless ai.mcp.enabled, so /mcp is not routed
at all on a default install and the path 404s.

SECURITY: the endpoint serves cluster telemetry with no LLM in the path. Be
precise about what that changes. A workload already in the cluster can read
the same data straight from the Broker today (broker.auth.enabled is false by
default), so /mcp does not newly expose it in-cluster. What /mcp adds is a
route OUT: it is built to be consumed from a workstation over port-forward, by
a client whose config may be shared or committed.

So the chart FAILS TO RENDER when the endpoint is enabled with neither a token
nor an explicit opt-out, rather than quietly serving it open. This is a new
endpoint with no existing users, which makes the strict default free now and
impossible to add later without breaking people. The opt-out exists because a
default-deny NetworkPolicy or a mesh with mTLS makes the token genuinely
redundant, and refusing outright would be the chart overruling the operator
about their own cluster — but it has to be *stated*, so it shows up in a
values diff.

The Broker's open-by-default API is the wider gap, and it is deliberately not
addressed here: changing that default is a breaking change and needs its own
upgrade note rather than riding along with an opt-in feature.

MCP_AUTH_TOKEN is deliberately NOT `optional: true`, unlike the provider API
keys above. An optional secretKeyRef whose Secret is missing leaves the env
var unset, and the bridge reads unset as "no auth" — a typo in the Secret name
would silently serve the endpoint wide open. Without `optional` the pod fails
to start instead, which is the correct direction to fail.
Usage: {{- include "kguardian.mcpEnv" . | nindent 12 }}
*/}}
{{- define "kguardian.mcpEnv" -}}
{{- if .Values.ai.mcp.enabled -}}
{{- $secret := .Values.ai.mcp.auth.existingSecret | default "" | toString | trim -}}
{{- $limit := .Values.ai.mcp.rateLimitPerMin | default "" | toString | trim -}}
- name: MCP_ENABLED
  value: "true"
{{- if $secret }}
- name: MCP_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ .Values.ai.mcp.auth.secretKey }}
{{- else if not .Values.ai.mcp.auth.allowUnauthenticated -}}
{{- fail "ai.mcp.enabled=true requires ai.mcp.auth.existingSecret — /mcp serves cluster telemetry (pod traffic, syscalls, audit verdicts) to any caller that reaches it, and it exists to be consumed from OUTSIDE the cluster over kubectl port-forward, by a client whose config may be shared or committed. Create a token Secret:\n  kubectl create secret generic kguardian-mcp-token --from-literal=token=\"$(openssl rand -hex 32)\"\nand set ai.mcp.auth.existingSecret=kguardian-mcp-token.\nIf llm-bridge is already fronted by a default-deny NetworkPolicy or a mesh with mTLS, set ai.mcp.auth.allowUnauthenticated=true to serve it without a token deliberately." -}}
{{- end }}
{{- if $limit }}
- name: MCP_RATE_LIMIT_PER_MIN
  value: {{ $limit | quote }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
ImageTrustPolicy evaluation in the evaluator (#1533 P2-2): "true" or "".
evaluator.imageTrust.enabled wins when set; unset (null) follows
supplychain.signatureDiscovery.enabled. Used by the evaluator Deployment,
its ClusterRole and the broker NetworkPolicy, so they cannot disagree.
*/}}
{{- define "kguardian.imageTrustEnabled" -}}
{{- $it := .Values.evaluator.imageTrust | default dict -}}
{{- $on := and .Values.evaluator.enabled .Values.supplychain.enabled (.Values.supplychain.signatureDiscovery | default dict).enabled -}}
{{- if not (kindIs "invalid" $it.enabled) -}}
{{- $on = and .Values.evaluator.enabled $it.enabled -}}
{{- end -}}
{{- if $on -}}true{{- end -}}
{{- end -}}
