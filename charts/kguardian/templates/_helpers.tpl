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
Optional BROKER_AUTH_TOKEN env entry. Emits nothing unless
broker.auth.enabled. The token lives in a Secret the operator provides
(broker.auth.existingSecret) — we deliberately do not generate one in the
template so it stays stable across upgrades. Include with the right
nindent per consumer (broker/mcp env are indented 12, controller 10).
Usage: {{- include "kguardian.brokerAuthEnv" . | nindent 12 }}
*/}}
{{- define "kguardian.brokerAuthEnv" -}}
{{- if .Values.broker.auth.enabled -}}
- name: BROKER_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ required "broker.auth.existingSecret is required when broker.auth.enabled=true" .Values.broker.auth.existingSecret }}
      key: {{ .Values.broker.auth.secretKey }}
{{- end -}}
{{- end -}}

{{/*
AI-path component gate (SIMPLIFICATION-GOAL.md WS-D). ai.enabled=true turns
on the assistant with one value. Since WS-B/WS-C the assistant is a single
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
AI provider env (SIMPLIFICATION-GOAL.md WS-D). The one-line provider path:
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

SECURITY: the endpoint hands cluster telemetry to any caller that can reach
the Service, with no LLM in the path. ClusterIP is not a boundary — every pod
in the cluster can route to it unless a NetworkPolicy says otherwise, and this
chart ships no llm-bridge NetworkPolicy. So the chart FAILS TO RENDER when the
endpoint is enabled with neither a token nor an explicit opt-out, rather than
quietly serving it open. The opt-out exists because a default-deny
NetworkPolicy or a mesh with mTLS makes the token genuinely redundant, and
refusing outright would be the chart overruling the operator about their own
cluster — but it has to be *stated*, so it shows up in a values diff.

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
{{- fail "ai.mcp.enabled=true requires ai.mcp.auth.existingSecret — the MCP endpoint exposes cluster telemetry (pod traffic, syscalls, audit verdicts) to anything that can reach the ClusterIP Service, which is every pod in the cluster unless a NetworkPolicy says otherwise. Create a token Secret:\n  kubectl create secret generic kguardian-mcp-token --from-literal=token=\"$(openssl rand -hex 32)\"\nand set ai.mcp.auth.existingSecret=kguardian-mcp-token.\nIf llm-bridge is already fronted by a default-deny NetworkPolicy or a mesh with mTLS, set ai.mcp.auth.allowUnauthenticated=true to serve it without a token deliberately." -}}
{{- end }}
{{- if $limit }}
- name: MCP_RATE_LIMIT_PER_MIN
  value: {{ $limit | quote }}
{{- end }}
{{- end -}}
{{- end -}}
