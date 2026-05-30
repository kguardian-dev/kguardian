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
