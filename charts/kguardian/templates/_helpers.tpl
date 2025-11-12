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
