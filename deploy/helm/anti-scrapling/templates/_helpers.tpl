{{/*
Expand the name of the chart.
*/}}
{{- define "anti-scrapling.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "anti-scrapling.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "anti-scrapling.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "anti-scrapling.labels" -}}
helm.sh/chart: {{ include "anti-scrapling.chart" . }}
{{ include "anti-scrapling.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "anti-scrapling.selectorLabels" -}}
app.kubernetes.io/name: {{ include "anti-scrapling.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the token secret to use
*/}}
{{- define "anti-scrapling.tokenSecretName" -}}
{{- if .Values.token.existingSecret }}
{{- .Values.token.existingSecret }}
{{- else }}
{{- include "anti-scrapling.fullname" . }}-token
{{- end }}
{{- end }}

{{/*
Name of the policy configmap
*/}}
{{- define "anti-scrapling.configmapName" -}}
{{- include "anti-scrapling.fullname" . }}-policy
{{- end }}
