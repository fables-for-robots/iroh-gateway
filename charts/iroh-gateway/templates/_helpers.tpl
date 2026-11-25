{{- define "iroh-gateway.name" -}}
{{ default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "iroh-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- $name := include "iroh-gateway.name" . -}}
{{- if contains $name .Release.Name -}}
{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{ printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "iroh-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iroh-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "iroh-gateway.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "iroh-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "iroh-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "iroh-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end }}

{{/*
The namespaces the operator serves Gateways in, comma-separated: gatewayNamespaces without
repeats, or the release namespace when it is empty.
*/}}
{{- define "iroh-gateway.gatewayNamespaces" -}}
{{ .Values.gatewayNamespaces | default (list .Release.Namespace) | uniq | join "," }}
{{- end }}
