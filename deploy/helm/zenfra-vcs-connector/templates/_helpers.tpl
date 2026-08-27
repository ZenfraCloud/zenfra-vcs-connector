{{/* Chart name, overridable. */}}
{{- define "zenfra-vcs-connector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified release name. */}}
{{- define "zenfra-vcs-connector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "zenfra-vcs-connector.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "zenfra-vcs-connector.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "zenfra-vcs-connector.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "zenfra-vcs-connector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zenfra-vcs-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "zenfra-vcs-connector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "zenfra-vcs-connector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Absolute path of the mounted upstream credential. */}}
{{- define "zenfra-vcs-connector.secretFilePath" -}}
{{- printf "%s/%s" (trimSuffix "/" .Values.secret.mountPath) .Values.secret.credentialKey -}}
{{- end -}}
