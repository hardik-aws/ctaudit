{{/* Base name for every object: <release>-ctaudit, or the release name when it already contains "ctaudit". */}}
{{- define "ctaudit.fullname" -}}
{{- if contains "ctaudit" .Release.Name -}}
{{- .Release.Name | trunc 32 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-ctaudit" .Release.Name | trunc 32 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Name of one scanner's Deployment and Service. Call with (dict "root" $ "scanner" $s). */}}
{{- define "ctaudit.scannerName" -}}
{{- printf "%s-%s" (include "ctaudit.fullname" .root) .scanner.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ctaudit.selectorLabels" -}}
app.kubernetes.io/name: ctaudit
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ctaudit.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "ctaudit.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ctaudit.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ctaudit.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* True when the chart renders its own Loki Secret. */}}
{{- define "ctaudit.managedLokiSecret" -}}
{{- if and .Values.loki.auth (not .Values.loki.existingSecret) -}}true{{- end -}}
{{- end -}}

{{/* Secret loaded with envFrom, or empty for none. */}}
{{- define "ctaudit.lokiSecretName" -}}
{{- if .Values.loki.existingSecret -}}
{{- .Values.loki.existingSecret -}}
{{- else if include "ctaudit.managedLokiSecret" . -}}
{{- printf "%s-loki" (include "ctaudit.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Prometheus job selector for this release's scanners. */}}
{{- define "ctaudit.jobSelector" -}}
job=~"{{ include "ctaudit.fullname" . }}-.*"
{{- end -}}

{{/* Checks the schema cannot express. */}}
{{- define "ctaudit.validate" -}}
{{- $seen := dict -}}
{{- range .Values.scanners -}}
{{- if hasKey $seen .name -}}
{{- fail (printf "scanners: duplicate name %q" .name) -}}
{{- end -}}
{{- $_ := set $seen .name true -}}
{{- if not (or .bucket $.Values.aws.bucket) -}}
{{- fail (printf "scanners[%s]: set bucket or aws.bucket" .name) -}}
{{- end -}}
{{- if not (or .accounts $.Values.aws.accounts) -}}
{{- fail (printf "scanners[%s]: set accounts or aws.accounts" .name) -}}
{{- end -}}
{{- if not (or .regions $.Values.aws.regions) -}}
{{- fail (printf "scanners[%s]: set regions or aws.regions" .name) -}}
{{- end -}}
{{- end -}}
{{- with .Values.loki.auth -}}
{{- if and .token (or .user .password) -}}
{{- fail "loki.auth: set either token or user and password, not both" -}}
{{- end -}}
{{- if and .password (not .user) -}}
{{- fail "loki.auth: password is set but user is not" -}}
{{- end -}}
{{- end -}}
{{- end -}}
