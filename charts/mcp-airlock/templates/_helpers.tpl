{{- define "mcp-airlock.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-airlock.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "mcp-airlock.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "mcp-airlock.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mcp-airlock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-airlock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "mcp-airlock.secretName" -}}
{{ .Values.existingSecret | default (include "mcp-airlock.fullname" .) }}
{{- end }}

{{- /* A quoted env value or argument. A values file decodes a whole number as float64, which
       quote prints as 1.048576e+08; --set gives int64 and is fine. Whole floats go through
       int64 so the proxy gets "104857600". */ -}}
{{- define "mcp-airlock.scalar" -}}
{{- if or (kindIs "map" .) (kindIs "slice" .) }}
{{- fail (printf "env values and extraArgs must be scalars, got %v; an entry with valueFrom goes in extraEnv" .) }}
{{- else if and (kindIs "float64" .) (eq (float64 (int64 .)) .) }}
{{- int64 . | quote }}
{{- else }}
{{- . | quote }}
{{- end }}
{{- end }}
