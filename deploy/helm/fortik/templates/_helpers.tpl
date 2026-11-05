{{- define "fortik.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fortik.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "fortik.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Refuse settings that would make Fortik unsafe or wrong. */}}
{{- define "fortik.validate" -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- if or (ne (default "memory" .Values.config.counters.provider) "redis") (ne (default "memory" .Values.config.events.provider) "nats") -}}
{{- fail "replicaCount > 1 needs config.counters.provider: redis and config.events.provider: nats (shared counters and events)" -}}
{{- end -}}
{{- if and (eq .Values.config.secrets.provider "encfile") .Values.secretStore.encfilePersistence -}}
{{- fail "replicaCount > 1 needs config.secrets.provider: vault (an encfile store is one pod's volume)" -}}
{{- end -}}
{{- end -}}
{{- if .Values.config.auth.dev_login.enabled -}}
{{- fail "config.auth.dev_login must stay disabled outside local development" -}}
{{- end -}}
{{- if .Values.config.approvals.allow_token_pairs -}}
{{- fail "config.approvals.allow_token_pairs is for local demos only" -}}
{{- end -}}
{{- end -}}

{{- define "fortik.securityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "fortik.env" -}}
- name: FORTIK_DATABASE_URL
  valueFrom: {secretKeyRef: {name: {{ .Values.existingSecret }}, key: database-url}}
- name: REDIS_URL
  valueFrom: {secretKeyRef: {name: {{ .Values.existingSecret }}, key: redis-url, optional: true}}
{{- if eq .Values.config.secrets.provider "encfile" }}
- name: FORTIK_MASTER_KEY
  valueFrom: {secretKeyRef: {name: {{ .Values.existingSecret }}, key: master-key}}
{{- else if eq .Values.config.secrets.provider "vault" }}
- name: VAULT_TOKEN
  valueFrom: {secretKeyRef: {name: {{ .Values.existingSecret }}, key: vault-token}}
{{- end }}
{{- end -}}
