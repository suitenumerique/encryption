{{/*
Chart name, release-qualified name, labels: the standard trio.
*/}}
{{- define "encryption.name" -}}
{{- default "encryption" .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "encryption.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "encryption" .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "encryption.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "encryption.selectorLabels" -}}
app.kubernetes.io/name: {{ include "encryption.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The server pods only. The migration Job's pods carry the selector labels too, so a
budget or a spread constraint on those alone would count them: a budget then fails on a
Job ("jobs.batch does not implement the scale subresource") and turns Degraded. Not in
the Deployment's selector, which cannot change on an existing release.
*/}}
{{- define "encryption.serverLabel" -}}
app.kubernetes.io/component: server
{{- end }}

{{- define "encryption.labels" -}}
helm.sh/chart: {{ include "encryption.chart" . }}
{{ include "encryption.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.Version | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "encryption.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "encryption.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "encryption.migrationServiceAccountName" -}}
{{- $sa := .Values.database.migration.serviceAccount }}
{{- if $sa.create }}
{{- default (printf "%s-migrate" (include "encryption.fullname" .)) $sa.name }}
{{- else }}
{{- default "default" $sa.name }}
{{- end }}
{{- end }}

{{/*
The image reference, in Docker's own grammar: `repository:tag@digest`. The digest names
exact bytes and is what the runtime resolves; the tag is the label a human reads next to
it. Without a digest the tag alone is used, and one of the two is required: the chart is
versioned apart from the application and has no default image of its own.
*/}}
{{- define "encryption.image" -}}
{{- if not (or .Values.image.tag .Values.image.digest) }}
{{- fail "image.tag or image.digest is required: the chart has no default application version" }}
{{- end }}
{{- $reference := .Values.image.repository }}
{{- if .Values.image.tag }}
{{- $reference = printf "%s:%s" $reference .Values.image.tag }}
{{- end }}
{{- if .Values.image.digest }}
{{- $reference = printf "%s@%s" $reference .Values.image.digest }}
{{- end }}
{{- $reference }}
{{- end }}

{{/*
A required scalar, with the value path in the message so the operator knows which key
to set. Usage: include "encryption.required" (list .Values.hosts.vault "hosts.vault")
*/}}
{{- define "encryption.required" -}}
{{- $value := index . 0 -}}
{{- $path := index . 1 -}}
{{- required (printf "%s is required" $path) $value -}}
{{- end }}

{{/*
One env entry read from a Secret. Args: dict "root" $ "env" NAME "value" inline
"existing" {name,key} "key" KEY_IN_CHART_SECRET, and optionally "secretName" when the
inline value lives in a Secret other than the release's own. An existing Secret wins over
an inline value; nothing is rendered when neither is given.
*/}}
{{- define "encryption.secretEnv" -}}
{{- if .existing.name }}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ .existing.name | quote }}
      key: {{ .existing.key | default .key | quote }}
{{- else if .value }}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ .secretName | default (include "encryption.fullname" .root) | quote }}
      key: {{ .key | quote }}
{{- end }}
{{- end }}

{{/*
Same for a user/password pair. Args: dict "root" $ "prefix" MAILER_SMTP "relay" <relay values>
*/}}
{{- define "encryption.relayCredentialsEnv" -}}
{{- $userEnv := printf "%s_USER" .prefix -}}
{{- $passwordEnv := printf "%s_PASSWORD" .prefix -}}
{{- if .relay.existingSecret.name }}
- name: {{ $userEnv }}
  valueFrom:
    secretKeyRef:
      name: {{ .relay.existingSecret.name | quote }}
      key: {{ .relay.existingSecret.userKey | quote }}
- name: {{ $passwordEnv }}
  valueFrom:
    secretKeyRef:
      name: {{ .relay.existingSecret.name | quote }}
      key: {{ .relay.existingSecret.passwordKey | quote }}
{{- else if or .relay.user .relay.password }}
- name: {{ $userEnv }}
  valueFrom:
    secretKeyRef:
      name: {{ include "encryption.fullname" .root | quote }}
      key: {{ $userEnv | quote }}
- name: {{ $passwordEnv }}
  valueFrom:
    secretKeyRef:
      name: {{ include "encryption.fullname" .root | quote }}
      key: {{ $passwordEnv | quote }}
{{- end }}
{{- end }}

{{/*
Whether the chart has to own a Secret: true as soon as one secret value is given
inline rather than through an existing Secret.
*/}}
{{- define "encryption.hasInlineSecrets" -}}
{{- $v := .Values -}}
{{- if or
  (and $v.database.url (not $v.database.existingSecret.name))
  (and $v.config.oidc.clientSecret (not $v.config.oidc.existingSecret.name))
  (and $v.sentry.enabled $v.sentry.dsn (not $v.sentry.existingSecret.name))
  (and (or $v.config.mailer.user $v.config.mailer.password) (not $v.config.mailer.existingSecret.name))
  (and (or $v.config.mailer.fallback.user $v.config.mailer.fallback.password) (not $v.config.mailer.fallback.existingSecret.name))
-}}true{{- end -}}
{{- end }}

{{/*
The server's environment, every variable of src/server/env-schema.ts that a deployment
must or may set. Plain values are inline; secrets come from a Secret, never as `value`.
*/}}
{{- define "encryption.env" -}}
{{- $v := .Values -}}
{{- $vaultHost := include "encryption.required" (list $v.hosts.vault "hosts.vault") -}}
{{- $interfaceHost := include "encryption.required" (list $v.hosts.interface "hosts.interface") -}}
- name: NODE_ENV
  value: production
- name: PORT
  value: "7200"
- name: VAULT_URL
  value: {{ printf "https://%s" $vaultHost | quote }}
- name: UI_URL
  value: {{ printf "https://%s" $interfaceHost | quote }}
- name: ALLOWED_FRAME_ANCESTORS
  value: {{ include "encryption.required" (list (join "," $v.config.allowedFrameAncestors) "config.allowedFrameAncestors") | quote }}
- name: OIDC_ISSUER
  value: {{ include "encryption.required" (list $v.config.oidc.issuer "config.oidc.issuer") | quote }}
- name: OIDC_CLIENT_ID
  value: {{ include "encryption.required" (list $v.config.oidc.clientId "config.oidc.clientId") | quote }}
{{- if not (or $v.config.oidc.clientSecret $v.config.oidc.existingSecret.name) }}
{{- fail "config.oidc.clientSecret or config.oidc.existingSecret.name is required: the server exchanges the authorization code as a confidential client" }}
{{- end }}
{{- include "encryption.secretEnv" (dict "root" $ "env" "OIDC_CLIENT_SECRET" "value" $v.config.oidc.clientSecret "existing" $v.config.oidc.existingSecret "key" "OIDC_CLIENT_SECRET") }}
- name: OIDC_REDIRECT_URI
  value: {{ $v.config.oidc.redirectUri | default (printf "https://%s/auth/callback" $interfaceHost) | quote }}
- name: OIDC_ACCEPT_UNVERIFIED_EMAIL
  value: {{ $v.config.oidc.acceptUnverifiedEmail | toString | quote }}
- name: OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION
  value: {{ $v.config.oidc.fallbackToEmailForIdentification | toString | quote }}
- name: OIDC_TOKEN_ENDPOINT_AUTH_METHOD
  value: {{ $v.config.oidc.tokenEndpointAuthMethod | quote }}
- name: OIDC_SCOPES
  value: {{ $v.config.oidc.scopes | quote }}
{{- if not (or $v.config.oidc.claims.lastName $v.config.oidc.claims.fullName) }}
{{- fail "config.oidc.claims.lastName or config.oidc.claims.fullName must name at least one claim: without either, every sign-in is refused" }}
{{- end }}
- name: OIDC_CLAIMS_FIRST_NAME
  value: {{ join "," $v.config.oidc.claims.firstName | quote }}
- name: OIDC_CLAIMS_LAST_NAME
  value: {{ join "," $v.config.oidc.claims.lastName | quote }}
- name: OIDC_CLAIMS_FULL_NAME
  value: {{ join "," $v.config.oidc.claims.fullName | quote }}
- name: OIDC_STEP_UP_ENABLED
  value: {{ $v.config.oidc.stepUp.enabled | toString | quote }}
- name: OIDC_STEP_UP_ACR_VALUES
  value: {{ join "," $v.config.oidc.stepUp.acrValues | quote }}
- name: OIDC_STEP_UP_AMR_VALUES
  value: {{ join "," $v.config.oidc.stepUp.amrValues | quote }}
- name: OIDC_STEP_UP_MAX_AGE_SECONDS
  value: {{ $v.config.oidc.stepUp.maxAgeSeconds | toString | quote }}
- name: DOCS_ENABLED
  value: {{ $v.config.docsEnabled | toString | quote }}
- name: MAILER_SMTP_HOST
  value: {{ include "encryption.required" (list $v.config.mailer.smtpHost "config.mailer.smtpHost") | quote }}
- name: MAILER_SMTP_PORT
  value: {{ $v.config.mailer.smtpPort | toString | quote }}
- name: MAILER_SMTP_SECURE
  value: {{ $v.config.mailer.secure | toString | quote }}
- name: MAILER_SMTP_REQUIRE_TLS
  value: {{ $v.config.mailer.requireTls | toString | quote }}
{{- include "encryption.relayCredentialsEnv" (dict "root" $ "prefix" "MAILER_SMTP" "relay" $v.config.mailer) }}
{{- if $v.config.mailer.fallback.smtpHost }}
- name: MAILER_FALLBACK_SMTP_HOST
  value: {{ $v.config.mailer.fallback.smtpHost | quote }}
- name: MAILER_FALLBACK_SMTP_PORT
  value: {{ $v.config.mailer.fallback.smtpPort | toString | quote }}
- name: MAILER_FALLBACK_SMTP_SECURE
  value: {{ $v.config.mailer.fallback.secure | toString | quote }}
- name: MAILER_FALLBACK_SMTP_REQUIRE_TLS
  value: {{ $v.config.mailer.fallback.requireTls | toString | quote }}
{{- include "encryption.relayCredentialsEnv" (dict "root" $ "prefix" "MAILER_FALLBACK_SMTP" "relay" $v.config.mailer.fallback) }}
{{- end }}
- name: MAILER_SENDER_ADDRESS
  value: {{ include "encryption.required" (list $v.config.mailer.senderAddress "config.mailer.senderAddress") | quote }}
- name: EMAIL_PRODUCT_URL
  value: {{ include "encryption.required" (list $v.config.emailProductUrl "config.emailProductUrl") | quote }}
{{- if $v.config.brandFont }}
- name: BRAND_FONT
  value: {{ $v.config.brandFont | quote }}
{{- end }}
- name: VAULT_PURGE_AFTER_DAYS
  value: {{ $v.config.retention.vaultPurgeAfterDays | toString | quote }}
- name: VAULT_DEVICE_INACTIVITY_DAYS
  value: {{ $v.config.retention.deviceInactivityDays | toString | quote }}
{{- if $v.config.securityContactUrl }}
- name: SECURITY_CONTACT_URL
  value: {{ $v.config.securityContactUrl | quote }}
{{- end }}
{{- if $v.config.maintenanceEscrowKeys }}
- name: MAINTENANCE_ESCROW_KEYS
  value: {{ $v.config.maintenanceEscrowKeys | toJson | quote }}
{{- end }}
{{- if not (or $v.database.url $v.database.existingSecret.name) }}
{{- fail "database.url or database.existingSecret.name is required" }}
{{- end }}
{{- include "encryption.secretEnv" (dict "root" $ "env" "DATABASE_URL" "value" $v.database.url "existing" $v.database.existingSecret "key" "DATABASE_URL") }}
{{- if $v.sentry.enabled }}
{{- if not (or $v.sentry.dsn $v.sentry.existingSecret.name) }}
{{- fail "sentry.dsn or sentry.existingSecret.name is required when sentry.enabled" }}
{{- end }}
{{- include "encryption.secretEnv" (dict "root" $ "env" "SENTRY_DSN" "value" $v.sentry.dsn "existing" $v.sentry.existingSecret "key" "SENTRY_DSN") }}
{{- if $v.sentry.environment }}
- name: SENTRY_ENVIRONMENT
  value: {{ $v.sentry.environment | quote }}
{{- end }}
{{- if $v.sentry.release }}
- name: SENTRY_RELEASE
  value: {{ $v.sentry.release | quote }}
{{- end }}
{{- end }}
{{- with $v.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}
