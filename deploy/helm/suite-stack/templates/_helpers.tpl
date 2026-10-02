{{- define "suite-stack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "suite-stack.fullname" -}}
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

{{- define "suite-stack.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "suite-stack.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "suite-stack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "suite-stack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* The shared services, by the names the product blocks reach them with. */}}
{{- define "suite-stack.postgresHost" -}}
{{- required "shared.postgres.serviceNameOverride is required: the product blocks reach PostgreSQL by that fixed name" .Values.shared.postgres.serviceNameOverride }}
{{- end }}

{{- define "suite-stack.minioHost" -}}
{{- required "shared.minio.serviceNameOverride is required: the product blocks reach MinIO by that fixed name" .Values.shared.minio.serviceNameOverride }}
{{- end }}

{{/* The shared chart names Keycloak's Service after its own full name, with no override. */}}
{{- define "suite-stack.keycloakHost" -}}
{{- printf "%s-%s" (required "shared.fullnameOverride is required: the bootstrap Job reaches Keycloak by that fixed name" .Values.shared.fullnameOverride) .Values.shared.keycloak.name | trunc 52 | trimSuffix "-" }}
{{- end }}

{{- define "suite-stack.issuer" -}}
{{- printf "https://%s/realms/%s" .Values.shared.keycloak.hostname .Values.shared.keycloak.realm.name }}
{{- end }}

{{- define "suite-stack.encryptionDatabaseUrl" -}}
{{- printf "postgresql://encryption_%s:%s@%s:5432/%s?schema=encryption" .role .password .host .database }}
{{- end }}

{{/* The image of the encryption service, the way its own chart builds the reference. */}}
{{- define "suite-stack.encryptionImage" -}}
{{- $image := .Values.encryption.image }}
{{- $reference := $image.repository }}
{{- if $image.tag }}{{ $reference = printf "%s:%s" $reference $image.tag }}{{ end }}
{{- if $image.digest }}{{ $reference = printf "%s@%s" $reference $image.digest }}{{ end }}
{{- $reference }}
{{- end }}
