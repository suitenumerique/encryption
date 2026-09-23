{{/*
The four subcharts each read their own block of values, so the same hostname, database
name or client id is written several times. A mismatch does not fail the render, it
produces a stack where a product cannot log in, cannot reach its database, or embeds an
iframe the encryption service refuses. These checks turn every such mismatch into a
render error naming the two values that disagree. Included once, from the bootstrap Job.
*/}}
{{- define "suite-stack.checks" -}}
{{- $v := .Values }}
{{- $clients := $v.bootstrap.keycloak.clients }}
{{- $issuer := include "suite-stack.issuer" . }}

{{- range $service := list "postgres" "redis" "minio" "keycloak" }}
{{- if not (index $v.shared $service).enabled }}
{{- fail (printf "shared.%s.enabled must be true: every product block below reaches it" $service) }}
{{- end }}
{{- end }}

{{- /* The encryption service against the shared services and the bootstrap. */}}
{{- if $v.encryption.enabled }}
{{- $e := $v.encryption }}
{{- $b := $v.bootstrap.encryption }}
{{- if not (has $b.database $v.bootstrap.postgres.databases) }}
{{- fail (printf "bootstrap.encryption.database %q must be listed in bootstrap.postgres.databases" $b.database) }}
{{- end }}
{{- $runtimeUrl := include "suite-stack.encryptionDatabaseUrl" (dict "role" "runtime" "password" $b.runtimePassword "host" (include "suite-stack.postgresHost" $) "database" $b.database) }}
{{- if ne $e.database.url $runtimeUrl }}
{{- fail (printf "encryption.database.url must be the runtime role's URL the bootstrap creates: %q (got %q)" $runtimeUrl $e.database.url) }}
{{- end }}
{{- if $e.database.migration.enabled }}
{{- fail "encryption.database.migration.enabled must be false: the service's migration hook would run before the shared PostgreSQL exists, so the bootstrap Job runs the migration instead" }}
{{- end }}
{{- if ne $e.config.oidc.issuer $issuer }}
{{- fail (printf "encryption.config.oidc.issuer must be the shared Keycloak's realm: %q (got %q)" $issuer $e.config.oidc.issuer) }}
{{- end }}
{{- $jwks := printf "%s/protocol/openid-connect/certs" $issuer }}
{{- if ne $e.config.oidc.jwksUrl $jwks }}
{{- fail (printf "encryption.config.oidc.jwksUrl must be %q (got %q)" $jwks $e.config.oidc.jwksUrl) }}
{{- end }}
{{- $callback := printf "https://%s/auth/callback" $e.hosts.interface }}
{{- $found := false }}
{{- range $clients }}
{{- if eq .clientId $e.config.oidc.clientId }}
{{- $found = true }}
{{- if not .public }}
{{- fail (printf "bootstrap.keycloak.clients[%s] must be public: the encryption interface signs in from the browser" .clientId) }}
{{- end }}
{{- if not (has $callback .redirectUris) }}
{{- fail (printf "bootstrap.keycloak.clients[%s].redirectUris must contain %q, the interface's callback" .clientId $callback) }}
{{- end }}
{{- end }}
{{- end }}
{{- if not $found }}
{{- fail (printf "encryption.config.oidc.clientId %q has no entry in bootstrap.keycloak.clients" $e.config.oidc.clientId) }}
{{- end }}
{{- if and $v.mailpit.enabled (ne $e.config.mailer.smtpHost "mailpit") }}
{{- fail (printf "encryption.config.mailer.smtpHost must be \"mailpit\", the mail catcher's Service (got %q)" $e.config.mailer.smtpHost) }}
{{- end }}
{{- end }}

{{- /* One Redis: two products on the same database index would share Celery queues. */}}
{{- $redisUrls := dict }}
{{- range $product := list "docs" "drive" }}
{{- $p := index $v $product }}
{{- if $p.enabled }}
{{- $url := toString $p.backend.envVars.REDIS_URL }}
{{- if hasKey $redisUrls $url }}
{{- fail (printf "%s and %s share the Redis URL %q: give each product its own database index" (index $redisUrls $url) $product $url) }}
{{- end }}
{{- $_ := set $redisUrls $url $product }}
{{- end }}
{{- end }}

{{- /* Each Django product against the shared services, the bootstrap and the encryption service. */}}
{{- range $product := list "docs" "drive" }}
{{- $p := index $v $product }}
{{- if $p.enabled }}
{{- $env := $p.backend.envVars }}
{{- $origin := printf "https://%s" $p.ingress.host }}
{{- if ne (toString $env.DB_HOST) (include "suite-stack.postgresHost" $) }}
{{- fail (printf "%s.backend.envVars.DB_HOST must be the shared PostgreSQL, %q (got %q)" $product (include "suite-stack.postgresHost" $) (toString $env.DB_HOST)) }}
{{- end }}
{{- if not (has (toString $env.DB_NAME) $v.bootstrap.postgres.databases) }}
{{- fail (printf "%s.backend.envVars.DB_NAME %q must be listed in bootstrap.postgres.databases" $product (toString $env.DB_NAME)) }}
{{- end }}
{{- if and (ne (toString $env.AWS_STORAGE_BUCKET_NAME) $v.shared.minio.bucket) (not (has (toString $env.AWS_STORAGE_BUCKET_NAME) $v.bootstrap.minio.buckets)) }}
{{- fail (printf "%s.backend.envVars.AWS_STORAGE_BUCKET_NAME %q must be shared.minio.bucket or listed in bootstrap.minio.buckets" $product (toString $env.AWS_STORAGE_BUCKET_NAME)) }}
{{- end }}
{{- if ne (toString $env.OIDC_OP_JWKS_ENDPOINT) (printf "%s/protocol/openid-connect/certs" $issuer) }}
{{- fail (printf "%s.backend.envVars.OIDC_OP_JWKS_ENDPOINT must be under the shared Keycloak's realm %q (got %q)" $product $issuer (toString $env.OIDC_OP_JWKS_ENDPOINT)) }}
{{- end }}
{{- $found := false }}
{{- range $clients }}
{{- if eq .clientId (toString $env.OIDC_RP_CLIENT_ID) }}
{{- $found = true }}
{{- if .public }}
{{- fail (printf "bootstrap.keycloak.clients[%s] must be confidential: a Django product signs in with a secret" .clientId) }}
{{- end }}
{{- if ne .secret (toString $env.OIDC_RP_CLIENT_SECRET) }}
{{- fail (printf "%s.backend.envVars.OIDC_RP_CLIENT_SECRET differs from bootstrap.keycloak.clients[%s].secret" $product .clientId) }}
{{- end }}
{{- if not (has (printf "%s/*" $origin) .redirectUris) }}
{{- fail (printf "bootstrap.keycloak.clients[%s].redirectUris must contain %q" .clientId (printf "%s/*" $origin)) }}
{{- end }}
{{- end }}
{{- end }}
{{- if not $found }}
{{- fail (printf "%s.backend.envVars.OIDC_RP_CLIENT_ID %q has no entry in bootstrap.keycloak.clients" $product (toString $env.OIDC_RP_CLIENT_ID)) }}
{{- end }}
{{- if $v.encryption.enabled }}
{{- $e := $v.encryption }}
{{- if ne (toString $env.ENCRYPTION_FEATURE_ENABLED) "True" }}
{{- fail (printf "%s.backend.envVars.ENCRYPTION_FEATURE_ENABLED must be \"True\" when the encryption service is deployed" $product) }}
{{- end }}
{{- $vault := printf "https://%s" $e.hosts.vault }}
{{- if ne (toString $env.ENCRYPTION_VAULT_URL) $vault }}
{{- fail (printf "%s.backend.envVars.ENCRYPTION_VAULT_URL must be %q (got %q)" $product $vault (toString $env.ENCRYPTION_VAULT_URL)) }}
{{- end }}
{{- $interface := printf "https://%s" $e.hosts.interface }}
{{- if ne (toString $env.ENCRYPTION_INTERFACE_URL) $interface }}
{{- fail (printf "%s.backend.envVars.ENCRYPTION_INTERFACE_URL must be %q (got %q)" $product $interface (toString $env.ENCRYPTION_INTERFACE_URL)) }}
{{- end }}
{{- if not (has $origin $e.config.allowedFrameAncestors) }}
{{- fail (printf "encryption.config.allowedFrameAncestors must contain %q, or the vault refuses to be embedded by %s" $origin $product) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{- /* Drive against the document server it opens office files with. */}}
{{- if and $v.onlyoffice.enabled $v.drive.enabled }}
{{- $env := $v.drive.backend.envVars }}
{{- if ne (toString $env.WOPI_CLIENTS) "onlyoffice" }}
{{- fail (printf "drive.backend.envVars.WOPI_CLIENTS must be \"onlyoffice\", the document server deployed with the stack (got %q)" (toString $env.WOPI_CLIENTS)) }}
{{- end }}
{{- if ne (toString $env.WOPI_ONLYOFFICE_DISCOVERY_URL) "http://onlyoffice/hosting/discovery" }}
{{- fail (printf "drive.backend.envVars.WOPI_ONLYOFFICE_DISCOVERY_URL must be \"http://onlyoffice/hosting/discovery\", the document server's Service (got %q)" (toString $env.WOPI_ONLYOFFICE_DISCOVERY_URL)) }}
{{- end }}
{{- $src := printf "https://%s" $v.drive.ingress.host }}
{{- if ne (toString $env.WOPI_SRC_BASE_URL) $src }}
{{- fail (printf "drive.backend.envVars.WOPI_SRC_BASE_URL must be %q, Drive's own origin the document server fetches files from (got %q)" $src (toString $env.WOPI_SRC_BASE_URL)) }}
{{- end }}
{{- if ne (toString $env.WOPI_ONLYOFFICE_CONVERT_JWT_SECRET) $v.onlyoffice.jwtSecret }}
{{- fail "drive.backend.envVars.WOPI_ONLYOFFICE_CONVERT_JWT_SECRET differs from onlyoffice.jwtSecret" }}
{{- end }}
{{- end }}
{{- end }}
