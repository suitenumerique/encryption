{{/*
The five subcharts each read their own block of values, so the same hostname, database
name or client id is written several times. A mismatch does not fail the render, it
produces a stack where a product cannot log in, cannot reach its database, or embeds an
iframe the encryption service refuses. These checks turn every such mismatch into a
render error naming the two values that disagree. Included once, from the bootstrap Job.

The products sign in with ONE provider, `$issuer`: Accounts when it is deployed (its
applications in bootstrap.accounts.applications, redirect URIs compared exactly), else
the shared Keycloak's realm (its clients in bootstrap.keycloak.clients, wildcards
allowed). Accounts itself always signs in at Keycloak.
*/}}
{{- define "suite-stack.checks" -}}
{{- $v := .Values }}
{{- $clients := $v.bootstrap.keycloak.clients }}
{{- $keycloakIssuer := include "suite-stack.keycloakIssuer" . }}
{{- $issuer := include "suite-stack.issuer" . }}
{{- $viaAccounts := $v.accounts.enabled }}
{{- $provider := ternary "Accounts" "the shared Keycloak's realm" $viaAccounts }}
{{- $registry := ternary "bootstrap.accounts.applications" "bootstrap.keycloak.clients" $viaAccounts }}
{{- $productClients := ternary $v.bootstrap.accounts.applications $clients $viaAccounts }}

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
{{- fail (printf "encryption.config.oidc.issuer must be the issuer of %s: %q (got %q)" $provider $issuer $e.config.oidc.issuer) }}
{{- end }}
{{- $callback := printf "https://%s/auth/callback" $e.hosts.interface }}
{{- $found := false }}
{{- range $productClients }}
{{- if eq .clientId $e.config.oidc.clientId }}
{{- $found = true }}
{{- if .public }}
{{- fail (printf "%s[%s] must be confidential: the encryption server signs its interface's users in with a secret" $registry .clientId) }}
{{- end }}
{{- /* A secret kept in an existing Secret cannot be read at render time: it is the operator's to match. */}}
{{- if and (not $e.config.oidc.existingSecret.name) (ne (toString .secret) (toString $e.config.oidc.clientSecret)) }}
{{- fail (printf "encryption.config.oidc.clientSecret differs from %s[%s].secret" $registry .clientId) }}
{{- end }}
{{- /* Accounts' ID tokens last 10 hours; Keycloak's the access token's lifespan, 5 minutes in the realm. */}}
{{- if and (not $viaAccounts) (not .idTokenLifespanSeconds) }}
{{- fail (printf "bootstrap.keycloak.clients[%s].idTokenLifespanSeconds is required: the interface's session lasts as long as the ID token, and the realm's default is 5 minutes" .clientId) }}
{{- end }}
{{- if not (has $callback .redirectUris) }}
{{- fail (printf "%s[%s].redirectUris must contain %q, the interface's callback" $registry .clientId $callback) }}
{{- end }}
{{- end }}
{{- end }}
{{- if not $found }}
{{- fail (printf "encryption.config.oidc.clientId %q has no entry in %s" $e.config.oidc.clientId $registry) }}
{{- end }}
{{- /* Accounts filters its claims by scope and ignores the `claims` parameter. */}}
{{- if $viaAccounts }}
{{- $scopes := splitList " " (toString $e.config.oidc.scopes) }}
{{- range $scope := list "email" "profile" }}
{{- if not (has $scope $scopes) }}
{{- fail (printf "encryption.config.oidc.scopes must contain %q: Accounts only sends the claims of the scopes granted, and the service needs the email and the names (got %q)" $scope (toString $e.config.oidc.scopes)) }}
{{- end }}
{{- end }}
{{- /* Accounts' `auth_time` is the start of its session, which `prompt=login` does not renew (see the values). */}}
{{- $session := int ($v.accounts.backend.envVars.SESSION_COOKIE_AGE | default 43200) }}
{{- if lt (int $e.config.oidc.stepUp.maxAgeSeconds) $session }}
{{- fail (printf "encryption.config.oidc.stepUp.maxAgeSeconds must be at least Accounts' session lifetime, %d seconds: Accounts never renews auth_time within a session, so a shorter max age refuses every sensitive action once the session is older (got %d)" $session (int $e.config.oidc.stepUp.maxAgeSeconds)) }}
{{- end }}
{{- end }}
{{- if and $v.mailpit.enabled (ne $e.config.mailer.smtpHost "mailpit") }}
{{- fail (printf "encryption.config.mailer.smtpHost must be \"mailpit\", the mail catcher's Service (got %q)" $e.config.mailer.smtpHost) }}
{{- end }}
{{- end }}

{{- /* One Redis: two products on the same database index would share Celery queues. */}}
{{- $redisUrls := dict }}
{{- range $product := list "docs" "drive" "accounts" }}
{{- $p := index $v $product }}
{{- if $p.enabled }}
{{- $url := toString $p.backend.envVars.REDIS_URL }}
{{- if hasKey $redisUrls $url }}
{{- fail (printf "%s and %s share the Redis URL %q: give each product its own database index" (index $redisUrls $url) $product $url) }}
{{- end }}
{{- $_ := set $redisUrls $url $product }}
{{- end }}
{{- end }}

{{- /* Each Django product, Accounts included, against the shared services, the bootstrap and the encryption service. */}}
{{- range $product := list "docs" "drive" "accounts" }}
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
{{- /* media-auth signs S3 headers for the host of AWS_S3_ENDPOINT_URL, and MinIO verifies them against the Host the ingress forwards. */}}
{{- $s3Host := get (urlParse (toString $env.AWS_S3_ENDPOINT_URL)) "host" }}
{{- range $ingress := list "ingressMedia" "ingressMediaPreview" }}
{{- $i := get $p $ingress }}
{{- if and $i $i.enabled }}
{{- $vhost := get ($i.annotations | default dict) "nginx.ingress.kubernetes.io/upstream-vhost" }}
{{- if ne (toString $vhost) $s3Host }}
{{- fail (printf "%s.%s upstream-vhost must be the host of AWS_S3_ENDPOINT_URL, %q (got %q): MinIO would refuse the media-auth signature" $product $ingress $s3Host (toString $vhost)) }}
{{- end }}
{{- end }}
{{- end }}
{{- /* Accounts is no client of itself: it signs in at Keycloak, checked below. */}}
{{- if ne $product "accounts" }}
{{- range $endpoint := list "JWKS" "AUTHORIZATION" "TOKEN" "USER" "LOGOUT" }}
{{- $url := toString (get $env (printf "OIDC_OP_%s_ENDPOINT" $endpoint)) }}
{{- if not (hasPrefix (printf "%s/" $issuer) $url) }}
{{- fail (printf "%s.backend.envVars.OIDC_OP_%s_ENDPOINT must be under the issuer of %s, %q (got %q)" $product $endpoint $provider $issuer $url) }}
{{- end }}
{{- end }}
{{- /* Accounts compares redirect URIs exactly; Keycloak takes a wildcard. */}}
{{- $redirectUris := ternary (list (printf "%s/api/v1.0/callback/" $origin)) (list (printf "%s/*" $origin)) $viaAccounts }}
{{- $found := false }}
{{- range $productClients }}
{{- if eq .clientId (toString $env.OIDC_RP_CLIENT_ID) }}
{{- $found = true }}
{{- if .public }}
{{- fail (printf "%s[%s] must be confidential: a Django product signs in with a secret" $registry .clientId) }}
{{- end }}
{{- if ne (toString .secret) (toString $env.OIDC_RP_CLIENT_SECRET) }}
{{- fail (printf "%s.backend.envVars.OIDC_RP_CLIENT_SECRET differs from %s[%s].secret" $product $registry .clientId) }}
{{- end }}
{{- $client := . }}
{{- range $uri := $redirectUris }}
{{- if not (has $uri $client.redirectUris) }}
{{- fail (printf "%s[%s].redirectUris must contain %q" $registry $client.clientId $uri) }}
{{- end }}
{{- end }}
{{- if $viaAccounts }}
{{- $logout := printf "%s/api/v1.0/logout-callback/" $origin }}
{{- if not (has $logout ($client.postLogoutRedirectUris | default list)) }}
{{- fail (printf "%s[%s].postLogoutRedirectUris must contain %q, or Accounts refuses the product's logout" $registry $client.clientId $logout) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if not $found }}
{{- fail (printf "%s.backend.envVars.OIDC_RP_CLIENT_ID %q has no entry in %s" $product (toString $env.OIDC_RP_CLIENT_ID) $registry) }}
{{- end }}
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
{{- /* The products' user menu links to Accounts ("Manage account"), where encryption is managed; without Accounts they offer the interface's own encryption home. */}}
{{- if ne $product "accounts" }}
{{- $settings := ternary (printf "https://%s/" $v.accounts.ingress.host) "" $viaAccounts }}
{{- if ne (toString ($env.ACCOUNT_SETTINGS_URL | default "")) $settings }}
{{- fail (printf "%s.backend.envVars.ACCOUNT_SETTINGS_URL must be %q (got %q)" $product $settings (toString ($env.ACCOUNT_SETTINGS_URL | default ""))) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{- /* Accounts against the realm it signs the testers in at, and as the products' issuer. */}}
{{- if $viaAccounts }}
{{- $env := $v.accounts.backend.envVars }}
{{- $origin := printf "https://%s" $v.accounts.ingress.host }}
{{- $accountsIssuer := include "suite-stack.accountsIssuer" . }}
{{- if ne (toString $env.OAUTH2_PROVIDER_OIDC_ISS_ENDPOINT) $accountsIssuer }}
{{- fail (printf "accounts.backend.envVars.OAUTH2_PROVIDER_OIDC_ISS_ENDPOINT must be %q, under accounts.ingress.host (got %q)" $accountsIssuer (toString $env.OAUTH2_PROVIDER_OIDC_ISS_ENDPOINT)) }}
{{- end }}
{{- if not $env.OAUTH2_PROVIDER_OIDC_RSA_PRIVATE_KEY }}
{{- fail "accounts.backend.envVars.OAUTH2_PROVIDER_OIDC_RSA_PRIVATE_KEY is required: Accounts refuses to start without the key its ID tokens are signed with" }}
{{- end }}
{{- if ne (toString $env.SOCIAL_AUTH_PRO_CONNECT_OIDC_ENDPOINT) $keycloakIssuer }}
{{- fail (printf "accounts.backend.envVars.SOCIAL_AUTH_PRO_CONNECT_OIDC_ENDPOINT must be the shared Keycloak's realm, %q (got %q)" $keycloakIssuer (toString $env.SOCIAL_AUTH_PRO_CONNECT_OIDC_ENDPOINT)) }}
{{- end }}
{{- $found := false }}
{{- range $clients }}
{{- if eq .clientId (toString $env.SOCIAL_AUTH_PRO_CONNECT_KEY) }}
{{- $found = true }}
{{- if .public }}
{{- fail (printf "bootstrap.keycloak.clients[%s] must be confidential: Accounts signs in with a secret" .clientId) }}
{{- end }}
{{- if ne (toString .secret) (toString $env.SOCIAL_AUTH_PRO_CONNECT_SECRET) }}
{{- fail (printf "accounts.backend.envVars.SOCIAL_AUTH_PRO_CONNECT_SECRET differs from bootstrap.keycloak.clients[%s].secret" .clientId) }}
{{- end }}
{{- if not (has (printf "%s/*" $origin) .redirectUris) }}
{{- fail (printf "bootstrap.keycloak.clients[%s].redirectUris must contain %q" .clientId (printf "%s/*" $origin)) }}
{{- end }}
{{- if ne (toString (get (.attributes | default dict) "user.info.response.signature.alg")) "RS256" }}
{{- fail (printf "bootstrap.keycloak.clients[%s].attributes must set user.info.response.signature.alg to RS256: Accounts reads the userinfo answer as a signed JWT" .clientId) }}
{{- end }}
{{- /* The scopes its ProConnect backend always asks for, beyond openid and email: Keycloak refuses a request for a scope the client lacks. */}}
{{- $client := . }}
{{- range $scope := list "given_name" "usual_name" "siret" }}
{{- if not (has $scope ($client.optionalClientScopes | default list)) }}
{{- fail (printf "bootstrap.keycloak.clients[%s].optionalClientScopes must contain %q: Accounts asks for it at every sign-in" $client.clientId $scope) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if not $found }}
{{- fail (printf "accounts.backend.envVars.SOCIAL_AUTH_PRO_CONNECT_KEY %q has no entry in bootstrap.keycloak.clients" (toString $env.SOCIAL_AUTH_PRO_CONNECT_KEY)) }}
{{- end }}
{{- end }}

{{- /* Every optional scope a client names must exist in the realm, which imports none of these. */}}
{{- $declared := list }}
{{- range $v.bootstrap.keycloak.clientScopes }}
{{- $declared = append $declared .name }}
{{- end }}
{{- range $client := $clients }}
{{- range $scope := ($client.optionalClientScopes | default list) }}
{{- if not (has $scope $declared) }}
{{- fail (printf "bootstrap.keycloak.clients[%s].optionalClientScopes names %q, absent from bootstrap.keycloak.clientScopes" $client.clientId $scope) }}
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

{{- /* Drive against the relay of its encrypted office editor: the browser connects to it
on Drive's own host, and it checks the session cookie against Drive's origin. */}}
{{- if and $v.driveRelay.enabled $v.drive.enabled }}
{{- if ne (toString $v.driveRelay.host) (toString $v.drive.ingress.host) }}
{{- fail (printf "driveRelay.host must be Drive's host, %q, where its frontend connects to the relay (got %q)" (toString $v.drive.ingress.host) (toString $v.driveRelay.host)) }}
{{- end }}
{{- $origin := printf "https://%s" $v.drive.ingress.host }}
{{- if ne (toString $v.driveRelay.driveApiUrl) $origin }}
{{- fail (printf "driveRelay.driveApiUrl must be %q, the origin Drive's backend answers to (got %q)" $origin (toString $v.driveRelay.driveApiUrl)) }}
{{- end }}
{{- end }}
{{- end }}
