# LaSuite Encryption : End-to-End Encryption Service

A shared end-to-end encryption service for [La Suite numérique](https://lasuite.numerique.gouv.fr/) products (Docs, Drive, Fichier, Visio). It provides encryption capabilities via isolated iframes, ensuring private keys never leave the user's browser.

## Architecture

The service runs on **two isolated domains** served by a single server:

| Domain            | Role                                                          | Visibility       |
| ----------------- | ------------------------------------------------------------- | ---------------- |
| `data.encryption` | **Vault** — stores private keys in IndexedDB, runs all crypto | invisible iframe |
| `encryption`      | **Interface** — onboarding, backup, restore, device transfer  | visible iframe   |

Products load a client SDK (`client.js`) from `data.encryption` via a `<script>` tag. The SDK manages both iframes and exposes a simple `VaultClient` API.

Private keys **never leave** the `data.encryption` domain. Communication happens exclusively via `postMessage` with origin validation. See [the integration guide](src/ui/docs/technical/integration.mdx) for the full security model, SDK reference, and step-by-step integration instructions.

## Storage partitioning constraint

> **All products embedding this service must share the same registrable domain (eTLD+1).**

Since Chrome 115, IndexedDB in third-party iframes is partitioned by the embedding page's top-level site (eTLD+1). The vault stores encryption keys in IndexedDB — if products are on different registrable domains, each product gets a separate key store and keys are not shared across products.

| Scenario                                             | Works? | Why                                                                   |
| ---------------------------------------------------- | ------ | --------------------------------------------------------------------- |
| `docs.numerique.gouv.fr` + `drive.numerique.gouv.fr` | Yes    | Same eTLD+1 (`numerique.gouv.fr`) → shared partition                  |
| `docs.gouv.fr` + `drive.gouv.fr`                     | No     | `gouv.fr` is a public suffix → different eTLD+1 → separate partitions |

**Development pitfall:** testing with `localhost` on different ports (e.g., `:7201`, `:7202`) masks this issue because all ports share the site `localhost`. To properly test cross-product key sharing, use `/etc/hosts` aliases under a shared parent domain (e.g., `a.product.localhost` and `b.product.localhost` → shared eTLD+1 `product.localhost`).

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org/) >= 24.19.0
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

### `/etc/hosts` setup

Modern browsers resolve `*.localhost` to `127.0.0.1` automatically. If yours doesn't, add:

```
127.0.0.1 data.encryption.localhost
127.0.0.1 encryption.localhost
```

For cross-site testing (verifying storage partitioning works correctly):

```
127.0.0.1 a.product.localhost
127.0.0.1 b.product.localhost
```

### Run locally

```bash
# Start databases + Keycloak
docker compose up -d

# Install deps + generate Prisma client
npm install
npm run db:schema:compile

# Create database tables
npm run db:push

# Start server (API + vault + UI) + demos + storybook
npm run dev

# Open Demo Product A
open http://localhost:7201

# Open Demo Product B (different port = different origin, proves cross-origin works)
open http://localhost:7202

# Cross-site test (use different top-level sites to verify storage partitioning)
open http://a.product.localhost:7201
open http://b.product.localhost:7202
```

### Port scheme

| Port | Service                    | Hostname                                                          |
| ---- | -------------------------- | ----------------------------------------------------------------- |
| 7200 | Fastify (API + Vault + UI) | `data.encryption.localhost` (vault) / `encryption.localhost` (UI) |
| 7201 | Demo Product A             | `localhost`                                                       |
| 7202 | Demo Product B             | `localhost`                                                       |
| 7203 | Keycloak                   | `localhost`                                                       |
| 7204 | Storybook                  | `localhost`                                                       |
| 7205 | PostgreSQL (app)           | `localhost`                                                       |
| 7206 | PostgreSQL (Keycloak)      | `localhost`                                                       |

In development, a single Fastify server on port 7200 embeds Vault and UI via Vite middleware mode. Host-based routing dispatches requests to the correct Vite instance. The vault uses `data.encryption.localhost` for origin isolation. The UI uses `encryption.localhost`.

### Common commands

```bash
npm run dev              # Start server (API + vault + UI) + demos + storybook
npm run build            # Build server + vault + UI + client SDK
npm run test:unit        # Run tests
npm run test:helm        # Render and check the Helm chart (needs helm + kubeconform)
npm run lint             # ESLint + TypeScript check
npm run format           # Prettier write
npm run format:check     # Prettier check
npm run db:push          # Apply schema to database
npm run db:studio        # Open Prisma Studio
npm run dev:storybook    # Start Storybook on port 7204
npm run ci:simulate      # Run the CI pipeline locally with `act`
```

### Running the pipeline locally

`npm run ci:simulate` runs `.github/workflows/ci.yml` in Docker with
[act](https://github.com/nektos/act), which has to be installed separately.

It's not designed to release a new version, but to test most of the pipeline (packages, tests, build). Note the flags stay in the npm script rather than in `.actrc`, so they do not leak into other `act` invocations. Also, we cannot use concurrent jobs feature here due to our setup upgrading npm (jobs share the same folders and there is a conflict). Lastly, `act` copies the working tree without its `.git`, so the steps comparing against committed files are skipped locally: a green local run does not prove the generated API client is in sync.

### Published Storybook

The CI publishes the Storybook to [Chromatic](https://www.chromatic.com/), which hosts it and compares every story with its last accepted snapshot. Pushes to the CI branch are accepted as they come and are the baseline behind the permalink (https://main--6abd0198abd0e47162cae7c9.chromatic.com, any branch that was built is at `https://<branch>--6abd0198abd0e47162cae7c9.chromatic.com`); a pull request gets its own Storybook and its visual changes listed for review, without ever failing the pipeline. It needs the `CHROMATIC_PROJECT_TOKEN` repository secret (the project's settings in Chromatic).

## Tech stack

- **Crypto**: libsodium-wrappers-sumo (WASM), hybrid X25519 + post-quantum placeholder, XChaCha20-Poly1305
- **Server**: Fastify, Prisma 7 + PostgreSQL, esbuild (single .mjs bundle in production)
- **Frontend**: React, `@gouvfr-lasuite/ui-components` (LaSuite's design system), i18next, MDX docs
- **Build**: Vite (vault, UI, client SDK, demo), esbuild (server)
- **Tests**: Vitest (unit, Node) + Vitest browser mode via `@storybook/addon-vitest` (stories, Chromium/Playwright)
- **Auth**: OIDC authorization code flow run by the server as a confidential client (PKCE on top), then the provider's ID token as the interface's Bearer credential, verified locally on every call; step-up (RFC 9470) for replacing an identity; any OIDC provider (production), Keycloak (local dev)

## Security model

The two-domain architecture creates a **privilege separation**:

- **Vault** (`data.encryption`): holds private keys, has **no auth token** — can only read public keys from the server
- **Interface** (`encryption`): holds the provider's ID token, has **no access to private keys** — can write to the server but cannot decrypt content

Compromising one domain is insufficient to both access private keys AND manipulate the server. See [the integration guide](src/ui/docs/technical/integration.mdx) for the full security analysis.

### Headers and isolation

- CSP, COEP, COOP, CORP headers (vault is the most restrictive)
- SRI on all script tags in production
- Service Worker for offline support and version updates
- Runtime origin validation on every `postMessage`
- Domain validation enforced at startup
- Rate limiting on key creation and device transfers

## Deployment

The release is a single container image, `lasuite/encryption`, published on Docker Hub by the `release` job of the CI on every tag (`vX.Y.Z` gives `X.Y.Z` and `latest`) and on every push to `main` (`main`). The image carries a signed provenance attestation and an SBOM, and is scanned with Trivy before it is pushed.

### What the image is

- **Distroless and non-root**: no shell, no package manager, the process runs as `nonroot`. Use `docker debug` (or an ephemeral container) to look inside.
- **Zero `node_modules` at runtime**: the server is one bundled file, `dist/server/main.mjs`. The only extra tree is the Prisma CLI, kept for migrations (see below).
- **Node permission model**: the default command runs with `--allow-fs-read=/app --allow-fs-write=/tmp`, so the filesystem can be read-only except `/tmp`.
- **One process, two hostnames**: the server listens on `PORT` (7200) and routes on the `Host` header between the vault (`VAULT_URL`) and the interface (`UI_URL`). Point both hostnames at the same Service and make sure the proxy forwards `Host` unchanged.
- **Health**: `GET /health` returns 200 when the server can answer. The image declares it as its `HEALTHCHECK`.
- **Shutdown**: on `SIGTERM` the server stops accepting connections, drains, flushes pending error reports and exits. Give it a grace period of a few seconds.
- **Egress needed**: PostgreSQL, the SMTP host(s), the OIDC provider (its discovery, token and userinfo endpoints, and its JWKS) and, if set, the host in `SENTRY_DSN`. Nothing else: no registry, no CDN, no download at startup.

### Kubernetes

A Helm chart, [`deploy/helm/encryption`](deploy/helm/encryption), deploys the image as described on this page: the Deployment with the hardening of `docker-compose.production.yaml`, one Service for both hostnames, the migration Job as a pre-upgrade hook with the migrator role, and optional Ingress, network policy and error reporting. It manages none of the dependencies and has no default image: `image.tag` is required, because the chart is versioned on its own. A `chart/vX.Y.Z` git tag publishes it to Docker Hub as an OCI artifact, `lasuite/encryption-chart`, attested like the image; an application tag never touches it, and a chart tag runs nothing else.

Take it by version, keep the digest Helm prints, verify the digest with `cosign verify-attestation` exactly as for the image, then reference it as tag plus digest, which Helm refuses to deviate from:

```sh
helm pull oci://registry-1.docker.io/lasuite/encryption-chart --version 1.4.0   # prints Digest: sha256:…
helm install encryption oci://registry-1.docker.io/lasuite/encryption-chart:1.4.0@sha256:… --values my-values.yaml
```

Its values are schema-checked, so a typo or a missing required value fails the install rather than the pod. `npm run test:helm` renders it and checks it against the Kubernetes API schemas and against the server's own environment contract; `deploy/helm/smoke-k3d.sh` installs it for real in a local k3d cluster. Examples for helmfile and Argo CD live in [`deploy/helmfile`](deploy/helmfile) and [`deploy/argocd`](deploy/argocd). See [the chart README](deploy/helm/encryption/README.md).

### Environment

Every variable is listed in [`.env.model`](.env.model) with a production-shaped value; the server refuses to start and prints the offending names when one is missing or malformed. The ones that shape the deployment:

| Variable                       | Role                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VAULT_URL`, `UI_URL`          | The two public origins. TLS is mandatory: the vault needs a secure context, and the browser reporting endpoint is ignored over plain HTTP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `ALLOWED_FRAME_ANCESTORS`      | The product origins allowed to embed the iframes and to load the SDK as a module or with SRI (the only ones `Access-Control-Allow-Origin` names; no response carries `*`), comma-separated. They must share one registrable domain (see "Storage partitioning constraint"). `https://*.example.fr` allows every subdomain at any depth, like the CSP `frame-ancestors` it feeds; the server refuses to start on any other form (a lone `*`, a host without its scheme, a wildcard that is not the leftmost label, a path); prefer explicit origins in production, since every matching page can ask the vault to decrypt for the signed-in user (the server logs a warning). |
| `DATABASE_URL`                 | Connection string of the **runtime** role (below).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `OIDC_*`                       | The identity provider the interface authenticates against (see "Identity provider").                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MAILER_*`                     | SMTP for the emergency-access notifications, with an optional fallback host.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `SENTRY_*`                     | Optional error reporting (see "Error reporting").                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `VAULT_PURGE_AFTER_DAYS`       | Optional, 730 by default. Days a dormant vault (replaced by a start-over, or left by leaving encryption) stays restorable by its own recovery phrase before its content is deleted; the owner is emailed 30 and 7 days before, and once it is done. `0` keeps dormant vaults forever, otherwise at least 180. The active vault is never deleted.                                                                                                                                                                                                                                                                                                                             |
| `VAULT_DEVICE_INACTIVITY_DAYS` | Optional, 365 by default. Days without use after which a browser forgets its copy of the vault and must be enrolled again with another device or the recovery phrase. `0` never, otherwise at least 30.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `SECURITY_CONTACT_URL`         | Optional. Where researchers report a problem with your instance (`mailto:` or `https://`), published as `/.well-known/security.txt`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MAINTENANCE_ESCROW_KEYS`      | Optional. Enables the maintenance escrow: a JSON list of `{ "domains": [...], "publicKey": "..." }`, one public key per organization as the maintenance tool generates it, `*` for every other email (see "Maintenance escrow").                                                                                                                                                                                                                                                                                                                                                                                                                                             |

### Identity provider

The server runs the authorization-code flow itself, as a **confidential client** with PKCE on top: identity providers for public services commonly accept no public client. Register a client with:

- authentication `client_secret_post` (or `client_secret_basic`, set in `OIDC_TOKEN_ENDPOINT_AUTH_METHOD`), its secret in `OIDC_CLIENT_SECRET`;
- the redirect URI `https://<UI_URL host>/auth/callback`, in `OIDC_REDIRECT_URI`;
- ID tokens signed with RS256 or ES256 (verified against the keys at the `jwks_uri` of its discovery document, whose `issuer` must equal `OIDC_ISSUER` exactly).

The interface then presents the provider's **ID token** as its Bearer credential, and the server verifies it locally on every call (signature, `iss`, `aud` = `OIDC_CLIENT_ID`, `exp`): no refresh, nothing asked of the provider per request. The session therefore lasts as long as the ID token (commonly about 1 h), after which the user reconnects in one click while the provider's own session lives. The access token never leaves the server.

| Variable                       | Default                               | Role                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OIDC_SCOPES`                  | `openid`                              | Scopes of the sign-in. With `openid` alone, the email and names are asked for in userinfo through the OIDC `claims` parameter, so they never ride in the ID token. For a provider that ignores the parameter, grant the scopes here (e.g. `openid email profile`, or one scope per claim such as `openid email given_name usual_name` where the provider works that way). |
| `OIDC_CLAIMS_FIRST_NAME`       | `given_name`                          | Claims holding the first name, in order of preference. Required at sign-in (403 `name_claims_required` otherwise).                                                                                                                                                                                                                                                        |
| `OIDC_CLAIMS_LAST_NAME`        | `usual_name,family_name`              | Claims holding the last name (some providers use `usual_name`). Without one, the last name is derived from the full name below.                                                                                                                                                                                                                                           |
| `OIDC_CLAIMS_FULL_NAME`        | `name`                                | Claims holding the full name, for providers without a last name claim: the last name is the full name minus the first occurrence of the first name, trimmed (empty when nothing is left: the person is shown by their first name).                                                                                                                                        |
| `OIDC_STEP_UP_ACR_VALUES`      | `eidas0-mfa,eidas1-mfa,eidas2,eidas3` | `acr` values that prove a second factor (the eIDAS second-factor levels).                                                                                                                                                                                                                                                                                                 |
| `OIDC_STEP_UP_AMR_VALUES`      | `mfa,otp,totp,hwk,sc,pop`             | `amr` values that prove a second factor, accepted as an alternative to the `acr`.                                                                                                                                                                                                                                                                                         |
| `OIDC_STEP_UP_MAX_AGE_SECONDS` | `300`                                 | How recent the authentication (`auth_time`) must be for a step-up action.                                                                                                                                                                                                                                                                                                 |

**Step-up** applies to one action today: replacing a user's identity key (for example after losing every device). It needs a second factor, among the values above, and a sign-in younger than the max age; otherwise the API answers 401 `insufficient_user_authentication` and the interface asks the user to sign in again with a second factor. Leave both lists empty to require only a fresh sign-in, for a provider that reports no second factor (the local Keycloak, a beta stack).

### Database roles

Two PostgreSQL roles, created once by the database administrator with the scripts in [`deploy/postgres/`](deploy/postgres):

1. [`create-migrator-role.sql`](deploy/postgres/create-migrator-role.sql): `encryption_migrator`, owner of the `encryption` schema, the only role allowed to create and alter tables. Used by the migration step only.
2. [`create-runtime-role.sql`](deploy/postgres/create-runtime-role.sql): `encryption_runtime`, allowed to read and write rows and nothing else. This is the role in the server's `DATABASE_URL`.

```sh
psql "$ADMIN_DATABASE_URL" -v password="'…'" -f deploy/postgres/create-migrator-role.sql
psql "$ADMIN_DATABASE_URL" -v password="'…'" -f deploy/postgres/create-runtime-role.sql
```

The split means a compromised server process cannot change the schema, and a schema change cannot happen by accident from a pod: it only happens where the migrator credentials are, which is the release step. Every table lives in the `encryption` schema, never in `public`, so other roles on a shared server cannot even list them. Both connection strings carry `?schema=encryption`: the migration tooling reads it to place the tables and its own `_prisma_migrations` table there (the migrator has no right to create anything in `public`), and the server reads it to query that schema. A local database can leave it out and use `public`.

### Migrations

Migrations are applied **once per release, never per pod**. Run the same image with the migrator credentials and the Prisma CLI it ships:

```sh
docker run --rm \
  -e DATABASE_URL="postgresql://encryption_migrator:…@db-host:5432/encryption?schema=encryption" \
  lasuite/encryption:X.Y.Z node_modules/prisma/build/index.js migrate deploy
```

The command is idempotent and exits non-zero when a migration fails, which is what you want a deployment to stop on. Where it belongs:

- **Kubernetes**: a `Job` run as a Helm `pre-install`/`pre-upgrade` hook, or an Argo CD `PreSync` hook, which is what the chart does. A failed migration is then a failed Job and the rollout does not start. Not an init container: it would run on every replica and every restart, and each of those pods would need the migrator credentials.
- **Plain Docker**: a release step in the pipeline, before the new version starts.
- **PaaS that builds from source** (Scalingo, Clever Cloud, Heroku-like): there is no image, the platform runs `npm ci` and `npm run build` itself, so the migration is an npm script run between the build and the start, with the migrator credentials, then the server starts with the runtime ones. Scalingo, for example, runs the `postdeploy` entry of the `Procfile` after the build and before the new release takes traffic:

  ```
  postdeploy: DATABASE_URL="$MIGRATOR_DATABASE_URL" npm run db:migration:deploy:unsecure
  web: npm run start:unsecure
  ```

  Clever Cloud has the same two slots under `CC_POST_BUILD_HOOK` (or `CC_PRE_RUN_HOOK`) and `CC_RUN_COMMAND`. The `:unsecure` suffix means the script reads the platform's environment as is, instead of loading the local `.env.test`. The build needs `npm run db:schema:compile` before `npm run build`, exactly as the `Dockerfile` does.

### Error reporting

Optional. Set `SENTRY_DSN` to the DSN of any Sentry-compatible collector (Sentry, self-hosted Sentry, GlitchTip) and the server starts sending server errors and the reports the interface and the vault post to it. Unset, nothing is sent and nothing else changes.

There is no Sentry SDK in the image and nothing to upload: source maps ship inside the image and are resolved there, so the collector only ever sees the server, never a browser. The event is built from an allowlist (error type, redacted message, stack positions, a handful of tags such as route and status code) rather than scrubbed, and reports from the vault carry no message at all. `SENTRY_ENVIRONMENT` labels the deployment; `SENTRY_RELEASE` defaults to the commit the image was built from.

### Maintenance escrow

Optional, and each deployment's own choice: useful when you are not yet confident in the deployment, or to keep a guaranteed way out (a general failure of the encryption in a product, an organization that wants to stop encrypting, a migration to another tool). With it, the stored content can be decrypted in batch, offline, without any user taking part.

**A temporary mode, and a deliberate breach of end-to-end encryption.** While it runs, the custodians of a maintenance phrase can read every document it covers: the content is no longer readable only by the people it is shared with. Run it for a defined period, while the deployment earns its operators' confidence, and turn it off afterwards. It answers a massive loss (a technical failure of the encryption in a product, an organization stopping it), not a user who lost their keys: that is what the recovery phrase, the trusted contacts of emergency access and, later, a recovery council splitting each user's key (Shamir) are for, without anyone else ever reading the content.

**Setting it up, once per organization.** Download the maintenance tool from your deployment (`https://<interface host>/public-assets/maintenance-tool.html`), carry it to an isolated computer, open it in a browser and use "Generate a maintenance key". It shows 24 words, the **maintenance phrase**, which is the secret key. Keep it the way the place allows, as a user keeps their recovery phrase: shown on screen to write by hand, copied, downloaded as a text file to a removable drive, or printed (a sheet with the words, the date and the key's fingerprint). Every copy is the secret key and goes to the vault; it can be split between custodians, and it never lives on a connected computer, a shared drive or a printer that keeps its jobs. Add the public key it shows (downloadable as a text file, it is not secret) to `MAINTENANCE_ESCROW_KEYS`, with the email domains it covers. Most deployments serve one organization and need a single entry, `*`, covering every user:

```bash
MAINTENANCE_ESCROW_KEYS='[{ "domains": ["*"], "publicKey": "AUJC…" }]'
```

A deployment shared by several organizations can give each its own key, so that each one's custodians read only its documents:

```bash
MAINTENANCE_ESCROW_KEYS='[
  { "domains": ["agriculture.gouv.fr"], "publicKey": "AUJC…" },
  { "domains": ["interieur.gouv.fr", "outre-mer.gouv.fr"], "publicKey": "AUJD…" },
  { "domains": ["*"], "publicKey": "AUJE…" }
]'
```

A document is escrowed for the key covering its **owner**'s email (the creator, or whomever the product names as owner when it shares), the longest listed domain winning: `alice@monequipe.agriculture.gouv.fr` belongs to `agriculture.gouv.fr`, `bob@fauxagriculture.gouv.fr` does not. The `*` entry covers every other email; without one, their documents get no copy. At startup the server logs `Maintenance escrow for agriculture.gouv.fr: key fingerprint …` for each key: the same digits as the tool shows for that organization's phrase, or the server escrows for another key. From then on every resource key the vault wraps for its recipients is also wrapped, once more, for its owner's key, and products persist the copy next to the ciphertext.

**Recovering, when it is needed.**

1. The product team exports the content concerned, still encrypted, into a folder (format below): the **encrypted export**. It copies it to a removable drive, and keeps writes away from those documents until step 4 (or relies on the `updatedAt` check below). For one organization, it exports only the documents escrowed for that organization's key: it filters on that key's fingerprint, the 40 digits the server's startup log shows beside the organization's domains and the tool shows for its phrase (below).
2. On the isolated computer, the custodians open the tool, pick the encrypted export, type the phrase, and check the fingerprint it shows. The tool decrypts every item, lists the failures, previews any item, and writes the **decrypted copy**: the same structure in plaintext, as a folder or a `.zip`. Items escrowed for another organization's key are not failures. That happens when the encrypted export mixes organizations: a document whose owner belongs to another organization, or one created before its owner's domain was given its own key. The tool cannot open them, so it copies them, still encrypted and untouched, into a subfolder per key, `other-keys/<that key's fingerprint>/`. Each such subfolder is a complete encrypted export of its own (a `manifest.ndjson` and its files): hand it to that organization's custodians, who open it with their phrase exactly like the original. The import ignores it.
3. The decrypted copy goes back to the product team on the removable drive.
4. The product team imports it (the content back in plaintext, the encrypted columns cleared) and deletes it. Docs and Drive ship the two commands for steps 1 and 4 (`maintenance_export`, `maintenance_import`), described in their own repositories.

**Importing safely.** The import goes one document (or Drive tree) at a time, in a short transaction of its own, never one transaction for the whole export: a transaction over thousands of documents would hold locks and grow the write-ahead log for hours, and one failure would undo everything. For each document:

- the decrypted files are uploaded first, under **new** object keys, so the ciphertext stays readable until the switch; where the content names its objects by key (Docs: a document's blocks carry their attachments' keys), the import rewrites those references to the new keys in the plaintext content;
- the transaction checks the document was not edited since the export (its `updatedAt`), then points the rows at the new objects and writes the plaintext columns; a content kept under a key that never changes (Docs' `<id>/file`) is written as a new version, last, just before the commit;
- after a rollback, the new plaintext objects (and that content version) are deleted; after the commit, the old ciphertext ones are **kept**, so that a problem found afterwards can still be investigated, and a separate command deletes them once the batch is checked (Drive's `delete_orphan_objects`, Docs' `maintenance_purge_versions`): no key opens them any more, and in Docs restoring one from the history would put ciphertext back as the content.

A document goes whole or not at all: if any of its items failed (an attachment missing from the folder, a damaged row), it stays encrypted, escrow copy included, for the next batch, since switching the document alone would lose the key its attachments depend on. Rerunning the import is harmless, and it is how an interrupted run is finished: a switched document is skipped, the others are tried again. What a process killed outright leaves depends on the storage model. The database is never wrong about the attachments: only objects no row points to remain, the plaintext of a document whose transaction never ran (Drive's clean-up deletes them; Docs records each new key in a table before uploading it, the switch deleting the record, so the next import or purge deletes exactly the objects of a switch that never committed). The one unreadable window left is Docs' content: a process killed between its content write and the commit leaves a row that still says encrypted over a plaintext content version, until the rerun switches it. One killed after the commit leaves the malware scan undone, which the rerun finishes when it skips that document. Documents skipped for an edit made meanwhile are exported again. `src/maintenance/escrow.test.ts` plays exactly this on a real PostgreSQL schema.

**Replacing an organization's key.** New custodians, or a phrase to retire: generate a new key in the tool and put its public key in place of the old one in `MAINTENANCE_ESCROW_KEYS`, so that new resources get copies for it. The existing copies are still for the old key, and the old phrase opens them for as long as they exist, so they are rotated before that phrase is destroyed, with the same tool and the same export format, the copies alone: the product exports one line per root with its copy (`maintenance_export --keys-only --fingerprint <old key's fingerprint>` in Docs and Drive); the "Rotate the maintenance key" tab takes the old phrase and the new public key, and hands back each line with the new copy in `maintenanceKey` and the one it replaces in `previousMaintenanceKey`; the product writes them back (`maintenance_rotate`) in one transaction, only where the stored copy is still that previous one. What the tool hands back holds no secret, only copies wrapped for a maintenance key, so it needs no care on its way back. Once an export for the old key's fingerprint comes back empty (a resource skipped, or backfilled with the old key meanwhile, needs another pass), destroy the old phrase. The products' `PATCH .../maintenance-key/` takes a copy only when the stored one is missing or made for another key, so a client refreshing a copy the rotation already moved is refused rather than writing an equivalent one.

The tool is one HTML file with everything inside: no installation, no Node.js, no network. Its Content-Security-Policy forbids any request, so even on a connected computer the phrase and the content cannot leave the page. It works in current Chrome, Edge and Firefox. To check that the file you downloaded is the one this repository builds, run `npm ci && npm run build:maintenance` on the same commit and compare `sha256sum dist/maintenance/maintenance-tool.html` (the build is reproducible).

**The encrypted export** is the same for every product, so there is one tool. `manifest.ndjson` has one JSON object per line, one line per encrypted item (a document, an attachment, a comment, a Drive folder or file); larger ciphertexts, such as attachments from object storage, sit in files of the folder named by the line. The full format is in the integration guide (`src/ui/docs/technical/integration.mdx`, "Maintenance escrow"). Binary columns go through `encode`, whose base64 PostgreSQL wraps every 76 characters, hence the `translate` (the tool refuses wrapped base64 rather than decoding garbage):

```bash
psql "$PRODUCT_DATABASE_URL" -At -o export/manifest.ndjson -c "
  SELECT json_build_object('id', d.id, 'type', 'document', 'updatedAt', d.updated_at,
    'maintenanceKey', translate(encode(d.maintenance_key, 'base64'), E'\n', ''),
    'content', translate(encode(d.encrypted_content, 'base64'), E'\n', ''))
  FROM documents d WHERE d.maintenance_key IS NOT NULL
  UNION ALL
  SELECT json_build_object('id', a.id, 'type', 'attachment', 'parent', a.document_id,
    'wrappedKey', translate(encode(a.wrapped_key, 'base64'), E'\n', ''),
    'file', a.object_key)
  FROM attachments a JOIN documents d ON d.id = a.document_id WHERE d.maintenance_key IS NOT NULL"
# then copy each object the manifest names into the folder, under its own key
jq -r 'select(.file) | .file' export/manifest.ndjson | while read -r key; do aws s3 cp "s3://$BUCKET/$key" "export/$key"; done
```

Every copy starts with the id of the key it was made for (bytes 2 to 17: the 128 bits the fingerprint writes in digits), so one organization's documents are exported by filtering on those bytes, with SQL alone and without having to work out who owns what: `WHERE substring(d.maintenance_key from 2 for 16) = decode('<key id>', 'hex')` on a binary column, `substring(decode(d.maintenance_key, 'base64') from 2 for 16)` on a base64 one. People only ever handle the fingerprint, which the server's startup log and the tool both show; the key id is the fingerprint without its leading `1`, read as a number and written in 16 bytes: `int(digits[1:]).to_bytes(16, 'big').hex()` in Python, `BigInt(digits.slice(1)).toString(16).padStart(32, '0')` in JavaScript. Docs' and Drive's `maintenance_export --fingerprint` takes the 40 digits, spaces allowed. Keep each line small and put any large ciphertext in a file, a document's content included: the tool reads the manifest whole, so 100,000 documents of a few pages inline (5 to 10 GB) would not open, while in files the manifest stays around 30 MB. Any other field of a line (a title, `updatedAt`...) comes back unchanged in the decrypted manifest, which is how the import can skip a document edited after the export and leave it for the next batch. The tool writes each item as soon as it is decrypted and keeps none in memory: into a folder you pick in Chrome and Edge (no limit but the disk's), or into a `.zip` archive built in the browser's storage in Firefox (ZIP64, so past 4 GiB and 65,535 files), in memory only where neither exists. An archive built in the browser's storage is plaintext on the computer's disk, inside the browser profile: the tool asks before the page is left while it exists, deletes it on leaving or on its button, and deletes any leftover the next time it opens. Deleting removes the file, as deleting any file does (no recycle bin, but no overwriting either), so the isolated computer's disk is treated like the drive the archive leaves on: a computer with full-disk encryption (BitLocker, FileVault, LUKS), whose key stays with the custodians, is the right one, and so is an encrypted drive for the archive. What has to fit in memory is one item at a time: an attachment is encrypted in one piece, so the largest one must fit, twice, which it already did in the browser that encrypted it. `src/maintenance/escrow.test.ts` runs this whole loop against a real PostgreSQL schema with attachments in an object storage.

Again: it lowers end-to-end encryption by exactly one holder, the custodians of the owner's organization's phrase, and keeps the protection that matters most: a leaked database or server still yields nothing readable, because the secret key exists only offline. Keep the phrase in a physical vault under the security officer (RSSI / CISO), ideally split between several people so that no one can read content alone. When the period ends, unset the variable, drop the column and destroy the phrases. See [architecture.md, Appendix E](architecture.md#appendix-e).

**Trying it locally.** `src/maintenance/sample-export/` is a ready encrypted export (documents, image attachments, a comment, a Drive-like tree, another organization's document, a damaged copy) encrypted for the development phrase: open the built tool, pick that folder and type `DEV_MAINTENANCE_PHRASE`. `.env.test` also configures, for every email (`*`), the public key of a committed development phrase (`DEV_MAINTENANCE_PHRASE` in `src/maintenance/dev-maintenance-key.ts`, a fixture, never for a real deployment), so every document created in the demo products carries a `maintenanceKey`. Build the tool with `npm run build:maintenance`, open `dist/maintenance/maintenance-tool.html`, and decrypt a folder built from the demo store, where each document is one line (`id`, `title`, `maintenanceKey`, `content` are the store's own names):

```bash
mkdir -p demo-export && curl -s 'http://localhost:7200/api/demo/documents?product=7201' \
  | jq -c '.[] | select(.maintenanceKey) | {id, title, maintenanceKey, content: .encryptedContent}' > demo-export/manifest.ndjson
```

## Reporting a security issue

Please do not open a public issue. For the code, use GitHub's private reporting as described in [`SECURITY.md`](SECURITY.md). For a running instance, its operator publishes the channel at `/.well-known/security.txt` (set with `SECURITY_CONTACT_URL`).

## License

MIT — see [LICENSE](LICENSE).
