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

## Tech stack

- **Crypto**: libsodium-wrappers-sumo (WASM), hybrid X25519 + post-quantum placeholder, XChaCha20-Poly1305
- **Server**: Fastify, Prisma 7 + PostgreSQL, esbuild (single .mjs bundle in production)
- **Frontend**: React, Cunningham (French gov design system) + UI Kit, i18next, MDX docs
- **Build**: Vite (vault, UI, client SDK, demo), esbuild (server)
- **Tests**: Vitest (unit, Node) + Vitest browser mode via `@storybook/addon-vitest` (stories, Chromium/Playwright)
- **Auth**: OIDC provider JWT (production), Keycloak (local dev)

## Security model

The two-domain architecture creates a **privilege separation**:

- **Vault** (`data.encryption`): holds private keys, has **no auth token** — can only read public keys from the server
- **Interface** (`encryption`): holds an OIDC token, has **no access to private keys** — can write to the server but cannot decrypt content

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
- **Egress needed**: PostgreSQL, the SMTP host(s), the OIDC provider (`OIDC_JWKS_URL`) and, if set, the host in `SENTRY_DSN`. Nothing else: no registry, no CDN, no download at startup.

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

| Variable                  | Role                                                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `VAULT_URL`, `UI_URL`     | The two public origins. TLS is mandatory: the vault needs a secure context, and the browser reporting endpoint is ignored over plain HTTP. |
| `ALLOWED_FRAME_ANCESTORS` | The product origins allowed to embed the iframes. They must share one registrable domain (see "Storage partitioning constraint").          |
| `DATABASE_URL`            | Connection string of the **runtime** role (below).                                                                                         |
| `OIDC_*`                  | The identity provider the interface authenticates against.                                                                                 |
| `MAILER_*`                | SMTP for the emergency-access notifications, with an optional fallback host.                                                               |
| `SENTRY_*`                | Optional error reporting (see "Error reporting").                                                                                          |
| `SECURITY_CONTACT_URL`    | Optional. Where researchers report a problem with your instance (`mailto:` or `https://`), published as `/.well-known/security.txt`.       |

### Database roles

Two PostgreSQL roles, created once by the database administrator with the scripts in [`deploy/postgres/`](deploy/postgres):

1. [`create-migrator-role.sql`](deploy/postgres/create-migrator-role.sql): `encryption_migrator`, owner of the `encryption` schema, the only role allowed to create and alter tables. Used by the migration step only.
2. [`create-runtime-role.sql`](deploy/postgres/create-runtime-role.sql): `encryption_runtime`, allowed to read and write rows and nothing else. This is the role in the server's `DATABASE_URL`.

```sh
psql "$ADMIN_DATABASE_URL" -v password="'…'" -f deploy/postgres/create-migrator-role.sql
psql "$ADMIN_DATABASE_URL" -v password="'…'" -f deploy/postgres/create-runtime-role.sql
```

The split means a compromised server process cannot change the schema, and a schema change cannot happen by accident from a pod: it only happens where the migrator credentials are, which is the release step. Every table lives in the `encryption` schema, never in `public`, so other roles on a shared server cannot even list them. Both connection strings carry `?schema=encryption`: the migration tooling reads it to place its own `_prisma_migrations` table there (the migrator has no right to create anything in `public`), and the server ignores it since its queries name the schema explicitly.

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

## Reporting a security issue

Please do not open a public issue. For the code, use GitHub's private reporting as described in [`SECURITY.md`](SECURITY.md). For a running instance, its operator publishes the channel at `/.well-known/security.txt` (set with `SECURITY_CONTACT_URL`).

## License

MIT — see [LICENSE](LICENSE).
