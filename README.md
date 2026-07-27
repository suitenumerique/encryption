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

- [Node.js](https://nodejs.org/) >= 24.14.0
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
npm run lint             # ESLint + TypeScript check
npm run format           # Prettier write
npm run format:check     # Prettier check
npm run db:push          # Apply schema to database
npm run db:studio        # Open Prisma Studio
npm run dev:storybook    # Start Storybook on port 7204
```

## Tech stack

- **Crypto**: libsodium-wrappers-sumo (WASM), hybrid X25519 + post-quantum placeholder, XChaCha20-Poly1305
- **Server**: Fastify, Prisma 7 + PostgreSQL, esbuild (single .mjs bundle in production)
- **Frontend**: React, Cunningham (French gov design system) + UI Kit, i18next, MDX docs
- **Build**: Vite (vault, UI, client SDK, demo), esbuild (server)
- **Tests**: Jest + ts-jest
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

## License

MIT — see [LICENSE](LICENSE).
