# Encryption Service — Developer Context

## What is this project?

A centralized end-to-end encryption service for a collaborative suite (Docs, Drive, Fichier, Visio). It provides encryption capabilities via isolated iframes on two domains served by a single server:

- **`data.encryption`** (vault) — invisible iframe loaded by products. Stores private keys in IndexedDB, performs all crypto operations via libsodium WASM. Communicates only via postMessage. Minimal attack surface.
- **`encryption`** (UI) — visible iframe for onboarding, backup, restore, device transfer, settings, and documentation. Uses React + Cunningham (French gov design system).

Products load a client SDK (`client.js`) from `data.encryption` via a `<script>` tag. The SDK orchestrates both iframes.

## Project structure

Single `package.json`, no workspaces. Source in `src/` with clear module separation:

- `src/crypto/` — libsodium encryption, hybrid X25519 key pairs, BIP-39 mnemonics, fingerprints
- `src/vault/` — vault entry point, postMessage handler, operations, Service Worker, origin guard
- `src/client/` — VaultClient SDK (framework-agnostic, served as IIFE + ESM)
- `src/ui/` — React app (Cunningham, i18next, MDX docs, browser check)
- `src/server/` — Fastify server, Host-based routing, API routes, security headers
- `src/shared/` — constants, Zod schemas, error codes (shared between server and client)
- `src/prisma/` — Prisma 7 schema, client with `@prisma/adapter-pg`
- `src/demo/` — fake product pages for testing (two instances on different ports)
- `src/i18n/` — French translations, i18next setup
- `src/build/` — build-time helpers (browser versions from browserslist)
- `.storybook/` — Storybook config with factory pattern from assistant-declaration

## Tech stack

- **Crypto**: libsodium-wrappers-sumo (WASM), hybrid X25519 + post-quantum placeholder, XChaCha20-Poly1305
- **Server**: Fastify (plain), Prisma 7 + PostgreSQL, esbuild bundle (single .mjs, zero node_modules in production)
- **Frontend**: React, Cunningham + UI Kit, i18next, MDX docs
- **Build**: Vite (vault, UI, client SDK, demo), esbuild (server), vite-plugin-sri-gen
- **Tests**: Jest + ts-jest
- **Auth**: Keycloak (local dev), ProConnect JWT (production). Local Keycloak access tokens expire after **5 minutes**, refresh tokens after **1080 seconds** (18 min). The interface refreshes tokens lazily (only when an API call needs a valid token and it expires within 1 minute), using Web Locks to prevent concurrent refreshes across tabs.
- **Package manager**: npm with all versions pinned (no ^ or ~)

## Key conventions

- **All imports use `@encryption/src/...`** — zero relative imports. The alias maps to the project root via tsconfig paths.
- **All UI text goes through i18next** (`useTranslation('common')`) — translations in `src/i18n/fr/common.json`.
- **Server API returns error codes, not messages** — codes defined in `src/shared/error-codes.ts`, translated on the frontend.
- **PostMessage type keys are centralized** in `src/shared/constants.ts` as `MSG_VAULT_*` and `MSG_INTERFACE_*` constants.
- **Comments and logs in English** — only i18n JSON and MDX user documentation are in French.
- **Fingerprints stored as 16-char lowercase hex** without spaces — formatted with `formatFingerprint()` for display only.
- **Test files sit next to source files** (e.g., `encryption.test.ts` next to `encryption.ts`), not in `__tests__/` directories.
- **Dev tooling follows the betagouv pattern** (etabli, assistant-declaration): prettier with Trivago import sorting, ESLint, EditorConfig, VS Code configs, dotenv-run-script.

## Cryptography architecture

**Asymmetric (user keys)**: Hybrid scheme with two slots:

- Slot 1: X25519 (classical, permanent)
- Slot 2: X25519 placeholder (same `KeyEncapsulation` interface as ML-KEM, will be swapped when libsodium.js exposes ML-KEM bindings)
- Shared secret: `HKDF(slot1_shared || slot2_shared)`

**Symmetric (documents)**: XChaCha20-Poly1305 via `crypto_secretbox`. Quantum-safe.

**Backup passphrase**: Full secret keys serialized as base64url JSON (~400 chars). NOT seed-based — using a shared seed would reduce hybrid security to the seed's entropy, losing the independent-compromise benefit.

**Device transfer**: Ephemeral AES-256 key encoded as 24-word BIP-39 mnemonic (`@scure/bip39`). The encrypted payload goes to the server, the mnemonic stays with the user.

## PostMessage API

Two categories of operations:

- **Product operations** (any allowed origin): `has-keys`, `get-public-key`, `encrypt-without-key`, `encrypt-with-key`, `decrypt-with-key`, `share-keys`, fingerprint checks
- **Privileged operations** (only `encryption`): `generate-keys`, `export-backup`, `import-backup`, `destroy-keys`, device transfer

The vault enforces this via `PRIVILEGED_OPERATIONS` set + `isInterfaceOrigin()` check.

## Security measures

- CSP, COEP, COOP, CORP headers (vault is the most restrictive)
- SRI on all script tags in HTML (generated at build time)
- Service Worker for offline support and version updates
- Runtime origin validation on every postMessage
- Domain validation: `VAULT_DOMAIN` must start with `data.`, `UI_DOMAIN` must start with `interface.`
- Direct access blocked on both domains (iframe check in HTML)
- Browser version check (from browserslist) shown as warning
- Extensions warning during onboarding
- `robots.txt` + `<meta name="robots" content="noindex, nofollow">`
- Rate limiting: 10 key creations per 30 days, 10 device transfers per hour
- Device transfer sessions auto-deleted after 1 hour

## Port scheme (local development)

| Port | Service                      | Hostname                            |
| ---- | ---------------------------- | ----------------------------------- |
| 7200 | Fastify (API + Vault + UI)   | `data.encryption.localhost` / `encryption.localhost` |
| 7201 | Demo Product A               | `localhost`                         |
| 7202 | Demo Product B               | `localhost`                         |
| 7203 | Keycloak                     | `localhost`                         |
| 7204 | Storybook                    | `localhost`                         |
| 7205 | PostgreSQL (app)             | `localhost`                         |
| 7206 | PostgreSQL (Keycloak)        | `localhost`                         |

In development, a single Fastify server on port 7200 embeds Vault and UI via Vite middleware mode. Host-based routing dispatches requests to the correct Vite instance. Everything works on `localhost:7200`, but for proper origin isolation (matching production), use the `.localhost` subdomains above. Modern browsers resolve `*.localhost` to `127.0.0.1` automatically and treat them as secure contexts (required for `crypto.subtle`). If your browser doesn't resolve them, add these entries to `/etc/hosts`:

```
127.0.0.1 data.encryption.localhost
127.0.0.1 encryption.localhost
```

## How to run locally

```bash
# Start databases + Keycloak
docker compose up -d

# Install deps + generate Prisma client
npm install
npm run db:schema:compile

# Create database tables
npm run db:push

# Start everything (server with vault+UI, 2 demo products)
npm run dev

# Open Demo Product A
open http://localhost:7201

# Open Demo Product B (different port = different origin, proves cross-origin works)
open http://localhost:7202
```

## Common commands

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

## What's next / known TODOs

- **ML-KEM**: When `libsodium.js` exposes ML-KEM bindings, swap the post-quantum slot in `src/crypto/encryption.ts` (`getPostQuantumKem` function). The `KeyEncapsulation` interface is already designed for this swap.
- **English translations**: Only French (`fr`) is available. The i18next setup supports multiple languages, just add `src/i18n/en/common.json`.
