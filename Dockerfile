ARG NODE_VERSION=24.19.0
ARG NODE_DIGEST=sha256:ab3eebe934147fee049b5eb83c570f68c849a13c930bdfa482de99fcdfa3b3de
ARG NPM_VERSION=12.0.2

ARG NODE_DISTROLESS_IMAGE=gcr.io/distroless/nodejs24-debian13:nonroot
ARG NODE_DISTROLESS_DIGEST=sha256:774b7d020b24214835769e24c3544835526cd0288f0b094eae48e8b2c2429a79

# ---- Build stage: install deps, bundle server, build vault + UI + client ----
FROM node:${NODE_VERSION}-trixie-slim@${NODE_DIGEST} AS builder

ARG NODE_VERSION
ARG NPM_VERSION

# Make sure priority digest is aligned with tag
RUN node -v | grep -qx "v${NODE_VERSION}" || { \
  echo "NODE_VERSION=${NODE_VERSION} does not match the image behind NODE_DIGEST ($(node -v)). Update both together."; \
  exit 1; \
  }

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
  && rm -rf /var/lib/apt/lists/* \
  && npm install -g "npm@${NPM_VERSION}"

WORKDIR /app

COPY package.json package-lock.json .npmrc ./

# Make sure used version is aligned with the one specified in package.json
RUN want="$(node -p "require('./package.json').packageManager")"; \
  have="npm@$(npm -v)"; \
  [ "$want" = "$have" ] || { \
  echo "package.json declares $want but this image has $have. Update NPM_VERSION and packageManager together."; \
  exit 1; \
  }

# Despite it installs `devDependencies` here for the build, they won't end into the published image
RUN npm ci

COPY . .

# Generate Prisma client
RUN npm run db:schema:compile

# Build everything: server (esbuild single-file bundle), vault, UI, client SDK
RUN npm run build

# ---- Migration tree: the Prisma CLI and its dependencies, nothing else ----
FROM builder AS migrator-tree

RUN set -eu; \
  npx tsx src/build/prisma-migration-closure.ts > /tmp/keep.txt; \
  mkdir -p /opt/migrator; \
  tar -cf - -T /tmp/keep.txt prisma.config.ts src/prisma | tar -xf - -C /opt/migrator

# ---- Production stage: the server and the migration tooling, nothing else (use `docker debug` to debug the container) ----
FROM ${NODE_DISTROLESS_IMAGE}@${NODE_DISTROLESS_DIGEST}

ENV NODE_ENV=production

# Commit SHA helps with monitoring reports to know what version is having a bug
ARG SOURCE_COMMIT=
ENV SOURCE_COMMIT=${SOURCE_COMMIT}

USER nonroot
WORKDIR /app

# First, because it changes only when the lockfile does, while `dist` changes on every
# commit: the Prisma CLI, its dependencies, the schema and the migrations. The 21 MB
# native `schema-engine` binary is part of it on purpose — `migrate deploy` runs it, and
# when it is absent the CLI tries to DOWNLOAD it on the spot, which a read-only filesystem
# refuses and which would need registry egress the deployment must not grant.
COPY --from=migrator-tree --chown=nonroot:nonroot /opt/migrator ./

# Then all build outputs — this is the entire application:
# - dist/server/main.mjs  (bundled server, all deps included via esbuild)
# - dist/vault/            (HTML + JS for data.encryption)
# - dist/ui/               (HTML + JS for encryption)
# - dist/client/           (SDK served from encryption)
# - dist/*/sbom.cdx.json   (what each bundle is made of, for security scanners)
COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist

EXPOSE 7200

HEALTHCHECK --interval=10s --timeout=2s --start-period=15s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://localhost:' + (process.env.PORT || 7200) + '/health').then(r => { if (!r.ok) throw new Error(); process.exit(0); }).catch(() => process.exit(1))"]

# Below the default command running the server, but it's also possible override to it to apply database migrations:
# `docker run [...] lasuite/encryption:latest node_modules/prisma/build/index.js migrate deploy`
CMD ["--permission", "--allow-fs-read=/app", "--allow-fs-write=/tmp", "--max-old-space-size-percentage=70", "--enable-source-maps", "dist/server/main.mjs"]
