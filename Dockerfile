ARG NODE_VERSION=24.19.0
ARG NODE_DIGEST=sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
ARG NPM_VERSION=12.0.2

# ---- Build stage: install deps, bundle server, build vault + UI + client ----
FROM node:${NODE_VERSION}-alpine@${NODE_DIGEST} AS builder

ARG NODE_VERSION
ARG NPM_VERSION

# Make sure priority digest is aligned with tag
RUN node -v | grep -qx "v${NODE_VERSION}" || { \
  echo "NODE_VERSION=${NODE_VERSION} does not match the image behind NODE_DIGEST ($(node -v)). Update both together."; \
  exit 1; \
  }

RUN apk -U upgrade && npm install -g "npm@${NPM_VERSION}"

WORKDIR /app

COPY package.json package-lock.json ./

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

# ---- Production stage: just Node.js + the bundled files, nothing else ----
FROM node:${NODE_VERSION}-alpine@${NODE_DIGEST}

RUN apk -U upgrade

USER node
WORKDIR /app

# Copy all build outputs — this is the entire application:
# - dist/server/main.mjs  (bundled server, all deps included via esbuild)
# - dist/vault/            (HTML + JS for data.encryption)
# - dist/ui/               (HTML + JS for encryption)
# - dist/client/           (SDK served from encryption)
COPY --from=builder --chown=node:node /app/dist ./dist

EXPOSE 7200

HEALTHCHECK --interval=10s --timeout=2s --start-period=15s \
  CMD node -e "fetch('http://localhost:' + (process.env.PORT || 7200) + '/health').then(r => { if (!r.ok) throw new Error(); process.exit(0); }).catch(() => process.exit(1))"

CMD ["node", "dist/server/main.mjs"]
