ARG NODE_VERSION=24.19.0

# ---- Build stage: install deps, bundle server, build vault + UI + client ----
FROM node:${NODE_VERSION}-alpine AS builder

RUN apk -U upgrade

WORKDIR /app

COPY package.json package-lock.json ./

# `npm ci` installs devDependencies (the build needs them) and playwright is one of
# them, for the Storybook story tests. Its postinstall would otherwise pull ~400 MB
# of browsers into a stage that never runs one. Nothing reaches the final image
# anyway: only `dist/` is copied, and the server bundle carries no node_modules.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

RUN npm ci

COPY . .

# Generate Prisma client
RUN npm run db:schema:compile

# Build everything: server (esbuild single-file bundle), vault, UI, client SDK
RUN npm run build

# ---- Production stage: just Node.js + the bundled files, nothing else ----
FROM node:${NODE_VERSION}-alpine

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
