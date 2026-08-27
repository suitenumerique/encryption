# Base images are pinned by DIGEST, not by tag. A tag can be repointed at different
# content by whoever controls the namespace; a digest is the content. Renovate keeps
# both the digest and the trailing version comment up to date.
ARG NODE_BUILDER=node:24.19.0-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
# distroless: no shell, no package manager, no busybox. If an attacker reaches code
# execution inside the container there is no `sh`, no `apk`, no `curl` and no `wget`
# to pivot with. Runs as the `nonroot` user (uid 65532) by default.
ARG NODE_RUNTIME=gcr.io/distroless/nodejs24-debian12:nonroot@sha256:14d42e2511532589a7c7e01a753667a74fcc96266e137e8125006b87b0c32d0a

# ---- Build stage: install deps, bundle server, build vault + UI + client ----
FROM ${NODE_BUILDER} AS builder

# npm 12 is what enforces `allowScripts` and `min-release-age`. Installing it
# explicitly means the policy holds regardless of which npm the base image ships.
ARG NPM_VERSION=12.0.2

RUN apk -U upgrade && npm install -g "npm@${NPM_VERSION}"

WORKDIR /app

# .npmrc is copied deliberately: it carries the supply chain policy, and an install
# that silently ran without it would not be the install that was reviewed.
COPY package.json package-lock.json .npmrc ./

# --omit=dev drops every test-only package (Storybook, Jest, Playwright, MSW, ESLint,
# Prettier: roughly 840 of 2290) from the environment that produces the shipped bytes.
# The build toolchain lives in `dependencies` precisely so this is possible.
#
# No install script runs: `allowScripts` in package.json approves none of them, which
# was verified by building this image with all of them blocked.
RUN npm ci --omit=dev

COPY . .

# Generate Prisma client
RUN npm run db:schema:compile

# Build everything: server (esbuild single-file bundle), vault, UI, client SDK
RUN npm run build

# ---- Production stage: a Node runtime and the bundled files, nothing else ----
FROM ${NODE_RUNTIME}

ENV NODE_ENV=production

WORKDIR /app

# Copy all build outputs — this is the entire application:
# - dist/server/main.mjs  (bundled server, all deps included via esbuild)
# - dist/vault/            (HTML + JS for data.encryption)
# - dist/ui/               (HTML + JS for encryption)
# - dist/client/           (SDK served from encryption)
#
# There is no node_modules in this image: esbuild bundled every runtime dependency
# into the server file, so the production attack surface is one JS file plus Node.
COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist

USER nonroot

EXPOSE 7200

# Exec form with an absolute path: there is no shell in this image to resolve `node`.
HEALTHCHECK --interval=10s --timeout=2s --start-period=15s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://localhost:' + (process.env.PORT || 7200) + '/health').then(r => { if (!r.ok) throw new Error(); process.exit(0); }).catch(() => process.exit(1))"]

# The distroless entrypoint is /nodejs/bin/node, so CMD carries only its arguments.
#
# Node's permission model narrows what a compromised RUNTIME dependency can do, which
# is the one threat none of the install-time controls touch. With it enabled, nothing
# in the bundle can spawn a child process, load a native addon, start a worker, or
# write anywhere except /tmp, whatever the code says.
#
# Verified: the server boots, serves, and runs its scheduled database jobs under these
# flags. If a future dependency legitimately needs one of the denied capabilities the
# failure is explicit (ERR_ACCESS_DENIED), and the fix is to add the matching
# --allow-* flag here after understanding why it is needed.
#
# There is no --allow-net on this Node line, so outbound network is not restricted
# here; that is the deployment's job (see docker-compose.production.yaml).
# `--max-old-space-size-percentage` (Node 24) sizes the V8 heap from the container's
# memory limit instead of a default nobody has measured, leaving the rest for the
# non-heap side. Without it the heap follows whatever cgroup limit the deployment
# happens to set, which is fine until it is not.
#
# `--enable-source-maps` makes Node resolve `dist/server/main.mjs.map` itself, so
# every stack the process produces already points at `src/server/....ts:42` instead
# of a column of a 26 MB bundle. That fixes the logs and the reported stacks at once,
# and it is why nothing is ever uploaded to an error collector: the map stays in this
# image and never leaves it. It costs roughly 20 MB of heap, once, at startup.

CMD ["--permission", "--allow-fs-read=/app", "--allow-fs-write=/tmp", "--max-old-space-size-percentage=70", "--enable-source-maps", "dist/server/main.mjs"]
