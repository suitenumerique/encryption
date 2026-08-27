# Supply chain hardening plan (CI/CD, npm, Docker)

Status: proposal, nothing implemented yet.
Scope: this repository only. Deployment infrastructure is out of scope except where it is named explicitly.

---

## 1. Threat model

Four distinct attacker positions. Most advice on the internet mixes them, which is why it feels
contradictory. Each control below is tagged with the position it actually addresses.

| #      | Position                                                               | Concrete example                                                                                            | What it buys the attacker here                                                                                      |
| ------ | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **T1** | Malicious code runs at **install time** on a dev laptop or a CI runner | Shai-Hulud / Shai-Hulud 2.0, via `preinstall` / `postinstall`                                               | Reads `GITHUB_TOKEN`, `CONTAINER_REGISTRY_TOKEN`, `~/.docker/config.json`, `.env*`, then exfiltrates or republishes |
| **T2** | Malicious code runs at **build time** as part of the toolchain         | a compromised Vite plugin, esbuild plugin, PostCSS transform, Storybook addon                               | Injects arbitrary code **into the shipped bundle**. SRI does not help: the hash is computed after the injection     |
| **T3** | Malicious code is a **runtime dependency** of the server or the vault  | a compromised `fastify` plugin, `pg`, `jose`, `libsodium-wrappers-sumo`                                     | Adds a backend endpoint, leaks private keys out of the vault, weakens crypto                                        |
| **T4** | The **pipeline itself** is compromised                                 | a poisoned GitHub Action (tj-actions, trivy-action, Megalodon), a stolen registry token, a force-pushed tag | Publishes an image nobody reviewed, under a legitimate tag                                                          |

Given what this service holds (users' private keys), **T2 and T3 are the ones that matter most**, and
they are the two that neither CVE feeds nor SRI cover. T1 is the easiest to close and the most
commonly exploited, so it is still phase 0.

---

## 2. Direct answers to the three questions asked

### 2.1 "Should we stop running postinstall scripts and allowlist only the ones that need it?"

Yes. This is the single highest value change in the whole document, and it is nearly free here.

The dependency tree has **2288 packages**, but only **5** declare a real install-time hook
(`preinstall` / `install` / `postinstall`, the only three npm actually runs for dependencies):

```
prisma@7.5.0            preinstall   node scripts/preinstall-entry.js   (node version check, droppable)
@prisma/engines@7.5.0   postinstall  node scripts/postinstall.js        (downloads query engine, likely needed)
esbuild@0.25.12         postinstall  node install.js                    (validates the platform binary)
@swc/core@1.15.46       postinstall  node postinstall.js                (Storybook transitive, test-only)
msw@2.15.0              postinstall  writes mockServiceWorker.js        (already committed at .storybook/public/, droppable)
```

The other ~96 hits found by a naive scan are `prepare` scripts. npm does **not** run `prepare` for
registry dependencies, only for git dependencies and for the root project, so they are noise.

So the exposure is 5 packages out of 2288, and probably only 2 of them are actually required.

Also relevant: none of the root `scripts` in `package.json` are `pre*` / `post*` pairs, so turning
scripts off globally does not break `npm run build`, `npm run test:unit`, etc. Explicitly invoked
scripts still run under `ignore-scripts=true`.

**npm 12 makes this the default.** Released July 2026, it blocks dependency lifecycle scripts unless
the root package's `allowScripts` policy allows them, and additionally defaults `allow-git=none` and
`allow-remote=none`. Node 24 LTS still ships npm 11, so this repo will hit it at the next Node bump
or the next `npm i -g npm`. Doing the allowlist now means npm 12 is a non-event instead of a broken
pipeline.

Note for the record: Shai-Hulud 2.0 moved from `postinstall` to `preinstall` specifically because
`preinstall` runs earlier. Both are covered by the same switch.

### 2.2 "`npm install` or `npm ci`?"

`npm ci`, without exception, everywhere except when you are deliberately changing dependencies.

The CI workflow currently runs `npm install` (`.github/workflows/ci.yml`, "Install dependencies"
step). That is a real finding, not a style preference:

- `npm install` is free to **resolve versions the lockfile does not contain** and to silently rewrite
  `package-lock.json` inside the runner. Pinning versions in `package.json` does not prevent this,
  because transitive dependencies are not pinned by your `package.json`, only by the lockfile.
- `npm ci` fails if `package.json` and the lockfile disagree, never writes the lockfile, and wipes
  `node_modules` first, so the tree is exactly the reviewed one.

The Dockerfile already does the right thing (`npm ci`). CI does not.

Version pinning in `package.json` is good and worth keeping, but understand what it does: it pins
your ~90 direct dependencies. `package-lock.json` is what pins the other ~2200. The lockfile
carries `integrity` for all 2288 entries and every `resolved` URL points at `registry.npmjs.org`,
which is healthy, and `npm ci` is what enforces it.

### 2.3 "Should dev and prod dependencies be installed separately? Is a two-phase install worth it?"

The intuition is right, but the framing needs correcting, and the conclusion is different from a
"two `npm install`" split.

**Where the intuition is wrong:** the production runtime here already has zero npm dependencies.
esbuild bundles the whole server into `dist/server/main.mjs`, and the final Docker stage copies only
`dist/`. So "a dev library contaminating production at runtime" is already impossible. There is
no `node_modules` in the deployed image.

**Where the intuition is right, and it is a bigger problem than the one asked about:** a dev
dependency does not need to reach production at runtime to reach production. It only needs to be
_present while the artifact is built_ (T2). Vite, esbuild, their plugins and everything those pull in
execute with full permissions during `npm run build`, and their output is the file you ship. A
compromised Storybook transitive dependency that happens to also be loaded by the Vite config is
game over, and it would be invisible in the final image.

So the useful split is not "dev vs prod". It is:

> **packages present when the release artifact is built** vs **packages present only when tests and
> linting run**

npm gives exactly one lever for this, `dependencies` vs `devDependencies`, so repurpose it:

- `dependencies` = runtime deps **plus the build toolchain** (`vite`, `esbuild`, `typescript`,
  `prisma`, `@vitejs/plugin-react`, `vite-plugin-dts`, `vite-plugin-sri-gen`, `react`, `react-dom`,
  `remark-gfm`, and whatever else `npm run build` and `npm run db:schema:compile` actually touch)
- `devDependencies` = test, lint, format, Storybook, MSW, Playwright, Jest, ESLint, Prettier,
  `@hey-api/openapi-ts`, `tsx`, `@types/*`

Then the Docker builder runs `npm ci --omit=dev`, and the release artifact is produced by a tree that
never contained Storybook, Playwright, Jest, MSW or ESLint.

Measured on the current lockfile:

```
full tree (npm ci)                    2288 packages
dev-only packages                     1058
build-capable tree (proposed split)   ~1453 packages
```

**~835 packages, about 36% of the tree, removed from the environment that produces the shipped
bytes.** That is a real reduction in T2 surface, and it is worth doing.

Caveat to check during implementation: `react` and `react-dom` are currently `devDependencies` but
the UI build needs them, so `--omit=dev` would break the build today. The recategorization has to
come first.

**On the "differential install" idea** (install prod, build, then add dev on top): do not. `npm ci`
deliberately deletes `node_modules` before installing, so it cannot be incremental, and `npm install`
on top would defeat 2.2. `npm prune --omit=dev` after the fact is also the wrong direction: it prunes
_after_ everything already ran. The correct sequencing is two separate CI **jobs** on separate
runners, each doing one clean `npm ci` (see 4.2), not two installs in one job. The cost is one extra
install from a warm cache, roughly a minute, which is cheap for what it buys.

---

## 3. Findings in the current repository

Ranked by how much they matter. All verified against the tree at the time of writing.

### F1. Tests and image publication share one job, one filesystem, one token (T1, T4): critical

`.github/workflows/ci.yml` is a single job named `requirements` that, in order:
`npm install` → lint → unit tests → Storybook e2e in a real browser → `docker login` with
`CONTAINER_REGISTRY_TOKEN` → `docker buildx build --push`.

Every one of those steps runs as the same user on the same disk. So any of the 2288 packages that
executes during install or during the test run can:

- wait for the `docker login` step to write `~/.docker/config.json`, then read the registry
  credentials out of it;
- read `GITHUB_TOKEN` from the runner environment (the job grants `packages: write`, `issues: write`,
  `pull-requests: write`);
- modify files under `src/` so the modification is picked up by the Docker build two steps later
  (see F2).

This is precisely what the Shai-Hulud family automates. Splitting jobs is the fix.

### F2. The Docker build context is the post-test working tree, not a clean checkout (T1, T2): critical

`docker/build-push-action` is called with `context: .` in the same job, after `npm run api:schema:sync`
and after the whole test suite has run. `.dockerignore` excludes `node_modules` and `dist`, but not
`src`. So anything that mutated `src/`, `package.json`, `vite.config.ts` or `Dockerfile` during the
test phase is copied into the builder image and lands in the published artifact.

The existing guard only covers two paths:

```yaml
git diff --exit-code -- openapi.json src/ui/api/generated
```

### F3. `npm install` instead of `npm ci` in CI (T3): high

Covered in 2.2. The Docker build uses `npm ci`, CI does not, so CI can legitimately test a different
dependency tree than the one that gets shipped.

### F4. Actions are unpinned and outdated (T4): high

```
actions/checkout@v4                     mutable tag, v5 available
actions/setup-node@v3                   mutable tag, v5 available
actions/cache@v3                        mutable tag, v4 available
docker/setup-buildx-action@v3           mutable tag
docker/login-action@v2                  mutable tag, v3 available
docker/build-push-action@v5             mutable tag, v6 available
SimenB/github-actions-cpu-cores@v2      third party, mutable tag, single maintainer
```

A mutable tag means the maintainer, or anyone who steals their account, can change what runs in your
pipeline without any change on your side. This is the exact mechanism of the tj-actions compromise
(March 2025) and the trivy-action compromise (March 2026, 75 of 76 tags force-pushed, secrets
exfiltrated from every pipeline that ran a scan). Only 3.9% of repositories pin all third-party
actions to a SHA.

`SimenB/github-actions-cpu-cores` in particular is a third-party action running on a job that holds
your registry token, to compute a number that `nproc` gives you for free.

### F5. Job-level permissions are broad and applied to pull requests (T4): high

There is no top-level `permissions:` block, and the single job requests `packages: write`,
`issues: write`, `pull-requests: write`. Those are granted on every pull request build too, where
nothing needs them.

### F6. A rogue backend endpoint would not be caught by the current openapi check (T2, T3): high

This is the direct answer to "if it touches backend endpoints, is there a way to notice?".

The `api:schema:sync` diff check is a genuinely good control and is unusual to find in a repo, but
`src/build/generate-openapi.ts` builds the document from `app.swagger()`, and by design
"routes without a `schema` are omitted". A route registered by a compromised dependency via a
Fastify plugin, with no Zod `schema`, is invisible to it. 33 paths are documented today.

The fix is small and fits the existing pattern exactly: also snapshot the **full** Fastify route
table, which includes routes with no schema, and diff that in CI. See 4.5.

### F7. No dependency update policy and no cooldown (T1, T2, T3): medium

No `.github/dependabot.yml`, no Renovate config. Updates are manual, which is safe against automated
merges but means a known-vulnerable transitive dependency can sit unnoticed. Conversely, once
automation is added, it must not merge a version published 20 minutes ago: most malicious npm
versions are detected and unpublished within hours, so a cooldown converts most of these incidents
into non-events.

npm shipped `min-release-age` in 11.10.0 (February 2026). This repo runs npm 11.9.0, one minor
version below it. `packageManager` also declares `npm@10.4.0`, which contradicts both the installed
version and `engines.node >= 24.14.0`.

### F8. No provenance, no SBOM, no signature on the published image (T4): medium

`build-push-action` is called without `provenance:` or `sbom:`, no attestation is generated, nothing
is signed, and deployment (explicitly outside this repo) has no way to verify that
`lasuite/encryption:main` came from this workflow rather than from a stolen Docker Hub token.

### F9. Docker image details (T3, T4): medium

- Base image `node:24.14.0-alpine` is pinned by tag but **not by digest**, so the same tag can be
  repointed.
- The final stage runs `apk -U upgrade`, which requires keeping `apk`, `busybox` and a full shell in
  the production image. An attacker with code execution in the server gets a usable toolbox.
- `NODE_ENV` is not set to `production` in the final image.
- `.dockerignore` is a denylist (`node_modules`, `dist`, `.git`, `*.md`). Anything new and sensitive
  added to the repo root is included in the build context by default. `.env.test` and
  `.env.test.product` are copied into the builder stage today.
- `USER node`, multi-stage, and a `HEALTHCHECK` are already correct. Credit where due.

### F10. Repository-level protections (T4): medium

No `CODEOWNERS`, no `SECURITY.md`, no OpenSSF Scorecard, no workflow linting. Branch protection
settings are not visible from the repository contents and need to be checked in the GitHub UI.

### F11. SRI does not do what it is being counted on to do (T2): worth stating explicitly

`vite-plugin-sri-gen` computes the integrity hashes **at build time, from the files it just built**.
If a compromised Vite plugin injected code into those files, the SRI hash is computed over the
injected code and matches perfectly. SRI protects against tampering **in transport or at rest on the
host**, it does not protect against a poisoned build. It is worth keeping, it is simply not the
control for this threat.

What _does_ work against T2 on the frontend is already in place and is genuinely strong: the vault
CSP is `default-src 'none'; script-src 'self'; connect-src 'self'`, so injected code cannot load a
remote script and cannot beacon out over fetch/XHR/WebSocket. The gaps to close are the exfiltration
channels CSP does not cover (top-level navigation) and the absence of any reporting, see 4.7.

---

## 4. The plan

### Phase 0. Install-time execution and lockfile discipline (highest value / lowest effort)

**0.1 Add a committed `.npmrc` at the repository root**

```ini
# Dependency lifecycle scripts are the single largest code-execution surface in npm.
# npm 12 makes this the default; we adopt it early. Packages that genuinely need a
# build step are rebuilt explicitly, see `npm run deps:rebuild`.
ignore-scripts=true

# Never resolve a dependency from a git ref or an arbitrary tarball URL.
# (npm >= 12 defaults these to `none`; harmless and inert on npm 11.)
allow-git=none
allow-remote=none

# Do not install a version published less than 7 days ago: most malicious versions
# are detected and unpublished within hours. Requires npm >= 11.10.
min-release-age=7

# `npm install <pkg>` writes an exact version, matching the repo convention.
save-exact=true

engine-strict=true
fund=false
```

Then bump the toolchain so `min-release-age` is actually honoured:

```jsonc
// package.json
"packageManager": "npm@11.19.0"   // currently npm@10.4.0, which is stale and wrong
```

and make CI install that npm version explicitly rather than inheriting whatever Node ships.

**0.2 Add an explicit rebuild allowlist**

```jsonc
// package.json  (name and membership to be confirmed by 0.3)
"scripts": {
  "deps:rebuild": "npm rebuild --no-ignore-scripts prisma @prisma/engines esbuild"
}
```

Candidate exclusions, to confirm empirically:

- `msw` writes `mockServiceWorker.js`, which is already committed at `.storybook/public/`, so its
  postinstall is redundant.
- `@swc/core` is a Storybook transitive dependency, so it never needs to run in the release build.
- `prisma`'s `preinstall` is a Node version check, and `engines.node` already covers that.
- `esbuild` normally resolves its binary through the 26 `@esbuild/*` optional platform packages,
  which the lockfile contains, so its `install.js` may be unnecessary. Verify before dropping it.

**0.3 Verify the allowlist against a clean tree before merging**

```bash
rm -rf node_modules
npm ci                      # now implies --ignore-scripts via .npmrc
npm run deps:rebuild
npm run db:schema:compile
npm run build
npm run test:unit
npm run test:e2e:headless
```

Any failure names exactly the package to add to `deps:rebuild`. This is the whole migration.

**0.4 Prepare the npm 12 form**

Once running on npm 12, the same policy moves into `package.json` as the `allowScripts` field, which
is generated by the approve command (`npm install-scripts approve`, spelling has moved during the
prereleases, check `npm help install-scripts` on the installed version) and committed. Keep `.npmrc`
as the belt-and-braces version for contributors still on npm 11.

**0.5 Split `dependencies` / `devDependencies` along the build/test line**

Per 2.3. Move `vite`, `esbuild`, `typescript`, `prisma`, `@vitejs/plugin-react`, `vite-plugin-dts`,
`vite-plugin-sri-gen`, `react`, `react-dom`, `remark-gfm` and any other build-time requirement into
`dependencies`. Verify with:

```bash
rm -rf node_modules && npm ci --omit=dev && npm run db:schema:compile && npm run build
```

The build must succeed with **zero** test tooling installed. That is the acceptance criterion.

---

### Phase 1. Restructure the pipeline

**1.1 Split the single job into a graph**

```
                 ┌─ verify   (lint, tsc, format, api:schema:sync + full-tree git diff)
  (fan out) ─────┼─ test     (jest)
                 ├─ e2e      (storybook test-runner, the only job that needs a browser)
                 └─ audit    (npm audit signatures, osv-scanner, zizmor)
                       │
                       ▼
                    release   (main/tags only, fresh checkout, holds the registry credential)
```

Rules for the `release` job:

- `needs: [verify, test, e2e, audit]`
- `if: github.ref_name == 'main' || github.ref_type == 'tag'`
- its own `actions/checkout` from scratch, so the build context is a pristine tree (fixes F2)
- it is the **only** job that can see `CONTAINER_REGISTRY_*` (fixes F1)
- it runs no test tooling, no linters, no Storybook

**1.2 Least privilege**

```yaml
permissions:
  contents: read # top level, applies to every job

jobs:
  release:
    permissions:
      contents: read
      id-token: write # OIDC, for attestations and keyless login
      attestations: write # for actions/attest-build-provenance
```

Drop `issues: write` and `pull-requests: write` entirely unless something actually uses them
(nothing in the current workflow does).

**1.3 `npm ci`, and pin every action to a full commit SHA**

```yaml
- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
  with:
    persist-credentials: false # do not leave a usable git token on disk
    fetch-depth: 1 # fetch-depth: 0 is not needed by anything here
```

Apply the same to `setup-node`, `cache`, `setup-buildx-action`, `login-action`,
`build-push-action`. Delete `SimenB/github-actions-cpu-cores` and use `$(nproc)`.

Adopt a policy: **no third-party action without a SHA pin and a reason**. GitHub Actions policy now
supports enforcing SHA pinning at the org level, which is worth enabling for `numerique-gouv`.

**1.4 Egress control on the runners**

```yaml
- uses: step-security/harden-runner@<sha> # pin it too
  with:
    egress-policy: audit # then switch to `block` with an allowlist
    disable-sudo: true
```

Run in `audit` mode for a week, read the generated network report, then move to `block` with an
allowlist of `registry.npmjs.org`, `github.com`, `objects.githubusercontent.com`, the Docker
registry, and the Playwright CDN. After that, an install-time payload trying to POST your tokens to
an attacker webhook fails at the network layer, whether or not anyone knew the package was
malicious. This is the one control that works against a **zero-day** supply chain attack, which is
what CVE subscriptions structurally cannot give you.

**1.5 Full-tree drift guard before the build**

In the `verify` job, widen F2's check:

```yaml
- name: Fail if anything mutated the working tree
  run: |
    git status --porcelain
    git diff --exit-code || (echo "::error::Working tree was modified during CI. \
      This is either a stale generated file or a dependency writing to the repo." && exit 1)
```

---

### Phase 2. Make the artifact verifiable

**2.1 Emit provenance and an SBOM**

```yaml
- uses: docker/build-push-action@<sha>
  id: build
  with:
    context: .
    push: true
    tags: ${{ steps.docker-meta.outputs.tags }}
    provenance: mode=max
    sbom: true
```

**2.2 Sign it with a GitHub artifact attestation (Sigstore keyless, no key to steal)**

```yaml
- uses: actions/attest-build-provenance@<sha>
  with:
    subject-name: ${{ env.CONTAINER_IMAGE }}
    subject-digest: ${{ steps.build.outputs.digest }}
    push-to-registry: true
```

**2.3 Verify at deploy time**

The deployment lives outside this repository, so this is a requirement to hand to whoever operates
it. It is the step that makes 2.1 and 2.2 worth anything:

```bash
gh attestation verify oci://lasuite/encryption:1.2.3 \
  --repo numerique-gouv/encryption \
  --signer-workflow numerique-gouv/encryption/.github/workflows/ci.yml
```

An image pushed with a stolen Docker Hub token has no valid attestation for that workflow and is
refused. Note the honest limit: provenance proves _which workflow built it_, not that the source was
benign. If an attacker gets a commit merged, the resulting image has perfect provenance. Provenance
is a forensic and anti-token-theft control, not an anti-malicious-code control.

**2.4 Replace the long-lived Docker Hub token with OIDC**

Docker shipped OIDC connections for GitHub Actions on 31 July 2026: `docker/login-action` exchanges
the workflow's OIDC token for a per-run credential that dies with the run, and
`CONTAINER_REGISTRY_TOKEN` disappears from the repository secrets entirely. It requires a Docker
Team / Business / DHI subscription **or** enrolment in the Docker Sponsored Open Source program,
which a `numerique-gouv` project should qualify for. Worth applying for.

Same logic applies to any npm publishing this project ever does: npm classic tokens were fully
revoked on 9 December 2025, granular write tokens are now capped at 90 days, and Trusted Publishing
(OIDC) is the supported path.

**2.5 Reproducible build check (optional, high signal)**

Add a job that builds `dist/` a second time on a clean runner and compares SHA-256 of every emitted
file against the release build. Publish the manifest as a release asset.

- If the hashes match, you have a second, independent confirmation that the bytes correspond to the
  commit, and any future third party can reproduce it.
- If they do not match, you have found either genuine non-determinism in the toolchain (worth fixing
  anyway) or an injection that behaves differently per run.

Start by measuring: `npm run build` twice on the same machine and diff the hashes. If Vite and
esbuild are already deterministic here, this is nearly free.

---

### Phase 3. Contain the running process

These reduce what an attacker can do **after** the fact, which is the honest answer to "and if all
the above fails".

**3.1 Dockerfile**

```dockerfile
# Pin the base by digest, not just by tag. A tag can be repointed.
ARG NODE_IMAGE=node:24.14.0-alpine@sha256:<digest>

FROM ${NODE_IMAGE} AS builder
WORKDIR /app
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    NODE_ENV=production
COPY package.json package-lock.json .npmrc ./
# --omit=dev becomes possible once phase 0.5 lands: no Storybook, Jest, Playwright,
# MSW or ESLint in the environment that produces the shipped bytes.
RUN npm ci --omit=dev && npm run deps:rebuild
COPY . .
RUN npm run db:schema:compile && npm run build
```

For the final stage, prefer an image with **no shell and no package manager**:

```dockerfile
FROM gcr.io/distroless/nodejs24-debian12@sha256:<digest>
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist
USER nonroot
EXPOSE 7200
CMD ["dist/server/main.mjs"]
```

Trade-offs to weigh before committing to distroless: it removes `apk -U upgrade` (good, that is what
rebuilding on a fresh base is for), but it also removes the shell used by the current `HEALTHCHECK`
form. The `node -e` healthcheck already used here works fine in exec form. If distroless turns out
to be inconvenient, staying on `node:24-alpine` pinned by digest, with `apk` removed in the final
layer, captures most of the benefit.

**3.2 `.dockerignore` as an allowlist**

```
*
!package.json
!package-lock.json
!.npmrc
!tsconfig.json
!tsconfig.sw.json
!prisma.config.ts
!openapi-ts.config.ts
!src
!config
```

Deny by default, allow what the build needs. Today `.env.test`, `.env.test.product`, `.DS_Store` and
`architecture.md` all land in the builder stage for no reason.

**3.3 Runtime flags at deployment (not in the Dockerfile)**

```
--read-only
--tmpfs /tmp:rw,noexec,nosuid,size=64m
--cap-drop=ALL
--security-opt no-new-privileges:true
--pids-limit 256
--memory 1g
```

A read-only root filesystem defeats most code-drop and web-shell techniques. `no-new-privileges`
blocks setuid escalation. Add these to `docker-compose.yaml` for local parity so nobody discovers a
write-to-disk dependency in production.

**3.4 Node.js permission model (experiment, then adopt)**

Node 24 promoted the permission model out of experimental. Running the server bundle under it turns
"a compromised runtime dependency" (T3) from "arbitrary code execution as the app" into something
much narrower:

```
node --permission \
     --allow-fs-read=/app/dist \
     --allow-fs-write=/tmp \
     dist/server/main.mjs
```

`--allow-child-process` stays off, so nothing in the bundle can spawn a process. Check on the exact
Node version whether the network flag (`--allow-net`) is available and what granularity it offers,
since restricting outbound network to the database and the OIDC provider would be the highest value
piece here. Expect friction with `pg` and Prisma, so gate it behind an env flag and roll it out
progressively.

---

### Phase 4. Detection, which is what CVE feeds cannot give you

This section answers "I am subscribed to CVEs but I do not think it is enough". It is not: a CVE
exists only after someone has found and reported the malicious package, and the Shai-Hulud waves did
most of their damage within hours. Detection has to be **behavioural and differential**, not
signature based.

**4.1 Snapshot the complete route table, not just the documented one (fixes F6)**

The strongest available answer to "would I notice if a dependency added a backend endpoint". Extend
`src/build/generate-openapi.ts`, or add a sibling script, to also write the full Fastify route
table:

```ts
// The OpenAPI document only contains routes that declare a Zod `schema`, by design.
// This snapshot contains every route Fastify actually serves, so a route registered
// by a compromised dependency, which would carry no schema, shows up as a CI diff.
writeFileSync(resolve(process.cwd(), 'routes.snapshot.txt'), app.printRoutes({ commonPrefix: false }));
```

Commit `routes.snapshot.txt` and extend the existing CI guard:

```yaml
git diff --exit-code -- openapi.json routes.snapshot.txt src/ui/api/generated
```

Now any new endpoint, from any source, fails the build until a human commits the change. This costs
about ten lines and fits the conventions already in the repository.

Consider snapshotting the registered Fastify plugin list and the `onSend`/`onRequest` hook count the
same way, since a hook is the other natural place to hide an interception.

**4.2 Diff the built frontend bundles across releases**

Commit a manifest of SHA-256 hashes plus byte sizes for every file in `dist/vault/` and `dist/ui/`,
generated at build time, and have CI report the delta on each release. A commit that touches no
frontend source but changes the vault bundle hash is the signal you are looking for. Sudden growth
in `dist/vault/` is a strong smell given how small and stable that surface is.

**4.3 Diff the SBOM between releases**

Phase 2.1 already generates one. Store it and diff it: new package, removed package, version bump,
maintainer change. This catches "a transitive dependency you have never heard of appeared" long
before any CVE is published for it.

**4.4 Verify registry signatures on every install**

```yaml
- run: npm audit signatures
```

Verifies the registry's ECDSA signatures and the Sigstore provenance attestations of the installed
tree, and fails on a package whose signature is missing or invalid. Cheap, fast, and it runs before
your code touches the dependency.

**4.5 Add scanners that are not CVE-only**

- `osv-scanner` on `package-lock.json`: broader and faster-moving than `npm audit`, and it does not
  execute package code.
- `zizmor`: static analysis for GitHub Actions workflows (template injection, unpinned actions,
  excessive permissions, credential leaks). Run it on `.github/workflows/`.
- `trivy` or `docker scout` on the built image, before push.
- OpenSSF Scorecard action, scheduled weekly, as a regression check on the repo's own posture.
- Consider a behavioural npm scanner (Socket, or equivalent) that flags _what a package does_
  (network at install, filesystem access, obfuscated payload) rather than whether it has a CVE. This
  is the category that actually catches Shai-Hulud-class packages on day zero.

**4.6 Dependency updates with a cooldown**

`.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: weekly }
    cooldown: # do not propose a version published days ago
      default-days: 7
    groups:
      dev-dependencies:
        dependency-type: development
    open-pull-requests-limit: 5

  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
```

Never auto-merge. The cooldown plus `min-release-age=7` in `.npmrc` gives two independent layers of
the same protection, one at proposal time, one at install time.

**4.7 CSP reporting on the frontend**

`src/server/plugins/security-headers.ts` already has a genuinely strict policy. Add reporting so a
blocked attempt becomes a **signal** instead of a silent failure:

- add `report-to` / `report-uri` and an endpoint that logs violations;
- on the vault, a single `script-src` or `connect-src` violation in production is close to proof of
  compromise, because the vault has no legitimate reason to ever attempt an external load. Alert on
  it, do not just log it;
- close the residual exfiltration channel that CSP does not cover: the vault iframe can still
  exfiltrate by navigating the top-level window to an attacker URL. Products embedding the vault
  should use `<iframe sandbox="allow-scripts allow-same-origin">` (no `allow-top-navigation`), and
  that requirement belongs in the SDK integration documentation;
- consider `require-trusted-types-for 'script'` on the vault. Its surface is small enough that the
  migration cost is low, and it would neutralise a whole class of injected DOM sinks.

**4.8 Publish the SDK's SRI hash per release**

Products load `client.js` from `data.encryption` via a `<script>` tag. Publish the expected
`integrity` value with each release so products can pin it. That does not protect against a poisoned
build (F11), but it does mean a product notices if the file it receives is not the file you shipped.

---

### Phase 5. Repository governance

- `CODEOWNERS` requiring an explicit review for `.github/workflows/`, `Dockerfile`, `package.json`,
  `package-lock.json`, `src/crypto/`, `src/vault/`. These are the files where a supply chain attack
  lands, and they are the ones most likely to be skimmed in review.
- Branch protection on `main`: required PR review, required status checks, linear history, no force
  push, and **require signed commits**. The May 2026 Megalodon campaign pushed malicious workflows
  directly into 5561 repositories whose default branch did not require review.
- Enable GitHub secret scanning **with push protection**, so a token never reaches the history.
- Enable private vulnerability reporting, add `SECURITY.md` with a disclosure address. For a service
  holding users' private keys this is table stakes.
- Tag protection so a released tag cannot be moved (the trivy-action attack was a tag force-push).
- Require 2FA, ideally hardware-backed, for every member of the `numerique-gouv` org with write
  access here.

---

## 5. Suggested order

| Step | Content                                                                                                               | Effort                             | Threat closed                               |
| ---- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ------------------------------------------- |
| 1    | `.npmrc` with `ignore-scripts` + rebuild allowlist + npm 11.19 + `@lavamoat/preinstall-always-fail` (0.1 to 0.4, 7.2) | half a day                         | T1, most of the real-world attacks          |
| 2    | `npm ci` in CI, split the release job, least privilege, SHA-pin every action (1.1 to 1.3, 1.5, 9)                     | one day                            | T1, T4, the token theft path                |
| 3    | The three delta checks: route table, install-script list, bin table (4.1, 7.1, 7.3)                                   | half a day                         | T2, T3 detection, the specific worry raised |
| 4    | Renovate with the shared `numerique-gouv` preset, 7-day cooldown (8, replaces 4.6)                                    | one hour                           | T1, T2, T3                                  |
| 5    | dependencies/devDependencies split + `--omit=dev` in the builder (0.5, 3.1)                                           | half a day                         | T2, 36% less build surface                  |
| 6    | `npm audit` gates + `npm audit signatures` + osv-scanner + Trivy on the image (4.4, 4.5, 7.5)                         | half a day                         | known vulns, tampered packages              |
| 7    | harden-runner in audit then block (1.4)                                                                               | half a day + a week of observation | zero-day exfiltration                       |
| 8    | Provenance, SBOM, attestation, verify at deploy (2.1 to 2.3)                                                          | one day                            | T4                                          |
| 9    | `.dockerignore` allowlist, digest pinning, distroless, runtime flags (3.1 to 3.3)                                     | one day                            | T3 blast radius                             |
| 10   | `SECURITY.md`, CODEOWNERS, branch protection, CSP reporting (4.7, phase 5)                                            | one day                            | T4, detection                               |
| 11   | Docker Hub OIDC, Node permission model, reproducible build check (2.4, 2.5, 3.4)                                      | ongoing                            | T4, T3                                      |

Steps 1 to 4 are where the ratio of value to effort is overwhelming, and step 4 is an hour of work
that the rest of LaSuite already has. Everything after step 7 is defence in depth and can land
progressively.

Separate from this repository, and worth raising with the platform team regardless of what we do here:
**`numerique-gouv/action-trivy-cache@main` and `numerique-gouv/action-argocd-webhook-notification@main`
should be SHA-pinned in `docs`, `drive` and `meet`** (see 8, last subsection). It is the highest
severity finding in the whole survey and it is not in our repository.

---

## 6. Residual risk, stated honestly

None of this stops an attacker who compromises a **runtime** dependency that this service genuinely
imports and that gets merged through a normal, reviewed dependency bump. If `jose` or
`libsodium-wrappers-sumo` ships a subtly weakened version, `min-release-age` buys days, provenance
proves the build was legitimate, CSP contains exfiltration from the frontend, and the route snapshot
catches a new endpoint, but a change in the _behaviour_ of an existing code path is not caught by any
of them.

The two things that address that specific residue, and both are larger projects than this document:

1. **Reduce the count of runtime dependencies in the vault and crypto paths.** The vault is the
   crown jewel and its dependency list should be short enough to audit by hand, ideally vendored and
   reviewed rather than tracked. Auditing what `src/vault/` and `src/crypto/` actually pull in
   transitively is a worthwhile standalone task.
2. **End-to-end verification that does not trust the server**, which this architecture already leans
   towards: out-of-band fingerprint verification, binding signatures verified client-side, and the
   registry design in `architecture.md`. That is what makes a compromised _backend_ survivable, and
   it is the reason this codebase is in better shape than most against T3.

---

## Sources

- [npm 12 Disables Install Scripts by Default to Reduce Supply Chain Risk (The Hacker News)](https://thehackernews.com/2026/07/npm-12-disables-install-scripts-by.html)
- [Upcoming breaking changes for npm v12 (GitHub Changelog)](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/)
- [npm config reference: allow-scripts, allow-git, allow-remote, min-release-age](https://docs.npmjs.com/cli/v12/using-npm/config)
- [npm introduces minimumReleaseAge and bulk OIDC configuration (Socket)](https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration)
- [npm security update: classic token creation disabled (GitHub Changelog)](https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes/)
- [Shai-Hulud 2.0 ongoing supply chain attack (Wiz)](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [The Shai-Hulud 2.0 npm worm: analysis (Datadog Security Labs)](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Shai-Hulud worm compromises npm ecosystem (Unit 42)](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Maintainers' guide: securing CI/CD pipelines after tj-actions and reviewdog (OpenSSF)](https://openssf.org/blog/2025/06/11/maintainers-guide-securing-ci-cd-pipelines-after-the-tj-actions-and-reviewdog-supply-chain-attacks/)
- [Hardening GitHub Actions: lessons from recent attacks (Wiz)](https://www.wiz.io/blog/github-actions-security-guide)
- [GitHub Actions Security Cheat Sheet (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html)
- [Pinning GitHub Actions for enhanced security (StepSecurity)](https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide)
- [GitHub Actions policy now supports blocking and SHA pinning actions](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/)
- [Enhance build security and reach SLSA Level 3 with GitHub Artifact Attestations](https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/)
- [Docker OIDC connections for GitHub Actions available for Docker orgs](https://www.docker.com/blog/docker-oidc-connections-for-github-actions-available-for-docker-orgs/)
- [npm audit signatures / verifying registry signatures (npm Docs)](https://docs.npmjs.com/verifying-registry-signatures/)
- [Introducing npm package provenance (GitHub Blog)](https://github.blog/security/supply-chain-security/introducing-npm-package-provenance/)
- [Node.js permissions documentation](https://nodejs.org/api/permissions.html)
- [Docker security best practices 2026: hardening containers from build to runtime](https://zeonedge.com/blog/docker-security-best-practices-2026-hardening-containers-build-runtime)
- [npm bin script confusion (Socket)](https://socket.dev/blog/npm-bin-script-confusion)
- [@lavamoat/preinstall-always-fail (npm)](https://www.npmjs.com/package/@lavamoat/preinstall-always-fail)
- [numerique-gouv/renovate-configuration (shared Renovate preset used by docs, drive, meet)](https://github.com/numerique-gouv/renovate-configuration)
- [npm supply chain security in 2026: what your package manager does and does not protect you from (Mondoo)](https://mondoo.com/blog/npm-supply-chain-security-package-manager-defenses-2026)

---

## 7. Additional controls (added after review)

### 7.1 Detect install scripts without installing anything

Better than any web tool: **the lockfile already records it.** npm writes `hasInstallScript: true` on every
entry that declares `preinstall` / `install` / `postinstall`, so the answer is available offline, with
no install, no execution, and without sending the dependency graph to a third party.

```bash
node -e "
const l = JSON.parse(require('fs').readFileSync('package-lock.json','utf8'));
for (const [k, v] of Object.entries(l.packages)) if (v.hasInstallScript) console.log(k + '@' + v.version);
"
```

Current answer for this repository, **8 entries out of 2288**:

```
@prisma/engines@7.5.0        @swc/core@1.15.46 (dev)      esbuild@0.25.12 (dev)
prisma@7.5.0                 msw@2.15.0 (dev)             fsevents@2.3.3 (darwin-only, never installed on CI)
tsx/node_modules/esbuild@0.27.4 (dev)                     playwright/node_modules/fsevents@2.3.2 (dev)
```

This is the authoritative version of the count in 2.1 (the earlier scan of `node_modules` found 5
because `fsevents` is darwin-only and one `esbuild` copy is deduped on Linux).

**Turn it into a gate.** The interesting property is not the count, it is the _delta_: a new
install-script package appearing in the tree is a strong signal. Commit the list and diff it in CI:

```jsonc
// package.json
"scripts": {
  "deps:install-scripts:snapshot": "node scripts/install-scripts-snapshot.mjs > install-scripts.snapshot.txt"
}
```

```yaml
- name: No new install-script dependency without review
  run: |
    npm run deps:install-scripts:snapshot
    git diff --exit-code -- install-scripts.snapshot.txt \
      || (echo "::error::A dependency with an install script entered the tree. Review it, then commit the snapshot." && exit 1)
```

Same pattern as the route snapshot in 4.1: cheap, offline, and it converts an invisible change into a
red build. `can-i-ignore-scripts` does the same job but requires uploading or installing; prefer the
local version.

### 7.2 `@lavamoat/preinstall-always-fail` as a tripwire

**Verified from the published tarball** (`npm pack`, extracted without installing, v3.0.0): the package
contains exactly four files, `package.json`, `README.md`, `CHANGELOG.md`, `LICENSE`. **There is no
code at all.** No dependencies. MIT, from the LavaMoat project (Consensys). The entire mechanism is
one line:

```jsonc
"scripts": {
  "preinstall": "echo \"Don't run npm lifecycle scripts by default! ...\" && exit 1"
}
```

Verdict: **yes, add it**, pinned exact, as a devDependency. It costs nothing and it closes a real gap,
namely "someone ran an install in a context where `.npmrc` was not picked up": wrong working
directory, a runner that checked out only part of the repo, a Docker layer that copies `package.json`
without `.npmrc`, a contributor who typed `npm i --dangerously-allow-all-scripts`. In all of those the
install fails loudly instead of silently running 8 install scripts.

Two honest limits, so it is not oversold:

- **It is a tripwire, not a barrier.** It works by _being_ an install script, and npm does not
  guarantee it runs first. A malicious `preinstall` elsewhere in the tree can execute before it. It
  detects a misconfiguration, it does not stop an attack.
- Under npm 12 it is blocked like every other install script, which is the correct behaviour: scripts
  are off, so there is nothing to warn about. It still fires if someone forces scripts back on.

It is a complement to `.npmrc` and to 7.1, never a replacement.

### 7.3 Bin script confusion: the hole that `ignore-scripts` does not cover

This is an important gap in phase 0 and it deserves to be called out explicitly.

npm symlinks every dependency's `bin` entries into `node_modules/.bin`, and npm puts
`node_modules/.bin` at the **front of `$PATH`** for every `npm run` script. npm places almost no
restriction on what a package may name its bin. So a package can ship:

```jsonc
{ "bin": { "node": "payload.sh", "npm": "payload.sh" } }
```

and then **any** `npm run build` in the project executes the attacker's `node`.

`--ignore-scripts` provides **zero** protection here, because this is not a lifecycle script. Neither
does `min-release-age` beyond the usual delay, nor SHA-pinned actions. `npm install --no-bin-links`
does stop it but is not usable here (the build needs `vite`, `tsc`, `prisma`, `esbuild`, `jest` on the
path), and it is not sticky, so the next `npm ci` re-enables links.

The practical control is the same delta pattern as 7.1: **snapshot the bin table and diff it**. Unlike
install scripts, `bin` is not recorded in the lockfile, so the check has to scan the installed tree,
which means it runs after `npm ci` and before the build. Two rules:

1. **Hard fail** if any bin name shadows a system command: `node`, `npm`, `npx`, `sh`, `bash`, `env`,
   `git`, `docker`, `curl`, `wget`, `make`, `python`, `ssh`, `openssl`.
2. **Fail on drift** of the committed `binName -> providing package` mapping, so a bin appearing, or
   changing owner, requires an explicit commit.

Measured on the current tree, so the check is known to be practical:

```
118 distinct bin names declared
0   shadowing a system command
1   claimed by two packages: `jest` <- jest, jest-cli   (benign, allowlist it)
```

One clean allowlist entry and the check is green today, which means every future hit is real signal.

### 7.4 `overrides` for transitive dependencies

Correct that pinning direct dependencies does nothing for the ~2200 transitive ones. The precision
worth keeping in mind: **`package-lock.json` already pins all 2288 with an `integrity` hash**, and
`npm ci` enforces it (see 2.2). So the standing protection is the lockfile, not `overrides`.

Where `overrides` genuinely earns its place is two specific situations, both worth writing down as
procedure rather than adding as standing configuration:

- **Incident response.** When a compromised version is announced at 9am, `overrides` is the fastest
  way to force a known-good version across the entire tree without waiting for every direct dependency
  to cut a release. It is the emergency lever, and knowing it exists _before_ the incident is the point.
- **A high-reach transitive package with a fix its parent has not adopted yet**, which is the same
  case `npm audit fix` tries and often fails to resolve.

```jsonc
// package.json
"overrides": {
  "some-inner-dep": "2.1.4"
}
```

Caveats: an override applies everywhere and can silently break a peer requirement, it needs
`npm install` plus a committed lockfile to take effect, and an override left in place for a year
becomes an invisible pin that blocks security updates. Add a comment with the reason and the date next
to each one, and review them when they are no longer needed. Do not adopt `overrides` as a broad
standing policy for "high-risk packages", because that is what the lockfile already does, and the
maintenance cost is real.

### 7.6 Pinning every transitive version, not just the direct ones

The worry is the right one: `A` depends on `B`, `B` depends on `^C`, and nothing in this
repository's `package.json` says anything about `C`. So what stops `C` from moving?

**`package-lock.json` already does, completely.** The lockfile does not store `^C`, it stores the
exact version npm resolved for it plus an `integrity` hash of the tarball. `npm ci` installs
precisely those entries and verifies every hash. The range inside `B`'s manifest is not consulted at
all. Measured on this tree: 2288 entries, every one carrying `resolved` and `integrity`, all pointing
at `registry.npmjs.org`. That is what `npm run security:lockfile` now asserts on every CI run, so the
property cannot quietly degrade.

Blanket `overrides` for transitive dependencies would therefore add **nothing** at install time,
while costing real maintenance: an override applies everywhere, ignores peer constraints, and
silently becomes an invisible pin that blocks security updates.

The range only matters at one moment: **when the lockfile is regenerated**, by `npm install`,
`npm update`, `npm audit fix`, or a Renovate PR. That is exactly the moment the cooldowns cover, and
they are the correct tool for it:

| Moment                      | Control                              | Effect                                                                |
| --------------------------- | ------------------------------------ | --------------------------------------------------------------------- |
| A version is proposed       | Renovate `minimumReleaseAge: 7 days` | No PR is opened for a release younger than a week                     |
| The lockfile is regenerated | `.npmrc` `min-release-age=7`         | npm refuses to resolve a version younger than a week, whoever runs it |
| Every install after that    | lockfile `integrity` + `npm ci`      | The exact reviewed bytes, or the install fails                        |

Three independent layers, none of which needs a hand-maintained list of versions.

`overrides` stays useful for exactly two things, both procedure rather than standing configuration,
and both described in 7.4: emergency pinning during an incident, and forcing a fixed version when a
parent has not adopted it yet.

### 7.5 `npm audit` in CI, with the right expectations

Add it, but place it correctly, because it addresses a **different threat** from everything else in
this document:

```yaml
- name: Known vulnerabilities in production dependencies
  run: npm audit --audit-level=high --omit=dev # blocking

- name: Known vulnerabilities in dev tooling
  run: npm audit --audit-level=critical || true # informational
```

Blocking on production dependencies and informational on dev tooling avoids the alert fatigue that
makes teams add `--audit-level=none` after three weeks.

The expectation to set clearly: **`npm audit` does not catch supply chain attacks.** It matches
against the GitHub Advisory Database, and a malicious package is normally _unpublished_ by npm rather
than assigned a CVE, so it frequently never appears there at all. Shai-Hulud would not have been
caught by `npm audit`. Audit is vulnerability management, which is necessary and worth doing;
`ignore-scripts`, the cooldown, egress blocking and the delta checks are the supply chain controls.
They are different jobs and neither substitutes for the other.

Pair it with `osv-scanner` (broader database, does not execute package code) and with
`npm audit signatures` from 4.4, which is the one that verifies the _provenance_ of what was installed
rather than looking up known bugs.

---

## 8. How this repository compares to the other LaSuite projects

Surveyed: `docs` (impress), `drive`, `meet`. All three are Django backends with a JS frontend, so the
comparison only covers the npm and CI/CD parts.

| Control                                          | encryption (us)        | docs                           | drive                          | meet                                            |
| ------------------------------------------------ | ---------------------- | ------------------------------ | ------------------------------ | ----------------------------------------------- |
| Lockfile-strict install                          | **No** (`npm install`) | Yes (`yarn --frozen-lockfile`) | Yes (`yarn --frozen-lockfile`) | Yes (`npm ci` + `yarn --frozen-lockfile`)       |
| Exact version pinning                            | **Yes, 91/92**         | No (ranges)                    | No (ranges)                    | Yes, 49/51                                      |
| `ignore-scripts` / script allowlist              | No                     | No                             | No                             | No                                              |
| Dependency update automation                     | **No**                 | Renovate                       | Renovate                       | Renovate                                        |
| Cooldown before adopting a version               | **No**                 | 7 days (shared preset)         | 7 days (shared preset)         | 7 days + `internalChecksFilter: strict`         |
| Actions pinned to a SHA                          | 0                      | 0                              | 0                              | 1 of ~30                                        |
| Actions pinned to a **mutable branch** (`@main`) | 0                      | **4**                          | **3**                          | **6**                                           |
| Top-level `permissions:`                         | No                     | No                             | No                             | Yes (`contents: read`)                          |
| Test job separated from publish job              | **No**                 | Yes (separate workflows)       | Yes                            | Yes                                             |
| Image vulnerability scanning                     | **No**                 | Trivy                          | Trivy                          | Trivy                                           |
| Automated security review on PRs                 | No                     | No                             | No                             | Yes (`claude-code-security-review`, SHA-pinned) |
| `SECURITY.md`                                    | **No**                 | Yes                            | Yes                            | Yes                                             |
| Provenance / SBOM / signed image                 | No                     | No                             | No                             | No                                              |
| Caches `node_modules` directly                   | No                     | **Yes**                        | **Yes**                        | No                                              |
| Egress control on runners                        | No                     | No                             | No                             | No                                              |

### What they do better than us, and should be copied

1. **Renovate with a 7-day cooldown.** All three extend `github>numerique-gouv/renovate-configuration`,
   which sets `minimumReleaseAge: "7 days"` for npm, GitHub Actions **and** Python, plus
   `prHourlyLimit: 2` and `prConcurrentLimit: 2`. We have no dependency automation at all. Adopting the
   shared preset is strictly better than writing our own `dependabot.yml` from scratch (4.6): same
   protection, plus consistency with the rest of the suite. `meet` goes further with
   `internalChecksFilter: "strict"`, which is worth copying too.
2. **Lockfile-strict installs everywhere.** All three do it, we are the only one running `npm install`.
   This confirms F3 is an outlier and not a house style.
3. **Trivy scanning of every image before push.** They use `numerique-gouv/action-trivy-cache`. We
   scan nothing. (See the caveat below about how it is pinned.)
4. **Separate workflows for test and for publish**, so the registry credential is not on the same
   runner as the test suite. This is F1, and we are the only repository with the problem.
5. **`SECURITY.md`.** All three have one, we do not, and we are the repository holding private keys.
6. **`meet` runs an automated security review on every PR**, pinned to a full commit SHA. It is the
   only SHA-pinned action in the entire fleet.
7. **`meet` sets a top-level `permissions: contents: read`.**

### What we do better than them

1. **Exact version pinning** of ~all direct dependencies (`docs` and `drive` use ranges). Only `meet`
   is comparable.
2. **A generated-artifact drift check in CI** (`api:schema:sync` + `git diff --exit-code`). Nothing
   equivalent exists in the other three. It is incomplete (F6) but the pattern is ours.
3. **A production image with zero npm dependencies at runtime**, thanks to the esbuild bundle. The
   others ship `node_modules` into their frontend images.
4. **A strict, per-host CSP** that is genuinely restrictive (`default-src 'none'` on the vault).

### One finding that applies to the whole fleet, not just to us

> **`numerique-gouv/action-trivy-cache@main` and `numerique-gouv/action-argocd-webhook-notification@main`
> are pinned to a mutable branch, in the jobs that hold `DOCKER_HUB_PASSWORD` and the ArgoCD webhook
> secret.**

13 usages across `docs`, `drive` and `meet`. `@main` is **worse than a version tag**: a tag at least
requires someone to deliberately re-tag, whereas `@main` picks up every single push automatically,
with no release step and no review by the consuming repositories. Anyone able to push to either of
those two action repositories, or anyone who compromises an account that can, immediately controls the
build and publish step of `docs`, `drive` and `meet`, including their Docker Hub credentials and their
ArgoCD deployment webhook.

This is exactly the tj-actions (March 2025) and trivy-action (March 2026, 75 of 76 tags force-pushed)
mechanism, with the extra-fast variant of a branch instead of a tag.

Both actions are first-party `numerique-gouv` repositories, which makes it feel safe. It is not: the
attack does not require the maintainers to be malicious, only for one of their accounts to be. This is
worth raising with the LaSuite platform team independently of anything in this plan, and it is cheap
to fix (pin the SHA, let Renovate bump it, which the shared preset already covers for GitHub Actions).

### Why caching `node_modules` directly is the wrong pattern

`docs` and `drive` both do this:

```yaml
- uses: actions/cache@v4
  id: front-node_modules
  with:
    path: 'src/frontend/**/node_modules'
    key: front-node_modules-${{ hashFiles('src/frontend/**/yarn.lock') }}
- run: yarn install --frozen-lockfile
  if: steps.front-node_modules.outputs.cache-hit != 'true'
```

On a cache hit the install **does not run at all**. The tree is restored as an opaque blob of files.
Three consequences, and they compound:

1. **No integrity check ever runs again.** The whole value of a lockfile is that every tarball is
   verified against its hash on every install. A restored `node_modules` skips that permanently:
   whatever is in the blob is what the build uses, and nothing ever compares it to the lockfile again.
2. **A poisoned tree becomes persistent.** If a malicious version is installed once, in any run that
   writes to that cache scope, every later run restores the poisoned tree straight from cache. It
   survives the version being unpublished from the registry, it survives the lockfile being
   corrected, and it keeps being used because the cache key still matches: the key is the hash of the
   lockfile, and the lockfile did not change.
3. **Scanners then look at the wrong thing.** `npm audit`, `osv-scanner` and any SBOM generated from
   the lockfile all describe the _lockfile_, which is clean. The tree actually on disk is a different
   set of bytes, and nothing reconciles the two. The pipeline reports green while building from
   something else entirely.

Caching the **npm cache** instead, which is what `actions/setup-node` with `cache: npm` does and what
this repository now uses, has none of those properties. The cache holds content-addressed tarballs,
`npm ci` runs on every job, and every tarball is re-verified against the lockfile hash each time. A
tampered cache entry fails the integrity check instead of being trusted. The saving is nearly the
same, because the expensive part is the download, not the unpack.

Worth raising with `docs` and `drive`; it is not this repository's problem to fix.

---

## 9. On SHA pinning: does it actually help?

Short answer: **yes, it is the single most effective fix for F4, and it is not a half measure.**

A git SHA is content-addressed. It commits to the full tree of the action repository at that commit,
so `actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8` runs exactly the bytes that were
reviewed, permanently. A maintainer, or an attacker holding their credentials, can move `v4`, delete
it, re-point `main`, force-push a tag. **They cannot make an existing SHA resolve to different
content.** That would require a chosen-prefix SHA-1 collision, and git has had collision detection
since 2.13. This is precisely why the tj-actions and trivy-action victims were the repositories using
`@v1` and `@main`, and why the ones pinned by SHA were unaffected.

So: pin every action, first-party and third-party, GitHub-owned included, with the version in a
trailing comment:

```yaml
uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
```

Three limits worth knowing, so the pin is not trusted beyond what it delivers:

1. **A SHA pin does not pin what that action itself calls.** A composite action frozen at a SHA can
   internally do `uses: another-action@v1` against a mutable tag, and your pin does nothing about it.
   This is the gap GitHub is closing with workflow dependency locking (a `dependencies:` section
   locking direct **and** transitive actions to SHAs, in the spirit of `go.sum`), which is on the 2026
   roadmap and not shipped. Until then: when you pin a third-party action, open its `action.yml` once
   and check what it calls. Prefer actions that pin their own dependencies.
2. **A SHA pin does not pin what the action downloads at runtime.** `action-trivy-cache@<sha>` still
   fetches a `trivy` binary; a Docker-based action still references an image by tag. The pin freezes
   the instructions, not the payload they fetch. Egress control (1.4) is what covers the remainder.
3. **A pin freezes security fixes too.** A pinned action never gets patched on its own, so pinning
   without automated bumping degrades into rot. Renovate handles SHA pins natively and the shared
   `numerique-gouv` preset already applies `minimumReleaseAge: 7 days` to the `github-actions`
   manager, so this is solved the moment we adopt Renovate (8, point 1).

One nuance on GitHub-owned actions: GitHub now offers **immutable releases**, where a published
release's tag and assets cannot be changed or deleted. That materially reduces tag risk for
`actions/*`. It does not extend to arbitrary third-party actions, and it does not cover `@main`
at all, which is where every real incident has happened. Pin everything anyway; the cost is one
comment per line.

---

## 10. Implementation status

Everything below is implemented and verified in this repository, not proposed. The
verification column says how, because "it is in the file" is not the same as "it works".

### Done

| Area                     | What landed                                                                                                                                                                                                                                                                                                                                     | Verified by                                                                                                                                                                                                                                              |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Install-time execution   | `.npmrc` policy (`allow-git=none`, `allow-remote=none`, `min-release-age=7`, `save-exact`, `engine-strict`), npm pinned to 12.0.2, `allowScripts` in package.json denying all 7 script-declaring packages by name                                                                                                                               | A clean `npm ci` with **every** install script blocked still passes `prisma generate`, `npm run build`, `npm run test:unit` and `npm run build:storybook`. Zero approvals were needed.                                                                   |
| npm 11 fallback          | `@lavamoat/preinstall-always-fail@3.0.0` as a devDependency                                                                                                                                                                                                                                                                                     | Read from the published tarball: 4 files, zero code, zero dependencies. Fires only if someone runs an install with scripts enabled.                                                                                                                      |
| Build surface            | `dependencies` = runtime + build toolchain, `devDependencies` = test/lint/Storybook only; Docker builder runs `npm ci --omit=dev`                                                                                                                                                                                                               | The image builds with no Storybook, Jest, Playwright, MSW, ESLint or Prettier present. `concurrently` had to move too, which the build failure found immediately.                                                                                        |
| Lockfile                 | `npm run security:lockfile` asserts every entry is https, from `registry.npmjs.org`, and carries an `integrity` hash, on lockfile v3+                                                                                                                                                                                                           | Passes on 2293 entries. `npm audit signatures` verifies 2204 registry signatures and 229 provenance attestations.                                                                                                                                        |
| Install scripts, tracked | No snapshot. `allowScripts` denies install-time execution outright, and `@lavamoat/preinstall-always-fail` throws if an install ever runs with scripts enabled, so a committed inventory of what is blocked adds nothing to enforce. (Section 4.2 proposed one; it was built, then removed as redundant.)                                       | The lockfile still records `hasInstallScript`, so the inventory can be regenerated in one command whenever a compromise indicator is worth checking by hand.                                                                                             |
| Bin script confusion     | Nothing. A check was built (`bin-table.snapshot.txt`, plus hard failures on a bin shadowing a system command or claiming a name another package already provides) and then removed as disproportionate for this tree.                                                                                                                           | Measured while it existed: 117 bin names, 0 shadowing, 1 reviewed duplicate. The exposure is a developer machine or a CI runner, never the production image, which contains no node_modules.                                                             |
| Route surface            | No snapshot. It was built (`createServer({ onRoute })` writing `routes.snapshot.txt`, 65 routes against 34 in openapi.json) and then removed: it covers route REGISTRATION only, and a compromised plugin can intercept an existing route from an `onRequest`/`preHandler` hook, reply directly, and register nothing. (Section 6 proposed it.) | Removed rather than extended. Snapshotting the hook chain as well would close that specific hole, but nothing declarative covers a dependency that patches Fastify at runtime, which is what the Node permission model and the distroless image are for. |
| Build output             | Nothing. `dist.manifest.txt` was built and then removed: nothing compared it, and comparing two builds of the same source proves the toolchain is deterministic, not that the source is trustworthy.                                                                                                                                            | The signed provenance attestation and the SBOM cover what the artifact is and where it came from, which is what the manifest was reaching for.                                                                                                           |
| Pipeline shape           | One job became six: `supply-chain`, `verify`, `test`, `e2e`, `build`, `release`. Only `release` sees a credential, and it checks out fresh.                                                                                                                                                                                                     | F1 and F2 are structurally gone: no test dependency shares a filesystem with the registry token, and the image is built from a pristine tree.                                                                                                            |
| Action pinning           | Every action pinned to a full commit SHA with the version in a trailing comment; `npm run security:actions` fails the build otherwise and also requires a `permissions:` block per workflow                                                                                                                                                     | Catches all 7 unpinned refs in the previous workflow. Verified by running it against the old file.                                                                                                                                                       |
| Least privilege          | Top-level `permissions: contents: read`; `id-token`/`attestations` only on `release`; `persist-credentials: false` everywhere                                                                                                                                                                                                                   | `issues: write` and `pull-requests: write` are gone.                                                                                                                                                                                                     |
| Egress                   | `step-security/harden-runner` on every job, `disable-sudo: true`, policy behind the `EGRESS_POLICY` env var                                                                                                                                                                                                                                     | Starts at `audit`; flipping the one variable to `block` is the whole switch.                                                                                                                                                                             |
| Drift                    | `git diff --exit-code` on openapi.json and the generated client, then a second check on the WHOLE tree                                                                                                                                                                                                                                          | A dependency writing to `src/` during install or lint now fails the build.                                                                                                                                                                               |
| Scanners                 | `npm audit` (blocking on critical, reporting on high), `npm audit signatures`, OSV on the lockfile, zizmor on the workflows, Trivy on the image before it is pushed                                                                                                                                                                             | The Trivy step runs on a locally loaded image, so a failing scan cannot publish.                                                                                                                                                                         |
| Artifact integrity       | `provenance: mode=max`, `sbom: true`, and `actions/attest-build-provenance` with Sigstore keyless signing                                                                                                                                                                                                                                       | Verification command documented in SECURITY.md and docker-compose.production.yaml.                                                                                                                                                                       |
| Container                | Builder pinned by digest; runtime is **distroless** (no shell, no package manager), non-root, `NODE_ENV=production`, `.dockerignore` rewritten as an allowlist                                                                                                                                                                                  | Built and run: `/bin/sh` and `/bin/busybox` do not exist, `/usr/bin` is empty, `/app` contains only `dist`.                                                                                                                                              |
| Runtime containment      | Node permission model in the image CMD (`--permission --allow-fs-read=/app --allow-fs-write=/tmp`), and `read_only` + `cap_drop: ALL` + `no-new-privileges` + `pids_limit` in docker-compose.production.yaml                                                                                                                                    | Container runs healthy under all of it, serves `/health` 200, and its scheduled database jobs still run. Nothing in the bundle can spawn a process, load a native addon or start a worker.                                                               |
| Frontend containment     | Reporting API endpoint (`Reporting-Endpoints: default` + `report-to` + `report-uri`) at `/api/browser-reports`, security report types logged at warn and the rest at info; `require-trusted-types-for 'script'` and `trusted-types 'none'` on the vault                                                                                         | End to end against the running container: a posted violation appears as a warn log with the blocked URI. The vault contains no DOM injection sink, so Trusted Types costs nothing.                                                                       |
| Dependency updates       | `renovate.json` extending the shared `numerique-gouv` preset (7-day cooldown on npm, actions, containers), `pinDigests`, individually-reviewed rules for install-script and bin-providing packages, and no cooldown on vulnerability alerts                                                                                                     | The cooldown proved itself during implementation: it refused `@prisma/adapter-pg@7.10.0` and `fastify@5.12.1` for being younger than 7 days.                                                                                                             |
| Code review              | `.github/workflows/security-review.yml`: `anthropics/claude-code-security-review` pinned to a commit SHA, advisory, same-repo pull requests only, `pull-requests: write` scoped to that one job                                                                                                                                                 | `npm run security:actions` passes on 3 workflows. The fork condition is explicit because the action is not hardened against prompt injection and holds an API key.                                                                                       |
| Governance               | `SECURITY.md` (disclosure, scope, release verification), `.github/CODEOWNERS`, OpenSSF Scorecard workflow                                                                                                                                                                                                                                       | CODEOWNERS ships with a placeholder team, flagged in the file.                                                                                                                                                                                           |
| Tests                    | 5 new suites in `src/security/` (49 tests) plus the CSP endpoint (10) and the new headers (4)                                                                                                                                                                                                                                                   | 583 tests pass, up from 569. `npm run lint` and `npm run format:check` clean.                                                                                                                                                                            |

Vulnerability bumps applied along the way, all non-major and all within the 7-day
cooldown: `@fastify/middie` 9.3.1 → 9.3.3 (**critical**, middleware authentication
bypass in child plugin scopes), `concurrently` 9.2.1 → 9.2.4 (**critical**, via
`shell-quote`), `fastify` 5.8.2 → 5.12.0, `vite` 6.4.1 → 6.4.3, and the Prisma trio
7.5.0 → 7.9.1. The build-and-runtime tree now has **zero critical advisories**, which
is why the blocking gate is set there.

Three unrelated files (`src/client/index.ts`, `src/crypto/encryption-db.test.ts`,
`src/shared/schemas/interface-context.ts`) were reformatted: they were already
violating Prettier at `HEAD`, so `npm run format:check` was failing on this branch
before any of this work.

### Deliberately left open

| Item                                                                                                          | Why it is not done                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@fastify/static` 8.3.0 → 10.1.3 (high)                                                                       | Two major versions. Static serving is what delivers the vault and UI bundles, so it needs a real read of the changelog, not a blind bump.                                                                            |
| `@gouvfr/dsfr` 1.12.1 → 1.15.2 (high)                                                                         | The advisory is against `browser-sync` and `localtunnel`, dev tooling **inside** that package that never reaches the artifact. Three minors of a design system is a visual-review change, not a security-urgent one. |
| `harden-runner` in `block` mode                                                                               | Needs one week of `audit` reports first. Flipping `EGRESS_POLICY` is then a one-line change.                                                                                                                         |
| Docker Hub OIDC instead of `CONTAINER_REGISTRY_TOKEN`                                                         | Requires a Docker Team/Business subscription or enrolment in the Sponsored Open Source programme. Worth applying for; until then the token exists but is now confined to one job.                                    |
| Branch protection, required reviews, signed commits, secret-scanning push protection, tag protection, org 2FA | GitHub repository and organisation settings, not files in this repository.                                                                                                                                           |
| The real CODEOWNERS team                                                                                      | The placeholder `@numerique-gouv/encryption-maintainers` must be replaced before branch protection is enabled: GitHub silently ignores an owner that does not exist.                                                 |
| Reproducible-build cross-check (2.5)                                                                          | The manifest that makes it possible now exists and is published per run. Adding a second independent rebuild and comparing is the next step.                                                                         |
| `--disallow-code-generation-from-strings`                                                                     | Would also block `eval` and `new Function` in the bundle. Not enabled because nothing verified that no runtime dependency uses them; worth testing.                                                                  |
| Deploy-time `gh attestation verify`                                                                           | Deployment lives outside this repository. The command is written down in SECURITY.md and in docker-compose.production.yaml.                                                                                          |
| The fleet-wide `@main` action pins in `docs`, `drive` and `meet`                                              | Not this repository. Still the highest-severity finding of the whole survey.                                                                                                                                         |
