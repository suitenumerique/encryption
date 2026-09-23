# suite-stack

One Helm release that deploys everything a beta tester needs to try the encryption feature inside the products: the encryption service, Docs and Drive built from the branches under test, and the services all three share (one PostgreSQL, one Redis, one MinIO, one Keycloak, one mail catcher).

It exists because the products' own pipelines only ship images of `main`, and the feature cannot be merged there behind a flag. So the developer builds the product images from the integration branches, pushes them to a registry of their own, and this chart deploys them next to the service, on infrastructure it creates itself. Nothing in it is a production pattern: passwords are plaintext values, the shared services are the products' own development chart, and a `helm uninstall` throws the lot away.

## What is in the release

| Piece         | Chart                                                                                 | Notes                                                                           |
| ------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `encryption`  | `../encryption`, packaged from this checkout                                          | Its migration hook is off; the bootstrap Job migrates instead (see below).      |
| `docs`        | [suitenumerique/docs](https://github.com/suitenumerique/docs), `src/helm`             | Pinned in `Chart.yaml`; pick the version that matches the branch's era.         |
| `drive`       | [suitenumerique/drive](https://github.com/suitenumerique/drive), `src/helm`           | Same.                                                                           |
| `shared`      | [suitenumerique/helm-dev-backend](https://github.com/suitenumerique/helm-dev-backend) | PostgreSQL, Redis, MinIO, Keycloak (realm imported at first boot).              |
| bootstrap Job | `templates/bootstrap.yaml`                                                            | Databases, roles, buckets, OIDC clients, tester accounts, encryption migration. |
| Mailpit       | `templates/mailpit.yaml`                                                              | SMTP for every product, a web mailbox for the testers.                          |
| OnlyOffice    | `templates/onlyoffice.yaml`                                                           | The document server Drive edits office files with (WOPI), collaborative.        |

Every product reaches the shared services by fixed names (`postgres`, `redis`, `minio`, `mailpit`, `onlyoffice`, and the public Keycloak hostname), whatever the release is called, so the values of one product can be copied for the next.

## The bootstrap Job

The shared chart creates one database, one bucket and one realm with one user. Everything else the products need is created by a Job that runs once the services are up (a `post-install` hook) and, on an upgrade, before the products roll out (`pre-upgrade`). Every step is idempotent, and the Job runs on every upgrade: adding a tester or a client is editing the values and running `helm upgrade`.

1. `postgres`: creates every database of `bootstrap.postgres.databases`, then the encryption service's two roles with the scripts of `deploy/postgres/` (copied into `files/`, a test keeps them identical).
2. `minio`: creates every bucket of `bootstrap.minio.buckets`.
3. `keycloak`: creates or updates the OIDC clients of `bootstrap.keycloak.clients` and the accounts of `bootstrap.keycloak.users` (email marked verified, password reset each run). It also writes `bootstrap.keycloak.notice` on the realm: the header of every sign-in page, and the terms every new account accepts before its first sign-in. Registration is open to anyone with the URL, and the admin console and the mailbox are public, so the notice is what tells a tester that nothing here is private.
4. `migrate`: `prisma migrate deploy` with the encryption image of the release and the migrator role, exactly what the service's own migration hook runs. That hook is a `pre-install` one, which Helm runs before the shared PostgreSQL exists, so the stack turns it off (`encryption.database.migration.enabled: false`) and runs the migration here, after the database and the role exist.

The Docs and Drive migration Jobs are not hooks: they start with the release and wait for their database in a loop, so they settle on their own once step 1 is done.

## Under Argo CD

The bootstrap Job is a Helm hook (`post-install`, `pre-upgrade`), which Argo CD would translate into PreSync and run before the shared services exist: the Job's first container would wait for a PostgreSQL that is never created. Argo CD ignores the Helm annotations of an object that carries its own, so the Job and its Secret are Argo CD `Sync` hooks instead, applied together with everything else. No sync wave orders them: each step of the Job waits for the service it needs, the Docs and Drive migration Jobs (also `Sync` hooks) wait for their database in a loop, and the encryption pods restart on their startup probe until the migration has run. That is the same shape as the Docs deployment.

Sync waves were tried and do not work here: a wave waits for every object before it to be healthy, and the shared chart ships a bucket-creation Job with `ttlSecondsAfterFinished: 0`, which Kubernetes deletes the moment it completes. Argo CD then reports it Missing, and a wave placed after it never starts. The same Job shows as OutOfSync on every sync, which is harmless: it is idempotent and the bootstrap creates the buckets anyway.

The hooks run again at every sync, which is what makes editing the testers' list or rotating a password a plain commit.

## Coherence checks

The four subcharts each read their own block, so a hostname or a client id is written in several places. `templates/_checks.tpl` makes the render fail, naming both values, when they disagree: a product's `DB_NAME` absent from the databases the bootstrap creates, an `OIDC_RP_CLIENT_ID` without a client, a client secret that differs, a redirect URI that does not cover the product's origin, `ENCRYPTION_VAULT_URL` that is not the vault's host, a product origin missing from `allowedFrameAncestors`, two products on the same Redis database index, and the encryption database URL not being the runtime role the bootstrap creates. `helm template` on your values is therefore the first test to run.

## Images

Whichever way the product images are produced, the stack only ever sees a reference: `ci/staging-values.yaml` (or the `images` inputs of the preview helmfile) is where it is set, and the coherence checks do not look at it. Two ways exist:

1. **The products' own preview publishing.** A pull request in the upstream Docs repository carrying the `preview` label gets its images pushed by the Docs CI as `lasuite/impress-backend:pr-<number>`, `impress-frontend:pr-<number>` and `impress-y-provider:pr-<number>`, republished on every push to that pull request. This is the path with no manual step: open the integration branches as upstream pull requests, label them, and point the stack at the `pr-<number>` tags. Drive does not push images for pull requests today; once it does, the same applies to it.
2. **A build by hand**, pushed to a registry account of your own (the targets are those of each repository's `docker-hub.yml`):

   ```bash
   # Docs: backend, frontend, y-provider
   docker build --target backend-production -t myaccount/impress-backend:e2ee .
   docker build --target frontend-production -t myaccount/impress-frontend:e2ee -f src/frontend/Dockerfile .
   docker build --target y-provider -t myaccount/impress-y-provider:e2ee -f src/frontend/servers/y-provider/Dockerfile .
   # Drive: backend, frontend
   docker build --target backend-production -t myaccount/drive-backend:e2ee .
   docker build --target frontend-production -t myaccount/drive-frontend:e2ee -f src/frontend/Dockerfile .
   # The encryption service (this repository), or use the `main` tag the CI publishes
   docker build -t myaccount/encryption:e2ee .
   docker push ...
   ```

   Build for the architecture of the cluster's nodes (`--platform linux/amd64` from an ARM laptop).

## Deploying

Prerequisites on the cluster: an ingress controller answering to the `nginx` class, cert-manager with a ClusterIssuer named `letsencrypt` (both names are inputs), and one wildcard DNS record on the domain. The encryption service needs TLS, the browser refuses the vault otherwise; and its vault keys are shared between products only when all origins share one registrable domain (see the encryption chart's README, "Storage partitioning constraint").

**Through the helmfile (the normal way).** `deploy/helmfile/preview/` derives every hostname from two inputs, `feature` (a short label) and `domain`, plus the image references, and passes the result to the chart. Nothing is written twice: the chart's `values.yaml` keeps its defaults and the helmfile overrides only what carries a hostname, the namespace or an image. `feature` is any label: the testers' environment is `feature=beta`, a pull request preview is its number.

```bash
helmfile -e preview -f deploy/helmfile/preview/helmfile.yaml.gotmpl \
  --state-values-set feature=beta,domain=suite.example.org \
  --state-values-set images.docs.tag=pr-2694,images.docsFrontend.tag=pr-2694,images.docsYProvider.tag=pr-2694 \
  --state-values-set images.drive.tag=e2ee,images.driveFrontend.tag=e2ee \
  template > /dev/null   # then `apply` instead of `template`
kubectl -n preview-beta get jobs,pods -w
```

Hosts come out as `beta-docs.suite.example.org`, `beta-drive`, `beta-encryption` and `data.beta-encryption`, `beta-auth`, `beta-s3`, `beta-s3-console`, `beta-mail`, in the namespace `preview-beta`. Everything else (testers, passwords, replicas) is the chart's defaults; to change those too, add a values file to the release in the helmfile.

**With plain Helm.** The chart alone cannot derive one hostname from another: each subchart reads its own block, and Helm gives a parent no way to compute a subchart's values. So without the helmfile the domain is written out in full: copy `values.yaml`, replace `suite.example.org` by your domain and `suite` (in the two `minio.suite.svc.cluster.local` names) by your namespace, put the image references in a second file shaped like `ci/staging-values.yaml`, then:

```bash
cd deploy/helm/suite-stack
helm dependency update .   # not `build`: with a Chart.lock, `build` wants the repositories registered
helm template stack . --namespace suite -f my-values.yaml -f my-images.yaml > /dev/null
helm upgrade --install stack . --namespace suite --create-namespace -f my-values.yaml -f my-images.yaml
```

A missed replacement is caught by the coherence checks for every value they cover, and `SUITE_STACK_VALUES=my-values.yaml npm run test:helm` renders your file through every assertion of `deploy/helm/suite-stack.test.ts` as well.

The notes printed at the end of either path list every URL and account. Keycloak's admin console (`shared.keycloak.username` / `password`) lets you add accounts by hand too; the encryption service accepts unverified emails in this stack (`acceptUnverifiedEmail: true`) so an account created there works without a second step.

## One environment per pull request

The same helmfile with `feature` set to the pull request number is the preview environment: the chart is read from the checkout, so a pull request that changes it is previewed with its own chart, and nothing is published for it. The machinery lives in the deployment repository, not here: `deploy/argocd/applicationset-preview.example.yaml` is an ApplicationSet whose pull request generator lists the pull requests of this repository carrying the `preview` label and renders the helmfile at each one's commit through a helmfile plugin; when the pull request closes or loses the label, the Application goes and prunes its namespace. The inputs travel as environment variables of the Application, `FEATURE` (the number) and `DOMAIN`, because that is what a plugin can pass to the command it runs: the helmfile reads them (also under the `ARGOCD_ENV_` prefix a sidecar plugin adds) when no state value is given. An Ingress carrying `ci-docs.example.org`, the defaults, means the variables did not reach the render. This repository's part is `.github/workflows/preview.yml`: a comment with the URLs, and a webhook nudge so Argo CD re-evaluates now rather than at its next poll.

## Adding another product

The stack is the unit to copy for the next integration, not the encryption chart. To add a product whose chart is published:

1. A `dependencies` entry in `Chart.yaml`, with a `condition: <name>.enabled`.
2. A `<name>:` block in `values.yaml`: that chart's own values, with its database, Redis, S3 and OIDC coordinates pointed at the fixed names above (the Docs and Drive blocks are the template, they differ only in names and ports).
3. Its database in `bootstrap.postgres.databases`, its bucket in `bootstrap.minio.buckets`, its client in `bootstrap.keycloak.clients`, its origin in `encryption.config.allowedFrameAncestors`.
4. Its lines in `templates/_checks.tpl` and the test file, so a mismatch fails the render.

## Known limits

- The shared chart's MinIO StatefulSet has no `serviceName`, which the 1.30 API schemas reject; the chart test validates only the objects this repository renders. Clusters from 1.32 accept it.
- The realm is imported once, at first boot. Changing `shared.keycloak.realm` afterwards does nothing; the bootstrap's clients and users are the way to change the realm.
- On an upgrade that changes the encryption image, the migration runs before the new pods (the hook is `pre-upgrade`); a change of the shared chart's passwords in the same upgrade is not seen by that run.
- Passwords, secrets and names go through shell quoting in the bootstrap scripts, so the values schema refuses quotes in them.
- The document server keeps nothing: a restart of its pod ends the editing sessions that were open (the files themselves are in MinIO). Drive learns its capabilities once, through the `configure-wopi` Job, and again every night at 3:00; a change of `onlyoffice.host` needs that Job to run again (a sync does it under Argo CD, `helm upgrade` does it too).
