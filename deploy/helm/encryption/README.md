# encryption Helm chart

Deploys the encryption service: one Deployment running the `lasuite/encryption` image
behind one Service answering on the two public hostnames, plus a migration Job run as a
pre-install/pre-upgrade hook. Nothing else: PostgreSQL, the SMTP relay, the OIDC provider
and an error collector are the operator's, the chart only takes their coordinates and
never creates persistent storage.

## Two versions, two tag families

The chart and the application are versioned apart. A `vX.Y.Z` git tag releases the
application image; a `chart/vX.Y.Z` tag releases the chart, and nothing else runs on it.
The chart therefore has no default image: `image.tag` (or `image.digest`) is required,
and a chart version says nothing about which application it deploys. Both can be tagged
on the same commit when a release changes both; the rule that keeps that safe is that a
chart tolerates the previous application version and vice versa, so they can also roll
out separately.

## Getting the chart

It is published on Docker Hub as an OCI artifact, in its own repository next to the
image: `lasuite/encryption-chart`. Pull by version, and keep the digest Helm prints:

```sh
helm pull oci://registry-1.docker.io/lasuite/encryption-chart --version 1.4.0
# Pulled: registry-1.docker.io/lasuite/encryption-chart:1.4.0
# Digest: sha256:9888faa6…
```

Then check who built it before trusting it. The digest is only a checksum; the build
provenance attestation is what binds it to a run of this repository's release workflow,
signed through Sigstore and logged in the public ledger, exactly as for the image:

```sh
cosign verify-attestation --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/suitenumerique/encryption/\.github/workflows/ci\.yml@' \
  lasuite/encryption-chart@sha256:9888faa6…
```

From then on, reference the chart the way Docker references an image, tag for humans
and digest for the machine. Helm resolves the digest and refuses anything else, whatever
happens to the tag later:

```sh
helm install encryption oci://registry-1.docker.io/lasuite/encryption-chart:1.4.0@sha256:9888faa6… \
  --namespace encryption --create-namespace --values my-values.yaml
```

Do the same for the image inside the values: verify `lasuite/encryption@<digest>` the
same way (the command is in `docker-compose.production.yaml`) and set both `image.tag`
and `image.digest`, which renders `lasuite/encryption:1.37.0@sha256:…`.

### With helmfile

The chart can be a helmfile release from the OCI artifact or from this repository, with
the values kept in the deployment's own files. A complete example lives in
[`deploy/helmfile/`](../../helmfile): a `helmfile.yaml.gotmpl` with one environment
per cluster and a `values.yaml.gotmpl` per environment. One limit, checked with
helmfile 1.1: it resolves an OCI chart by semver `version` only and rejects a digest in
`chart:`. To pin content from helmfile, take the chart from git with the commit id of
the `chart/vX.Y.Z` tag as `ref`, which the example shows.

### With Argo CD

Two example manifests live in [`deploy/argocd/`](../../argocd): an `Application` that
takes the chart from this repository at a `chart/vX.Y.Z` tag (or from the OCI artifact)
with the values in a separate deployment repository, and an `AppProject` restricting
which repositories may feed it. Both are commented with what pins what.

## Values

`values.yaml` documents every key; `values.schema.json` enforces them, so an unknown key
or a wrong type fails `helm install` instead of producing a pod that starts without a
variable. The required ones fail the render with their path in the message.

Two complete examples live in [`ci/`](ci): [`full-values.yaml`](ci/full-values.yaml)
turns every feature on with inline secrets, [`existing-secrets-values.yaml`](ci/existing-secrets-values.yaml)
is the production shape with every secret read from Secrets you created beforehand.
The chart test renders both.

The shape to know:

- `image.tag` and `image.digest`: which application to run, see above.
- `hosts.vault` and `hosts.interface`: the two public hostnames. TLS in front of them
  is mandatory.
- `config.*`: the non-secret variables, named after `.env.model`.
- `database.url` or `database.existingSecret`: the **runtime** role. `database.migration.*`:
  the **migrator** role, used by the hook Job only. The two roles are described in
  [`deploy/postgres/`](../../postgres).
- `sentry.enabled` with a DSN: error reporting, off by default.
- `extraEnv` and `extraEnvFrom`: raw Kubernetes `env` and `envFrom` entries for what
  the chart has no key for. They are appended, and Kubernetes keeps the first
  occurrence of a name, so they cannot override a chart-managed variable.
- `ingress.*`: one Ingress with a rule per host, both to the Service, one TLS entry
  covering both. Leave it disabled to route yourself.
- `podSecurityContext`, `securityContext`, `tmpVolume`, `resources`: the hardening of
  `docker-compose.production.yaml` (read-only root, no capabilities, non-root,
  memory-backed `/tmp` as the only writable path).
- `replicaCount`, `podDisruptionBudget`, `topologySpreadConstraints`, `networkPolicy`.

## Migrations

The Job named `<release>-encryption-migrate-<revision>` runs `prisma migrate deploy`
from the image with the migrator credentials before the Deployment is touched, on
install and on every upgrade. Helm waits for it; a failure stops the rollout and the
failed Job stays for its logs. Argo CD reads the same annotations and runs it as a
`PreSync` hook. Set `database.migration.enabled: false` to run migrations elsewhere.

## Tests

Two layers, one fast and one real.

`npm run test:helm` (helm and kubeconform on the PATH: `brew install helm kubeconform`).
It lints, validates the values schema, renders both examples, checks every object
against the Kubernetes API schemas, asserts on the rendered objects, and compares the
full render to a committed snapshot so any change shows in review. The one assertion to
keep in mind: the Deployment must pass every variable `src/server/env-schema.ts`
requires, read from that schema, so adding a required variable to the server without
adding it to the chart fails the build. In CI this runs on pull requests, on `main` and
on chart tags, never on application tags.

`deploy/helm/smoke-k3d.sh` (docker, k3d, kubectl, helm) creates a throwaway k3s cluster,
imports a locally built image, installs the chart into a namespace enforcing the
`restricted` Pod Security level, runs `helm test` (a pod inside the cluster calling
`/health` through the Service), upgrades in place and tests again. This is what a
render cannot show: admission, probes on the real image, the rolling update. Local only,
about a minute, `KEEP=1` leaves the cluster up for `kubectl`.
